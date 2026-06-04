#!/usr/bin/env python3
"""
UartSniffer Config Editor

An interactive CLI for editing .cfg rule files used by uartsniffer.
Syntax reference: src/parser_syntax.md

Usage:
    python tools/cfgedit.py [path-to-cfg]
"""

import os
import sys
from dataclasses import dataclass, field as dc_field
from typing import List, Optional, Tuple

# --- Limits (mirror src/uspy.h) --------------------------------------------
MAX_RULES        = 64
MAX_FILTERS      = 16
MAX_FIELDS       = 64
MAX_LABEL_LEN    = 64
MAX_UNIT_LEN     = 12
MAX_ENUM_ENTRIES = 16
MAX_ENUM_NAME    = 24

# --- ANSI colors -----------------------------------------------------------
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

R     = "\x1b[0m"
BOLD  = "\x1b[1m"
DIM   = "\x1b[2m"
RED   = "\x1b[91m"
GREEN = "\x1b[92m"
YEL   = "\x1b[93m"
BLUE  = "\x1b[94m"
MAG   = "\x1b[95m"
CYAN  = "\x1b[96m"
GRAY  = "\x1b[90m"


# --- Data Model ------------------------------------------------------------

FILTER_TYPES   = ("len", "minlen", "maxlen", "idx", "first", "last")
BASE_INT_TYPES = ("u8", "s8", "u16", "s16", "u32", "s32")
FLOAT_TYPES    = ("float", "double")
ENDIAN_TYPES   = ("u16", "s16", "u32", "s32", "float", "double")
ARRAY_TYPES    = ("array", "str", "bcd")
ALL_FIELD_TYPES = BASE_INT_TYPES + FLOAT_TYPES + ARRAY_TYPES


@dataclass
class Filter:
    type: str            # one of FILTER_TYPES
    value: int = 0
    idx: int = 0         # only meaningful for type == 'idx'

    def to_str(self) -> str:
        if self.type == "idx":
            return f"idx{self.idx}=0x{self.value:02X}"
        if self.type in ("first", "last"):
            return f"{self.type}=0x{self.value:02X}"
        return f"{self.type}={self.value}"


@dataclass
class EnumEntry:
    value: int
    name: str

    def to_str(self) -> str:
        return f"|{self.value}={self.name}"


@dataclass
class Field:
    type: str                              # 'u8'..'double', 'array', 'str', 'bcd'
    endian: str = ""                       # '', 'le', 'be'
    array_size: int = 0
    label: str = ""
    scale: float = 1.0
    offset: float = 0.0
    unit: str = ""
    fmt: str = ""                          # '', 'x','d','b','o','c'
    enums: List[EnumEntry] = dc_field(default_factory=list)

    def size_bytes(self) -> int:
        if self.type in ("u8", "s8"):                       return 1
        if self.type in ("u16", "s16"):                     return 2
        if self.type in ("u32", "s32", "float"):            return 4
        if self.type == "double":                           return 8
        if self.type in ARRAY_TYPES:                        return self.array_size
        return 0

    def type_token(self) -> str:
        if self.type == "array": return f"array-{self.array_size}"
        if self.type == "str":   return f"str-{self.array_size}"
        if self.type == "bcd":   return f"bcd-{self.array_size}"
        if self.type in ENDIAN_TYPES and self.endian:
            return f"{self.type}{self.endian}"
        return self.type

    def modifiers_str(self) -> str:
        parts: List[str] = []
        if self.scale != 1.0:
            parts.append(f"@{_fmt_num(self.scale)}")
        if self.offset != 0.0:
            if self.offset > 0:
                parts.append(f"+{_fmt_num(self.offset)}")
            else:
                parts.append(_fmt_num(self.offset))   # negative number includes '-'
        if self.unit:
            parts.append(f"={self.unit}")
        if self.fmt:
            parts.append(f"%{self.fmt}")
        for e in self.enums:
            parts.append(e.to_str())
        return "".join(parts)

    def to_str(self) -> str:
        inner = self.type_token()
        mods = self.modifiers_str()
        if self.label or mods:
            inner += f"({self.label})"
        inner += mods
        return f"[{inner}]"

    def has_any_modifier(self) -> bool:
        return (self.scale != 1.0 or self.offset != 0.0 or
                bool(self.unit) or bool(self.fmt) or bool(self.enums))


@dataclass
class Rule:
    filters: List[Filter] = dc_field(default_factory=list)
    fields:  List[Field]  = dc_field(default_factory=list)
    label:   str          = ""

    def to_str(self) -> str:
        parts: List[str] = []
        if self.filters:
            parts.append("{" + ", ".join(f.to_str() for f in self.filters) + "}")
        for f in self.fields:
            parts.append(f.to_str())
        line = " ".join(parts)
        if self.label:
            line += f"   # {self.label}"
        return line

    def total_field_bytes(self) -> int:
        return sum(f.size_bytes() for f in self.fields)


def _fmt_num(v: float) -> str:
    """Compact numeric format: integers stay as integers, floats use %g."""
    if v == int(v):
        return str(int(v))
    return f"{v:g}"


# --- Parser ----------------------------------------------------------------

def parse_int(s: str) -> int:
    """Accept dec or 0x-prefixed hex."""
    return int(s.strip(), 0)


def _parse_filter_block(text: str) -> List[Filter]:
    out: List[Filter] = []
    for tok in text.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            if tok.startswith("len="):
                out.append(Filter("len", parse_int(tok[4:])))
            elif tok.startswith("minlen="):
                out.append(Filter("minlen", parse_int(tok[7:])))
            elif tok.startswith("maxlen="):
                out.append(Filter("maxlen", parse_int(tok[7:])))
            elif tok.startswith("first="):
                out.append(Filter("first", parse_int(tok[6:])))
            elif tok.startswith("last="):
                out.append(Filter("last", parse_int(tok[5:])))
            elif tok.startswith("idx"):
                eq = tok.find("=")
                if eq < 0:
                    continue
                out.append(Filter("idx", parse_int(tok[eq+1:]),
                                  int(tok[3:eq])))
        except ValueError:
            pass
    return out


_MOD_TERMINATORS = set("@+-=%|")


def _parse_field_modifiers(text: str, fld: Field) -> None:
    i, n = 0, len(text)
    while i < n:
        c = text[i]; i += 1
        if c in " \t":
            continue
        if c == "@":
            j = i
            while j < n and text[j] not in _MOD_TERMINATORS:
                j += 1
            try:
                fld.scale = float(text[i:j].strip())
            except ValueError:
                pass
            i = j
        elif c in "+-":
            j = i
            while j < n and text[j] not in _MOD_TERMINATORS:
                j += 1
            try:
                v = float(text[i:j].strip())
                fld.offset = -v if c == "-" else v
            except ValueError:
                pass
            i = j
        elif c == "=":
            j = i
            while j < n and text[j] not in _MOD_TERMINATORS:
                j += 1
            fld.unit = text[i:j].strip()[:MAX_UNIT_LEN]
            i = j
        elif c == "%":
            if i < n:
                fld.fmt = text[i]
                i += 1
        elif c == "|":
            eq = text.find("=", i)
            if eq < 0:
                break
            try:
                val = parse_int(text[i:eq])
            except ValueError:
                i = eq + 1
                continue
            i = eq + 1
            j = i
            while j < n and text[j] not in ("|", "@", "%"):
                j += 1
            name = text[i:j].strip()[:MAX_ENUM_NAME]
            if name and len(fld.enums) < MAX_ENUM_ENTRIES:
                fld.enums.append(EnumEntry(val, name))
            i = j


def _parse_field_block(text: str) -> Optional[Field]:
    text = text.strip()
    fld = Field(type="")

    mod_str = ""
    lp = text.find("(")
    if lp >= 0:
        rp = text.rfind(")")
        if rp < 0 or rp <= lp:
            return None
        fld.label = text[lp+1:rp][:MAX_LABEL_LEN]
        mod_str = text[rp+1:]
        type_str = text[:lp].strip()
    else:
        type_str = text

    if type_str.startswith("array-"):
        try: fld.array_size = int(type_str[6:])
        except ValueError: return None
        fld.type = "array"
    elif type_str.startswith("str-"):
        try: fld.array_size = int(type_str[4:])
        except ValueError: return None
        fld.type = "str"
    elif type_str.startswith("bcd-"):
        try: fld.array_size = int(type_str[4:])
        except ValueError: return None
        fld.type = "bcd"
    elif type_str in BASE_INT_TYPES + FLOAT_TYPES:
        fld.type = type_str
    else:
        if len(type_str) >= 2 and type_str[-2:] in ("le", "be"):
            base = type_str[:-2]
            if base in ("u16", "s16", "u32", "s32", "float", "double"):
                fld.type = base
                fld.endian = type_str[-2:]
            else:
                return None
        else:
            return None

    if mod_str:
        _parse_field_modifiers(mod_str, fld)
    return fld


def parse_rule_line(line: str) -> Optional[Rule]:
    rule_label = ""
    hash_pos = line.find("#")
    if hash_pos >= 0:
        rule_label = line[hash_pos+1:].strip()
        line = line[:hash_pos]
    line = line.strip()

    rule = Rule(label=rule_label)
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c in " \t":
            i += 1; continue
        if c == "{":
            end = line.find("}", i)
            if end < 0: return None
            rule.filters.extend(_parse_filter_block(line[i+1:end]))
            i = end + 1
        elif c == "[":
            end = line.find("]", i)
            if end < 0: return None
            f = _parse_field_block(line[i+1:end])
            if f is not None:
                rule.fields.append(f)
            i = end + 1
        else:
            i += 1

    if not rule.filters and not rule.fields:
        return None
    return rule


# --- File I/O --------------------------------------------------------------

def load_file(path: str) -> Tuple[List[str], List[Rule]]:
    """Returns (header_lines, rules). header_lines = lines before first rule line."""
    with open(path, "r", encoding="utf-8") as f:
        raw = f.readlines()

    header: List[str] = []
    rules:  List[Rule] = []
    in_rules = False
    for ln in raw:
        ln = ln.rstrip("\n").rstrip("\r")
        s = ln.strip()
        is_rule = bool(s) and not s.startswith("#") and not s.startswith(";")
        if is_rule:
            in_rules = True
            r = parse_rule_line(ln)
            if r is not None:
                rules.append(r)
        elif not in_rules:
            header.append(ln)
    while header and not header[-1].strip():
        header.pop()
    return header, rules


def save_file(path: str, header: List[str], rules: List[Rule]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        if header:
            for ln in header:
                f.write(ln + "\n")
            f.write("\n")
        for r in rules:
            f.write(r.to_str() + "\n")


# --- Input helpers ---------------------------------------------------------

def _input(prompt_text: str) -> Optional[str]:
    try:
        return input(prompt_text)
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def prompt_str(msg: str, default: Optional[str] = None,
               allow_empty: bool = True) -> Optional[str]:
    if default is not None and default != "":
        suffix = f" [{GRAY}{default}{R}]"
    elif default == "":
        suffix = f" [{GRAY}<empty>{R}]"
    else:
        suffix = ""
    s = _input(f"{msg}{suffix}: ")
    if s is None:
        return None
    s = s.rstrip("\r\n")
    if s == "":
        if default is not None:
            return default
        return "" if allow_empty else None
    return s


def prompt_int(msg: str, default: Optional[int] = None) -> Optional[int]:
    while True:
        s = prompt_str(msg, str(default) if default is not None else None)
        if s is None:
            return None
        if s == "":
            if default is None:
                continue
            return default
        try:
            return int(s, 0)
        except ValueError:
            print(f"  {RED}Invalid number: {s!r}{R}")


def prompt_float(msg: str, default: Optional[float] = None) -> Optional[float]:
    while True:
        s = prompt_str(msg, _fmt_num(default) if default is not None else None)
        if s is None:
            return None
        if s == "":
            if default is None:
                continue
            return default
        try:
            return float(s)
        except ValueError:
            print(f"  {RED}Invalid number: {s!r}{R}")


def prompt_menu(title: str, options: List[Tuple[str, str]],
                default: Optional[str] = None) -> Optional[str]:
    """options = [(key, label), ...]. Returns chosen key or None on Ctrl-C/EOF."""
    print(f"{CYAN}{title}{R}")
    valid = {k for k, _ in options}
    for k, lbl in options:
        marker = f" {GRAY}<default>{R}" if k == default else ""
        print(f"   [{BOLD}{k}{R}] {lbl}{marker}")
    while True:
        s = _input(f"{BOLD}> {R}")
        if s is None:
            return None
        s = s.strip()
        if not s and default is not None:
            return default
        if s in valid:
            return s
        print(f"  {RED}Invalid choice: {s!r}{R}")


def prompt_yes_no(msg: str, default: bool = False) -> bool:
    suffix = "[y/N]" if not default else "[Y/n]"
    while True:
        s = _input(f"{msg} {suffix}: ")
        if s is None:
            return False
        s = s.strip().lower()
        if not s:
            return default
        if s in ("y", "yes"): return True
        if s in ("n", "no"):  return False
        print(f"  {RED}Please answer y or n.{R}")


# --- Rule rendering --------------------------------------------------------

def render_rule_list(rules: List[Rule]) -> None:
    if not rules:
        print(f"   {DIM}(no rules yet){R}")
        return
    for i, r in enumerate(rules, 1):
        s = r.to_str()
        prefix = f"   {GRAY}#{i:2d}{R}  "
        ind    = "        "
        if len(s) <= 70:
            print(prefix + s)
        else:
            # naive wrap by token (split before each '[' or '{' that overflows)
            tokens = _split_tokens(s)
            line = prefix
            base_pad = len(prefix)
            for t in tokens:
                if len(line) + len(t) > 75 and line.strip() != prefix.strip():
                    print(line)
                    line = ind + t
                else:
                    line += t
            if line.strip():
                print(line)


def _split_tokens(s: str) -> List[str]:
    out: List[str] = []
    cur = ""
    depth_paren = 0
    for c in s:
        cur += c
        if c in "([{":  depth_paren += 1
        elif c in ")]}": depth_paren -= 1
        if c == " " and depth_paren == 0:
            out.append(cur)
            cur = ""
    if cur:
        out.append(cur)
    return out


# --- Filter wizard ---------------------------------------------------------

_FILTER_MENU = [
    ("1", "len=N        exact length"),
    ("2", "minlen=N     length >= N"),
    ("3", "maxlen=N     length <= N"),
    ("4", "idxN=V       byte at index N == V"),
    ("5", "first=V      first byte == V  (alias of idx0=)"),
    ("6", "last=V       last byte == V"),
]
_FKEY = {"1": "len", "2": "minlen", "3": "maxlen",
         "4": "idx", "5": "first", "6": "last"}
_FTYPE_TO_KEY = {v: k for k, v in _FKEY.items()}


def _wizard_one_filter(existing: Optional[Filter]) -> Optional[Filter]:
    cur_key = _FTYPE_TO_KEY.get(existing.type) if existing else None
    if existing:
        print(f"  {GRAY}current: {{{existing.to_str()}}}{R}")
    k = prompt_menu("  Filter type:", _FILTER_MENU + [("0", "Cancel")],
                    default=cur_key)
    if k is None or k == "0":
        return None
    ftype = _FKEY[k]
    f = Filter(type=ftype)

    if ftype == "idx":
        cur_idx = existing.idx if (existing and existing.type == "idx") else None
        cur_val = existing.value if (existing and existing.type == "idx") else None
        idx = prompt_int("    Index N (byte offset)", cur_idx)
        if idx is None: return None
        val = prompt_int("    Byte value (e.g. 0xAA or 170)", cur_val)
        if val is None: return None
        f.idx, f.value = idx, val
    elif ftype in ("first", "last"):
        cur = existing.value if (existing and existing.type == ftype) else None
        val = prompt_int("    Byte value (e.g. 0xAA)", cur)
        if val is None: return None
        f.value = val
    else:
        cur = existing.value if (existing and existing.type == ftype) else None
        val = prompt_int("    Length", cur)
        if val is None: return None
        f.value = val
    return f


def filter_loop(existing: List[Filter]) -> Optional[List[Filter]]:
    print(f"\n{MAG}-- Filters --{R}")
    out: List[Filter] = []

    for i, ef in enumerate(existing, 1):
        print(f"\n  {GRAY}existing filter #{i}: {{{ef.to_str()}}}{R}")
        k = prompt_menu("  Action:", [
            ("1", "Keep"),
            ("2", "Edit"),
            ("3", "Delete"),
        ], default="1")
        if k is None:
            return None
        if k == "1":
            out.append(ef)
        elif k == "2":
            new_f = _wizard_one_filter(ef)
            out.append(new_f if new_f is not None else ef)
        else:
            print(f"  {YEL}deleted{R}")

    while True:
        if len(out) >= MAX_FILTERS:
            print(f"  {YEL}reached MAX_FILTERS ({MAX_FILTERS}){R}")
            break
        cur_str = "{" + ", ".join(f.to_str() for f in out) + "}" if out else "(none)"
        print(f"\n  {GRAY}current filters: {cur_str}{R}")
        if not prompt_yes_no(f"  Add {'another' if out else 'a'} filter?",
                             default=False):
            break
        new_f = _wizard_one_filter(None)
        if new_f is not None:
            out.append(new_f)
    return out


# --- Field wizard ----------------------------------------------------------

_FIELD_MENU = [
    ("1",  "u8           1 byte unsigned"),
    ("2",  "s8           1 byte signed"),
    ("3",  "u16          2 bytes unsigned"),
    ("4",  "s16          2 bytes signed"),
    ("5",  "u32          4 bytes unsigned"),
    ("6",  "s32          4 bytes signed"),
    ("7",  "float        4 bytes IEEE-754"),
    ("8",  "double       8 bytes IEEE-754"),
    ("9",  "array-N      N raw bytes (hex dump)"),
    ("10", "str-N        N bytes ASCII string"),
    ("11", "bcd-N        N bytes BCD digits"),
]
_FLDKEY = {
    "1": "u8", "2": "s8", "3": "u16", "4": "s16",
    "5": "u32", "6": "s32", "7": "float", "8": "double",
    "9": "array", "10": "str", "11": "bcd",
}
_FLDTYPE_TO_KEY = {v: k for k, v in _FLDKEY.items()}


def _budget_from_filters(filters: List[Filter]) -> Optional[int]:
    """Returns budget if any filter constrains total length."""
    for f in filters:
        if f.type == "len":
            return f.value
    for f in filters:
        if f.type == "maxlen":
            return f.value
    return None


def _wizard_one_field(existing: Optional[Field],
                      budget_left: Optional[int]) -> Optional[Field]:
    if existing:
        print(f"  {GRAY}current: {existing.to_str()}{R}")
    if budget_left is not None:
        print(f"  {DIM}bytes available in this rule: {budget_left}{R}")

    cur_key = _FLDTYPE_TO_KEY.get(existing.type) if existing else None
    k = prompt_menu("  Field type:", _FIELD_MENU + [("0", "Cancel")],
                    default=cur_key)
    if k is None or k == "0":
        return None
    ftype = _FLDKEY[k]
    fld = Field(type=ftype)

    if ftype in ARRAY_TYPES:
        cur_sz = existing.array_size if (existing and existing.type == ftype) else None
        sz = prompt_int(f"    Size N in bytes", cur_sz)
        if sz is None or sz <= 0:
            return None
        fld.array_size = sz
    elif ftype in ENDIAN_TYPES:
        cur_e = existing.endian if (existing and existing.type == ftype) else ""
        endian_default = {"": "1", "le": "2", "be": "3"}.get(cur_e, "1")
        ek = prompt_menu("    Endian:", [
            ("1", "global (use CLI -lemode/-bemode)"),
            ("2", "little endian (le)"),
            ("3", "big endian (be)"),
        ], default=endian_default)
        if ek is None: return None
        fld.endian = {"1": "", "2": "le", "3": "be"}[ek]

    # label
    cur_label = existing.label if existing else ""
    lbl = prompt_str("    Label (Enter to skip)", default=cur_label)
    if lbl is None: return None
    if len(lbl) > MAX_LABEL_LEN:
        lbl = lbl[:MAX_LABEL_LEN]
        print(f"    {YEL}label truncated to {MAX_LABEL_LEN} chars{R}")
    fld.label = lbl

    # carry over modifiers as defaults (edit mode)
    if existing:
        fld.scale  = existing.scale
        fld.offset = existing.offset
        fld.unit   = existing.unit
        fld.fmt    = existing.fmt
        fld.enums  = list(existing.enums)

    _modifier_loop(fld)

    if budget_left is not None and fld.size_bytes() > budget_left:
        print(f"  {YEL}warning: this field needs {fld.size_bytes()} bytes "
              f"but only {budget_left} remain in the rule{R}")
        if not prompt_yes_no("  Add it anyway?", default=False):
            return None
    return fld


# --- Modifier wizard -------------------------------------------------------

_MOD_MENU = [
    ("1", "@scale       multiplier (e.g. @0.1)"),
    ("2", "+offset      add this value after scaling"),
    ("3", "-offset      subtract this value after scaling"),
    ("4", "=unit        unit suffix (e.g. =V)"),
    ("5", "%fmt         display format  x / d / b / o / c"),
    ("6", "|enum        enum mapping  value=name"),
]


def _list_existing_mods(fld: Field) -> List[Tuple[str, object]]:
    out: List[Tuple[str, object]] = []
    if fld.scale  != 1.0: out.append(("scale",  fld.scale))
    if fld.offset != 0.0: out.append(("offset", fld.offset))
    if fld.unit:           out.append(("unit",   fld.unit))
    if fld.fmt:            out.append(("fmt",    fld.fmt))
    for e in fld.enums:    out.append(("enum",   e))
    return out


def _apply_mod(fld: Field, mtype: str, mval) -> None:
    if   mtype == "scale":  fld.scale  = mval
    elif mtype == "offset": fld.offset = mval
    elif mtype == "unit":   fld.unit   = mval
    elif mtype == "fmt":    fld.fmt    = mval
    elif mtype == "enum":   fld.enums.append(mval)


def _format_mod(mtype: str, mval) -> str:
    if mtype == "scale":  return f"@{_fmt_num(mval)}"
    if mtype == "offset": return f"+{_fmt_num(mval)}" if mval > 0 else _fmt_num(mval)
    if mtype == "unit":   return f"={mval}"
    if mtype == "fmt":    return f"%{mval}"
    if mtype == "enum":   return mval.to_str()
    return "?"


def _wizard_one_mod(existing: Optional[Tuple[str, object]]) -> Optional[Tuple[str, object]]:
    cur_key = None
    if existing:
        et = existing[0]; ev = existing[1]
        cur_key = {"scale": "1", "unit": "4", "fmt": "5", "enum": "6"}.get(et)
        if et == "offset":
            cur_key = "2" if ev >= 0 else "3"

    k = prompt_menu("    Modifier type:", _MOD_MENU + [("0", "Cancel")],
                    default=cur_key)
    if k is None or k == "0":
        return None

    if k == "1":
        cur = existing[1] if (existing and existing[0] == "scale") else None
        v = prompt_float("      Scale factor", default=cur)
        return ("scale", v) if v is not None else None
    if k == "2":
        cur = existing[1] if (existing and existing[0] == "offset" and existing[1] >= 0) else None
        v = prompt_float("      Positive offset", default=cur)
        return ("offset", v) if v is not None else None
    if k == "3":
        cur = abs(existing[1]) if (existing and existing[0] == "offset" and existing[1] < 0) else None
        v = prompt_float("      Value to subtract (positive number)", default=cur)
        return ("offset", -v) if v is not None else None
    if k == "4":
        cur = existing[1] if (existing and existing[0] == "unit") else None
        v = prompt_str("      Unit string", default=cur, allow_empty=False)
        if not v: return None
        return ("unit", v[:MAX_UNIT_LEN])
    if k == "5":
        cur = existing[1] if (existing and existing[0] == "fmt") else None
        fk = prompt_menu("      Format char:", [
            ("1", "x   hex only        (e.g. 0x41)"),
            ("2", "d   decimal only    (e.g. 65)"),
            ("3", "b   binary          (e.g. 0b01000001)"),
            ("4", "o   octal           (e.g. 0101)"),
            ("5", "c   ASCII character (e.g. 'A')"),
        ], default={"x": "1", "d": "2", "b": "3", "o": "4", "c": "5"}.get(cur))
        if fk is None: return None
        return ("fmt", {"1": "x", "2": "d", "3": "b", "4": "o", "5": "c"}[fk])
    if k == "6":
        cur_v = existing[1].value if (existing and existing[0] == "enum") else None
        cur_n = existing[1].name  if (existing and existing[0] == "enum") else None
        v = prompt_int("      Enum integer value", default=cur_v)
        if v is None: return None
        n = prompt_str("      Enum name", default=cur_n, allow_empty=False)
        if not n: return None
        return ("enum", EnumEntry(v, n[:MAX_ENUM_NAME]))
    return None


def _modifier_loop(fld: Field) -> None:
    """Walk through existing modifiers on fld (keep/edit/delete), then prompt for new ones."""
    existing_mods = _list_existing_mods(fld)
    # Reset, then replay through keep/edit/delete
    fld.scale, fld.offset, fld.unit, fld.fmt, fld.enums = 1.0, 0.0, "", "", []

    for mt, mv in existing_mods:
        print(f"\n  {GRAY}existing modifier: {_format_mod(mt, mv)}{R}")
        k = prompt_menu("    Action:", [
            ("1", "Keep"),
            ("2", "Edit"),
            ("3", "Delete"),
        ], default="1")
        if k is None or k == "1":
            _apply_mod(fld, mt, mv)
        elif k == "2":
            new = _wizard_one_mod((mt, mv))
            if new is None:
                _apply_mod(fld, mt, mv)
            else:
                _apply_mod(fld, new[0], new[1])
        else:
            print(f"    {YEL}deleted{R}")

    while True:
        if len(fld.enums) >= MAX_ENUM_ENTRIES and not _can_add_other_mod(fld):
            print(f"  {YEL}all modifier slots used{R}")
            break
        ms = fld.modifiers_str()
        print(f"\n  {GRAY}current modifiers: {ms if ms else '(none)'}{R}")
        if not prompt_yes_no(f"    Add {'another' if ms else 'a'} modifier?",
                             default=False):
            break
        new = _wizard_one_mod(None)
        if new is None:
            continue
        if new[0] == "enum" and len(fld.enums) >= MAX_ENUM_ENTRIES:
            print(f"    {YEL}reached MAX_ENUM_ENTRIES ({MAX_ENUM_ENTRIES}){R}")
            continue
        _apply_mod(fld, new[0], new[1])


def _can_add_other_mod(fld: Field) -> bool:
    return (fld.scale == 1.0 or fld.offset == 0.0 or
            not fld.unit or not fld.fmt)


# --- Field loop ------------------------------------------------------------

def field_loop(existing: List[Field],
               filters: List[Filter]) -> Optional[List[Field]]:
    print(f"\n{MAG}-- Fields --{R}")
    if filters:
        cur = "{" + ", ".join(f.to_str() for f in filters) + "}"
        print(f"  {GRAY}confirmed filters: {cur}{R}")
    budget = _budget_from_filters(filters)
    if budget is not None:
        src = "len" if any(f.type == "len" for f in filters) else "maxlen"
        print(f"  {GRAY}bytes budget: {budget} (from {src}=){R}")
    else:
        print(f"  {GRAY}no length filter, bytes budget unlimited{R}")

    out: List[Field] = []
    def used():      return sum(f.size_bytes() for f in out)
    def remaining(): return (budget - used()) if budget is not None else None

    for i, ef in enumerate(existing, 1):
        print(f"\n  {GRAY}existing field #{i}: {ef.to_str()}{R}")
        if budget is not None:
            print(f"  {DIM}bytes used: {used()} / {budget}{R}")
        k = prompt_menu("  Action:", [
            ("1", "Keep"),
            ("2", "Edit"),
            ("3", "Delete"),
        ], default="1")
        if k is None:
            return None
        if k == "1":
            out.append(ef)
        elif k == "2":
            new_f = _wizard_one_field(ef, remaining())
            out.append(new_f if new_f is not None else ef)
        else:
            print(f"  {YEL}deleted{R}")

    while True:
        if len(out) >= MAX_FIELDS:
            print(f"  {YEL}reached MAX_FIELDS ({MAX_FIELDS}){R}")
            break
        if budget is not None:
            r = remaining()
            print(f"\n  {GRAY}bytes used: {used()} / {budget} "
                  f"({r if r is not None and r >= 0 else 0} remaining){R}")
            if r is not None and r <= 0:
                if not prompt_yes_no("  Budget full; add more anyway?",
                                     default=False):
                    break
        else:
            print()
        if not prompt_yes_no(f"  Add {'another' if out else 'a'} field?",
                             default=False):
            break
        new_f = _wizard_one_field(None, remaining())
        if new_f is not None:
            out.append(new_f)
    return out


# --- Rule wizard (top level) -----------------------------------------------

def rule_wizard(existing: Optional[Rule]) -> Optional[Rule]:
    title = "Editing rule" if existing else "New rule"
    print(f"\n{BOLD}{MAG}+== {title} ==+{R}")
    if existing:
        print(f"  {DIM}current: {existing.to_str()}{R}")

    filters = filter_loop(existing.filters if existing else [])
    if filters is None: return None

    fields = field_loop(existing.fields if existing else [], filters)
    if fields is None: return None

    if not filters and not fields:
        print(f"  {RED}rule must contain at least one filter or field{R}")
        return None

    print(f"\n{MAG}-- Rule label --{R}")
    cur_lbl = existing.label if existing else ""
    new_lbl = prompt_str("  Rule label (will appear after '#' at end of line; Enter to skip)",
                         default=cur_lbl)
    if new_lbl is None: return None
    label = new_lbl[:MAX_LABEL_LEN]

    rule = Rule(filters=filters, fields=fields, label=label)
    print(f"\n{MAG}-- Composed rule --{R}")
    print(f"  {rule.to_str()}")
    if prompt_yes_no("  Save this rule?", default=True):
        return rule
    print(f"  {YEL}discarded{R}")
    return None


# --- Rule list menu --------------------------------------------------------

def rule_list_menu(state: dict) -> None:
    while True:
        print()
        print(f"{BOLD}{'=' * 64}{R}")
        title = f"  File: {BLUE}{state['file']}{R}"
        if state["dirty"]:
            title += f"  {YEL}[unsaved changes]{R}"
        if state.get("new", False):
            title += f"  {GRAY}(new){R}"
        print(title)
        print(f"{BOLD}{'=' * 64}{R}")
        render_rule_list(state["rules"])
        print(f"  {GRAY}-- total: {len(state['rules'])} rule(s){R}")
        print(f"{DIM}{'-' * 64}{R}")
        k = prompt_menu("Action:", [
            ("1", "Add rule"),
            ("2", "Edit rule"),
            ("3", "Delete rule"),
            ("4", "Save"),
            ("5", "Save as ..."),
            ("6", "Back to main menu"),
        ])
        if k is None or k == "6":
            if state["dirty"]:
                if not prompt_yes_no("  Unsaved changes; discard?", default=False):
                    continue
            return

        if k == "1":
            if len(state["rules"]) >= MAX_RULES:
                print(f"  {RED}reached MAX_RULES ({MAX_RULES}){R}")
                continue
            r = rule_wizard(None)
            if r is not None:
                state["rules"].append(r)
                state["dirty"] = True
                print(f"  {GREEN}rule added (now {len(state['rules'])} total){R}")
        elif k == "2":
            if not state["rules"]:
                print(f"  {YEL}no rules to edit{R}"); continue
            idx = prompt_int(f"  Rule number to edit (1..{len(state['rules'])})")
            if idx is None or not (1 <= idx <= len(state["rules"])):
                print(f"  {RED}invalid number{R}"); continue
            r = rule_wizard(state["rules"][idx - 1])
            if r is not None:
                state["rules"][idx - 1] = r
                state["dirty"] = True
                print(f"  {GREEN}rule #{idx} updated{R}")
        elif k == "3":
            if not state["rules"]:
                print(f"  {YEL}no rules to delete{R}"); continue
            idx = prompt_int(f"  Rule number to delete (1..{len(state['rules'])})")
            if idx is None or not (1 <= idx <= len(state["rules"])):
                print(f"  {RED}invalid number{R}"); continue
            r = state["rules"][idx - 1]
            print(f"    {GRAY}{r.to_str()}{R}")
            if prompt_yes_no(f"  Really delete rule #{idx}?", default=False):
                del state["rules"][idx - 1]
                state["dirty"] = True
                print(f"  {GREEN}deleted{R}")
        elif k == "4":
            try:
                save_file(state["file"], state["header"], state["rules"])
                state["dirty"] = False
                state["new"]   = False
                print(f"  {GREEN}saved to {state['file']}{R}")
            except OSError as e:
                print(f"  {RED}save failed: {e}{R}")
        elif k == "5":
            path = prompt_str("  Save-as path", allow_empty=False)
            if not path: continue
            if os.path.exists(path):
                if not prompt_yes_no(f"  {path} exists; overwrite?", default=False):
                    continue
            try:
                save_file(path, state["header"], state["rules"])
                state["file"]  = path
                state["dirty"] = False
                state["new"]   = False
                print(f"  {GREEN}saved to {path}{R}")
            except OSError as e:
                print(f"  {RED}save failed: {e}{R}")


# --- Main menu -------------------------------------------------------------

def open_file_flow() -> Optional[dict]:
    path = prompt_str("  File to open", allow_empty=False)
    if not path: return None
    if not os.path.exists(path):
        print(f"  {RED}not found: {path}{R}")
        return None
    try:
        header, rules = load_file(path)
    except OSError as e:
        print(f"  {RED}cannot read: {e}{R}")
        return None
    print(f"  {GREEN}loaded {len(rules)} rule(s) from {path}{R}")
    return {"file": path, "header": header, "rules": rules,
            "dirty": False, "new": False}


def new_file_flow() -> Optional[dict]:
    path = prompt_str("  New file path", allow_empty=False)
    if not path: return None
    if os.path.exists(path):
        print(f"  {YEL}{path} already exists{R}")
        k = prompt_menu("  Choose:", [
            ("1", "Open existing instead"),
            ("2", "Replace (will overwrite on Save)"),
            ("3", "Cancel"),
        ], default="1")
        if k == "1":
            try:
                header, rules = load_file(path)
            except OSError as e:
                print(f"  {RED}cannot read: {e}{R}")
                return None
            return {"file": path, "header": header, "rules": rules,
                    "dirty": False, "new": False}
        if k != "2":
            return None
    return {"file": path, "header": [], "rules": [],
            "dirty": True, "new": True}


def main_menu() -> None:
    # Allow direct file argument
    initial_state = None
    if len(sys.argv) > 1:
        path = sys.argv[1]
        if os.path.exists(path):
            try:
                header, rules = load_file(path)
                print(f"  {GREEN}loaded {len(rules)} rule(s) from {path}{R}")
                initial_state = {"file": path, "header": header, "rules": rules,
                                 "dirty": False, "new": False}
            except OSError as e:
                print(f"  {RED}cannot read {path}: {e}{R}")
        else:
            initial_state = {"file": path, "header": [], "rules": [],
                             "dirty": True, "new": True}
    if initial_state:
        rule_list_menu(initial_state)

    while True:
        print()
        print(f"{BOLD}{'=' * 64}{R}")
        print(f"{BOLD}      UartSniffer Config Editor{R}")
        print(f"{BOLD}{'=' * 64}{R}")
        k = prompt_menu("Main menu:", [
            ("1", "New file"),
            ("2", "Open file"),
            ("3", "Quit"),
        ])
        if k is None or k == "3":
            print("bye.")
            return
        if k == "1":
            s = new_file_flow()
            if s: rule_list_menu(s)
        elif k == "2":
            s = open_file_flow()
            if s: rule_list_menu(s)


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nbye.")
