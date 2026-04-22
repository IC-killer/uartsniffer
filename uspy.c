/*
 * sniffer.c  —  Serial Port Sniffer
 *
 * Features:
 *   -i <port>     input port  (required)
 *   -o <port>     output port (required)
 *   -b <baud>     baud rate   (default 9600)
 *   -c <file>     protocol config file
 *   -lemode       parse as little-endian (default)
 *   -bemode       parse as big-endian
 *
 * Config field types:
 *   u8  s8  u16  s16  u32  s32  float  double
 *   array-N(label)   raw N-byte array, printed as hex
 *   *be / *le suffix overrides global endian per-field
 *
 * Hotkeys:
 *   Ctrl+R  or  Alt+R   clear terminal
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* ── limits ──────────────────────────────────────────────────────────────── */
#define BUF_SIZE 1024
#define MAX_PORT_LEN 32
#define LOG_FILE "sniff.log"
#define COLS_PER_ROW 16
#define MAX_RULES 64
#define MAX_FILTERS 16
#define MAX_FIELDS 64
#define MAX_LABEL_LEN 64
#define MAX_LINE_LEN 512

/* ── ANSI ────────────────────────────────────────────────────────────────── */
#define R "\x1b[0m"
#define GRAY "\x1b[90m"
#define GREEN "\x1b[92m"
#define CYAN "\x1b[96m"
#define YEL "\x1b[93m"
#define RED "\x1b[91m"
#define MAG "\x1b[95m"
#define BOLD "\x1b[1m"
#define DIM "\x1b[2m"
#define BLUE "\x1b[94m"
#define WHT "\x1b[97m"

/* ── box chars (plain ASCII) ─────────────────────────────────────────────── */
#define BOX_TL "+"
#define BOX_TR "+"
#define BOX_BL "+"
#define BOX_BR "+"
#define BOX_H "-"
#define BOX_V "|"
#define BOX_ML "+" /* mid-left  tee */
#define BOX_MR "+" /* mid-right tee */

/* ═════════════════════════════════════════════════════════════════════════
   Data structures
   ═════════════════════════════════════════════════════════════════════════ */

typedef enum { FT_LEN, FT_IDX } FilterType;
typedef struct {
  FilterType type;
  int idx;
  int value;
} Filter;

/* DT_ARRAY is endian-agnostic; endian_override only matters for numeric types
 */
typedef enum {
  DT_U8,
  DT_S8,
  DT_U16,
  DT_S16,
  DT_U32,
  DT_S32,
  DT_FLOAT,
  DT_DOUBLE,
  DT_ARRAY, /* [array-N(label)] */
} DataType;

/* per-field endian override */
typedef enum { EO_GLOBAL = 0, EO_LE, EO_BE } EndianOverride;

typedef struct {
  DataType type;
  int array_size;        /* DT_ARRAY: number of bytes */
  EndianOverride endian; /* EO_GLOBAL = use cfg->big_endian */
  char label[MAX_LABEL_LEN];
} Field;

typedef struct {
  char raw[MAX_LINE_LEN];
  Filter filters[MAX_FILTERS];
  int filter_count;
  Field fields[MAX_FIELDS];
  int field_count;
  char rule_label[MAX_LABEL_LEN];
} Rule;

typedef struct {
  Rule rules[MAX_RULES];
  int count;
} RuleSet;

typedef struct {
  char portIn[MAX_PORT_LEN];
  char portOut[MAX_PORT_LEN];
  int baud;
  char cfgFile[256];
  int useParser;
  int big_endian; /* 0=LE (default), 1=BE */
  FILE *logFile;
  RuleSet rs;
} Config;

typedef struct {
  HANDLE hSrc;
  HANDLE hDst;
  const char *label;
  const char *color;
  Config *cfg;
} ForwardArgs;

/* shared mutex so console output from two threads doesn't interleave */
static CRITICAL_SECTION g_print_lock;

/* ═════════════════════════════════════════════════════════════════════════
   String helpers
   ═════════════════════════════════════════════════════════════════════════ */
static void str_trim(char *s) {
  int i = 0;
  while (s[i] == ' ' || s[i] == '\t')
    i++;
  if (i)
    memmove(s, s + i, strlen(s + i) + 1);
  int n = (int)strlen(s);
  while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' ||
                   s[n - 1] == '\n'))
    s[--n] = '\0';
}
static int str_starts(const char *s, const char *p) {
  return strncmp(s, p, strlen(p)) == 0;
}

/* ═════════════════════════════════════════════════════════════════════════
   Config parser
   ═════════════════════════════════════════════════════════════════════════ */

/* parse base type string (without be/le suffix), returns byte size or -1 */
static int parse_base_type(const char *tok, DataType *out) {
  if (!strcmp(tok, "u8")) {
    *out = DT_U8;
    return 1;
  } else if (!strcmp(tok, "s8")) {
    *out = DT_S8;
    return 1;
  } else if (!strcmp(tok, "u16")) {
    *out = DT_U16;
    return 2;
  } else if (!strcmp(tok, "s16")) {
    *out = DT_S16;
    return 2;
  } else if (!strcmp(tok, "u32")) {
    *out = DT_U32;
    return 4;
  } else if (!strcmp(tok, "s32")) {
    *out = DT_S32;
    return 4;
  } else if (!strcmp(tok, "float")) {
    *out = DT_FLOAT;
    return 4;
  } else if (!strcmp(tok, "double")) {
    *out = DT_DOUBLE;
    return 8;
  }
  return -1;
}

static void parse_filters(const char *block, Rule *rule) {
  char tmp[MAX_LINE_LEN];
  strncpy_s(tmp, MAX_LINE_LEN, block, MAX_LINE_LEN - 1);
  char *ctx = NULL, *tok = strtok_s(tmp, ",", &ctx);
  while (tok) {
    while (*tok == ' ')
      tok++;
    Filter f = {0};
    if (str_starts(tok, "len=")) {
      f.type = FT_LEN;
      f.value = (int)strtol(tok + 4, NULL, 0);
      if (rule->filter_count < MAX_FILTERS)
        rule->filters[rule->filter_count++] = f;
    } else if (str_starts(tok, "idx")) {
      char *eq = strchr(tok, '=');
      if (eq) {
        f.type = FT_IDX;
        f.idx = atoi(tok + 3);
        f.value = (int)strtol(eq + 1, NULL, 0);
        if (rule->filter_count < MAX_FILTERS)
          rule->filters[rule->filter_count++] = f;
      }
    } else {
      fprintf(stderr, YEL "[CFG] Unknown filter: '%s'\n" R, tok);
    }
    tok = strtok_s(NULL, ",", &ctx);
  }
}

/*
 * Parse a field block content (between [ ]).
 * Supported syntax:
 *   u8                  basic type, no label
 *   u16(voltage)        basic type with label
 *   u16le(voltage)      basic type, force LE
 *   u32be(timestamp)    basic type, force BE
 *   array-12            raw 12-byte array
 *   array-12(payload)   raw 12-byte array with label
 */
static int parse_field(const char *block, Field *fld) {
  char tmp[MAX_LINE_LEN];
  strncpy_s(tmp, MAX_LINE_LEN, block, MAX_LINE_LEN - 1);
  str_trim(tmp);

  fld->label[0] = '\0';
  fld->array_size = 0;
  fld->endian = EO_GLOBAL;

  /* extract optional (label) */
  char *lp = strchr(tmp, '(');
  if (lp) {
    char *rp = strrchr(lp, ')');
    if (!rp)
      return -1;
    int llen = (int)(rp - lp - 1);
    if (llen > 0 && llen < MAX_LABEL_LEN)
      strncpy_s(fld->label, MAX_LABEL_LEN, lp + 1, llen);
    *lp = '\0'; /* truncate type string */
  }
  str_trim(tmp);

  /* array-N */
  if (str_starts(tmp, "array-")) {
    int n = atoi(tmp + 6);
    if (n <= 0) {
      fprintf(stderr, YEL "[CFG] Invalid array size: %s\n" R, tmp);
      return -1;
    }
    fld->type = DT_ARRAY;
    fld->array_size = n;
    return 0;
  }

  /* check for explicit endian suffix: u16le, u32be, s16be, etc. */
  char type_str[MAX_LABEL_LEN];
  strncpy_s(type_str, MAX_LABEL_LEN, tmp, MAX_LABEL_LEN - 1);
  int tlen = (int)strlen(type_str);

  if (tlen >= 2) {
    char *tail = type_str + tlen - 2;
    if (!strcmp(tail, "le")) {
      fld->endian = EO_LE;
      *tail = '\0';
    } else if (!strcmp(tail, "be")) {
      fld->endian = EO_BE;
      *tail = '\0';
    }
  }

  DataType dt;
  if (parse_base_type(type_str, &dt) < 0)
    return -1;
  fld->type = dt;
  return 0;
}

static int parse_rule_line(const char *line, Rule *rule) {
  memset(rule, 0, sizeof(Rule));
  char tmp[MAX_LINE_LEN];
  strncpy_s(tmp, MAX_LINE_LEN, line, MAX_LINE_LEN - 1);
  char *hash = strchr(tmp, '#');
  if (hash) {
    char *lbl = hash + 1;
    while (*lbl == ' ')
      lbl++;
    strncpy_s(rule->rule_label, MAX_LABEL_LEN, lbl, MAX_LABEL_LEN - 1);
    str_trim(rule->rule_label);
    *hash = '\0';
  }
  str_trim(tmp);
  strncpy_s(rule->raw, MAX_LINE_LEN, line, MAX_LINE_LEN - 1);
  str_trim(rule->raw);
  const char *p = tmp;
  while (*p) {
    while (*p == ' ' || *p == '\t')
      p++;
    if (!*p)
      break;
    if (*p == '{') {
      const char *end = strchr(p, '}');
      if (!end) {
        fprintf(stderr, RED "[CFG] Unclosed '{'\n" R);
        return -1;
      }
      char block[MAX_LINE_LEN];
      int blen = (int)(end - p - 1);
      if (blen > 0)
        strncpy_s(block, MAX_LINE_LEN, p + 1, blen);
      else
        block[0] = '\0';
      parse_filters(block, rule);
      p = end + 1;
    } else if (*p == '[') {
      const char *end = strchr(p, ']');
      if (!end) {
        fprintf(stderr, RED "[CFG] Unclosed '['\n" R);
        return -1;
      }
      char block[MAX_LINE_LEN];
      int blen = (int)(end - p - 1);
      if (blen < 0)
        blen = 0;
      strncpy_s(block, MAX_LINE_LEN, p + 1, blen);
      block[blen] = '\0';
      if (rule->field_count < MAX_FIELDS) {
        Field f;
        if (parse_field(block, &f) == 0)
          rule->fields[rule->field_count++] = f;
        else
          fprintf(stderr, YEL "[CFG] Unknown field: [%s]\n" R, block);
      }
      p = end + 1;
    } else {
      p++;
    }
  }
  if (!rule->field_count && !rule->filter_count)
    return -1;
  return 0;
}

static int load_config(const char *path, RuleSet *rs) {
  rs->count = 0;
  FILE *f;
  if (fopen_s(&f, path, "r") != 0 || !f) {
    fprintf(stderr, RED "[CFG] Cannot open: %s\n" R, path);
    return -1;
  }
  char line[MAX_LINE_LEN];
  int linenum = 0, loaded = 0;
  while (fgets(line, MAX_LINE_LEN, f)) {
    linenum++;
    str_trim(line);
    if (!line[0] || line[0] == '#' || line[0] == ';')
      continue;
    if (rs->count >= MAX_RULES) {
      fprintf(stderr, YEL "[CFG] Max rules reached.\n" R);
      break;
    }
    Rule rule;
    if (parse_rule_line(line, &rule) == 0) {
      rs->rules[rs->count++] = rule;
      loaded++;
    } else
      fprintf(stderr, YEL "[CFG] Line %d skipped: %s\n" R, linenum, line);
  }
  fclose(f);
  return loaded;
}

/* ═════════════════════════════════════════════════════════════════════════
   Runtime: filter match + field decode
   ═════════════════════════════════════════════════════════════════════════ */
static int rule_matches(const Rule *rule, const BYTE *data, DWORD len) {
  for (int i = 0; i < rule->filter_count; i++) {
    const Filter *f = &rule->filters[i];
    if (f->type == FT_LEN && (int)len != f->value)
      return 0;
    if (f->type == FT_IDX) {
      if (f->idx < 0 || (DWORD)f->idx >= len)
        return 0;
      if ((int)(unsigned char)data[f->idx] != f->value)
        return 0;
    }
  }
  return 1;
}

static const char *dtype_name(const Field *fld) {
  switch (fld->type) {
  case DT_U8:
    return "u8";
  case DT_S8:
    return "s8";
  case DT_U16:
    if (fld->endian == EO_BE)
      return "u16be";
    if (fld->endian == EO_LE)
      return "u16le";
    return "u16";
  case DT_S16:
    if (fld->endian == EO_BE)
      return "s16be";
    if (fld->endian == EO_LE)
      return "s16le";
    return "s16";
  case DT_U32:
    if (fld->endian == EO_BE)
      return "u32be";
    if (fld->endian == EO_LE)
      return "u32le";
    return "u32";
  case DT_S32:
    if (fld->endian == EO_BE)
      return "s32be";
    if (fld->endian == EO_LE)
      return "s32le";
    return "s32";
  case DT_FLOAT:
    return "float";
  case DT_DOUBLE:
    return "double";
  case DT_ARRAY:
    return "array";
  default:
    return "?";
  }
}

static int field_size(const Field *fld) {
  switch (fld->type) {
  case DT_U8:
  case DT_S8:
    return 1;
  case DT_U16:
  case DT_S16:
    return 2;
  case DT_U32:
  case DT_S32:
  case DT_FLOAT:
    return 4;
  case DT_DOUBLE:
    return 8;
  case DT_ARRAY:
    return fld->array_size;
  default:
    return 0;
  }
}

static uint16_t rd_u16le(const BYTE *p) {
  return (uint16_t)(p[0] | (p[1] << 8));
}
static uint16_t rd_u16be(const BYTE *p) {
  return (uint16_t)((p[0] << 8) | p[1]);
}
static uint32_t rd_u32le(const BYTE *p) {
  return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24));
}
static uint32_t rd_u32be(const BYTE *p) {
  return (uint32_t)(((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

/* resolve endian: field override wins, else global config */
static int use_be(const Field *fld, int cfg_be) {
  if (fld->endian == EO_BE)
    return 1;
  if (fld->endian == EO_LE)
    return 0;
  return cfg_be;
}

/*
 * Print one parsed field row.
 * Format:  [offset]  label           hex bytes     decoded value
 */
static void print_field_value(const Field *fld, const BYTE *data, DWORD avail,
                              DWORD *consumed, DWORD offset, int cfg_be,
                              FILE *logFile) {
  int sz = field_size(fld);
  if (!sz || sz < 0) {
    printf(RED "  [!] Zero-size field '%s'\n" R, dtype_name(fld));
    return;
  }
  if ((DWORD)sz > avail) {
    printf(RED "  " BOX_V " [%04lX]  [!] Not enough bytes for %s"
               " (need %d, have %lu)\n" R,
           (unsigned long)offset, dtype_name(fld), sz, (unsigned long)avail);
    *consumed += avail;
    return;
  }

  /* label */
  char lbl[MAX_LABEL_LEN + 4];
  _snprintf_s(lbl, sizeof(lbl), sizeof(lbl) - 1, "%-16s",
              fld->label[0] ? fld->label : dtype_name(fld));

  /* hex bytes — for arrays, print up to 8 then "..." */
  char hexbuf[64] = {0};
  if (fld->type == DT_ARRAY) {
    int show = sz > 8 ? 8 : sz;
    int pos = 0;
    for (int i = 0; i < show; i++)
      pos += _snprintf_s(hexbuf + pos, (int)sizeof(hexbuf) - pos,
                         (int)sizeof(hexbuf) - pos - 1, "%02X ", data[i]);
    if (sz > 8)
      _snprintf_s(hexbuf + pos, (int)sizeof(hexbuf) - pos,
                  (int)sizeof(hexbuf) - pos - 1, "...");
  } else {
    for (int i = 0; i < sz; i++)
      _snprintf_s(hexbuf + i * 3, (int)sizeof(hexbuf) - i * 3, 3, "%02X ",
                  data[i]);
  }

  /* decoded value */
  char valbuf[128] = {0};
  int be = use_be(fld, cfg_be);
  switch (fld->type) {
  case DT_U8:
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%3u  (0x%02X)",
                data[0], data[0]);
    break;
  case DT_S8:
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%4d",
                (int8_t)data[0]);
    break;
  case DT_U16: {
    uint16_t v = be ? rd_u16be(data) : rd_u16le(data);
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%5u  (0x%04X)", v,
                v);
    break;
  }
  case DT_S16: {
    int16_t v = (int16_t)(be ? rd_u16be(data) : rd_u16le(data));
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%6d", v);
    break;
  }
  case DT_U32: {
    uint32_t v = be ? rd_u32be(data) : rd_u32le(data);
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%10u  (0x%08X)", v,
                v);
    break;
  }
  case DT_S32: {
    int32_t v = (int32_t)(be ? rd_u32be(data) : rd_u32le(data));
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%11d", v);
    break;
  }
  case DT_FLOAT: {
    /* float bytes respect endian too */
    BYTE fb[4];
    if (be) {
      fb[0] = data[3];
      fb[1] = data[2];
      fb[2] = data[1];
      fb[3] = data[0];
    } else
      memcpy(fb, data, 4);
    float fv;
    memcpy(&fv, fb, 4);
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%g", fv);
    break;
  }
  case DT_DOUBLE: {
    BYTE db[8];
    if (be) {
      for (int i = 0; i < 8; i++)
        db[i] = data[7 - i];
    } else
      memcpy(db, data, 8);
    double dv;
    memcpy(&dv, db, 8);
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%g", dv);
    break;
  }
  case DT_ARRAY: {
    /* print full hex inline */
    int pos = 0;
    pos += _snprintf_s(valbuf + pos, (int)sizeof(valbuf) - pos,
                       (int)sizeof(valbuf) - pos - 1, "[%d bytes] ", sz);
    for (int i = 0; i < sz && pos < (int)sizeof(valbuf) - 4; i++)
      pos += _snprintf_s(valbuf + pos, (int)sizeof(valbuf) - pos,
                         (int)sizeof(valbuf) - pos - 1, "%02X ", data[i]);
    break;
  }
  }

  printf("  " BOX_V "  " GRAY "[%04lX]" R "  " BLUE "%-16s" R "  " GRAY
         "%-25s" R "  " WHT "%s" R "\n",
         (unsigned long)offset, lbl, hexbuf, valbuf);

  if (logFile)
    fprintf(logFile, "  | [%04lX]  %-16s  %-25s  %s\n", (unsigned long)offset,
            lbl, hexbuf, valbuf);

  *consumed += (DWORD)sz;
}

/* ── horizontal rule helper ───────────────────────────────────────────── */
static void hline(const char *left, const char *fill, const char *right, int w,
                  const char *color) {
  printf("%s%s", color, left);
  for (int i = 0; i < w; i++)
    printf("%s", fill);
  printf("%s%s\n", right, R);
}

static int try_parse(Config *cfg, const BYTE *data, DWORD len, const char *dir,
                     FILE *logFile) {
  const int W = 58; /* inner width */
  for (int r = 0; r < cfg->rs.count; r++) {
    const Rule *rule = &cfg->rs.rules[r];
    if (!rule_matches(rule, data, len))
      continue;

    char hdr[MAX_LINE_LEN];
    if (rule->rule_label[0])
      _snprintf_s(hdr, sizeof(hdr), sizeof(hdr) - 1,
                  "Rule #%d \"%s\"  [%s]  %lu bytes", r + 1, rule->rule_label,
                  dir, (unsigned long)len);
    else
      _snprintf_s(hdr, sizeof(hdr), sizeof(hdr) - 1,
                  "Rule #%d  [%s]  %lu bytes", r + 1, dir, (unsigned long)len);

    /* top border */
    hline(BOX_TL, BOX_H, BOX_TR, W, MAG);
    printf("  " BOX_V "  " BOLD MAG "%-*s" R "\n", W - 2, hdr);
    /* column header separator */
    hline(BOX_ML, BOX_H, BOX_MR, W, MAG);
    printf("  " BOX_V "  " DIM "%-6s  %-16s  %-25s  %s" R "\n", "Offset",
           "Field", "Hex", "Value");
    hline(BOX_ML, BOX_H, BOX_MR, W, GRAY);

    if (logFile) {
      fprintf(logFile, "+%.*s+\n", W,
              "==========================================================");
      fprintf(logFile, "| %-*s|\n", W - 1, hdr);
      fprintf(logFile, "+%.*s+\n", W,
              "----------------------------------------------------------");
    }

    const BYTE *p = data;
    DWORD remain = len, offset = 0;
    for (int fi = 0; fi < rule->field_count && remain > 0; fi++) {
      DWORD before = offset;
      print_field_value(&rule->fields[fi], p, remain, &offset, before,
                        cfg->big_endian, logFile);
      DWORD consumed = offset - before;
      p += consumed;
      remain -= consumed;
    }

    /* trailing bytes */
    if (remain > 0) {
      char trail[128] = {0};
      int pos = 0;
      for (DWORD i = 0; i < remain && pos < (int)sizeof(trail) - 4; i++)
        pos += _snprintf_s(trail + pos, (int)sizeof(trail) - pos,
                           (int)sizeof(trail) - pos - 1, "%02X ", p[i]);
      printf("  " BOX_V "  " GRAY "[%04lX]" R "  " YEL "%-16s" R "  " GRAY
             "%-25s" R "  %s\n",
             (unsigned long)offset, "(trailing)", "", trail);
    }

    /* bottom border */
    hline(BOX_BL, BOX_H, BOX_BR, W, MAG);
    printf("\n");

    if (logFile) {
      fprintf(logFile, "+%.*s+\n\n", W,
              "----------------------------------------------------------");
      fflush(logFile);
    }
    return 1;
  }
  return 0;
}

/* ═════════════════════════════════════════════════════════════════════════
   Hex dump
   ═════════════════════════════════════════════════════════════════════════ */
static void log_data(Config *cfg, const char *label, const char *color,
                     const BYTE *data, DWORD len) {
  SYSTEMTIME st;
  GetLocalTime(&st);

  EnterCriticalSection(&g_print_lock);

  /* header */
  printf("%s[%02d:%02d:%02d.%03d]%s  %s%-20s%s  %s%lu bytes%s\n", GRAY,
         st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, R, color, label, R,
         GRAY, (unsigned long)len, R);
  if (cfg->logFile)
    fprintf(cfg->logFile, "[%02d:%02d:%02d.%03d]  %-20s  %lu bytes\n", st.wHour,
            st.wMinute, st.wSecond, st.wMilliseconds, label,
            (unsigned long)len);

  /* hex dump */
  for (DWORD row = 0; row < len; row += COLS_PER_ROW) {
    DWORD end = row + COLS_PER_ROW;
    if (end > len)
      end = len;
    printf("  %s%04lX%s  ", GRAY, (unsigned long)row, R);
    for (DWORD i = row; i < end; i++)
      printf("%s%02X%s ", color, data[i], R);
    for (DWORD i = end; i < row + COLS_PER_ROW; i++)
      printf("   ");
    printf(" %s|%s ", GRAY, R);
    for (DWORD i = row; i < end; i++) {
      char c = (data[i] >= 0x20 && data[i] < 0x7F) ? (char)data[i] : '.';
      printf("%s%c%s", color, c, R);
    }
    printf("\n");
    if (cfg->logFile) {
      fprintf(cfg->logFile, "  %04lX  ", (unsigned long)row);
      for (DWORD i = row; i < end; i++)
        fprintf(cfg->logFile, "%02X ", data[i]);
      for (DWORD i = end; i < row + COLS_PER_ROW; i++)
        fprintf(cfg->logFile, "   ");
      fprintf(cfg->logFile, " | ");
      for (DWORD i = row; i < end; i++)
        fputc((data[i] >= 0x20 && data[i] < 0x7F) ? (char)data[i] : '.',
              cfg->logFile);
      fputc('\n', cfg->logFile);
    }
  }

  /* protocol parse */
  if (cfg->useParser) {
    printf("\n");
    if (!try_parse(cfg, data, len, label, cfg->logFile))
      printf("  %s(no rule matched)%s\n\n", DIM, R);
  } else {
    printf("\n");
  }
  if (cfg->logFile) {
    fputc('\n', cfg->logFile);
    fflush(cfg->logFile);
  }

  LeaveCriticalSection(&g_print_lock);
}

/* ═════════════════════════════════════════════════════════════════════════
   Ctrl+R / Alt+R keyboard listener thread  (clear screen)
   ═════════════════════════════════════════════════════════════════════════ */
DWORD WINAPI hotkey_thread(LPVOID param) {
  (void)param;
  HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
  SetConsoleMode(hIn, ENABLE_EXTENDED_FLAGS | ENABLE_WINDOW_INPUT |
                          ENABLE_MOUSE_INPUT);

  INPUT_RECORD rec;
  DWORD cnt;
  while (1) {
    ReadConsoleInputA(hIn, &rec, 1, &cnt);
    if (rec.EventType != KEY_EVENT || !rec.Event.KeyEvent.bKeyDown)
      continue;

    KEY_EVENT_RECORD *ke = &rec.Event.KeyEvent;
    BOOL ctrl =
        (ke->dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) != 0;
    BOOL alt =
        (ke->dwControlKeyState & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED)) != 0;
    char ch = ke->uChar.AsciiChar;

    /* Ctrl+R → ch==0x12 (18)  |  Alt+R → ch=='r' with alt set */
    if ((ctrl && (ch == 0x12 || ch == 'r' || ch == 'R')) ||
        (alt && (ch == 'r' || ch == 'R'))) {
      EnterCriticalSection(&g_print_lock);
      /* ANSI: clear screen + move cursor home */
      printf("\x1b[2J\x1b[H");
      printf(BOLD MAG
             "  Serial Port Sniffer  " R GRAY
             "  (screen cleared — Ctrl+R / Alt+R to clear again)\n\n" R);
      LeaveCriticalSection(&g_print_lock);
    }
  }
  return 0;
}

/* ═════════════════════════════════════════════════════════════════════════
   Serial helpers
   ═════════════════════════════════════════════════════════════════════════ */
static void enable_vt(void) {
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD m = 0;
  GetConsoleMode(h, &m);
  SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}
static void make_port_path(const char *name, char *out, int outsz) {
  if (strncmp(name, "\\\\.\\", 4) == 0)
    strncpy_s(out, outsz, name, outsz - 1);
  else
    _snprintf_s(out, outsz, outsz - 1, "\\\\.\\%s", name);
}
static HANDLE open_port(const char *path, int baud) {
  HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return INVALID_HANDLE_VALUE;
  DCB dcb = {0};
  dcb.DCBlength = sizeof(dcb);
  GetCommState(h, &dcb);
  dcb.BaudRate = baud;
  dcb.ByteSize = 8;
  dcb.Parity = NOPARITY;
  dcb.StopBits = ONESTOPBIT;
  SetCommState(h, &dcb);
  COMMTIMEOUTS to = {1, 0, 10, 0, 10};
  SetCommTimeouts(h, &to);
  return h;
}

DWORD WINAPI forward_thread(LPVOID param) {
  ForwardArgs *args = (ForwardArgs *)param;
  BYTE buf[BUF_SIZE];
  DWORD bytesRead, bytesWritten;
  while (1) {
    if (!ReadFile(args->hSrc, buf, BUF_SIZE, &bytesRead, NULL)) {
      fprintf(stderr, RED "[ERR] Read failed: %s (code %lu)\n" R, args->label,
              GetLastError());
      break;
    }
    if (bytesRead > 0) {
      log_data(args->cfg, args->label, args->color, buf, bytesRead);
      if (!WriteFile(args->hDst, buf, bytesRead, &bytesWritten, NULL)) {
        fprintf(stderr, RED "[ERR] Write failed: %s (code %lu)\n" R,
                args->label, GetLastError());
        break;
      }
    }
  }
  return 0;
}

/* ═════════════════════════════════════════════════════════════════════════
   Usage
   ═════════════════════════════════════════════════════════════════════════ */
static void print_usage(const char *exe) {
  fprintf(
      stderr,
      BOLD
      "Usage:\n" R
      "  %s -i <IN> -o <OUT> [-b <BAUD>] [-lemode|-bemode] [-c <CFG>]\n\n"
      "Options:\n"
      "  -i <port>    Input  port  (e.g. COM6)          [required]\n"
      "  -o <port>    Output port  (e.g. COM7)          [required]\n"
      "  -b <baud>    Baud rate    (default: 9600)\n"
      "  -lemode      Parse multi-byte fields as little-endian (default)\n"
      "  -bemode      Parse multi-byte fields as big-endian\n"
      "  -c <file>    Protocol config file              [optional]\n\n"
      "Config field types  (inside []):\n"
      "  u8  s8\n"
      "  u16  s16  u32  s32           uses global endian (-lemode/-bemode)\n"
      "  u16le  u16be  u32le  u32be   per-field endian override\n"
      "  s16le  s16be  s32le  s32be\n"
      "  float  double\n"
      "  array-N                      N raw bytes, printed as hex (no endian)\n"
      "  Add (label) after type:  [u16(voltage)]  [array-8(payload)]\n\n"
      "Filters  (inside {}, AND logic):\n"
      "  len=N          total packet length == N\n"
      "  idxN=0xVV      byte[N] == 0xVV\n\n"
      "Hotkeys:\n"
      "  Ctrl+R  or  Alt+R    clear terminal\n\n"
      "Example config line:\n"
      "  {len=13,idx0=0x02} [u8(addr)] [u16(volt)] [s16(temp)] [array-4(raw)] "
      "[u32(ts)]  # frame\n\n"
      "Example run:\n"
      "  %s -i COM6 -o COM7 -b 115200 -bemode -c sniff.cfg\n",
      exe, exe);
}

static void print_ruleset(const RuleSet *rs, int big_endian) {
  printf(BOLD "  Loaded %d rule(s)  " R GRAY "(%s)" R "\n", rs->count,
         big_endian ? "big-endian" : "little-endian");
  for (int i = 0; i < rs->count; i++) {
    const Rule *r = &rs->rules[i];
    printf("  " GRAY "#%d" R " ", i + 1);
    if (r->rule_label[0])
      printf(YEL "\"%s\"" R "  ", r->rule_label);
    for (int f = 0; f < r->filter_count; f++) {
      const Filter *fl = &r->filters[f];
      if (fl->type == FT_LEN)
        printf(CYAN "{len=%d}" R " ", fl->value);
      else
        printf(CYAN "{idx%d=0x%02X}" R " ", fl->idx, fl->value);
    }
    for (int f = 0; f < r->field_count; f++) {
      const Field *fld = &r->fields[f];
      char tag[MAX_LABEL_LEN + 16];
      if (fld->type == DT_ARRAY)
        _snprintf_s(tag, sizeof(tag), sizeof(tag) - 1, "array-%d",
                    fld->array_size);
      else
        strncpy_s(tag, sizeof(tag), dtype_name(fld), sizeof(tag) - 1);
      if (fld->label[0])
        printf(GREEN "[%s:%s]" R " ", tag, fld->label);
      else
        printf(GREEN "[%s]" R " ", tag);
    }
    printf("\n");
  }
}

/* ═════════════════════════════════════════════════════════════════════════
   main
   ═════════════════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[]) {
  enable_vt();
  InitializeCriticalSection(&g_print_lock);

  Config cfg = {0};
  cfg.baud = 9600;

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-b") && i + 1 < argc)
      cfg.baud = atoi(argv[++i]);
    else if (!strcmp(argv[i], "-i") && i + 1 < argc)
      strncpy_s(cfg.portIn, MAX_PORT_LEN, argv[++i], MAX_PORT_LEN - 1);
    else if (!strcmp(argv[i], "-o") && i + 1 < argc)
      strncpy_s(cfg.portOut, MAX_PORT_LEN, argv[++i], MAX_PORT_LEN - 1);
    else if (!strcmp(argv[i], "-c") && i + 1 < argc)
      strncpy_s(cfg.cfgFile, sizeof(cfg.cfgFile), argv[++i],
                sizeof(cfg.cfgFile) - 1);
    else if (!strcmp(argv[i], "-lemode"))
      cfg.big_endian = 0;
    else if (!strcmp(argv[i], "-bemode"))
      cfg.big_endian = 1;
    else {
      fprintf(stderr, RED "[ERR] Unknown argument: %s\n\n" R, argv[i]);
      print_usage(argv[0]);
      return 1;
    }
  }
  if (!cfg.portIn[0] || !cfg.portOut[0]) {
    fprintf(stderr, RED "[ERR] -i and -o are required.\n\n" R);
    print_usage(argv[0]);
    return 1;
  }

  if (cfg.cfgFile[0]) {
    int n = load_config(cfg.cfgFile, &cfg.rs);
    if (n < 0)
      return 1;
    cfg.useParser = (n > 0);
  }

  fopen_s(&cfg.logFile, LOG_FILE, "a");

  char pathIn[MAX_PORT_LEN + 8], pathOut[MAX_PORT_LEN + 8];
  make_port_path(cfg.portIn, pathIn, sizeof(pathIn));
  make_port_path(cfg.portOut, pathOut, sizeof(pathOut));

  HANDLE hIn = open_port(pathIn, cfg.baud);
  HANDLE hOut = open_port(pathOut, cfg.baud);
  if (hIn == INVALID_HANDLE_VALUE) {
    fprintf(stderr, RED "[ERR] Cannot open input  port %s (code %lu)\n" R,
            pathIn, GetLastError());
    return 1;
  }
  if (hOut == INVALID_HANDLE_VALUE) {
    fprintf(stderr, RED "[ERR] Cannot open output port %s (code %lu)\n" R,
            pathOut, GetLastError());
    CloseHandle(hIn);
    return 1;
  }

  /* banner */
  const int BW = 46;
  hline(BOX_TL, BOX_H, BOX_TR, BW, BOLD);
  printf(BOLD BOX_V R "  %-*s" BOLD BOX_V R "\n", BW - 1,
         "  Serial Port Sniffer");
  hline(BOX_ML, BOX_H, BOX_MR, BW, BOLD);
  printf(BOX_V "  " GREEN "In " R "  %-10s  " GRAY "Baud" R " " YEL "%-8d" R
               "          " BOX_V "\n",
         cfg.portIn, cfg.baud);
  printf(BOX_V "  " CYAN "Out" R "  %-10s  " GRAY "Baud" R " " YEL "%-8d" R
               "          " BOX_V "\n",
         cfg.portOut, cfg.baud);
  printf(BOX_V "  " GRAY "Log" R "  %-*s" BOX_V "\n", BW - 7, LOG_FILE);
  printf(BOX_V "  " GRAY "End" R "  %-*s" BOX_V "\n", BW - 7,
         cfg.big_endian ? "big-endian (-bemode)"
                        : "little-endian (-lemode, default)");
  if (cfg.useParser) {
    printf(BOX_V "  " MAG "CFG" R "  %-*s" BOX_V "\n", BW - 7, cfg.cfgFile);
  } else {
    printf(BOX_V "  " GRAY "CFG  (none)" R "%-*s" BOX_V "\n", BW - 12, "");
  }
  hline(BOX_BL, BOX_H, BOX_BR, BW, BOLD);

  if (cfg.useParser)
    print_ruleset(&cfg.rs, cfg.big_endian);

  printf(GRAY
         "\n  Hotkeys: Ctrl+R / Alt+R = clear screen   Ctrl+C = quit\n\n" R);

  /* start hotkey listener */
  CreateThread(NULL, 0, hotkey_thread, NULL, 0, NULL);

  char labelAB[MAX_PORT_LEN * 2 + 4], labelBA[MAX_PORT_LEN * 2 + 4];
  _snprintf_s(labelAB, sizeof(labelAB), sizeof(labelAB) - 1, "%s -> %s",
              cfg.portIn, cfg.portOut);
  _snprintf_s(labelBA, sizeof(labelBA), sizeof(labelBA) - 1, "%s -> %s",
              cfg.portOut, cfg.portIn);

  ForwardArgs argsAB = {hIn, hOut, labelAB, GREEN, &cfg};
  ForwardArgs argsBA = {hOut, hIn, labelBA, CYAN, &cfg};

  HANDLE threads[2];
  threads[0] = CreateThread(NULL, 0, forward_thread, &argsAB, 0, NULL);
  threads[1] = CreateThread(NULL, 0, forward_thread, &argsBA, 0, NULL);
  WaitForMultipleObjects(2, threads, TRUE, INFINITE);

  CloseHandle(hIn);
  CloseHandle(hOut);
  if (cfg.logFile)
    fclose(cfg.logFile);
  DeleteCriticalSection(&g_print_lock);
  return 0;
}
