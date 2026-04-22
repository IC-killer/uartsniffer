/*
 * sniffer.c  --  Serial Port Sniffer
 *
 * Usage:
 *   sniffer -i <IN> -o <OUT> [-b <BAUD>] [-lemode|-bemode] [-c <CFG>]
 *
 * Hotkeys (via ReadConsoleInput, works in cmd / PowerShell / WT):
 *   Alt+C   clear screen
 *   Alt+X   quit
 *
 * Config file is watched and hot-reloaded automatically when saved.
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

/* ── box (plain ASCII) ───────────────────────────────────────────────────── */
#define BOX_TL "+"
#define BOX_TR "+"
#define BOX_BL "+"
#define BOX_BR "+"
#define BOX_H "-"
#define BOX_V "|"
#define BOX_ML "+"
#define BOX_MR "+"

/* ==========================================================================
   Data structures
   ========================================================================== */
typedef enum { FT_LEN, FT_IDX } FilterType;
typedef struct {
  FilterType type;
  int idx;
  int value;
} Filter;

typedef enum {
  DT_U8,
  DT_S8,
  DT_U16,
  DT_S16,
  DT_U32,
  DT_S32,
  DT_FLOAT,
  DT_DOUBLE,
  DT_ARRAY,
} DataType;

typedef enum { EO_GLOBAL = 0, EO_LE, EO_BE } EndianOverride;

typedef struct {
  DataType type;
  int array_size;
  EndianOverride endian;
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
  int big_endian;
  FILE *logFile;
} Config;

typedef struct {
  HANDLE hSrc;
  HANDLE hDst;
  const char *label;
  const char *color;
  Config *cfg;
} ForwardArgs;

/* ==========================================================================
   Globals shared between threads
   ========================================================================== */

/* console output: serialises printf across forward + hotkey + watcher threads
 */
static CRITICAL_SECTION g_print_lock;

/* live ruleset: written by watcher thread, read by forward threads */
static RuleSet g_rs;
static CRITICAL_SECTION g_rs_lock;
static volatile LONG g_useParser = 0; /* atomic flag */

/* signals all threads to stop */
static volatile LONG g_quit = 0;

/* ==========================================================================
   String helpers
   ========================================================================== */
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

/* ==========================================================================
   Config parser
   ========================================================================== */
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
    } else
      fprintf(stderr, YEL "[CFG] Unknown filter: '%s'\n" R, tok);
    tok = strtok_s(NULL, ",", &ctx);
  }
}

static int parse_field(const char *block, Field *fld) {
  char tmp[MAX_LINE_LEN];
  strncpy_s(tmp, MAX_LINE_LEN, block, MAX_LINE_LEN - 1);
  str_trim(tmp);
  fld->label[0] = '\0';
  fld->array_size = 0;
  fld->endian = EO_GLOBAL;

  char *lp = strchr(tmp, '(');
  if (lp) {
    char *rp = strrchr(lp, ')');
    if (!rp)
      return -1;
    int llen = (int)(rp - lp - 1);
    if (llen > 0 && llen < MAX_LABEL_LEN)
      strncpy_s(fld->label, MAX_LABEL_LEN, lp + 1, llen);
    *lp = '\0';
  }
  str_trim(tmp);

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
    } else
      p++;
  }
  if (!rule->field_count && !rule->filter_count)
    return -1;
  return 0;
}

/* returns number of rules loaded, or -1 on file open failure */
static int load_config_into(const char *path, RuleSet *rs) {
  rs->count = 0;
  FILE *f;
  if (fopen_s(&f, path, "r") != 0 || !f)
    return -1;
  char line[MAX_LINE_LEN];
  int linenum = 0, loaded = 0;
  while (fgets(line, MAX_LINE_LEN, f)) {
    linenum++;
    str_trim(line);
    if (!line[0] || line[0] == '#' || line[0] == ';')
      continue;
    if (rs->count >= MAX_RULES)
      break;
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

/* ==========================================================================
   Runtime helpers
   ========================================================================== */
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
    return fld->endian == EO_BE   ? "u16be"
           : fld->endian == EO_LE ? "u16le"
                                  : "u16";
  case DT_S16:
    return fld->endian == EO_BE   ? "s16be"
           : fld->endian == EO_LE ? "s16le"
                                  : "s16";
  case DT_U32:
    return fld->endian == EO_BE   ? "u32be"
           : fld->endian == EO_LE ? "u32le"
                                  : "u32";
  case DT_S32:
    return fld->endian == EO_BE   ? "s32be"
           : fld->endian == EO_LE ? "s32le"
                                  : "s32";
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
static int use_be(const Field *fld, int cfg_be) {
  if (fld->endian == EO_BE)
    return 1;
  if (fld->endian == EO_LE)
    return 0;
  return cfg_be;
}

static void hline(const char *l, const char *fill, const char *r, int w,
                  const char *col) {
  printf("%s%s", col, l);
  for (int i = 0; i < w; i++)
    printf("%s", fill);
  printf("%s%s\n", r, R);
}

/* ==========================================================================
   print_ruleset  --  display loaded rules  (caller holds g_print_lock)
   ========================================================================== */
static void print_ruleset_locked(const RuleSet *rs, int big_endian) {
  printf(BOLD "  Rules: %d  " R GRAY "(%s)\n" R, rs->count,
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

/* ==========================================================================
   Field value printer  (caller holds g_print_lock)
   ========================================================================== */
static void print_field_value(const Field *fld, const BYTE *data, DWORD avail,
                              DWORD *consumed, DWORD offset, int cfg_be,
                              FILE *logf) {
  int sz = field_size(fld);
  if (sz <= 0) {
    printf(RED "  [!] zero-size field '%s'\n" R, dtype_name(fld));
    return;
  }
  if ((DWORD)sz > avail) {
    printf(RED "  " BOX_V
               " [%04lX]  [!] need %d bytes for '%s', only %lu left\n" R,
           (unsigned long)offset, sz, dtype_name(fld), (unsigned long)avail);
    *consumed += avail;
    return;
  }

  /* label */
  char lbl[MAX_LABEL_LEN + 4];
  _snprintf_s(lbl, sizeof(lbl), sizeof(lbl) - 1, "%-16s",
              fld->label[0] ? fld->label : dtype_name(fld));

  /* hex summary */
  char hexbuf[72] = {0};
  if (fld->type == DT_ARRAY) {
    int show = sz > 8 ? 8 : sz, pos = 0;
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
  char valbuf[160] = {0};
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
    int pos = 0;
    pos += _snprintf_s(valbuf + pos, (int)sizeof(valbuf) - pos,
                       (int)sizeof(valbuf) - pos - 1, "[%d] ", sz);
    for (int i = 0; i < sz && pos < (int)sizeof(valbuf) - 4; i++)
      pos += _snprintf_s(valbuf + pos, (int)sizeof(valbuf) - pos,
                         (int)sizeof(valbuf) - pos - 1, "%02X ", data[i]);
    break;
  }
  }

  printf("  " BOX_V "  " GRAY "[%04lX]" R "  " BLUE "%-16s" R "  " GRAY
         "%-24s" R "  " WHT "%s" R "\n",
         (unsigned long)offset, lbl, hexbuf, valbuf);
  if (logf)
    fprintf(logf, "  | [%04lX]  %-16s  %-24s  %s\n", (unsigned long)offset, lbl,
            hexbuf, valbuf);
  *consumed += (DWORD)sz;
}

/* ==========================================================================
   Protocol parse  (caller holds g_print_lock)
   ========================================================================== */
static int try_parse(Config *cfg, const BYTE *data, DWORD len, const char *dir,
                     FILE *logf) {
  /* snapshot ruleset without holding g_rs_lock across printf calls */
  RuleSet snap;
  EnterCriticalSection(&g_rs_lock);
  snap = g_rs;
  LeaveCriticalSection(&g_rs_lock);

  const int W = 62;
  for (int r = 0; r < snap.count; r++) {
    const Rule *rule = &snap.rules[r];
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

    hline(BOX_TL, BOX_H, BOX_TR, W, MAG);
    printf("  " BOX_V "  " BOLD MAG "%-*s" R "\n", W - 2, hdr);
    hline(BOX_ML, BOX_H, BOX_MR, W, MAG);
    printf("  " BOX_V "  " DIM "%-6s  %-16s  %-24s  %s" R "\n", "Offset",
           "Field", "Hex", "Value");
    hline(BOX_ML, BOX_H, BOX_MR, W, GRAY);

    if (logf) {
      fprintf(logf, "+%.*s+\n", W,
              "==============================================================");
      fprintf(logf, "| %-*s|\n", W - 1, hdr);
      fprintf(logf, "+%.*s+\n", W,
              "--------------------------------------------------------------");
    }

    const BYTE *p = data;
    DWORD remain = len, offset = 0;
    for (int fi = 0; fi < rule->field_count && remain > 0; fi++) {
      DWORD before = offset;
      print_field_value(&rule->fields[fi], p, remain, &offset, before,
                        cfg->big_endian, logf);
      DWORD consumed = offset - before;
      p += consumed;
      remain -= consumed;
    }

    if (remain > 0) {
      char trail[128] = {0};
      int pos = 0;
      for (DWORD i = 0; i < remain && pos < (int)sizeof(trail) - 4; i++)
        pos += _snprintf_s(trail + pos, (int)sizeof(trail) - pos,
                           (int)sizeof(trail) - pos - 1, "%02X ", p[i]);
      printf("  " BOX_V "  " GRAY "[%04lX]" R "  " YEL "%-16s" R "  " GRAY
             "%-24s" R "  %s\n",
             (unsigned long)offset, "(trailing)", "", trail);
    }

    hline(BOX_BL, BOX_H, BOX_BR, W, MAG);
    printf("\n");

    if (logf) {
      fprintf(logf, "+%.*s+\n\n", W,
              "--------------------------------------------------------------");
      fflush(logf);
    }
    return 1;
  }
  return 0;
}

/* ==========================================================================
   Hex dump + parse  (forward thread entry point for output)
   ========================================================================== */
static void log_data(Config *cfg, const char *label, const char *color,
                     const BYTE *data, DWORD len) {
  SYSTEMTIME st;
  GetLocalTime(&st);

  EnterCriticalSection(&g_print_lock);

  printf("%s[%02d:%02d:%02d.%03d]%s  %s%-20s%s  %s%lu bytes%s\n", GRAY,
         st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, R, color, label, R,
         GRAY, (unsigned long)len, R);
  if (cfg->logFile)
    fprintf(cfg->logFile, "[%02d:%02d:%02d.%03d]  %-20s  %lu bytes\n", st.wHour,
            st.wMinute, st.wSecond, st.wMilliseconds, label,
            (unsigned long)len);

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

  if (InterlockedOr(&g_useParser, 0)) {
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

/* ==========================================================================
   Config hot-reload watcher thread
   ========================================================================== */
typedef struct {
  char path[256];
  int big_endian;
} WatcherArgs;

DWORD WINAPI watcher_thread(LPVOID param) {
  WatcherArgs *args = (WatcherArgs *)param;

  /* extract directory from path */
  char watchDir[256];
  int dirLen = 0;
  {
    const char *p = args->path;
    int last = -1;
    for (int i = 0; p[i]; i++)
      if (p[i] == '\\' || p[i] == '/')
        last = i;
    if (last >= 0) {
      dirLen = last;
      strncpy_s(watchDir, sizeof(watchDir), args->path, dirLen);
      watchDir[dirLen] = '\0';
    } else {
      strcpy_s(watchDir, sizeof(watchDir), ".");
    }
  }

  HANDLE hDir = CreateFileA(
      watchDir, FILE_LIST_DIRECTORY,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);

  if (hDir == INVALID_HANDLE_VALUE) {
    EnterCriticalSection(&g_print_lock);
    fprintf(stderr,
            YEL
            "[WATCH] Cannot open dir '%s' (err %lu), hot-reload disabled.\n" R,
            watchDir, GetLastError());
    LeaveCriticalSection(&g_print_lock);
    return 0;
  }

  /* OVERLAPPED + event so we can also react to g_quit */
  OVERLAPPED ov = {0};
  ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);

  /* buffer for ReadDirectoryChangesW */
  BYTE notifBuf[4096];

  while (!InterlockedOr(&g_quit, 0)) {
    ResetEvent(ov.hEvent);
    DWORD bytesRet = 0;
    BOOL ok = ReadDirectoryChangesW(
        hDir, notifBuf, sizeof(notifBuf), FALSE, /* don't watch subtree */
        FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE, &bytesRet, &ov,
        NULL);

    if (!ok) {
      /* GetLastError()==ERROR_IO_PENDING is normal for OVERLAPPED */
      if (GetLastError() != ERROR_IO_PENDING)
        break;
    }

    /* Wait for either a change notification or a quit signal */
    HANDLE waitHandles[1] = {ov.hEvent};
    DWORD w = WaitForMultipleObjects(1, waitHandles, FALSE,
                                     500); /* 500ms poll for g_quit */
    if (InterlockedOr(&g_quit, 0))
      break;
    if (w != WAIT_OBJECT_0)
      continue;

    GetOverlappedResult(hDir, &ov, &bytesRet, FALSE);

    /* Walk the notification records to find if our file changed */
    int changed = 0;
    if (bytesRet > 0) {
      const char *cfgBase = args->path + (dirLen > 0 ? dirLen + 1 : 0);
      FILE_NOTIFY_INFORMATION *fni = (FILE_NOTIFY_INFORMATION *)notifBuf;
      for (;;) {
        if (fni->Action == FILE_ACTION_MODIFIED ||
            fni->Action == FILE_ACTION_ADDED) {
          /* convert wide filename to narrow for comparison */
          char narrow[256] = {0};
          WideCharToMultiByte(CP_ACP, 0, fni->FileName,
                              fni->FileNameLength / sizeof(WCHAR), narrow,
                              sizeof(narrow) - 1, NULL, NULL);
          if (_stricmp(narrow, cfgBase) == 0) {
            changed = 1;
            break;
          }
        }
        if (!fni->NextEntryOffset)
          break;
        fni = (FILE_NOTIFY_INFORMATION *)((BYTE *)fni + fni->NextEntryOffset);
      }
    } else {
      /* bytesRet==0 means buffer overflow — assume something changed */
      changed = 1;
    }

    if (!changed)
      continue;

    /* small debounce: editors often trigger two writes in quick succession */
    Sleep(80);

    RuleSet tmp;
    int n = load_config_into(args->path, &tmp);
    if (n >= 0) {
      EnterCriticalSection(&g_rs_lock);
      g_rs = tmp;
      LeaveCriticalSection(&g_rs_lock);
      InterlockedExchange(&g_useParser, (n > 0) ? 1 : 0);

      EnterCriticalSection(&g_print_lock);
      printf("\n" MAG "+-- CFG reloaded: %s -- %d rule(s) --+" R "\n",
             args->path, n);
      if (n > 0) {
        /* safe: we hold g_print_lock; take g_rs_lock briefly for snapshot */
        RuleSet snap;
        EnterCriticalSection(&g_rs_lock);
        snap = g_rs;
        LeaveCriticalSection(&g_rs_lock);
        print_ruleset_locked(&snap, args->big_endian);
      }
      printf("\n");
      LeaveCriticalSection(&g_print_lock);
    } else {
      EnterCriticalSection(&g_print_lock);
      printf(RED "[CFG] Reload failed for '%s'\n" R, args->path);
      LeaveCriticalSection(&g_print_lock);
    }
  }

  CloseHandle(ov.hEvent);
  CloseHandle(hDir);
  return 0;
}

/* ==========================================================================
   Hotkey thread
   --------------------------------------------------------------------------
   Strategy: ReadConsoleInput in raw mode.
   Alt+key generates two KEY_EVENT records back-to-back:
     1) VK_MENU  (wVirtualKeyCode=0x12), bKeyDown=TRUE
     2) the letter key, bKeyDown=TRUE, with LEFT_ALT_PRESSED set in
   dwControlKeyState

   We look for record #2: letter key + LEFT_ALT_PRESSED (or RIGHT_ALT_PRESSED).

   Chosen combos  (low conflict in cmd, PowerShell, Windows Terminal):
     Alt+C  --  clear screen    (C = Clear)
     Alt+X  --  quit            (X = eXit)

   These avoid:
     Alt+F4   (window close)
     Alt+F    (menu bar in older terminals)
     Alt+L/Q  (used by some shell line editors like PSReadLine)
     Alt+Enter (full-screen toggle in conhost)
   ========================================================================== */
typedef struct {
  Config *cfg;
} HotkeyArgs;

static void do_clear_screen(void) {
  EnterCriticalSection(&g_print_lock);
  /* ANSI: erase display + move cursor to home */
  printf("\x1b[2J\x1b[H");
  hline(BOX_TL, BOX_H, BOX_TR, 46, BOLD MAG);
  printf(BOLD MAG BOX_V R "  %-43s" BOLD MAG BOX_V R "\n",
         "  Serial Port Sniffer  (screen cleared)");
  printf(BOLD MAG BOX_V R "  %-43s" BOLD MAG BOX_V R "\n",
         "  Alt+C = clear   Alt+X = quit");
  hline(BOX_BL, BOX_H, BOX_BR, 46, BOLD MAG);
  printf("\n");
  fflush(stdout);
  LeaveCriticalSection(&g_print_lock);
}

DWORD WINAPI hotkey_thread(LPVOID param) {
  HotkeyArgs *args = (HotkeyArgs *)param;
  HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);

  /* Save original console mode, switch to raw input */
  DWORD origMode = 0;
  GetConsoleMode(hIn, &origMode);
  /* Enable window/mouse/extended so KEY_EVENTs flow through */
  SetConsoleMode(hIn, ENABLE_WINDOW_INPUT | ENABLE_EXTENDED_FLAGS);

  INPUT_RECORD rec;
  DWORD cnt;

  while (!InterlockedOr(&g_quit, 0)) {
    /* Peek with a short timeout so we check g_quit regularly */
    DWORD w = WaitForSingleObject(hIn, 200);
    if (w != WAIT_OBJECT_0)
      continue;

    if (!ReadConsoleInputA(hIn, &rec, 1, &cnt))
      break;
    if (rec.EventType != KEY_EVENT)
      continue;
    if (!rec.Event.KeyEvent.bKeyDown)
      continue;

    DWORD ks = rec.Event.KeyEvent.dwControlKeyState;
    BOOL altDown = ((ks & LEFT_ALT_PRESSED) || (ks & RIGHT_ALT_PRESSED));
    WORD vk = rec.Event.KeyEvent.wVirtualKeyCode;

    if (!altDown)
      continue;

    /* Normalise: accept upper or lower case */
    if (vk == 'C' || vk == 0x43) { /* Alt+C  -> clear */
      do_clear_screen();
    } else if (vk == 'X' || vk == 0x58) { /* Alt+X  -> quit  */
      EnterCriticalSection(&g_print_lock);
      printf(YEL "\n[HK] Alt+X -- exiting...\n" R);
      LeaveCriticalSection(&g_print_lock);
      InterlockedExchange(&g_quit, 1);
      if (args->cfg->logFile)
        fclose(args->cfg->logFile);
      Sleep(100);
      ExitProcess(0);
    }
  }

  /* restore console mode */
  SetConsoleMode(hIn, origMode);
  return 0;
}

/* ==========================================================================
   Serial helpers
   ========================================================================== */
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
  DWORD br, bw;
  while (!InterlockedOr(&g_quit, 0)) {
    if (!ReadFile(args->hSrc, buf, BUF_SIZE, &br, NULL)) {
      if (!InterlockedOr(&g_quit, 0))
        fprintf(stderr, RED "[ERR] Read: %s (code %lu)\n" R, args->label,
                GetLastError());
      break;
    }
    if (br > 0) {
      log_data(args->cfg, args->label, args->color, buf, br);
      if (!WriteFile(args->hDst, buf, br, &bw, NULL)) {
        if (!InterlockedOr(&g_quit, 0))
          fprintf(stderr, RED "[ERR] Write: %s (code %lu)\n" R, args->label,
                  GetLastError());
        break;
      }
    }
  }
  return 0;
}

/* ==========================================================================
   Usage / main
   ========================================================================== */
static void print_usage(const char *exe) {
  fprintf(stderr,
          BOLD
          "Usage:\n" R
          "  %s -i <IN> -o <OUT> [-b <BAUD>] [-lemode|-bemode] [-c <CFG>]\n\n"
          "Options:\n"
          "  -i <port>    Input  port  (e.g. COM6)           [required]\n"
          "  -o <port>    Output port  (e.g. COM7)           [required]\n"
          "  -b <baud>    Baud rate    (default: 9600)\n"
          "  -lemode      Little-endian parse (default)\n"
          "  -bemode      Big-endian parse\n"
          "  -c <file>    Protocol config file (auto-reloaded on save)\n\n"
          "Config field types:\n"
          "  u8  s8  u16  s16  u32  s32  float  double\n"
          "  u16le u16be u32le u32be s16be etc.  (per-field endian override)\n"
          "  array-N  array-N(label)             (N raw bytes, no endian)\n\n"
          "Filters (inside {}, AND logic):\n"
          "  len=N   idxN=0xVV\n\n"
          "Hotkeys (work in cmd, PowerShell, Windows Terminal):\n"
          "  Alt+C   clear screen\n"
          "  Alt+X   quit\n\n"
          "Example:\n"
          "  %s -i COM6 -o COM7 -b 115200 -bemode -c sniff.cfg\n",
          exe, exe);
}

int main(int argc, char *argv[]) {
  enable_vt();
  InitializeCriticalSection(&g_print_lock);
  InitializeCriticalSection(&g_rs_lock);

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
      fprintf(stderr, RED "[ERR] Unknown: %s\n\n" R, argv[i]);
      print_usage(argv[0]);
      return 1;
    }
  }
  if (!cfg.portIn[0] || !cfg.portOut[0]) {
    fprintf(stderr, RED "[ERR] -i and -o are required.\n\n" R);
    print_usage(argv[0]);
    return 1;
  }

  /* initial config load */
  if (cfg.cfgFile[0]) {
    int n = load_config_into(cfg.cfgFile, &g_rs);
    if (n < 0) {
      fprintf(stderr, RED "[ERR] Cannot open config: %s\n" R, cfg.cfgFile);
      return 1;
    }
    cfg.useParser = (n > 0);
    InterlockedExchange(&g_useParser, cfg.useParser);
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

  /* ── banner ────────────────────────────────────────────────────────── */
  const int BW = 52;
  hline(BOX_TL, BOX_H, BOX_TR, BW, BOLD);
  printf(BOLD BOX_V R "  %-*s" BOLD BOX_V R "\n", BW - 1,
         "  Serial Port Sniffer");
  hline(BOX_ML, BOX_H, BOX_MR, BW, BOLD);
  printf(BOX_V "  " GREEN "In " R "  %-10s  " GRAY "Baud " R YEL "%-8d" R
               "         " BOX_V "\n",
         cfg.portIn, cfg.baud);
  printf(BOX_V "  " CYAN "Out" R "  %-10s  " GRAY "Baud " R YEL "%-8d" R
               "         " BOX_V "\n",
         cfg.portOut, cfg.baud);
  printf(BOX_V "  " GRAY "Log  %-*s" R BOX_V "\n", BW - 8, LOG_FILE);
  printf(BOX_V "  " GRAY "End  %-*s" R BOX_V "\n", BW - 8,
         cfg.big_endian ? "big-endian" : "little-endian (default)");
  if (cfg.cfgFile[0])
    printf(BOX_V "  " MAG "CFG  %-*s" R BOX_V "\n", BW - 8, cfg.cfgFile);
  else
    printf(BOX_V "  " GRAY "CFG  (none -- hex dump only)%-*s" R BOX_V "\n",
           BW - 30, "");
  hline(BOX_ML, BOX_H, BOX_MR, BW, BOLD);
  printf(BOX_V "  " GRAY "Hotkeys:  Alt+C = clear screen   Alt+X = quit" R
               "\n");
  hline(BOX_BL, BOX_H, BOX_BR, BW, BOLD);
  printf("\n");

  if (InterlockedOr(&g_useParser, 0)) {
    EnterCriticalSection(&g_rs_lock);
    RuleSet snap = g_rs;
    LeaveCriticalSection(&g_rs_lock);
    print_ruleset_locked(&snap, cfg.big_endian);
    printf("\n");
  }

  /* ── start background threads ──────────────────────────────────────── */
  static HotkeyArgs hkArgs;
  hkArgs.cfg = &cfg;
  CreateThread(NULL, 0, hotkey_thread, &hkArgs, 0, NULL);

  if (cfg.cfgFile[0]) {
    static WatcherArgs wArgs;
    strncpy_s(wArgs.path, sizeof(wArgs.path), cfg.cfgFile,
              sizeof(wArgs.path) - 1);
    wArgs.big_endian = cfg.big_endian;
    CreateThread(NULL, 0, watcher_thread, &wArgs, 0, NULL);
  }

  /* ── forward threads ───────────────────────────────────────────────── */
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
  DeleteCriticalSection(&g_rs_lock);
  return 0;
}
