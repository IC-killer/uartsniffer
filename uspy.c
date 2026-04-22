#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define BUF_SIZE 1024
#define MAX_PORT_LEN 32
#define LOG_FILE "sniff.log"
#define COLS_PER_ROW 16
#define MAX_RULES 64
#define MAX_FILTERS 16
#define MAX_FIELDS 64
#define MAX_LABEL_LEN 64
#define MAX_LINE_LEN 512

/* ─── ANSI ───────────────────────────────────────────────────────────────────
 */
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

/* ═══════════════════════════════════════════════════════════════════════════
   Config / Rule structures
   ═══════════════════════════════════════════════════════════════════════════
 */

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
  DT_U16BE,
  DT_S16BE,
  DT_U32,
  DT_S32,
  DT_U32BE,
  DT_S32BE,
  DT_FLOAT,
  DT_DOUBLE,
} DataType;

typedef struct {
  DataType type;
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

/* ═══════════════════════════════════════════════════════════════════════════
   String helpers
   ═══════════════════════════════════════════════════════════════════════════
 */
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

/* ═══════════════════════════════════════════════════════════════════════════
   Config parser
   ═══════════════════════════════════════════════════════════════════════════
 */
static int parse_dtype(const char *tok, DataType *out) {
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
  } else if (!strcmp(tok, "u16be")) {
    *out = DT_U16BE;
    return 2;
  } else if (!strcmp(tok, "s16be")) {
    *out = DT_S16BE;
    return 2;
  } else if (!strcmp(tok, "u32")) {
    *out = DT_U32;
    return 4;
  } else if (!strcmp(tok, "s32")) {
    *out = DT_S32;
    return 4;
  } else if (!strcmp(tok, "u32be")) {
    *out = DT_U32BE;
    return 4;
  } else if (!strcmp(tok, "s32be")) {
    *out = DT_S32BE;
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

static int parse_field(const char *block, Field *fld) {
  char tmp[MAX_LINE_LEN];
  strncpy_s(tmp, MAX_LINE_LEN, block, MAX_LINE_LEN - 1);
  str_trim(tmp);
  char type_str[MAX_LABEL_LEN] = {0};
  fld->label[0] = '\0';
  char *lp = strchr(tmp, '(');
  if (lp) {
    int tlen = (int)(lp - tmp);
    if (tlen <= 0 || tlen >= MAX_LABEL_LEN)
      return -1;
    strncpy_s(type_str, MAX_LABEL_LEN, tmp, tlen);
    str_trim(type_str);
    char *rp = strrchr(lp, ')');
    if (!rp)
      return -1;
    int llen = (int)(rp - lp - 1);
    if (llen > 0 && llen < MAX_LABEL_LEN)
      strncpy_s(fld->label, MAX_LABEL_LEN, lp + 1, llen);
  } else {
    strncpy_s(type_str, MAX_LABEL_LEN, tmp, MAX_LABEL_LEN - 1);
    str_trim(type_str);
  }
  DataType dt;
  if (parse_dtype(type_str, &dt) < 0)
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

/* ═══════════════════════════════════════════════════════════════════════════
   Runtime: filter match + field decode
   ═══════════════════════════════════════════════════════════════════════════
 */
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

static const char *dtype_name(DataType dt) {
  switch (dt) {
  case DT_U8:
    return "u8";
  case DT_S8:
    return "s8";
  case DT_U16:
    return "u16";
  case DT_S16:
    return "s16";
  case DT_U16BE:
    return "u16be";
  case DT_S16BE:
    return "s16be";
  case DT_U32:
    return "u32";
  case DT_S32:
    return "s32";
  case DT_U32BE:
    return "u32be";
  case DT_S32BE:
    return "s32be";
  case DT_FLOAT:
    return "float";
  case DT_DOUBLE:
    return "double";
  default:
    return "?";
  }
}
static int dtype_size(DataType dt) {
  switch (dt) {
  case DT_U8:
  case DT_S8:
    return 1;
  case DT_U16:
  case DT_S16:
  case DT_U16BE:
  case DT_S16BE:
    return 2;
  case DT_U32:
  case DT_S32:
  case DT_U32BE:
  case DT_S32BE:
  case DT_FLOAT:
    return 4;
  case DT_DOUBLE:
    return 8;
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

static void print_field_value(const Field *fld, const BYTE *data, DWORD avail,
                              DWORD *consumed, FILE *logFile) {
  int sz = dtype_size(fld->type);
  if ((DWORD)sz > avail) {
    printf(RED "  [!] Not enough bytes for %s (need %d, have %lu)\n" R,
           dtype_name(fld->type), sz, (unsigned long)avail);
    *consumed += avail;
    return;
  }
  char lbl[MAX_LABEL_LEN + 4];
  _snprintf_s(lbl, sizeof(lbl), sizeof(lbl) - 1, "%-16s",
              fld->label[0] ? fld->label : dtype_name(fld->type));

  char hexbuf[32] = {0};
  for (int i = 0; i < sz; i++)
    _snprintf_s(hexbuf + i * 3, sizeof(hexbuf) - i * 3, 3, "%02X ", data[i]);

  char valbuf[64] = {0};
  switch (fld->type) {
  case DT_U8:
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%3u (0x%02X)",
                data[0], data[0]);
    break;
  case DT_S8:
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%4d",
                (int8_t)data[0]);
    break;
  case DT_U16:
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%5u (0x%04X)",
                rd_u16le(data), rd_u16le(data));
    break;
  case DT_S16:
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%6d",
                (int16_t)rd_u16le(data));
    break;
  case DT_U16BE:
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%5u (0x%04X)",
                rd_u16be(data), rd_u16be(data));
    break;
  case DT_S16BE:
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%6d",
                (int16_t)rd_u16be(data));
    break;
  case DT_U32:
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%10u (0x%08X)",
                rd_u32le(data), rd_u32le(data));
    break;
  case DT_S32:
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%11d",
                (int32_t)rd_u32le(data));
    break;
  case DT_U32BE:
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%10u (0x%08X)",
                rd_u32be(data), rd_u32be(data));
    break;
  case DT_S32BE:
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%11d",
                (int32_t)rd_u32be(data));
    break;
  case DT_FLOAT: {
    float fv;
    memcpy(&fv, data, 4);
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%g", fv);
    break;
  }
  case DT_DOUBLE: {
    double dv;
    memcpy(&dv, data, 8);
    _snprintf_s(valbuf, sizeof(valbuf), sizeof(valbuf) - 1, "%g", dv);
    break;
  }
  }

  printf("    %s%-16s%s  %s%-12s%s  %s%s%s\n", BLUE, lbl, R, GRAY, hexbuf, R,
         WHT, valbuf, R);
  if (logFile)
    fprintf(logFile, "    %-16s  %-12s  %s\n", lbl, hexbuf, valbuf);
  *consumed += sz;
}

static int try_parse(Config *cfg, const BYTE *data, DWORD len, const char *dir,
                     FILE *logFile) {
  for (int r = 0; r < cfg->rs.count; r++) {
    const Rule *rule = &cfg->rs.rules[r];
    if (!rule_matches(rule, data, len))
      continue;

    char hdr[MAX_LINE_LEN];
    if (rule->rule_label[0])
      _snprintf_s(hdr, sizeof(hdr), sizeof(hdr) - 1, "Rule #%d  \"%s\"", r + 1,
                  rule->rule_label);
    else
      _snprintf_s(hdr, sizeof(hdr), sizeof(hdr) - 1, "Rule #%d", r + 1);

    printf("  %s - %s%s%s  %s[%s]%s  %s%lu bytes%s\n", MAG, BOLD, hdr, R, GRAY,
           dir, R, GRAY, (unsigned long)len, R);
    if (logFile)
      fprintf(logFile, "  -- %s [%s] %lu bytes\n", hdr, dir,
              (unsigned long)len);

    /* column header */
    printf("  %s|%s  %s%-16s  %-12s  Value%s\n", MAG, R, DIM, "Field", "Hex",
           R);
    printf("  %s|%s  %s%s%s\n", MAG, R, GRAY,
           "---------------------------------------------", R);

    const BYTE *p = data;
    DWORD remain = len, offset = 0;
    for (int fi = 0; fi < rule->field_count && remain > 0; fi++) {
      printf("  %s|%s  " GRAY "[%02lu]" R "  ", MAG, R, (unsigned long)offset);
      /* move cursor back to start of field print line — just print offset
       * inline */
      /* rewrite: offset is printed inside the line */
      /* Actually, print offset as prefix then field */
      /* Let's redo this line cleanly: */
      /* We already printed "  │  [offset]  " so now print field inline */
      DWORD before = offset;
      /* print_field_value prints its own newline */
      /* Need to absorb the "    " it prints. Workaround: just call it, it
       * starts with spaces */
      print_field_value(&rule->fields[fi], p, remain, &offset, logFile);
      DWORD consumed = offset - before;
      p += consumed;
      remain -= consumed;
    }
    if (remain > 0) {
      printf("  %s|%s  " GRAY "[%02lu]" R "  " YEL "%-16s" R "  " GRAY, MAG, R,
             (unsigned long)offset, "(trailing)");
      for (DWORD i = 0; i < remain; i++)
        printf("%02X ", p[i]);
      printf(R "\n");
    }
    printf("  %s ------------------------------------------------%s\n\n", MAG,
           R);
    if (logFile) {
      fprintf(logFile, "  --------------------------------\n");
      fflush(logFile);
    }
    return 1;
  }
  return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
   Hex dump
   ═══════════════════════════════════════════════════════════════════════════
 */
static void log_data(Config *cfg, const char *label, const char *color,
                     const BYTE *data, DWORD len) {
  SYSTEMTIME st;
  GetLocalTime(&st);
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
}

/* ═══════════════════════════════════════════════════════════════════════════
   Serial helpers
   ═══════════════════════════════════════════════════════════════════════════
 */
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

/* ═══════════════════════════════════════════════════════════════════════════
   Usage / main
   ═══════════════════════════════════════════════════════════════════════════
 */
static void print_usage(const char *exe) {
  fprintf(
      stderr,
      BOLD
      "Usage:\n" R "  %s -i <IN> -o <OUT> [-b <BAUD>] [-c <CFG>]\n\n"
      "Options:\n"
      "  -i <port>    Input  port  (e.g. COM6)          [required]\n"
      "  -o <port>    Output port  (e.g. COM7)          [required]\n"
      "  -b <baud>    Baud rate    (default: 9600)\n"
      "  -c <file>    Protocol config file              [optional]\n\n"
      "Config file format (one rule per line):\n"
      "  {filter,...} [type] [type(label)] ...          # optional rule "
      "name\n\n"
      "  Filters (inside {}, comma-separated, AND logic):\n"
      "    len=N          total packet length == N\n"
      "    idxN=0xVV      byte[N] == 0xVV  (hex or decimal)\n\n"
      "  Field types (inside []):\n"
      "    u8  s8\n"
      "    u16  s16  u16be  s16be   (default little-endian)\n"
      "    u32  s32  u32be  s32be\n"
      "    float  double\n"
      "    Wrap with (label) to name a field: [u16(voltage)]\n\n"
      "  Comments: lines starting with # or ;  |  inline: ... # note\n\n"
      "Example config:\n"
      "  # sensor packet: addr u8, voltage u16LE, temp s16LE, timestamp u32LE\n"
      "  {len=9, idx0=0x01} [u8(addr)] [u16(voltage)] [s16(temp)] "
      "[u32(timestamp)]\n\n"
      "  # motor command: id must be 0xA0\n"
      "  {idx0=0xA0} [u8(id)] [u8(cmd)] [s16be(speed)]  # motor_cmd\n\n"
      "Example run:\n"
      "  %s -i COM6 -o COM7 -b 115200 -c sniff.cfg\n",
      exe, exe);
}

static void print_ruleset(const RuleSet *rs) {
  printf(BOLD "  Loaded %d rule(s):\n" R, rs->count);
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
      if (fld->label[0])
        printf(GREEN "[%s:%s]" R " ", dtype_name(fld->type), fld->label);
      else
        printf(GREEN "[%s]" R " ", dtype_name(fld->type));
    }
    printf("\n");
  }
}

int main(int argc, char *argv[]) {
  enable_vt();
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

  printf(BOLD " ========================================== \n"
              "|         Serial Port Sniffer              |\n"
              " ========================================== \n" R);
  printf("  " GREEN "In" R "   %-10s  " GRAY "Baud" R " " YEL "%d" R "\n",
         cfg.portIn, cfg.baud);
  printf("  " CYAN "Out" R "  %-10s  " GRAY "Baud" R " " YEL "%d" R "\n",
         cfg.portOut, cfg.baud);
  printf("  " GRAY "Log" R "  " GRAY "%s" R "\n", LOG_FILE);
  if (cfg.useParser) {
    printf("  " MAG "CFG" R "  " GRAY "%s" R "\n", cfg.cfgFile);
    print_ruleset(&cfg.rs);
  } else {
    printf("  " GRAY "CFG  (none — hex dump only)" R "\n");
  }
  printf(GRAY "\n  Press Ctrl+C to stop.\n\n" R);

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
  return 0;
}
