/*
 * uspy.c  --  UartSniffer core runtime (platform-adaptive)
 *
 * Provides:
 *   - output abstraction  (usp_out / usp_err)
 *   - formatted hex-dump + protocol parse  (usp_log_data)
 *   - ruleset management  (load / snapshot / replace)
 *   - thread-safe global state
 */

#include "uspy.h"

#ifdef _WIN32
  #include <windows.h>
  #include <stdarg.h>
#else
  #include <pthread.h>
  #include <stdarg.h>
  #include <unistd.h>
#endif

/* ==========================================================================
   Platform-adaptive synchronisation helpers
   ========================================================================== */

#ifdef _WIN32
  typedef CRITICAL_SECTION usp_mutex_t;
  #define usp_mutex_init(m)   InitializeCriticalSection(m)
  #define usp_mutex_lock(m)   EnterCriticalSection(m)
  #define usp_mutex_unlock(m) LeaveCriticalSection(m)
  #define usp_mutex_destroy(m) DeleteCriticalSection(m)
  #define usp_atomic_load(p)  (InterlockedOr((LONG volatile*)(p), 0))
  #define usp_atomic_store(p,v) InterlockedExchange((LONG volatile*)(p), (LONG)(v))
#else
  typedef pthread_mutex_t usp_mutex_t;
  #define usp_mutex_init(m)   pthread_mutex_init(m, NULL)
  #define usp_mutex_lock(m)   pthread_mutex_lock(m)
  #define usp_mutex_unlock(m) pthread_mutex_unlock(m)
  #define usp_mutex_destroy(m) pthread_mutex_destroy(m)
  #define usp_atomic_load(p)  __atomic_load_n((volatile int*)(p), __ATOMIC_SEQ_CST)
  #define usp_atomic_store(p,v) __atomic_store_n((volatile int*)(p), (int)(v), __ATOMIC_SEQ_CST)
#endif

/* ==========================================================================
   Globals
   ========================================================================== */

/* console / output serialisation */
static usp_mutex_t g_print_lock;

/* live ruleset */
RuleSet g_rs;
static usp_mutex_t g_rs_lock;

/* atomic parser enable flag */
volatile int g_useParser = 0;

/* global quit signal */
volatile int g_quit = 0;

/* ── output abstraction state ────────────────────────────────────────────── */

static usp_output_fn g_out_fn = NULL;
static usp_output_fn g_err_fn = NULL;
static void         *g_out_ctx = NULL;

unsigned usp_normalize_buffer_size(unsigned size) {
    if (size == 0)
        return USP_DEFAULT_BUFFER_SIZE;
    if (size < USP_MIN_BUFFER_SIZE)
        return USP_MIN_BUFFER_SIZE;
    if (size > USP_MAX_BUFFER_SIZE)
        return USP_MAX_BUFFER_SIZE;
    return size;
}

/* ==========================================================================
   Output abstraction
   ========================================================================== */

void usp_set_output(usp_output_fn out_fn, usp_output_fn err_fn, void *ctx) {
    usp_mutex_lock(&g_print_lock);
    g_out_fn  = out_fn;
    g_err_fn  = err_fn;
    g_out_ctx = ctx;
    usp_mutex_unlock(&g_print_lock);
}

static void usp_voutput(usp_output_fn fn, void *ctx,
                        const char *fmt, va_list args) {
    if (!fn) return;
    char buf[2048];
    vsnprintf(buf, sizeof(buf), fmt, args);
    fn(ctx, buf);
}

void usp_out(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    usp_voutput(g_out_fn, g_out_ctx, fmt, args);
    va_end(args);
}

void usp_err(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    usp_voutput(g_err_fn, g_out_ctx, fmt, args);
    va_end(args);
}

/* ==========================================================================
   Ruleset management
   ========================================================================== */

void usp_ruleset_snapshot(RuleSet *dst) {
    usp_mutex_lock(&g_rs_lock);
    *dst = g_rs;
    usp_mutex_unlock(&g_rs_lock);
}

void usp_ruleset_replace(const RuleSet *src) {
    usp_mutex_lock(&g_rs_lock);
    g_rs = *src;
    usp_mutex_unlock(&g_rs_lock);
}

/* convenience: load config file into global ruleset */
int usp_ruleset_load(const char *path) {
    /* RuleSet is too large to live on the stack on Windows (~2 MB > default 1 MB) */
    RuleSet *tmp = (RuleSet *)malloc(sizeof(RuleSet));
    if (!tmp) return -1;
    int n = load_config_into(path, tmp);
    if (n < 0) { free(tmp); return -1; }
    usp_ruleset_replace(tmp);
    usp_atomic_store(&g_useParser, (n > 0) ? 1 : 0);
    free(tmp);
    return n;
}

/* ==========================================================================
   Render helpers
   ========================================================================== */

static void hline(const char *l, const char *fill, const char *r,
                  int w, const char *col) {
    char buf[256];
    int pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - pos, "%s%s", col, l);
    for (int i = 0; i < w && pos < (int)sizeof(buf) - 2; i++)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "%s", fill);
    snprintf(buf + pos, sizeof(buf) - pos, "%s%s\n", r, R);
    usp_out("%s", buf);
}

static void print_ruleset_locked(const RuleSet *rs, int big_endian) {
    char buf[1024];
    snprintf(buf, sizeof(buf),
             BOLD "  Rules: %d  " R GRAY "(%s)\n" R,
             rs->count, big_endian ? "big-endian" : "little-endian");
    usp_out("%s", buf);

    for (int i = 0; i < rs->count; i++) {
        const Rule *r = &rs->rules[i];
        int pos = 0;
        pos += snprintf(buf + pos, sizeof(buf) - pos,
                        "  " GRAY "#%d" R " ", i + 1);
        if (r->rule_label[0])
            pos += snprintf(buf + pos, sizeof(buf) - pos,
                            YEL "\"%s\"" R "  ", r->rule_label);
        for (int f = 0; f < r->filter_count; f++) {
            const Filter *fl = &r->filters[f];
            switch (fl->type) {
            case FT_LEN:
                pos += snprintf(buf + pos, sizeof(buf) - pos,
                                CYAN "{len=%d}" R " ", fl->value); break;
            case FT_MINLEN:
                pos += snprintf(buf + pos, sizeof(buf) - pos,
                                CYAN "{minlen=%d}" R " ", fl->value); break;
            case FT_MAXLEN:
                pos += snprintf(buf + pos, sizeof(buf) - pos,
                                CYAN "{maxlen=%d}" R " ", fl->value); break;
            case FT_LAST:
                pos += snprintf(buf + pos, sizeof(buf) - pos,
                                CYAN "{last=0x%02X}" R " ", fl->value); break;
            case FT_IDX:
            default:
                pos += snprintf(buf + pos, sizeof(buf) - pos,
                                CYAN "{idx%d=0x%02X}" R " ", fl->idx, fl->value); break;
            }
        }
        for (int f = 0; f < r->field_count; f++) {
            const Field *fld = &r->fields[f];
            char tag[MAX_LABEL_LEN + 16];
            switch (fld->type) {
            case DT_ARRAY:  snprintf(tag, sizeof(tag), "array-%d", fld->array_size); break;
            case DT_STRING: snprintf(tag, sizeof(tag), "str-%d",   fld->array_size); break;
            case DT_BCD:    snprintf(tag, sizeof(tag), "bcd-%d",   fld->array_size); break;
            default:        snprintf(tag, sizeof(tag), "%s",       dtype_name(fld)); break;
            }
            if (fld->label[0])
                pos += snprintf(buf + pos, sizeof(buf) - pos,
                                GREEN "[%s:%s" R, tag, fld->label);
            else
                pos += snprintf(buf + pos, sizeof(buf) - pos,
                                GREEN "[%s" R, tag);

            /* modifiers */
            if (fld->scale != 1.0)
                pos += snprintf(buf + pos, sizeof(buf) - pos, GRAY "@%g" R, fld->scale);
            if (fld->offset != 0.0) {
                if (fld->offset > 0)
                    pos += snprintf(buf + pos, sizeof(buf) - pos, GRAY "+%g" R, fld->offset);
                else
                    pos += snprintf(buf + pos, sizeof(buf) - pos, GRAY "%g" R, fld->offset);
            }
            if (fld->unit[0])
                pos += snprintf(buf + pos, sizeof(buf) - pos, GRAY "=%s" R, fld->unit);
            if (fld->fmt)
                pos += snprintf(buf + pos, sizeof(buf) - pos, GRAY "%%%c" R, fld->fmt);
            if (fld->enum_count)
                pos += snprintf(buf + pos, sizeof(buf) - pos, GRAY "|%dx" R, fld->enum_count);

            pos += snprintf(buf + pos, sizeof(buf) - pos, GREEN "]" R " ");
        }
        pos += snprintf(buf + pos, sizeof(buf) - pos, "\n");
        usp_out("%s", buf);
    }
}

/* ── single field value printer ─────────────────────────────────────────── */

/* Format an integer in binary, max 64 bits. Caller supplies buf. */
static void format_binary(char *buf, size_t bufsz, unsigned long long v, int bits) {
    if (bufsz < (size_t)(bits + 3)) { buf[0] = '\0'; return; }
    size_t pos = 0;
    buf[pos++] = '0'; buf[pos++] = 'b';
    for (int i = bits - 1; i >= 0 && pos + 1 < bufsz; i--)
        buf[pos++] = ((v >> i) & 1) ? '1' : '0';
    buf[pos] = '\0';
}

/* Look up enum name for the given raw integer; returns NULL if no match. */
static const char *enum_lookup(const Field *fld, long long raw) {
    for (int i = 0; i < fld->enum_count; i++)
        if (fld->enums[i].value == (long)raw) return fld->enums[i].name;
    return NULL;
}

/* Append " -> scaled [unit]" and " (enum)" to valbuf if applicable. */
static void append_transforms(char *valbuf, size_t bufsz,
                              const Field *fld, double raw_d, long long raw_i,
                              int is_integer) {
    size_t cur = strlen(valbuf);
    if (cur >= bufsz) return;

    int has_scale = (fld->scale != 1.0 || fld->offset != 0.0);
    if (has_scale) {
        double scaled = raw_d * fld->scale + fld->offset;
        cur += snprintf(valbuf + cur, bufsz - cur, "  -> %g", scaled);
        if (cur < bufsz && fld->unit[0])
            cur += snprintf(valbuf + cur, bufsz - cur, " %s", fld->unit);
    } else if (fld->unit[0]) {
        cur += snprintf(valbuf + cur, bufsz - cur, " %s", fld->unit);
    }

    if (cur < bufsz && is_integer && fld->enum_count) {
        const char *nm = enum_lookup(fld, raw_i);
        if (nm) snprintf(valbuf + cur, bufsz - cur, "  (%s)", nm);
    }
}

/* Format the base (raw) numeric value into valbuf, honoring fld->fmt. */
static void format_integer(char *valbuf, size_t bufsz,
                           long long sval, unsigned long long uval,
                           int is_signed, int width_bits, char fmt) {
    int width_hex = width_bits / 4;
    switch (fmt) {
    case 'x':
        snprintf(valbuf, bufsz, "0x%0*llX", width_hex, uval); break;
    case 'd':
        if (is_signed) snprintf(valbuf, bufsz, "%lld", sval);
        else           snprintf(valbuf, bufsz, "%llu", uval);
        break;
    case 'o':
        snprintf(valbuf, bufsz, "0%llo", uval); break;
    case 'b': {
        char bin[80];
        format_binary(bin, sizeof(bin), uval, width_bits);
        snprintf(valbuf, bufsz, "%s", bin);
        break;
    }
    case 'c':
        if (uval >= 0x20 && uval < 0x7F)
            snprintf(valbuf, bufsz, "'%c'  (0x%02llX)", (char)uval, uval);
        else
            snprintf(valbuf, bufsz, "0x%02llX", uval);
        break;
    default:
        if (is_signed) {
            if (width_bits <= 8)       snprintf(valbuf, bufsz, "%4lld", sval);
            else if (width_bits <= 16) snprintf(valbuf, bufsz, "%6lld", sval);
            else                       snprintf(valbuf, bufsz, "%11lld", sval);
        } else {
            if (width_bits <= 8)       snprintf(valbuf, bufsz, "%3llu  (0x%02llX)", uval, uval);
            else if (width_bits <= 16) snprintf(valbuf, bufsz, "%5llu  (0x%04llX)", uval, uval);
            else                       snprintf(valbuf, bufsz, "%10llu  (0x%08llX)", uval, uval);
        }
        break;
    }
}

static void print_field_value(const Field *fld, const unsigned char *data,
                              unsigned avail, unsigned *consumed,
                              unsigned offset, int cfg_be, FILE *logf) {
    int sz = field_size(fld);
    if (sz <= 0) {
        usp_err(RED "  [!] zero-size field '%s'\n" R, dtype_name(fld));
        return;
    }
    if ((unsigned)sz > avail) {
        char ebuf[256];
        snprintf(ebuf, sizeof(ebuf),
                 RED "  " BOX_V " [%04X]  [!] need %d bytes for '%s', only %u left\n" R,
                 offset, sz, dtype_name(fld), avail);
        usp_out("%s", ebuf);
        *consumed += avail;
        return;
    }

    /* label cell (padded to 16 chars; long labels overflow gracefully) */
    char lbl[MAX_LABEL_LEN + 4];
    snprintf(lbl, sizeof(lbl), "%-16s",
             fld->label[0] ? fld->label : dtype_name(fld));

    /* hex summary cell */
    char hexbuf[72] = {0};
    {
        int show = sz > 8 ? 8 : sz, pos = 0;
        for (int i = 0; i < show; i++)
            pos += snprintf(hexbuf + pos, sizeof(hexbuf) - pos,
                            "%02X ", data[i]);
        if (sz > 8)
            snprintf(hexbuf + pos, sizeof(hexbuf) - pos, "...");
    }

    /* decoded value cell */
    char valbuf[256] = {0};
    int be = usp_parser_use_be(fld, cfg_be);

    switch (fld->type) {
    case DT_U8:
        format_integer(valbuf, sizeof(valbuf), data[0], data[0], 0, 8, fld->fmt);
        append_transforms(valbuf, sizeof(valbuf), fld,
                          (double)data[0], (long long)data[0], 1);
        break;
    case DT_S8: {
        signed char s = (signed char)data[0];
        format_integer(valbuf, sizeof(valbuf), s, (unsigned char)s, 1, 8, fld->fmt);
        append_transforms(valbuf, sizeof(valbuf), fld,
                          (double)s, (long long)s, 1);
        break;
    }
    case DT_U16: {
        unsigned short v;
        if (be) usp_parser_read_u16be(data, &v);
        else    usp_parser_read_u16le(data, &v);
        format_integer(valbuf, sizeof(valbuf), v, v, 0, 16, fld->fmt);
        append_transforms(valbuf, sizeof(valbuf), fld, (double)v, (long long)v, 1);
        break;
    }
    case DT_S16: {
        unsigned short raw;
        if (be) usp_parser_read_u16be(data, &raw);
        else    usp_parser_read_u16le(data, &raw);
        short s = (short)raw;
        format_integer(valbuf, sizeof(valbuf), s, raw, 1, 16, fld->fmt);
        append_transforms(valbuf, sizeof(valbuf), fld, (double)s, (long long)s, 1);
        break;
    }
    case DT_U32: {
        unsigned raw;
        if (be) usp_parser_read_u32be(data, &raw);
        else    usp_parser_read_u32le(data, &raw);
        format_integer(valbuf, sizeof(valbuf), raw, raw, 0, 32, fld->fmt);
        append_transforms(valbuf, sizeof(valbuf), fld, (double)raw, (long long)raw, 1);
        break;
    }
    case DT_S32: {
        unsigned raw;
        if (be) usp_parser_read_u32be(data, &raw);
        else    usp_parser_read_u32le(data, &raw);
        int s = (int)raw;
        format_integer(valbuf, sizeof(valbuf), s, raw, 1, 32, fld->fmt);
        append_transforms(valbuf, sizeof(valbuf), fld, (double)s, (long long)s, 1);
        break;
    }
    case DT_FLOAT: {
        unsigned char fb[4];
        if (be) { fb[0] = data[3]; fb[1] = data[2]; fb[2] = data[1]; fb[3] = data[0]; }
        else    { memcpy(fb, data, 4); }
        float fv;
        memcpy(&fv, fb, 4);
        snprintf(valbuf, sizeof(valbuf), "%g", fv);
        append_transforms(valbuf, sizeof(valbuf), fld, (double)fv, 0, 0);
        break;
    }
    case DT_DOUBLE: {
        unsigned char db[8];
        if (be) { for (int i = 0; i < 8; i++) db[i] = data[7 - i]; }
        else    { memcpy(db, data, 8); }
        double dv;
        memcpy(&dv, db, 8);
        snprintf(valbuf, sizeof(valbuf), "%g", dv);
        append_transforms(valbuf, sizeof(valbuf), fld, dv, 0, 0);
        break;
    }
    case DT_ARRAY: {
        int pos = 0;
        pos += snprintf(valbuf + pos, sizeof(valbuf) - pos, "[%d] ", sz);
        for (int i = 0; i < sz && pos < (int)sizeof(valbuf) - 4; i++)
            pos += snprintf(valbuf + pos, sizeof(valbuf) - pos,
                            "%02X ", data[i]);
        if (fld->unit[0])
            snprintf(valbuf + pos, sizeof(valbuf) - pos, " %s", fld->unit);
        break;
    }
    case DT_STRING: {
        int pos = 0;
        if (pos < (int)sizeof(valbuf) - 2) valbuf[pos++] = '"';
        for (int i = 0; i < sz && pos < (int)sizeof(valbuf) - 4; i++) {
            unsigned char c = data[i];
            if (c == 0) break;                 /* stop at embedded NUL */
            if (c >= 0x20 && c < 0x7F) valbuf[pos++] = (char)c;
            else                       valbuf[pos++] = '.';
        }
        if (pos < (int)sizeof(valbuf) - 1) valbuf[pos++] = '"';
        valbuf[pos] = '\0';
        if (fld->unit[0])
            snprintf(valbuf + pos, sizeof(valbuf) - pos, " %s", fld->unit);
        break;
    }
    case DT_BCD: {
        /* each byte = 2 BCD digits (high nibble first) */
        int pos = 0;
        for (int i = 0; i < sz && pos < (int)sizeof(valbuf) - 4; i++) {
            unsigned hi = (data[i] >> 4) & 0xF;
            unsigned lo =  data[i]       & 0xF;
            if (hi > 9 || lo > 9) {
                snprintf(valbuf, sizeof(valbuf), "<invalid BCD>");
                pos = (int)strlen(valbuf);
                break;
            }
            valbuf[pos++] = (char)('0' + hi);
            valbuf[pos++] = (char)('0' + lo);
        }
        valbuf[pos] = '\0';
        if (fld->unit[0])
            snprintf(valbuf + pos, sizeof(valbuf) - pos, " %s", fld->unit);
        break;
    }
    }

    char outbuf[768];
    snprintf(outbuf, sizeof(outbuf),
             "  " BOX_V "  " GRAY "[%04X]" R "  " BLUE "%-16s" R "  " GRAY
             "%-24s" R "  " WHT "%s" R "\n",
             offset, lbl, hexbuf, valbuf);
    usp_out("%s", outbuf);

    if (logf)
        fprintf(logf, "  | [%04X]  %-16s  %-24s  %s\n", offset, lbl, hexbuf, valbuf);
    *consumed += (unsigned)sz;
}

/* ==========================================================================
   Protocol parse
   ========================================================================== */

int usp_try_parse(Config *cfg, const unsigned char *data, unsigned len,
                  const char *dir) {
    /* RuleSet is too large for the stack; allocate on heap. */
    RuleSet *snap = (RuleSet *)malloc(sizeof(RuleSet));
    if (!snap) return 0;
    usp_ruleset_snapshot(snap);

    const int W = 62;
    int matched = 0;
    for (int r = 0; r < snap->count; r++) {
        const Rule *rule = &snap->rules[r];
        if (!rule_matches(rule, data, len)) continue;

        char hdr[MAX_LINE_LEN];
        if (rule->rule_label[0])
            snprintf(hdr, sizeof(hdr),
                     "Rule #%d \"%s\"  [%s]  %u bytes",
                     r + 1, rule->rule_label, dir, len);
        else
            snprintf(hdr, sizeof(hdr),
                     "Rule #%d  [%s]  %u bytes", r + 1, dir, len);

        hline(BOX_TL, BOX_H, BOX_TR, W, MAG);
        {
            char tmp[1024];
            snprintf(tmp, sizeof(tmp),
                     "  " BOX_V "  " BOLD MAG "%-*s" R "\n", W - 2, hdr);
            usp_out("%s", tmp);
        }
        hline(BOX_ML, BOX_H, BOX_MR, W, MAG);
        {
            char tmp[256];
            snprintf(tmp, sizeof(tmp),
                     "  " BOX_V "  " DIM "%-6s  %-16s  %-24s  %s" R "\n",
                     "Offset", "Field", "Hex", "Value");
            usp_out("%s", tmp);
        }
        hline(BOX_ML, BOX_H, BOX_MR, W, GRAY);

        if (cfg->logFile) {
            fprintf(cfg->logFile, "+%.*s+\n", W,
                    "==============================================================");
            fprintf(cfg->logFile, "| %-*s|\n", W - 1, hdr);
            fprintf(cfg->logFile, "+%.*s+\n", W,
                    "--------------------------------------------------------------");
        }

        const unsigned char *p = data;
        unsigned remain = len, offset = 0;
        for (int fi = 0; fi < rule->field_count && remain > 0; fi++) {
            unsigned before = offset;
            print_field_value(&rule->fields[fi], p, remain, &offset, before,
                              cfg->big_endian, cfg->logFile);
            unsigned consumed = offset - before;
            p += consumed;
            remain -= consumed;
        }

        if (remain > 0) {
            char trail[128] = {0};
            int pos = 0;
            for (unsigned i = 0; i < remain && pos < (int)sizeof(trail) - 4; i++)
                pos += snprintf(trail + pos, sizeof(trail) - pos,
                                "%02X ", p[i]);
            char tmp[512];
            snprintf(tmp, sizeof(tmp),
                     "  " BOX_V "  " GRAY "[%04X]" R "  " YEL "%-16s" R "  " GRAY
                     "%-24s" R "  %s\n",
                     offset, "(trailing)", "", trail);
            usp_out("%s", tmp);
        }

        hline(BOX_BL, BOX_H, BOX_BR, W, MAG);
        usp_out("\n");

        if (cfg->logFile) {
            fprintf(cfg->logFile, "+%.*s+\n\n", W,
                    "--------------------------------------------------------------");
            fflush(cfg->logFile);
        }
        matched = 1;
        break;
    }
    free(snap);
    return matched;
}

/* ==========================================================================
   Hex dump + parse  (main data-entry point)
   ========================================================================== */

#ifdef _WIN32
static void get_local_time(int *h, int *m, int *s, int *ms) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    *h = st.wHour; *m = st.wMinute; *s = st.wSecond; *ms = st.wMilliseconds;
}
#else
#include <sys/time.h>
static void get_local_time(int *h, int *m, int *s, int *ms) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *lt = localtime(&tv.tv_sec);
    *h = lt->tm_hour; *m = lt->tm_min; *s = lt->tm_sec;
    *ms = tv.tv_usec / 1000;
}
#endif

void usp_log_data(const Config *cfg, const char *label, const char *color,
                  const unsigned char *data, unsigned len) {
    int hh, mm, ss, ms;
    get_local_time(&hh, &mm, &ss, &ms);

    usp_mutex_lock(&g_print_lock);

    /* timestamp + header */
    char hdr[256];
    snprintf(hdr, sizeof(hdr),
             "%s[%02d:%02d:%02d.%03d]%s  %s%-20s%s  %s%u bytes%s\n",
             GRAY, hh, mm, ss, ms, R, color, label, R, GRAY, len, R);
    usp_out("%s", hdr);

    if (cfg->logFile)
        fprintf(cfg->logFile, "[%02d:%02d:%02d.%03d]  %-20s  %u bytes\n",
                hh, mm, ss, ms, label, len);

    /* hex dump */
    char rowbuf[256];
    for (unsigned row = 0; row < len; row += COLS_PER_ROW) {
        unsigned end = row + COLS_PER_ROW;
        if (end > len) end = len;

        int pos = 0;
        pos += snprintf(rowbuf + pos, sizeof(rowbuf) - pos,
                        "  %s%04X%s  ", GRAY, row, R);
        for (unsigned i = row; i < end; i++)
            pos += snprintf(rowbuf + pos, sizeof(rowbuf) - pos,
                            "%s%02X%s ", color, data[i], R);
        for (unsigned i = end; i < row + COLS_PER_ROW; i++)
            pos += snprintf(rowbuf + pos, sizeof(rowbuf) - pos, "   ");
        pos += snprintf(rowbuf + pos, sizeof(rowbuf) - pos,
                        " %s|%s ", GRAY, R);
        for (unsigned i = row; i < end; i++) {
            char c = (data[i] >= 0x20 && data[i] < 0x7F) ? (char)data[i] : '.';
            pos += snprintf(rowbuf + pos, sizeof(rowbuf) - pos,
                            "%s%c%s", color, c, R);
        }
        pos += snprintf(rowbuf + pos, sizeof(rowbuf) - pos, "\n");
        usp_out("%s", rowbuf);

        if (cfg->logFile) {
            fprintf(cfg->logFile, "  %04X  ", row);
            for (unsigned i = row; i < end; i++)
                fprintf(cfg->logFile, "%02X ", data[i]);
            for (unsigned i = end; i < row + COLS_PER_ROW; i++)
                fprintf(cfg->logFile, "   ");
            fprintf(cfg->logFile, " | ");
            for (unsigned i = row; i < end; i++)
                fputc((data[i] >= 0x20 && data[i] < 0x7F) ? (char)data[i] : '.',
                      cfg->logFile);
            fputc('\n', cfg->logFile);
        }
    }

    if (usp_atomic_load(&g_useParser)) {
        usp_out("\n");
        if (!usp_try_parse((Config *)cfg, data, len, label))
            usp_out("  " DIM "(no rule matched)%s\n\n" R);
    } else {
        usp_out("\n");
    }

    if (cfg->logFile) {
        fputc('\n', cfg->logFile);
        fflush(cfg->logFile);
    }

    usp_mutex_unlock(&g_print_lock);
}

/* ── banner / reload output ─────────────────────────────────────────────── */

void usp_print_ruleset(const RuleSet *rs, int big_endian) {
    usp_mutex_lock(&g_print_lock);
    print_ruleset_locked(rs, big_endian);
    usp_mutex_unlock(&g_print_lock);
}

/* ==========================================================================
   Init / cleanup
   ========================================================================== */

/* Called once before any other usp_ function from the main thread. */
void usp_init(void) {
    usp_mutex_init(&g_print_lock);
    usp_mutex_init(&g_rs_lock);
    memset(&g_rs, 0, sizeof(g_rs));
    g_useParser = 0;
    g_quit = 0;
}

void usp_set_parser(int on) {
    usp_atomic_store(&g_useParser, on);
}

void usp_shutdown(void) {
    usp_atomic_store(&g_quit, 1);
    usp_mutex_destroy(&g_rs_lock);
    usp_mutex_destroy(&g_print_lock);
}

void usp_quit(void) {
    usp_atomic_store(&g_quit, 1);
}

void usp_reset_quit(void) {
    usp_atomic_store(&g_quit, 0);
}

int usp_should_quit(void) {
    return usp_atomic_load(&g_quit);
}
