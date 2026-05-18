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
    RuleSet tmp;
    int n = load_config_into(path, &tmp);
    if (n < 0) return -1;
    usp_ruleset_replace(&tmp);
    usp_atomic_store(&g_useParser, (n > 0) ? 1 : 0);
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
            if (fl->type == FT_LEN)
                pos += snprintf(buf + pos, sizeof(buf) - pos,
                                CYAN "{len=%d}" R " ", fl->value);
            else
                pos += snprintf(buf + pos, sizeof(buf) - pos,
                                CYAN "{idx%d=0x%02X}" R " ", fl->idx, fl->value);
        }
        for (int f = 0; f < r->field_count; f++) {
            const Field *fld = &r->fields[f];
            char tag[MAX_LABEL_LEN + 16];
            if (fld->type == DT_ARRAY)
                snprintf(tag, sizeof(tag), "array-%d", fld->array_size);
            else
                snprintf(tag, sizeof(tag), "%s", dtype_name(fld));
            if (fld->label[0])
                pos += snprintf(buf + pos, sizeof(buf) - pos,
                                GREEN "[%s:%s]" R " ", tag, fld->label);
            else
                pos += snprintf(buf + pos, sizeof(buf) - pos,
                                GREEN "[%s]" R " ", tag);
        }
        pos += snprintf(buf + pos, sizeof(buf) - pos, "\n");
        usp_out("%s", buf);
    }
}

/* ── single field value printer ─────────────────────────────────────────── */

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

    /* label */
    char lbl[MAX_LABEL_LEN + 4];
    snprintf(lbl, sizeof(lbl), "%-16s",
             fld->label[0] ? fld->label : dtype_name(fld));

    /* hex summary */
    char hexbuf[72] = {0};
    if (fld->type == DT_ARRAY) {
        int show = sz > 8 ? 8 : sz, pos = 0;
        for (int i = 0; i < show; i++)
            pos += snprintf(hexbuf + pos, sizeof(hexbuf) - pos,
                            "%02X ", data[i]);
        if (sz > 8)
            snprintf(hexbuf + pos, sizeof(hexbuf) - pos, "...");
    } else {
        for (int i = 0; i < sz; i++)
            snprintf(hexbuf + i * 3, sizeof(hexbuf) - i * 3,
                     "%02X ", data[i]);
    }

    /* decoded value */
    char valbuf[160] = {0};
    int be = usp_parser_use_be(fld, cfg_be);
    switch (fld->type) {
    case DT_U8:
        snprintf(valbuf, sizeof(valbuf), "%3u  (0x%02X)", data[0], data[0]);
        break;
    case DT_S8:
        snprintf(valbuf, sizeof(valbuf), "%4d", (signed char)data[0]);
        break;
    case DT_U16: {
        unsigned short v;
        if (be) usp_parser_read_u16be(data, &v);
        else    usp_parser_read_u16le(data, &v);
        snprintf(valbuf, sizeof(valbuf), "%5u  (0x%04X)", v, v);
        break;
    }
    case DT_S16: {
        unsigned short raw;
        if (be) usp_parser_read_u16be(data, &raw);
        else    usp_parser_read_u16le(data, &raw);
        snprintf(valbuf, sizeof(valbuf), "%6d", (short)raw);
        break;
    }
    case DT_U32: {
        unsigned raw;
        if (be) usp_parser_read_u32be(data, &raw);
        else    usp_parser_read_u32le(data, &raw);
        snprintf(valbuf, sizeof(valbuf), "%10u  (0x%08X)", raw, raw);
        break;
    }
    case DT_S32: {
        unsigned raw;
        if (be) usp_parser_read_u32be(data, &raw);
        else    usp_parser_read_u32le(data, &raw);
        snprintf(valbuf, sizeof(valbuf), "%11d", (int)raw);
        break;
    }
    case DT_FLOAT: {
        unsigned char fb[4];
        if (be) {
            fb[0] = data[3]; fb[1] = data[2];
            fb[2] = data[1]; fb[3] = data[0];
        } else {
            memcpy(fb, data, 4);
        }
        float fv;
        memcpy(&fv, fb, 4);
        snprintf(valbuf, sizeof(valbuf), "%g", fv);
        break;
    }
    case DT_DOUBLE: {
        unsigned char db[8];
        if (be) {
            for (int i = 0; i < 8; i++) db[i] = data[7 - i];
        } else {
            memcpy(db, data, 8);
        }
        double dv;
        memcpy(&dv, db, 8);
        snprintf(valbuf, sizeof(valbuf), "%g", dv);
        break;
    }
    case DT_ARRAY: {
        int pos = 0;
        pos += snprintf(valbuf + pos, sizeof(valbuf) - pos, "[%d] ", sz);
        for (int i = 0; i < sz && pos < (int)sizeof(valbuf) - 4; i++)
            pos += snprintf(valbuf + pos, sizeof(valbuf) - pos,
                            "%02X ", data[i]);
        break;
    }
    }

    char outbuf[512];
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
    RuleSet snap;
    usp_ruleset_snapshot(&snap);

    const int W = 62;
    for (int r = 0; r < snap.count; r++) {
        const Rule *rule = &snap.rules[r];
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
        return 1;
    }
    return 0;
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
