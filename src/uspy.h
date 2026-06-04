/*
 * uspy.h  --  UartSniffer shared header
 *
 * Platform-independent types, constants, and API declarations.
 * Used by both CLI and GUI builds.
 */

#ifndef USPY_H
#define USPY_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
  #include <windows.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ── limits ──────────────────────────────────────────────────────────────── */
#define USP_DEFAULT_BUFFER_SIZE 4096U
#define USP_MIN_BUFFER_SIZE     256U
#define USP_MAX_BUFFER_SIZE     65536U
#define BUF_SIZE        USP_DEFAULT_BUFFER_SIZE
#define MAX_PORT_LEN    32
#define LOG_FILE        "sniff.log"
#define COLS_PER_ROW    16
#define MAX_RULES        64
#define MAX_FILTERS      16
#define MAX_FIELDS       64
#define MAX_LABEL_LEN    64
#define MAX_LINE_LEN     512
#define MAX_UNIT_LEN     12
#define MAX_ENUM_NAME    24
#define MAX_ENUM_ENTRIES 16

/* ── ANSI ────────────────────────────────────────────────────────────────── */

/* ANSI escape codes (kept as-is for CLI; parsed/remapped by GUI) */
#define R     "\x1b[0m"
#define GRAY  "\x1b[90m"
#define GREEN "\x1b[92m"
#define CYAN  "\x1b[96m"
#define YEL   "\x1b[93m"
#define RED   "\x1b[91m"
#define MAG   "\x1b[95m"
#define BOLD  "\x1b[1m"
#define DIM   "\x1b[2m"
#define BLUE  "\x1b[94m"
#define WHT   "\x1b[97m"

/* ── box drawing (plain ASCII) ───────────────────────────────────────────── */
#define BOX_TL "+"
#define BOX_TR "+"
#define BOX_BL "+"
#define BOX_BR "+"
#define BOX_H  "-"
#define BOX_V  "|"
#define BOX_ML "+"
#define BOX_MR "+"

/* ==========================================================================
   Data structures
   ========================================================================== */
typedef enum {
    FT_LEN,      /* exact length */
    FT_IDX,      /* data[idx] == value */
    FT_MINLEN,   /* len >= value */
    FT_MAXLEN,   /* len <= value */
    FT_LAST,     /* data[len-1] == value */
} FilterType;
typedef struct {
    FilterType type;
    int        idx;
    int        value;
} Filter;

typedef enum {
    DT_U8, DT_S8, DT_U16, DT_S16,
    DT_U32, DT_S32, DT_FLOAT, DT_DOUBLE,
    DT_ARRAY,
    DT_STRING,   /* printable ASCII, N bytes */
    DT_BCD,      /* BCD-encoded decimal, N bytes (each byte = 2 digits) */
} DataType;

typedef enum { EO_GLOBAL = 0, EO_LE, EO_BE } EndianOverride;

typedef struct {
    long value;
    char name[MAX_ENUM_NAME];
} EnumEntry;

typedef struct {
    DataType        type;
    int             array_size;       /* for DT_ARRAY / DT_STRING / DT_BCD */
    EndianOverride  endian;
    char            label[MAX_LABEL_LEN];

    /* display modifiers (numeric types only, except `unit` which applies to all) */
    double          scale;            /* multiply raw value (default 1.0) */
    double          offset;           /* add after scale       (default 0.0) */
    char            unit[MAX_UNIT_LEN];  /* unit string e.g. "V", "°C"     */
    char            fmt;              /* display format: 'x' hex, 'd' dec,
                                                            'b' binary,
                                                            'o' octal,
                                                            'c' char,
                                                            0 = default      */
    EnumEntry       enums[MAX_ENUM_ENTRIES];
    int             enum_count;
} Field;

typedef struct {
    char    raw[MAX_LINE_LEN];
    Filter  filters[MAX_FILTERS];
    int     filter_count;
    Field   fields[MAX_FIELDS];
    int     field_count;
    char    rule_label[MAX_LABEL_LEN];
} Rule;

typedef struct {
    Rule rules[MAX_RULES];
    int  count;
} RuleSet;

typedef struct {
    char   portIn[MAX_PORT_LEN];
    char   portOut[MAX_PORT_LEN];
    int    baud;
    char   cfgFile[256];
    int    useParser;
    int    big_endian;
    unsigned buffer_size;
    FILE  *logFile;
} Config;

typedef struct {
    void       *hSrc;       /* platform handle */
    void       *hDst;       /* platform handle */
    const char *label;
    const char *color;
    Config     *cfg;
} ForwardArgs;

/* ── output abstraction ──────────────────────────────────────────────────── */

/*
 * Callback type for all user-visible output.
 * ctx   – opaque pointer set by the front-end
 * text  – NUL-terminated UTF-8 string (may contain ANSI escapes)
 */
typedef void (*usp_output_fn)(void *ctx, const char *text);

/* Set before calling any library function. */
void usp_set_output(usp_output_fn out_fn, usp_output_fn err_fn, void *ctx);

/* Formatted output – replaces printf / fprintf(stderr,…).
 * Internally formats into a stack buffer then calls the registered callback.
 * Newline is NOT appended automatically – callers must include \n.
 */
void usp_out(const char *fmt, ...);
void usp_err(const char *fmt, ...);

/* ==========================================================================
   API – parser (platform independent)
   ========================================================================== */

/* ── config parsing ─────────────────────────────────────────────────────── */

/* Parse a single rule line; returns 0 on success, -1 if skipped. */
int  parse_rule_line(const char *line, Rule *rule);

/* Load a .cfg file into a RuleSet. Returns number of rules loaded, -1 on
   file-open error. */
int  load_config_into(const char *path, RuleSet *rs);

/* ── runtime matching ───────────────────────────────────────────────────── */

/* Return 1 if the rule's filters all match the given packet. */
int  rule_matches(const Rule *rule, const unsigned char *data, unsigned len);

/* Total byte-size of a field. */
int  field_size(const Field *fld);

/* Human-readable type name (e.g. "u16be", "float") */
const char *dtype_name(const Field *fld);

/* ── endian-aware byte readers (implemented in parser.c) ─────────────────── */

void usp_parser_read_u16le(const unsigned char *p, unsigned short *v);
void usp_parser_read_u16be(const unsigned char *p, unsigned short *v);
void usp_parser_read_u32le(const unsigned char *p, unsigned *v);
void usp_parser_read_u32be(const unsigned char *p, unsigned *v);
int  usp_parser_use_be(const Field *fld, int cfg_be);

/* ==========================================================================
   API – serial abstraction (platform layer)
   ========================================================================== */

/*
 * Opaque handle (cast to platform type internally).
 * On Windows  → HANDLE
 * On Linux    → int fd
 */
typedef void *usp_serial_t;

/* Enumerate available serial ports.
   buf      – output array of port names (caller frees each with free())
   max      – capacity of buf
   returns  – number of ports written */
int  usp_serial_list(char **buf, int max);

/* Open a serial port.  port is a platform-native name ("COM6", "/dev/ttyUSB0").
   Returns NULL on failure. */
usp_serial_t usp_serial_open_ex(const char *port, int baud, unsigned buffer_size);
usp_serial_t usp_serial_open(const char *port, int baud);

/* Clamp user input to a usable serial bridge buffer size. */
unsigned usp_normalize_buffer_size(unsigned size);

/* Read up to `len` bytes. Returns bytes actually read, or 0 on error/timeout. */
unsigned usp_serial_read(usp_serial_t h, unsigned char *buf, unsigned len);

/* Write up to `len` bytes. Returns bytes actually written. */
unsigned usp_serial_write(usp_serial_t h, const unsigned char *buf, unsigned len);

/* Apply the platform serial-driver queue size where supported. */
void usp_serial_set_buffer_size(usp_serial_t h, unsigned buffer_size);

/* Close the port. */
void usp_serial_close(usp_serial_t h);

/* ==========================================================================
   API – file-watch abstraction (platform layer)
   ========================================================================== */

/*
 * Opaque watcher handle.
 */
typedef void *usp_watcher_t;

/*
 * Callback type: invoked when the watched file is modified.
 * ctx   – user pointer
 * path  – absolute or relative path to the watched file
 */
typedef void (*usp_watch_cb)(void *ctx, const char *path);

/*
 * Start watching `filepath` for modifications.
 * The callback is called from a background thread.
 * Returns NULL on failure.
 */
usp_watcher_t usp_watch_start(const char *filepath, usp_watch_cb cb, void *ctx);

/*
 * Stop watching. Blocks until the watcher thread exits.
 */
void usp_watch_stop(usp_watcher_t w);

/* ==========================================================================
   API – runtime (shared between CLI / GUI)
   ========================================================================== */

/*
 * Global parser flag.  Front-ends set this to enable or disable
 * protocol-parsing output.
 */
extern volatile int g_useParser;

/*
 * Global RuleSet.  Protected by g_rs_lock internally.
 */
extern RuleSet g_rs;

/* ── lifecycle ──────────────────────────────────────────────────────────── */

/* Call once before any other usp_ function. */
void usp_init(void);

/* Signal quit to all background threads, then destroy mutexes. */
void usp_shutdown(void);

/* Signal quit (non-blocking). */
void usp_quit(void);

/* Reset quit flag for next run. */
void usp_reset_quit(void);

/* Check quit flag. */
int  usp_should_quit(void);

/* Enable or disable protocol-parsing output (atomic). */
void usp_set_parser(int on);

/* ── thread-safe RuleSet access ─────────────────────────────────────────── */

/* Snapshot the current ruleset (caller must provide storage). */
void usp_ruleset_snapshot(RuleSet *dst);

/* Atomically replace the ruleset (used by watcher / manual load). */
void usp_ruleset_replace(const RuleSet *src);

/* Load a .cfg file into the global ruleset. Returns rule count, -1 on error. */
int  usp_ruleset_load(const char *path);

/* ── formatted data output ──────────────────────────────────────────────── */

/*
 * Hex-dump + optional protocol parse of a data packet.
 * cfg   – current configuration
 * label – direction label (e.g. "COM6 -> COM7")
 * color – ANSI colour prefix  (e.g. GREEN)
 * data  – raw bytes
 * len   – number of bytes
 *
 * This function is the main rendering entry-point – it calls usp_out / usp_err
 * internally.  GUI front-ends receive the output via the registered callback.
 */
void usp_log_data(const Config *cfg, const char *label, const char *color,
                  const unsigned char *data, unsigned len);

/*
 * Print a summary of the current ruleset (used for banner / reload).
 */
void usp_print_ruleset(const RuleSet *rs, int big_endian);

/* ── protocol parse (standalone, no output) ─────────────────────────────── */

/*
 * Try to match and format a parsed packet.  Returns 1 if a rule matched,
 * 0 otherwise.  Output goes through usp_out.
 */
int  usp_try_parse(Config *cfg, const unsigned char *data, unsigned len,
                   const char *dir);

#ifdef __cplusplus
}
#endif

#endif /* USPY_H */
