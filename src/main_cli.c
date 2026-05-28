/*
 * main_cli.c  --  CLI entry point for UartSniffer
 *
 * Platform-adaptive: Windows (ReadConsoleInput hotkeys) / Linux (Ctrl+C).
 * All serial / parse / watch logic is delegated to libuspy.
 */

#include "uspy.h"

#ifdef _WIN32
  #include <windows.h>
#else
  #include <pthread.h>
  #include <signal.h>
  #include <unistd.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ==========================================================================
   CLI output callbacks → printf
   ========================================================================== */

static void cli_out(void *ctx, const char *text) {
    (void)ctx;
    printf("%s", text);
    fflush(stdout);
}

static void cli_err(void *ctx, const char *text) {
    (void)ctx;
    fprintf(stderr, "%s", text);
    fflush(stderr);
}

/* ==========================================================================
   Banner
   ========================================================================== */

static void rep(char c, int n) { while (n-- > 0) putchar(c); }

static void print_banner(const Config *cfg, const RuleSet *rs) {
    const int BW = 52;
    #define P(fmt, ...) printf(fmt, ##__VA_ARGS__)

    P(BOLD "+"); rep('=', BW); P("+\n");
    P("|  %-*s|\n", BW - 1, "  Serial Port Sniffer");
    P("+"); rep('-', BW); P("+\n");
    P("|  " GREEN "In " R "  %-10s  " GRAY "Baud " R YEL "%-8d" R
      "         |\n", cfg->portIn, cfg->baud);
    P("|  " CYAN "Out" R "  %-10s  " GRAY "Baud " R YEL "%-8d" R
      "         |\n", cfg->portOut, cfg->baud);
    P("|  " GRAY "Log  %-*s" R "|\n", BW - 8, LOG_FILE);
    P("|  " GRAY "End  %-*s" R "|\n", BW - 8,
      cfg->big_endian ? "big-endian" : "little-endian (default)");
    P("|  " GRAY "Buf  %-10u bytes%-*s" R "|\n",
      cfg->buffer_size, BW - 24, "");
    if (cfg->cfgFile[0])
        P("|  " MAG "CFG  %-*s" R "|\n", BW - 8, cfg->cfgFile);
    else
        P("|  " GRAY "CFG  (none -- hex dump only)%-*s" R "|\n", BW - 30, "");
    P("+"); rep('-', BW); P("+\n");
    P("|  " GRAY "Hotkeys:  Alt+C = clear screen   Alt+X = quit" R "|\n");
    P("+"); rep('-', BW); P("+\n\n" R);

    #undef P
    fflush(stdout);

    if (rs->count > 0)
        usp_print_ruleset(rs, cfg->big_endian);
}

/* ==========================================================================
   Usage
   ========================================================================== */

static void print_usage(const char *exe) {
    fprintf(stderr,
            BOLD "Usage:\n" R
            "  %s -i <IN> -o <OUT> [-b <BAUD>] [-B <BYTES>] [-lemode|-bemode] [-c <CFG>]\n\n"
            "Options:\n"
            "  -i <port>    Input  port  (e.g. COM6, /dev/ttyUSB0)\n"
            "  -o <port>    Output port\n"
            "  -b <baud>    Baud rate    (default: 9600)\n"
            "  -B <bytes>   Bridge read/driver buffer size (default: %u, range: %u..%u)\n"
            "  --buffer-size <bytes>\n"
            "  -lemode      Little-endian parse (default)\n"
            "  -bemode      Big-endian parse\n"
            "  -c <file>    Protocol config file (auto-reloaded on save)\n\n"
            "Hotkeys (CLI):\n"
            "  Alt+C   clear screen   (Windows only)\n"
            "  Alt+X   quit           (Windows only)\n"
            "  Ctrl+C  quit           (all platforms)\n\n"
            "Example:\n"
            "  %s -i COM6 -o COM7 -b 115200 -B 8192 -bemode -c sniff.cfg\n",
            exe, USP_DEFAULT_BUFFER_SIZE, USP_MIN_BUFFER_SIZE,
            USP_MAX_BUFFER_SIZE, exe);
}

/* ==========================================================================
   Watcher callback
   ========================================================================== */

static void on_cfg_changed(void *ctx, const char *path) {
    Config *cfg = (Config *)ctx;
    int n = usp_ruleset_load(path);
    if (n >= 0) {
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "\n" MAG "+-- CFG reloaded: %s -- %d rule(s) --+" R "\n",
                 path, n);
        usp_out("%s", buf);
        if (n > 0) {
            RuleSet *snap = (RuleSet *)malloc(sizeof(RuleSet));
            if (snap) {
                usp_ruleset_snapshot(snap);
                usp_print_ruleset(snap, cfg->big_endian);
                free(snap);
            }
        }
        usp_out("\n");
    } else {
        char buf[256];
        snprintf(buf, sizeof(buf),
                 RED "[CFG] Reload failed for '%s'\n" R, path);
        usp_err("%s", buf);
    }
}

/* ==========================================================================
   Forward thread
   ========================================================================== */

typedef struct {
    usp_serial_t hSrc;
    usp_serial_t hDst;
    const char  *label;
    const char  *color;
    Config      *cfg;
} fwd_args_t;

#ifdef _WIN32
static DWORD WINAPI forward_thread(LPVOID param)
#else
static void *forward_thread(void *param)
#endif
{
    fwd_args_t *a = (fwd_args_t *)param;
    unsigned allocated = usp_normalize_buffer_size(a->cfg->buffer_size);
    unsigned buf_size = allocated;
    unsigned char *buf = (unsigned char *)malloc(allocated);
    if (!buf) {
        usp_err(RED "[ERR] Cannot allocate bridge buffer (%u bytes)\n" R,
                allocated);
        usp_quit();
        return 0;
    }

    while (!usp_should_quit()) {
        buf_size = usp_normalize_buffer_size(a->cfg->buffer_size);
        if (buf_size > allocated) {
            unsigned char *new_buf = (unsigned char *)realloc(buf, buf_size);
            if (!new_buf) {
                usp_err(RED "[ERR] Cannot resize bridge buffer (%u bytes)\n" R,
                        buf_size);
                usp_quit();
                break;
            }
            buf = new_buf;
            allocated = buf_size;
        }
        unsigned br = usp_serial_read(a->hSrc, buf, buf_size);
        if (br == 0) {
#ifdef _WIN32
            Sleep(1);
#else
            usleep(1000);
#endif
            continue;
        }
        usp_log_data(a->cfg, a->label, a->color, buf, br);
        usp_serial_write(a->hDst, buf, br);
    }
    free(buf);
    return 0;
}

/* ==========================================================================
   Hotkey thread  (Windows only)
   ========================================================================== */

#ifdef _WIN32

static void do_clear_screen(void) {
    usp_out("\x1b[2J\x1b[H");
    usp_out(BOLD MAG "+==============================================" R "\n");
    usp_out(BOLD MAG "|" R "  " "Serial Port Sniffer  (screen cleared)   "
            BOLD MAG "|" R "\n");
    usp_out(BOLD MAG "|" R "  " "Alt+C = clear   Alt+X = quit            "
            BOLD MAG "|" R "\n");
    usp_out(BOLD MAG "+==============================================" R "\n\n");
}

static DWORD WINAPI hotkey_thread(LPVOID param) {
    (void)param;
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD origMode = 0;
    GetConsoleMode(hIn, &origMode);
    SetConsoleMode(hIn, ENABLE_WINDOW_INPUT | ENABLE_EXTENDED_FLAGS);

    INPUT_RECORD rec;
    DWORD cnt;

    while (!usp_should_quit()) {
        DWORD w = WaitForSingleObject(hIn, 200);
        if (w != WAIT_OBJECT_0) continue;
        if (!ReadConsoleInputA(hIn, &rec, 1, &cnt)) break;
        if (rec.EventType != KEY_EVENT) continue;
        if (!rec.Event.KeyEvent.bKeyDown) continue;

        DWORD ks = rec.Event.KeyEvent.dwControlKeyState;
        BOOL altDown = ((ks & LEFT_ALT_PRESSED) || (ks & RIGHT_ALT_PRESSED));
        if (!altDown) continue;

        WORD vk = rec.Event.KeyEvent.wVirtualKeyCode;
        if (vk == 'C' || vk == 0x43) {
            do_clear_screen();
        } else if (vk == 'X' || vk == 0x58) {
            usp_out(YEL "\n[HK] Alt+X -- exiting...\n" R);
            usp_quit();
            break;
        }
    }

    SetConsoleMode(hIn, origMode);
    return 0;
}
#endif

/* ==========================================================================
   Signal handler (Linux)
   ========================================================================== */

#ifndef _WIN32
static void sigint_handler(int sig) {
    (void)sig;
    usp_out(YEL "\n[INT] Ctrl+C -- exiting...\n" R);
    usp_quit();
}
#endif

/* ==========================================================================
   main
   ========================================================================== */

int main(int argc, char *argv[]) {
    usp_init();

    /* ── parse arguments ──────────────────────────────────────────────── */
    Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.baud = 9600;
    cfg.buffer_size = USP_DEFAULT_BUFFER_SIZE;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_usage(argv[0]);
            return 0;
        } else if (!strcmp(argv[i], "-b") && i + 1 < argc)
            cfg.baud = atoi(argv[++i]);
        else if ((!strcmp(argv[i], "-B") || !strcmp(argv[i], "--buffer-size")) &&
                 i + 1 < argc)
            cfg.buffer_size = usp_normalize_buffer_size((unsigned)strtoul(argv[++i], NULL, 0));
        else if (!strcmp(argv[i], "-i") && i + 1 < argc)
            snprintf(cfg.portIn, MAX_PORT_LEN, "%s", argv[++i]);
        else if (!strcmp(argv[i], "-o") && i + 1 < argc)
            snprintf(cfg.portOut, MAX_PORT_LEN, "%s", argv[++i]);
        else if (!strcmp(argv[i], "-c") && i + 1 < argc)
            snprintf(cfg.cfgFile, sizeof(cfg.cfgFile), "%s", argv[++i]);
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

    /* ── setup output callbacks ───────────────────────────────────────── */
    usp_set_output(cli_out, cli_err, NULL);

    /* ── enable VT processing (Windows ANSI support) ──────────────────── */
#ifdef _WIN32
    {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        GetConsoleMode(hOut, &mode);
        SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
#endif

    /* ── load config ───────────────────────────────────────────────────── */
    /* RuleSet is too large for the stack on Windows; allocate on heap. */
    RuleSet *initial_rs = (RuleSet *)calloc(1, sizeof(RuleSet));
    if (!initial_rs) {
        usp_err(RED "[ERR] Out of memory\n" R);
        return 1;
    }
    if (cfg.cfgFile[0]) {
        int n = load_config_into(cfg.cfgFile, initial_rs);
        if (n < 0) {
            usp_err(RED "[ERR] Cannot open config: %s\n" R, cfg.cfgFile);
            free(initial_rs);
            return 1;
        }
        usp_ruleset_replace(initial_rs);
        usp_set_parser((n > 0) ? 1 : 0);
    }

    /* ── open log file ────────────────────────────────────────────────── */
    FILE *logFile = NULL;
    logFile = fopen(LOG_FILE, "a");
    cfg.logFile = logFile;

    /* ── open serial ports ────────────────────────────────────────────── */
    cfg.buffer_size = usp_normalize_buffer_size(cfg.buffer_size);
    usp_serial_t hIn  = usp_serial_open_ex(cfg.portIn,  cfg.baud, cfg.buffer_size);
    usp_serial_t hOut = usp_serial_open_ex(cfg.portOut, cfg.baud, cfg.buffer_size);

    if (!hIn) {
        usp_err(RED "[ERR] Cannot open input  port %s\n" R, cfg.portIn);
        if (logFile) fclose(logFile);
        return 1;
    }
    if (!hOut) {
        usp_err(RED "[ERR] Cannot open output port %s\n" R, cfg.portOut);
        usp_serial_close(hIn);
        if (logFile) fclose(logFile);
        return 1;
    }

    /* ── banner ───────────────────────────────────────────────────────── */
    print_banner(&cfg, initial_rs);

    /* ── signal handler (Linux) ───────────────────────────────────────── */
#ifndef _WIN32
    signal(SIGINT, sigint_handler);
#endif

    /* ── start watcher ────────────────────────────────────────────────── */
    usp_watcher_t watcher = NULL;
    if (cfg.cfgFile[0])
        watcher = usp_watch_start(cfg.cfgFile, on_cfg_changed, &cfg);

    /* ── start hotkey thread (Windows) ────────────────────────────────── */
#ifdef _WIN32
    CreateThread(NULL, 0, hotkey_thread, NULL, 0, NULL);
#endif

    /* ── start forward threads ────────────────────────────────────────── */
    char labelAB[MAX_PORT_LEN * 2 + 4], labelBA[MAX_PORT_LEN * 2 + 4];
    snprintf(labelAB, sizeof(labelAB), "%s -> %s", cfg.portIn,  cfg.portOut);
    snprintf(labelBA, sizeof(labelBA), "%s -> %s", cfg.portOut, cfg.portIn);

    fwd_args_t argsAB = {hIn, hOut, labelAB, GREEN, &cfg};
    fwd_args_t argsBA = {hOut, hIn, labelBA, CYAN,  &cfg};

#ifdef _WIN32
    HANDLE tAB = CreateThread(NULL, 0, forward_thread, &argsAB, 0, NULL);
    HANDLE tBA = CreateThread(NULL, 0, forward_thread, &argsBA, 0, NULL);
    HANDLE threads[2] = {tAB, tBA};
    WaitForMultipleObjects(2, threads, TRUE, INFINITE);
    CloseHandle(tAB);
    CloseHandle(tBA);
#else
    pthread_t tAB, tBA;
    pthread_create(&tAB, NULL, forward_thread, &argsAB);
    pthread_create(&tBA, NULL, forward_thread, &argsBA);
    pthread_join(tAB, NULL);
    pthread_join(tBA, NULL);
#endif

    /* ── cleanup ──────────────────────────────────────────────────────── */
    if (watcher) usp_watch_stop(watcher);
    usp_serial_close(hIn);
    usp_serial_close(hOut);
    if (logFile) fclose(logFile);
    free(initial_rs);
    usp_shutdown();
    return 0;
}
