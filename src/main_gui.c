/*
 * main_gui.c  --  GUI entry point for UartSniffer
 *
 * Uses SDL2 + Nuklear (immediate-mode GUI).
 * Put nuklear.h in vendor/nuklear.h  (download from
 * https://github.com/Immediate-Mode-UI/Nuklear)
 *
 * Build: see Makefile "gui" target.
 */

/* ── Nuklear / SDL2 headers ────────────────────────────────────────────────
 *
 * Before building, download these files into vendor/ :
 *
 *   vendor/nuklear.h
 *     https://raw.githubusercontent.com/Immediate-Mode-UI/Nuklear/master/nuklear.h
 *
 *   vendor/nuklear_sdl_gl2.h
 *     https://raw.githubusercontent.com/Immediate-Mode-UI/Nuklear/master/demo/sdl_opengl2/nuklear_sdl_gl2.h
 */

#define NK_INCLUDE_FIXED_TYPES
#define NK_INCLUDE_STANDARD_IO
#define NK_INCLUDE_STANDARD_VARARGS
#define NK_INCLUDE_DEFAULT_ALLOCATOR
#define NK_INCLUDE_VERTEX_BUFFER_OUTPUT
#define NK_INCLUDE_FONT_BAKING
#define NK_INCLUDE_DEFAULT_FONT

/* Fix MSVC __COUNTER__ compatibility issue with Nuklear
 * MSVC increments __COUNTER__ each time it's expanded, causing
 * NK_FILE_LINE to have different values when used multiple times
 * (e.g., in nk_tree_push macro), which triggers assertions. */
#ifndef NK_FILE_LINE
  #ifdef _MSC_VER
    #define NK_FILE_LINE __FILE__ ":" NK_MACRO_STRINGIFY(__LINE__)
  #endif
#endif

#define NK_IMPLEMENTATION
#include "../vendor/nuklear.h"

#include <SDL2/SDL.h>
#include <SDL2/SDL_opengl.h>

/* Nuklear SDL2 / OpenGL 2 backend */
#define NK_SDL_GL2_IMPLEMENTATION
#include "../vendor/nuklear_sdl_gl2.h"

/* ── our headers ─────────────────────────────────────────────────────────── */

#include "uspy.h"

#ifdef _WIN32
  #include <windows.h>
  #include <commdlg.h>
#else
  #include <pthread.h>
  #include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* ==========================================================================
   Platform thread helpers
   ========================================================================== */

#ifdef _WIN32
  #define THREAD_RET DWORD WINAPI
  #define THREAD_ARG LPVOID
  #define thread_create(h, fn, arg) \
      (*(h) = CreateThread(NULL, 0, (fn), (arg), 0, NULL))
  #define thread_join(h) WaitForSingleObject(h, INFINITE)
  typedef HANDLE thread_t;
#else
  #define THREAD_RET void *
  #define THREAD_ARG void *
  #define thread_create(h, fn, arg) pthread_create((h), NULL, (fn), (arg))
  #define thread_join(h) pthread_join(*(h), NULL)
  typedef pthread_t thread_t;
#endif

/* ==========================================================================
   Ring buffer for GUI output
   ========================================================================== */

#define RING_CAPACITY 2048
#define GUI_MAX_PORTS 64
#define OUTPUT_HISTORY_CAPACITY 4096

typedef struct {
    char text[512];
    int  color;  /* 0..7, index into gui_colors[] */
} ring_slot_t;

typedef struct {
    ring_slot_t slots[RING_CAPACITY];
    volatile int head;  /* writer advances */
    volatile int tail;  /* reader consumes  */
#ifdef _WIN32
    CRITICAL_SECTION lock;
#else
    pthread_mutex_t lock;
#endif
} ring_t;

static ring_t g_ring;
static struct nk_context *nk_ctx;

static void ring_init(ring_t *r) {
    memset(r, 0, sizeof(*r));
#ifdef _WIN32
    InitializeCriticalSection(&r->lock);
#else
    pthread_mutex_init(&r->lock, NULL);
#endif
}

static void ring_push(ring_t *r, const char *text, int color) {
#ifdef _WIN32
    EnterCriticalSection(&r->lock);
#else
    pthread_mutex_lock(&r->lock);
#endif
    int next = (r->head + 1) % RING_CAPACITY;
    if (next == r->tail) {
        /* buffer full – drop oldest */
        r->tail = (r->tail + 1) % RING_CAPACITY;
    }
    ring_slot_t *slot = &r->slots[r->head];
    strncpy(slot->text, text, sizeof(slot->text) - 1);
    slot->text[sizeof(slot->text) - 1] = '\0';
    slot->color = color;
    r->head = next;
#ifdef _WIN32
    LeaveCriticalSection(&r->lock);
#else
    pthread_mutex_unlock(&r->lock);
#endif
}

static int ring_pop(ring_t *r, ring_slot_t *out) {
#ifdef _WIN32
    EnterCriticalSection(&r->lock);
#else
    pthread_mutex_lock(&r->lock);
#endif
    if (r->tail == r->head) {
#ifdef _WIN32
        LeaveCriticalSection(&r->lock);
#else
        pthread_mutex_unlock(&r->lock);
#endif
        return 0;
    }
    *out = r->slots[r->tail];
    r->tail = (r->tail + 1) % RING_CAPACITY;
#ifdef _WIN32
    LeaveCriticalSection(&r->lock);
#else
    pthread_mutex_unlock(&r->lock);
#endif
    return 1;
}

/* ==========================================================================
   ANSI → colour index parser
   ========================================================================== */

/* Map ANSI escape codes to simple colour indices */
static int ansi_to_color(const char *p, const char **end) {
    if (p[0] != '\x1b' || p[1] != '[') return -1;
    const char *m = p + 2;
    int code = 0;
    while (*m >= '0' && *m <= '9') { code = code * 10 + (*m - '0'); m++; }
    if (*m != 'm') return -1;
    *end = m + 1;

    switch (code) {
    case 0:  return 0;   /* reset → default */
    case 1:  return -2;  /* bold – skip */
    case 2:  return -2;  /* dim – skip */
    case 90: return 1;   /* gray */
    case 91: return 2;   /* red */
    case 92: return 3;   /* green */
    case 93: return 4;   /* yellow */
    case 94: return 5;   /* blue */
    case 95: return 6;   /* magenta */
    case 96: return 7;   /* cyan */
    case 97: return 8;   /* white */
    default: return -2;  /* recognized ANSI SGR, but not color-mapped */
    }
}

/* Parse one text buffer that may contain ANSI escapes into ring slots */
static void output_ansi_lines(ring_t *r, const char *text) {
    const char *p = text;
    char line[512];
    int  linepos = 0;
    int  active_color = 0;

    while (*p) {
        if (*p == '\x1b') {
            const char *end = p;
            int c = ansi_to_color(p, &end);
            if (end != p) {
                if (c >= 0)
                    active_color = c;
                p = end;
                continue;
            }
        }
        if (*p == '\n') {
            line[linepos] = '\0';
            if (linepos > 0) ring_push(r, line, active_color);
            linepos = 0;
            p++;
            continue;
        }
        if (*p == '\r') { p++; continue; }
        if (linepos < (int)sizeof(line) - 1)
            line[linepos++] = *p;
        p++;
    }
    if (linepos > 0) {
        line[linepos] = '\0';
        ring_push(r, line, active_color);
    }
}

/* ==========================================================================
   GUI output callback  (called from worker threads)
   ========================================================================== */

static void gui_out_cb(void *ctx, const char *text) {
    ring_t *r = (ring_t *)ctx;
    output_ansi_lines(r, text);
}

static void gui_err_cb(void *ctx, const char *text) {
    ring_t *r = (ring_t *)ctx;
    output_ansi_lines(r, text);
}

/* ==========================================================================
   Nuklear colour palette
   ========================================================================== */

static struct nk_color gui_colors[] = {
    {220,220,220,255},  /* 0 default / reset */
    {140,140,140,255},  /* 1 gray */
    {255, 80, 80,255},  /* 2 red */
    { 80,255, 80,255},  /* 3 green */
    {255,255, 80,255},  /* 4 yellow */
    { 80,140,255,255},  /* 5 blue */
    {255, 80,255,255},  /* 6 magenta */
    { 80,255,255,255},  /* 7 cyan */
    {255,255,255,255},  /* 8 white */
};

/* ==========================================================================
   Config → GUI state
   ========================================================================== */

typedef struct {
    /* serial */
    char  portIn[MAX_PORT_LEN];
    char  portOut[MAX_PORT_LEN];
    int   baud;
    int   baud_text_len;
    char  baud_text[16];

    /* parser */
    int   big_endian;
    char  cfg_path[256];
    int   rule_count;

    /* discovered ports */
    char  ports[GUI_MAX_PORTS][MAX_PORT_LEN];
    int   port_count;

    /* status */
    int   running;
    int   byte_count_in;
    int   byte_count_out;

    /* persistent output view */
    ring_slot_t output[OUTPUT_HISTORY_CAPACITY];
    int   output_start;
    int   output_count;
    int   auto_scroll_output;

    /* handles */
    usp_serial_t   hIn;
    usp_serial_t   hOut;
    usp_watcher_t  watcher;
    thread_t       thread_ab;
    thread_t       thread_ba;
    Config         cfg;
} gui_state_t;

static void gui_output_append(gui_state_t *gs, const ring_slot_t *slot) {
    int idx;
    if (gs->output_count < OUTPUT_HISTORY_CAPACITY) {
        idx = (gs->output_start + gs->output_count) % OUTPUT_HISTORY_CAPACITY;
        gs->output_count++;
    } else {
        idx = gs->output_start;
        gs->output_start = (gs->output_start + 1) % OUTPUT_HISTORY_CAPACITY;
    }
    gs->output[idx] = *slot;
}

static int gui_output_drain(gui_state_t *gs) {
    int added = 0;
    ring_slot_t slot;
    while (ring_pop(&g_ring, &slot)) {
        gui_output_append(gs, &slot);
        added++;
    }
    return added;
}

static void gui_output_clear(gui_state_t *gs) {
    gs->output_start = 0;
    gs->output_count = 0;
}

static int gui_port_exists(gui_state_t *gs, const char *port) {
    for (int i = 0; i < gs->port_count; i++) {
        if (!strcmp(gs->ports[i], port))
            return 1;
    }
    return 0;
}

static void gui_scan_ports(gui_state_t *gs) {
    char *ports[GUI_MAX_PORTS];
    int n = usp_serial_list(ports, GUI_MAX_PORTS);

    gs->port_count = 0;
    ring_push(&g_ring, "Scanning ports...\n", 5);
    for (int i = 0; i < n; i++) {
        if (ports[i] && ports[i][0] && !gui_port_exists(gs, ports[i]) &&
            gs->port_count < GUI_MAX_PORTS) {
            snprintf(gs->ports[gs->port_count], MAX_PORT_LEN, "%s", ports[i]);
            gs->port_count++;
        }
        free(ports[i]);
    }

    if (gs->port_count == 0) {
        ring_push(&g_ring, "  no serial ports found\n", 2);
        return;
    }

    for (int i = 0; i < gs->port_count; i++) {
        char msg[128];
        snprintf(msg, sizeof(msg), "  found: %s\n", gs->ports[i]);
        ring_push(&g_ring, msg, 1);
    }

    if (!gs->portIn[0])
        snprintf(gs->portIn, sizeof(gs->portIn), "%s", gs->ports[0]);
    if (!gs->portOut[0] && gs->port_count > 1)
        snprintf(gs->portOut, sizeof(gs->portOut), "%s", gs->ports[1]);
}

static void gui_port_dropdown(gui_state_t *gs, char *target, size_t target_size,
                              const char *empty_label) {
    const char *label = target[0] ? target : empty_label;
    if (nk_combo_begin_label(nk_ctx, label, nk_vec2(180, 220))) {
        nk_layout_row_dynamic(nk_ctx, 20, 1);
        if (gs->port_count == 0) {
            nk_label(nk_ctx, "Scan first", NK_TEXT_LEFT);
        } else {
            for (int i = 0; i < gs->port_count; i++) {
                if (nk_combo_item_label(nk_ctx, gs->ports[i], NK_TEXT_LEFT)) {
                    snprintf(target, target_size, "%s", gs->ports[i]);
                    nk_combo_close(nk_ctx);
                }
            }
        }
        nk_combo_end(nk_ctx);
    }
}

static void gui_load_cfg(gui_state_t *gs) {
    if (!gs->cfg_path[0]) {
        ring_push(&g_ring, "CFG path is empty\n", 2);
        return;
    }

    int n = usp_ruleset_load(gs->cfg_path);
    if (n >= 0) {
        gs->rule_count = n;
        char msg[320];
        snprintf(msg, sizeof(msg), "CFG loaded: %s (%d rule(s))\n",
                 gs->cfg_path, n);
        ring_push(&g_ring, msg, 3);
    } else {
        ring_push(&g_ring, "CFG load failed!\n", 2);
    }
}

static void gui_browse_cfg(gui_state_t *gs) {
#ifdef _WIN32
    char path[sizeof(gs->cfg_path)];
    OPENFILENAMEA ofn;
    memset(path, 0, sizeof(path));
    snprintf(path, sizeof(path), "%s", gs->cfg_path);
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = path;
    ofn.nMaxFile = sizeof(path);
    ofn.lpstrFilter = "Config Files\0*.cfg;*.txt\0All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetOpenFileNameA(&ofn)) {
        snprintf(gs->cfg_path, sizeof(gs->cfg_path), "%s", path);
        gui_load_cfg(gs);
    } else {
        DWORD err = CommDlgExtendedError();
        if (err) {
            char msg[128];
            snprintf(msg, sizeof(msg), "Open file dialog failed: 0x%08lX\n",
                     (unsigned long)err);
            ring_push(&g_ring, msg, 2);
        }
    }
#else
    ring_push(&g_ring, "Browse is only implemented on Windows; type the path manually\n", 4);
#endif
}

/* ==========================================================================
   Config file watcher callback  (called from watcher thread)
   ========================================================================== */

static void on_cfg_changed_gui(void *ctx, const char *path) {
    gui_state_t *gs = (gui_state_t *)ctx;
    int n = usp_ruleset_load(path);
    if (n >= 0) {
        gs->rule_count = n;
        char msg[256];
        snprintf(msg, sizeof(msg), "CFG reloaded: %d rule(s)\n", n);
        ring_push(&g_ring, msg, 6); /* magenta */
    } else {
        ring_push(&g_ring, "CFG reload FAILED\n", 2); /* red */
    }
}

/* ==========================================================================
   Forward thread  (worker)
   ========================================================================== */

typedef struct {
    usp_serial_t hSrc;
    usp_serial_t hDst;
    const char  *label;
    const char  *color;
    Config      *cfg;
    int         *byte_count;
} fwd_args_gui_t;

static THREAD_RET forward_thread_gui(THREAD_ARG param) {
    fwd_args_gui_t *a = (fwd_args_gui_t *)param;
    unsigned char buf[BUF_SIZE];

    while (!usp_should_quit()) {
        unsigned br = usp_serial_read(a->hSrc, buf, BUF_SIZE);
        if (br == 0) {
#ifdef _WIN32
            Sleep(1);
#else
            usleep(1000);
#endif
            continue;
        }
        *(a->byte_count) += (int)br;
        usp_log_data(a->cfg, a->label, a->color, buf, br);
        usp_serial_write(a->hDst, buf, br);
    }
    return 0;
}

/* ==========================================================================
   SDL2 → Nuklear glue  (standard boilerplate)
   ========================================================================== */

static SDL_Window        *win;
static SDL_GLContext       gl_ctx;
static int                 win_w = 1100, win_h = 650;
static struct nk_font     *default_font;

static void nuklear_sdl_init(void) {
    SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
    SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);

    win = SDL_CreateWindow("UartSniffer GUI",
                           SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                           win_w, win_h,
                           SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE);
    gl_ctx = SDL_GL_CreateContext(win);

    nk_ctx = nk_sdl_init(win);
    {
        struct nk_font_atlas *atlas;
        nk_sdl_font_stash_begin(&atlas);
        default_font = nk_font_atlas_add_default(atlas, 14.0f, NULL);
        nk_sdl_font_stash_end();
        if (default_font)
            nk_style_set_font(nk_ctx, &default_font->handle);
    }
}

static void nuklear_sdl_shutdown(void) {
    nk_sdl_shutdown();
    SDL_GL_DeleteContext(gl_ctx);
    SDL_DestroyWindow(win);
    SDL_Quit();
}

static void nuklear_sdl_new_frame(void) {
    nk_input_begin(nk_ctx);
    SDL_Event evt;
    while (SDL_PollEvent(&evt)) {
        if (evt.type == SDL_QUIT) usp_quit();
        nk_sdl_handle_event(&evt);
        if (evt.type == SDL_WINDOWEVENT &&
            evt.window.event == SDL_WINDOWEVENT_SIZE_CHANGED) {
            win_w = evt.window.data1;
            win_h = evt.window.data2;
        }
    }
    nk_input_end(nk_ctx);
}

static void nuklear_sdl_render(void) {
    SDL_GL_MakeCurrent(win, gl_ctx);
    glViewport(0, 0, win_w, win_h);
    glClear(GL_COLOR_BUFFER_BIT);
    glClearColor(0.12f, 0.12f, 0.14f, 1.0f);
    nk_sdl_render(NK_ANTI_ALIASING_ON);
    SDL_GL_SwapWindow(win);
}

/* ==========================================================================
   GUI layout
   ========================================================================== */

static void gui_panel_serial(gui_state_t *gs) {
    nk_layout_row_dynamic(nk_ctx, 24, 1);
    nk_label(nk_ctx, "Serial Ports", NK_TEXT_LEFT);

    /* IN port: manual edit plus scanned-port dropdown */
    nk_layout_row_begin(nk_ctx, NK_STATIC, 24, 4);
    nk_layout_row_push(nk_ctx, 32);
    nk_label(nk_ctx, "IN:", NK_TEXT_LEFT);
    nk_layout_row_push(nk_ctx, 118);
    nk_edit_string_zero_terminated(nk_ctx, NK_EDIT_SIMPLE,
                                    gs->portIn, MAX_PORT_LEN,
                                    nk_filter_default);
    nk_layout_row_push(nk_ctx, 112);
    gui_port_dropdown(gs, gs->portIn, sizeof(gs->portIn), "Select IN");
    nk_layout_row_push(nk_ctx, 54);
    if (nk_button_label(nk_ctx, "Scan")) {
        gui_scan_ports(gs);
    }
    nk_layout_row_end(nk_ctx);

    /* OUT port: manual edit plus scanned-port dropdown */
    nk_layout_row_begin(nk_ctx, NK_STATIC, 24, 4);
    nk_layout_row_push(nk_ctx, 32);
    nk_label(nk_ctx, "OUT:", NK_TEXT_LEFT);
    nk_layout_row_push(nk_ctx, 118);
    nk_edit_string_zero_terminated(nk_ctx, NK_EDIT_SIMPLE,
                                    gs->portOut, MAX_PORT_LEN,
                                    nk_filter_default);
    nk_layout_row_push(nk_ctx, 112);
    gui_port_dropdown(gs, gs->portOut, sizeof(gs->portOut), "Select OUT");
    nk_layout_row_push(nk_ctx, 54);
    nk_spacer(nk_ctx);
    nk_layout_row_end(nk_ctx);

    /* Baud: label / edit / combo */
    nk_layout_row_dynamic(nk_ctx, 22, 3);
    nk_label(nk_ctx, "Baud:", NK_TEXT_LEFT);
    nk_edit_string_zero_terminated(nk_ctx, NK_EDIT_SIMPLE,
                                    gs->baud_text, sizeof(gs->baud_text),
                                    nk_filter_decimal);
    if (nk_combo_begin_label(nk_ctx, "presets", nk_vec2(200, 200))) {
        nk_layout_row_dynamic(nk_ctx, 20, 1);
        static const int presets[] = {9600,19200,38400,57600,115200,230400,460800,921600};
        for (int i = 0; i < 8; i++) {
            char buf[16];
            snprintf(buf, sizeof(buf), "%d", presets[i]);
            if (nk_combo_item_label(nk_ctx, buf, NK_TEXT_LEFT)) {
                snprintf(gs->baud_text, sizeof(gs->baud_text), "%d", presets[i]);
                gs->baud = presets[i];
                nk_combo_close(nk_ctx);
            }
        }
        nk_combo_end(nk_ctx);
    }
}

static void gui_panel_parser(gui_state_t *gs) {
    nk_layout_row_dynamic(nk_ctx, 24, 1);
    nk_label(nk_ctx, "Parser", NK_TEXT_LEFT);

    /* endian – radio group */
    nk_layout_row_dynamic(nk_ctx, 22, 2);
    if (nk_option_label(nk_ctx, "Little-Endian", !gs->big_endian))
        gs->big_endian = 0;
    if (nk_option_label(nk_ctx, "Big-Endian", gs->big_endian))
        gs->big_endian = 1;

    /* config file */
    nk_layout_row_dynamic(nk_ctx, 22, 2);
    nk_label(nk_ctx, "CFG:", NK_TEXT_LEFT);
    nk_edit_string_zero_terminated(nk_ctx, NK_EDIT_SIMPLE,
                                    gs->cfg_path, sizeof(gs->cfg_path),
                                    nk_filter_default);
    nk_layout_row_dynamic(nk_ctx, 22, 1);
    if (nk_button_label(nk_ctx, "Browse...")) {
        gui_browse_cfg(gs);
    }

    /* rule count */
    char rbuf[64];
    snprintf(rbuf, sizeof(rbuf), "Rules loaded: %d", gs->rule_count);
    nk_label(nk_ctx, rbuf, NK_TEXT_LEFT);

    if (nk_button_label(nk_ctx, "Reload CFG")) {
        gui_load_cfg(gs);
    }
}

static void gui_panel_control(gui_state_t *gs) {
    nk_layout_row_dynamic(nk_ctx, 24, 1);
    nk_label(nk_ctx, "Control", NK_TEXT_LEFT);

    nk_layout_row_dynamic(nk_ctx, 32, 2);
    if (!gs->running) {
        if (nk_button_label(nk_ctx, "Start")) {
            /* parse baud */
            gs->baud = atoi(gs->baud_text);
            if (gs->baud <= 0) gs->baud = 9600;

            gs->hIn  = usp_serial_open(gs->portIn,  gs->baud);
            gs->hOut = usp_serial_open(gs->portOut, gs->baud);

            if (!gs->hIn || !gs->hOut) {
                ring_push(&g_ring, "Cannot open serial port(s)!\n", 2);
                if (gs->hIn)  usp_serial_close(gs->hIn);
                if (gs->hOut) usp_serial_close(gs->hOut);
                gs->hIn = gs->hOut = NULL;
            } else {
                /* apply config */
                memset(&gs->cfg, 0, sizeof(gs->cfg));
                snprintf(gs->cfg.portIn,  MAX_PORT_LEN, "%s", gs->portIn);
                snprintf(gs->cfg.portOut, MAX_PORT_LEN, "%s", gs->portOut);
                gs->cfg.baud       = gs->baud;
                gs->cfg.big_endian = gs->big_endian;
                snprintf(gs->cfg.cfgFile, sizeof(gs->cfg.cfgFile), "%s", gs->cfg_path);
                gs->cfg.logFile = fopen(LOG_FILE, "a");

                /* load config if specified */
                if (gs->cfg_path[0]) {
                    int n = usp_ruleset_load(gs->cfg_path);
                    if (n >= 0) {
                        gs->rule_count = n;
                        usp_set_parser((n > 0) ? 1 : 0);
                    }
                }

                /* start watcher */
                if (gs->cfg_path[0])
                    gs->watcher = usp_watch_start(gs->cfg_path,
                                                  on_cfg_changed_gui, gs);

                /* start forward threads */
                static fwd_args_gui_t aAB, aBA;
                static char labelAB[MAX_PORT_LEN * 2 + 4];
                static char labelBA[MAX_PORT_LEN * 2 + 4];
                snprintf(labelAB, sizeof(labelAB), "%s -> %s",
                         gs->portIn,  gs->portOut);
                snprintf(labelBA, sizeof(labelBA), "%s -> %s",
                         gs->portOut, gs->portIn);

                aAB.hSrc = gs->hIn;  aAB.hDst = gs->hOut;
                aAB.label = labelAB; aAB.color = GREEN;
                aAB.cfg  = &gs->cfg; aAB.byte_count = &gs->byte_count_in;
                aBA.hSrc = gs->hOut; aBA.hDst = gs->hIn;
                aBA.label = labelBA; aBA.color = CYAN;
                aBA.cfg  = &gs->cfg; aBA.byte_count = &gs->byte_count_out;

                thread_create(&gs->thread_ab, forward_thread_gui, &aAB);
                thread_create(&gs->thread_ba, forward_thread_gui, &aBA);

                gs->running = 1;
                ring_push(&g_ring, "Started.\n", 3);
            }
        }
    } else {
        if (nk_button_label(nk_ctx, "Stop")) {
            usp_quit();
            thread_join(gs->thread_ab);
            thread_join(gs->thread_ba);
            if (gs->watcher) { usp_watch_stop(gs->watcher); gs->watcher = NULL; }
            usp_serial_close(gs->hIn);
            usp_serial_close(gs->hOut);
            if (gs->cfg.logFile) fclose(gs->cfg.logFile);
            gs->hIn = gs->hOut = NULL;
            gs->running = 0;
            gs->byte_count_in  = 0;
            gs->byte_count_out = 0;
            usp_reset_quit();
            usp_set_parser(0);
            ring_push(&g_ring, "Stopped.\n", 4);
        }
    }

    if (nk_button_label(nk_ctx, "Clear")) {
        /* reset ring buffer */
#ifdef _WIN32
        EnterCriticalSection(&g_ring.lock);
#else
        pthread_mutex_lock(&g_ring.lock);
#endif
        g_ring.head = g_ring.tail = 0;
#ifdef _WIN32
        LeaveCriticalSection(&g_ring.lock);
#else
        pthread_mutex_unlock(&g_ring.lock);
#endif
        gui_output_clear(gs);
    }

    /* status line */
    char status[128];
    if (gs->running) {
        snprintf(status, sizeof(status), "RUNNING  IN: %d  OUT: %d",
                 gs->byte_count_in, gs->byte_count_out);
        nk_label_colored(nk_ctx, status, NK_TEXT_LEFT,
                         nk_rgb(80, 255, 80));
    } else {
        nk_label_colored(nk_ctx, "STOPPED", NK_TEXT_LEFT,
                         nk_rgb(200, 200, 200));
    }
}

static void gui_panel_output(gui_state_t *gs) {
    int added = gui_output_drain(gs);

    nk_layout_row_begin(nk_ctx, NK_STATIC, 24, 3);
    nk_layout_row_push(nk_ctx, 80);
    nk_label(nk_ctx, "Output", NK_TEXT_LEFT);
    nk_layout_row_push(nk_ctx, 120);
    nk_checkbox_label(nk_ctx, "Auto-scroll", &gs->auto_scroll_output);
    nk_layout_row_push(nk_ctx, 80);
    if (nk_button_label(nk_ctx, "Bottom"))
        nk_group_set_scroll(nk_ctx, "output_panel", 0, 0x7fffffffU);
    nk_layout_row_end(nk_ctx);

    for (int i = 0; i < gs->output_count; i++) {
        int idx = (gs->output_start + i) % OUTPUT_HISTORY_CAPACITY;
        ring_slot_t *slot = &gs->output[idx];
        struct nk_color c = gui_colors[slot->color % 9];
        nk_layout_row_dynamic(nk_ctx, 18, 1);
        nk_label_colored(nk_ctx, slot->text, NK_TEXT_LEFT, c);
    }

    if (added && gs->auto_scroll_output)
        nk_group_set_scroll(nk_ctx, "output_panel", 0, 0x7fffffffU);
}

/* ==========================================================================
   main
   ========================================================================== */

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShow;
#else
int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
#endif

    usp_init();
    ring_init(&g_ring);
    usp_set_output(gui_out_cb, gui_err_cb, &g_ring);

    static gui_state_t gs;
    memset(&gs, 0, sizeof(gs));
    strcpy(gs.baud_text, "9600");
    gs.baud = 9600;
    gs.auto_scroll_output = 1;

    nuklear_sdl_init();

    while (!usp_should_quit()) {
        nuklear_sdl_new_frame();

        if (nk_begin(nk_ctx, "UartSniffer",
                     nk_rect(0, 0, (float)win_w, (float)win_h),
                     NK_WINDOW_BORDER | NK_WINDOW_TITLE)) {

            /* two columns: left panel (fixed) | right output (fill) */
            {
                float left_w  = 340.0f;
                float right_w = (float)win_w - left_w - 20.0f;
                float panel_h = (float)win_h - 72.0f;
                if (right_w < 100.0f) right_w = 100.0f;
                if (panel_h < 120.0f) panel_h = 120.0f;
                nk_layout_row_begin(nk_ctx, NK_STATIC, panel_h, 2);
                nk_layout_row_push(nk_ctx, left_w);
                {
                    if (nk_group_begin(nk_ctx, "left_panel",
                                       NK_WINDOW_BORDER)) {
                        gui_panel_serial(&gs);
                        nk_layout_row_dynamic(nk_ctx, 6, 1);
                        gui_panel_parser(&gs);
                        nk_layout_row_dynamic(nk_ctx, 6, 1);
                        gui_panel_control(&gs);
                        nk_group_end(nk_ctx);
                    }
                }
                nk_layout_row_push(nk_ctx, right_w);
                {
                    if (nk_group_begin(nk_ctx, "output_panel",
                                       NK_WINDOW_BORDER)) {
                        gui_panel_output(&gs);
                        nk_group_end(nk_ctx);
                    }
                }
                nk_layout_row_end(nk_ctx);
            }
        }
        nk_end(nk_ctx);

        nuklear_sdl_render();
    }

    /* cleanup */
    if (gs.running) {
        usp_quit();
        thread_join(gs.thread_ab);
        thread_join(gs.thread_ba);
        if (gs.watcher) usp_watch_stop(gs.watcher);
        usp_serial_close(gs.hIn);
        usp_serial_close(gs.hOut);
        if (gs.cfg.logFile) fclose(gs.cfg.logFile);
    }
    nuklear_sdl_shutdown();
    usp_shutdown();
    return 0;
}
