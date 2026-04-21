#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define BUF_SIZE 1024
#define MAX_PORT_LEN 32
#define LOG_FILE "sniff.log"
#define COLS_PER_ROW 16

/* ─── ANSI colors (works in Windows 10+ terminal) ───────────────────────────
 */
#define CLR_RESET "\x1b[0m"
#define CLR_GRAY "\x1b[90m"
#define CLR_GREEN "\x1b[92m"
#define CLR_CYAN "\x1b[96m"
#define CLR_YELLOW "\x1b[93m"
#define CLR_RED "\x1b[91m"
#define CLR_BOLD "\x1b[1m"

/* ─── Global config ──────────────────────────────────────────────────────────
 */
typedef struct {
  char portIn[MAX_PORT_LEN];  /* -i  e.g. COM6  */
  char portOut[MAX_PORT_LEN]; /* -o  e.g. COM7  */
  int baud;                   /* -b  e.g. 9600  */
  FILE *logFile;
} Config;

typedef struct {
  HANDLE hSrc;
  HANDLE hDst;
  const char *label;
  const char *color;
  Config *cfg;
} ForwardArgs;

/* ─── Helpers ────────────────────────────────────────────────────────────────
 */
static void enable_vt(void) {
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD mode = 0;
  GetConsoleMode(h, &mode);
  SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

static void print_usage(const char *exe) {
  fprintf(stderr,
          CLR_BOLD "Usage:" CLR_RESET
                   "  %s -i <IN_PORT> -o <OUT_PORT> [-b <BAUD>]\n\n"
                   "Options:\n"
                   "  -i <port>   Input  port  (e.g. COM6)  [required]\n"
                   "  -o <port>   Output port  (e.g. COM7)  [required]\n"
                   "  -b <baud>   Baud rate    (default: 9600)\n\n"
                   "Example:\n"
                   "  %s -i COM6 -o COM7 -b 115200\n",
          exe, exe);
}

/* Prefix \\.\ if not already present */
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

/* ─── Logging ────────────────────────────────────────────────────────────────
 */
static void log_data(Config *cfg, const char *label, const char *color,
                     const BYTE *data, DWORD len) {
  SYSTEMTIME st;
  GetLocalTime(&st);

  /* ── header line ── */
  printf("%s[%02d:%02d:%02d.%03d]%s %s%-10s%s %s%4lu bytes%s\n", CLR_GRAY,
         st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, CLR_RESET, color,
         label, CLR_RESET, CLR_GRAY, (unsigned long)len, CLR_RESET);

  /* ── hex + ascii dump, COLS_PER_ROW bytes per row ── */
  for (DWORD row = 0; row < len; row += COLS_PER_ROW) {
    DWORD end = row + COLS_PER_ROW;
    if (end > len)
      end = len;

    /* offset */
    printf("  %s%04lX%s  ", CLR_GRAY, (unsigned long)row, CLR_RESET);

    /* hex */
    for (DWORD i = row; i < end; i++)
      printf("%s%02X%s ", color, data[i], CLR_RESET);

    /* padding for short last row */
    for (DWORD i = end; i < row + COLS_PER_ROW; i++)
      printf("   ");

    /* separator */
    printf(" %s|%s ", CLR_GRAY, CLR_RESET);

    /* ascii */
    for (DWORD i = row; i < end; i++) {
      char c = (data[i] >= 0x20 && data[i] < 0x7F) ? (char)data[i] : '.';
      printf("%s%c%s", color, c, CLR_RESET);
    }
    printf("\n");
  }
  printf("\n");

  /* ── write plain text to log file ── */
  if (cfg->logFile) {
    fprintf(cfg->logFile, "[%02d:%02d:%02d.%03d] %-10s %lu bytes\n", st.wHour,
            st.wMinute, st.wSecond, st.wMilliseconds, label,
            (unsigned long)len);

    for (DWORD row = 0; row < len; row += COLS_PER_ROW) {
      DWORD end = row + COLS_PER_ROW;
      if (end > len)
        end = len;

      fprintf(cfg->logFile, "  %04lX  ", (unsigned long)row);
      for (DWORD i = row; i < end; i++)
        fprintf(cfg->logFile, "%02X ", data[i]);
      for (DWORD i = end; i < row + COLS_PER_ROW; i++)
        fprintf(cfg->logFile, "   ");
      fprintf(cfg->logFile, " | ");
      for (DWORD i = row; i < end; i++) {
        char c = (data[i] >= 0x20 && data[i] < 0x7F) ? (char)data[i] : '.';
        fputc(c, cfg->logFile);
      }
      fputc('\n', cfg->logFile);
    }
    fputc('\n', cfg->logFile);
    fflush(cfg->logFile);
  }
}

/* ─── Forward thread ─────────────────────────────────────────────────────────
 */
DWORD WINAPI forward_thread(LPVOID param) {
  ForwardArgs *args = (ForwardArgs *)param;
  BYTE buf[BUF_SIZE];
  DWORD bytesRead, bytesWritten;

  while (1) {
    if (!ReadFile(args->hSrc, buf, BUF_SIZE, &bytesRead, NULL)) {
      fprintf(stderr, CLR_RED "[ERR] Read failed on %s (code %lu)\n" CLR_RESET,
              args->label, GetLastError());
      break;
    }
    if (bytesRead > 0) {
      log_data(args->cfg, args->label, args->color, buf, bytesRead);
      if (!WriteFile(args->hDst, buf, bytesRead, &bytesWritten, NULL)) {
        fprintf(stderr,
                CLR_RED "[ERR] Write failed on %s (code %lu)\n" CLR_RESET,
                args->label, GetLastError());
        break;
      }
    }
  }
  return 0;
}

/* ─── main ───────────────────────────────────────────────────────────────────
 */
int main(int argc, char *argv[]) {
  enable_vt();

  Config cfg = {0};
  cfg.baud = 9600; /* default */

  /* ── parse args ── */
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-b") == 0 && i + 1 < argc)
      cfg.baud = atoi(argv[++i]);
    else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc)
      strncpy_s(cfg.portIn, MAX_PORT_LEN, argv[++i], MAX_PORT_LEN - 1);
    else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc)
      strncpy_s(cfg.portOut, MAX_PORT_LEN, argv[++i], MAX_PORT_LEN - 1);
    else {
      fprintf(stderr, CLR_RED "[ERR] Unknown argument: %s\n\n" CLR_RESET,
              argv[i]);
      print_usage(argv[0]);
      return 1;
    }
  }

  if (cfg.portIn[0] == '\0' || cfg.portOut[0] == '\0') {
    fprintf(stderr, CLR_RED "[ERR] -i and -o are required.\n\n" CLR_RESET);
    print_usage(argv[0]);
    return 1;
  }

  /* ── open log file ── */
  fopen_s(&cfg.logFile, LOG_FILE, "a");

  /* ── build full port paths ── */
  char pathIn[MAX_PORT_LEN + 8], pathOut[MAX_PORT_LEN + 8];
  make_port_path(cfg.portIn, pathIn, sizeof(pathIn));
  make_port_path(cfg.portOut, pathOut, sizeof(pathOut));

  /* ── open ports ── */
  HANDLE hIn = open_port(pathIn, cfg.baud);
  HANDLE hOut = open_port(pathOut, cfg.baud);

  if (hIn == INVALID_HANDLE_VALUE) {
    fprintf(stderr,
            CLR_RED "[ERR] Cannot open input port  %s (code %lu)\n" CLR_RESET,
            pathIn, GetLastError());
    return 1;
  }
  if (hOut == INVALID_HANDLE_VALUE) {
    fprintf(stderr,
            CLR_RED "[ERR] Cannot open output port %s (code %lu)\n" CLR_RESET,
            pathOut, GetLastError());
    CloseHandle(hIn);
    return 1;
  }

  /* ── banner ── */
  printf(CLR_BOLD " ====================================== \n"
                  "|        Serial Port Sniffer           |\n"
                  " ====================================== \n" CLR_RESET);
  printf("  %sIn%s   %-10s  baud %s%d%s\n", CLR_GREEN, CLR_RESET, cfg.portIn,
         CLR_YELLOW, cfg.baud, CLR_RESET);
  printf("  %sOut%s  %-10s  baud %s%d%s\n", CLR_CYAN, CLR_RESET, cfg.portOut,
         CLR_YELLOW, cfg.baud, CLR_RESET);
  printf("  Log  %s%s%s\n\n", CLR_GRAY, LOG_FILE, CLR_RESET);
  printf(CLR_GRAY "Press Ctrl+C to stop.\n\n" CLR_RESET);

  /* ── direction labels ── */
  char labelAB[MAX_PORT_LEN * 2 + 4], labelBA[MAX_PORT_LEN * 2 + 4];
  _snprintf_s(labelAB, sizeof(labelAB), sizeof(labelAB) - 1, "%s -> %s",
              cfg.portIn, cfg.portOut);
  _snprintf_s(labelBA, sizeof(labelBA), sizeof(labelBA) - 1, "%s -> %s",
              cfg.portOut, cfg.portIn);

  /* ── launch threads ── */
  ForwardArgs argsAB = {hIn, hOut, labelAB, CLR_GREEN, &cfg};
  ForwardArgs argsBA = {hOut, hIn, labelBA, CLR_CYAN, &cfg};

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
