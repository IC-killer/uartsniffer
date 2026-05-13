# UartSniffer – Makefile
#
# Targets:
#   make          build CLI  (uartsniffer / uartsniffer.exe)
#   make gui      build GUI  (uartsniffer-gui / uartsniffer-gui.exe)
#   make all      build both
#   make clean    remove build artifacts
#
# GUI dependencies: SDL2 + Nuklear headers in vendor/
#   vendor/nuklear.h            (single-header GUI)
#   vendor/nuklear_sdl_gl3.h    (SDL2 / OpenGL backend)

CC      ?= gcc
CFLAGS  ?= -Wall -O2 -Isrc
DEFINES  =

# ── platform detection ─────────────────────────────────────────────────────

# Override via: make PLATFORM=Linux   or   make PLATFORM=Windows
ifndef PLATFORM
  ifeq ($(OS),Windows_NT)
    PLATFORM = Windows
  else
    UNAME_S := $(shell uname -s 2>/dev/null)
    ifeq ($(UNAME_S),Linux)
      PLATFORM = Linux
    else
      # Assume Windows (MSYS2/MinGW returns e.g. MINGW64_NT-…)
      PLATFORM = Windows
    endif
  endif
endif

ifeq ($(PLATFORM),Linux)
    LDFLAGS_CLI  = -lpthread
    LDFLAGS_GUI  = -lSDL2 -lGL -lpthread
    CLI_EXE      = uartsniffer
    GUI_EXE      = uartsniffer-gui
    DEFINES     += -D_GNU_SOURCE
else
    # Windows (MSYS2/MinGW or cross-compile)
    LDFLAGS_CLI  = -lkernel32 -lsetupapi -luuid
    LDFLAGS_GUI  = -lSDL2 -lopengl32 -lkernel32 -lsetupapi -luuid -mwindows
    CLI_EXE      = uartsniffer.exe
    GUI_EXE      = uartsniffer-gui.exe
endif

# ── source files ───────────────────────────────────────────────────────────

SRCDIR    = src

CLI_SRCS  = $(SRCDIR)/uspy.c       \
            $(SRCDIR)/parser.c     \
            $(SRCDIR)/serial_win.c \
            $(SRCDIR)/serial_linux.c \
            $(SRCDIR)/watch_win.c  \
            $(SRCDIR)/watch_linux.c \
            $(SRCDIR)/main_cli.c

GUI_SRCS  = $(SRCDIR)/uspy.c       \
            $(SRCDIR)/parser.c     \
            $(SRCDIR)/serial_win.c \
            $(SRCDIR)/serial_linux.c \
            $(SRCDIR)/watch_win.c  \
            $(SRCDIR)/watch_linux.c \
            $(SRCDIR)/main_gui.c

# ── targets ────────────────────────────────────────────────────────────────

.PHONY: all cli gui clean

all: cli gui

cli: $(CLI_EXE)

gui: $(GUI_EXE)

$(CLI_EXE): $(CLI_SRCS) $(SRCDIR)/uspy.h
	$(CC) $(CFLAGS) $(DEFINES) -o $@ $(CLI_SRCS) $(LDFLAGS_CLI)

$(GUI_EXE): $(GUI_SRCS) $(SRCDIR)/uspy.h vendor/nuklear.h vendor/nuklear_sdl_gl2.h
	$(CC) $(CFLAGS) $(DEFINES) -o $@ $(GUI_SRCS) $(LDFLAGS_GUI)

clean:
	rm -f $(CLI_EXE) $(GUI_EXE)

# ── vendor download helper ─────────────────────────────────────────────────

vendor-deps:
	@echo "Downloading Nuklear headers into vendor/ ..."
	@mkdir -p vendor
	@curl -sL -o vendor/nuklear.h \
	  https://raw.githubusercontent.com/Immediate-Mode-UI/Nuklear/master/nuklear.h
	@curl -sL -o vendor/nuklear_sdl_gl2.h \
	  https://raw.githubusercontent.com/Immediate-Mode-UI/Nuklear/master/demo/sdl_opengl2/nuklear_sdl_gl2.h
	@echo "Done.  Now run:  make gui"

help:
	@echo "UartSniffer build targets:"
	@echo "  make           build CLI only"
	@echo "  make gui       build GUI only"
	@echo "  make all       build both"
	@echo "  make clean     remove binaries"
	@echo "  make vendor-deps   download Nuklear headers"
