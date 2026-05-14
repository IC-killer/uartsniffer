# UartSniffer Architecture

This project is a serial-port sniffer/forwarder with two front-ends:

- `uartsniffer`: command-line UI.
- `uartsniffer-gui`: SDL2 + Nuklear GUI.

Both front-ends share the same core runtime, serial abstraction, config parser, and file watcher.

## Build Files

- `Makefile`: simple GCC/MinGW build targets. Use `make`, `make gui`, or `make all`.
- `CMakeLists.txt`: CMake targets for CLI and GUI. The GUI target is enabled only when SDL2 is found.
- `vendor/`: third-party Nuklear headers used by the GUI.

## Source Map

- `src/uspy.h`: shared public API, constants, data structures, and callback declarations.
- `src/uspy.c`: core runtime, output callback dispatch, ruleset state, packet hex dump, protocol parse output, quit lifecycle.
- `src/parser.c`: protocol config parser and rule matching helpers.
- `src/serial_win.c`: Windows serial port enumeration/open/read/write/close.
- `src/serial_linux.c`: Linux serial port enumeration/open/read/write/close.
- `src/watch_win.c`: Windows config file watcher.
- `src/watch_linux.c`: Linux config file watcher.
- `src/main_cli.c`: CLI entry point, argument parsing, hotkeys, forwarding thread startup.
- `src/main_gui.c`: GUI entry point, SDL/Nuklear setup, GUI state, controls, serial forwarding threads, output windows.

## Runtime Flow

1. Front-end calls `usp_init()`.
2. Front-end registers output callbacks with `usp_set_output()`.
3. Optional config file is loaded through `usp_ruleset_load()` or `load_config_into()` + `usp_ruleset_replace()`.
4. Serial ports are opened through `usp_serial_open()`.
5. Two forwarding threads are started:
   - input port to output port
   - output port to input port
6. Each forwarding thread reads bytes, records/logs them, writes them to the opposite port, and exits when `usp_should_quit()` is true.
7. Shutdown signals `usp_quit()`, joins threads, closes serial handles and log file, then calls `usp_shutdown()`.

## Output Pipeline

The core never prints directly except through the configured callbacks:

- `usp_out()` and `usp_err()` format text and call the registered callbacks.
- CLI callbacks write to stdout/stderr.
- GUI callbacks parse ANSI color escapes and push lines into a ring buffer.

In the GUI, the main thread drains the ring buffer into `gui_state_t.output_text`, which backs the selectable log text editor. Recent raw packet summaries are stored separately in `gui_state_t.packets`.

## GUI Layout

`src/main_gui.c` uses one top-level Nuklear window named `UartSniffer`.

Inside it are three sibling panels:

- `left_panel`: serial ports, parser config, control buttons, status.
- `output_panel`: recent raw packet summaries and copy buttons.
- `selectable_log_panel`: full selectable text log.

The `Auto-scroll` checkbox and `Bottom` button call the same scroll helper so both `output_panel` and `selectable_log_panel` move to the newest content together.

## Config Rules

Protocol rules are loaded from `.cfg` files. A rule can combine packet filters and field definitions:

- Filters use `{...}`, such as `{len=9}` or `{idx0=0x01}`.
- Fields use `[...]`, such as `[u16(voltage)]`, `[s16be(speed)]`, or `[array-12(payload)]`.
- Multiple filters are ANDed.
- Endianness can be global or encoded in a field type such as `u16be`.

`parser.c` owns parsing, field sizing, endian handling, and rule matching.

## Threading Notes

- `uspy.c` protects global output and ruleset state with platform-adaptive mutexes.
- GUI output lines are transferred from worker threads to the main GUI thread through `g_ring`.
- GUI raw packet summaries are protected by `g_packet_lock`.
- Nuklear/SDL rendering stays on the main thread.

## Change Guide

- To change serial behavior, edit `serial_win.c` / `serial_linux.c` behind the `usp_serial_*` API.
- To change protocol config syntax or matching, edit `parser.c` and update `uspy.h` types if needed.
- To change packet formatting, edit `usp_log_data()` and `usp_try_parse()` in `uspy.c`.
- To change CLI options or hotkeys, edit `main_cli.c`.
- To change GUI controls or layout, edit `main_gui.c`, especially the `gui_panel_*` functions and the main layout block.
- To add shared behavior, prefer adding it behind an API in `uspy.h` so both front-ends can use it.
