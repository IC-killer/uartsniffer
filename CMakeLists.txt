cmake_minimum_required(VERSION 3.10)
project(uartsniffer LANGUAGES C)

set(CMAKE_C_STANDARD 11)

# ── common sources ─────────────────────────────────────────────────────────

set(COMMON_SRCS
    src/uspy.c
    src/parser.c
    src/serial_win.c
    src/serial_linux.c
    src/watch_win.c
    src/watch_linux.c
)

# ── CLI target ─────────────────────────────────────────────────────────────

add_executable(uartsniffer
    ${COMMON_SRCS}
    src/main_cli.c
)

if(WIN32)
    target_sources(uartsniffer PRIVATE resources/uartsniffer.rc)
endif()

target_include_directories(uartsniffer PRIVATE src)

if(WIN32)
    target_link_libraries(uartsniffer PRIVATE kernel32)
else()
    target_link_libraries(uartsniffer PRIVATE pthread)
    target_compile_definitions(uartsniffer PRIVATE _GNU_SOURCE)
endif()

# ── GUI target (requires SDL2 + Nuklear) ───────────────────────────────────

find_package(SDL2 QUIET)
if(SDL2_FOUND)
    add_executable(uartsniffer-gui
        ${COMMON_SRCS}
        src/main_gui.c
    )
    if(WIN32)
        target_sources(uartsniffer-gui PRIVATE resources/uartsniffer.rc)
    endif()
    target_include_directories(uartsniffer-gui PRIVATE
        src ${CMAKE_SOURCE_DIR}/vendor
    )
    target_link_libraries(uartsniffer-gui PRIVATE
        SDL2::SDL2
        ${OPENGL_LIBRARIES}
    )
    if(UNIX)
        target_link_libraries(uartsniffer-gui PRIVATE pthread)
        target_compile_definitions(uartsniffer-gui PRIVATE _GNU_SOURCE)
    endif()
    if(WIN32)
        target_link_libraries(uartsniffer-gui PRIVATE comdlg32)
        set_target_properties(uartsniffer-gui PROPERTIES
            WIN32_EXECUTABLE TRUE
        )
    endif()
    add_custom_command(TARGET uartsniffer-gui POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:uartsniffer-gui>/assets"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/assets/uartsniffer-icon.bmp"
            "$<TARGET_FILE_DIR:uartsniffer-gui>/assets/uartsniffer-icon.bmp"
    )
else()
    message(STATUS "SDL2 not found – GUI target skipped.")
endif()
