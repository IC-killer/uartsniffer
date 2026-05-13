/*
 * serial_win.c  --  Windows serial port implementation
 *
 * Builds on Win32 CreateFile / ReadFile / WriteFile / DCB.
 */

#include "uspy.h"
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>

/* ── port enumeration ────────────────────────────────────────────────────── */

int usp_serial_list(char **buf, int max) {
    int count = 0;
    HDEVINFO devInfo = SetupDiGetClassDevsA(
        &GUID_DEVCLASS_PORTS, NULL, NULL, DIGCF_PRESENT);
    if (devInfo == INVALID_HANDLE_VALUE) return 0;

    SP_DEVINFO_DATA devData;
    devData.cbSize = sizeof(SP_DEVINFO_DATA);

    for (DWORD i = 0; count < max &&
         SetupDiEnumDeviceInfo(devInfo, i, &devData); i++) {

        char friendly[256] = {0};
        SetupDiGetDeviceRegistryPropertyA(
            devInfo, &devData, SPDRP_FRIENDLYNAME,
            NULL, (BYTE *)friendly, sizeof(friendly) - 1, NULL);

        char *start = strstr(friendly, "COM");
        if (!start) start = strstr(friendly, "com");
        if (start) {
            char port[MAX_PORT_LEN];
            int plen = 0;
            char *p = start;
            while (*p && plen < MAX_PORT_LEN - 1 &&
                   (*p != ' ' && *p != ')' && *p != '(')) {
                port[plen++] = *p++;
            }
            port[plen] = '\0';
            buf[count] = strdup(port);
            count++;
        }
    }
    SetupDiDestroyDeviceInfoList(devInfo);
    return count;
}

/* ── open / close ────────────────────────────────────────────────────────── */

static void make_port_path(const char *name, char *out, int outsz) {
    if (strncmp(name, "\\\\.\\", 4) == 0)
        snprintf(out, outsz, "%s", name);
    else
        snprintf(out, outsz, "\\\\.\\%s", name);
}

usp_serial_t usp_serial_open(const char *port, int baud) {
    char path[MAX_PORT_LEN + 8];
    make_port_path(port, path, sizeof(path));

    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;

    DCB dcb = {0};
    dcb.DCBlength = sizeof(dcb);
    GetCommState(h, &dcb);
    dcb.BaudRate = baud;
    dcb.ByteSize = 8;
    dcb.Parity   = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    SetCommState(h, &dcb);

    COMMTIMEOUTS to = {1, 0, 10, 0, 10};
    SetCommTimeouts(h, &to);

    return (usp_serial_t)h;
}

void usp_serial_close(usp_serial_t h) {
    if (h) CloseHandle((HANDLE)h);
}

/* ── read / write ────────────────────────────────────────────────────────── */

unsigned usp_serial_read(usp_serial_t h, unsigned char *buf, unsigned len) {
    DWORD br = 0;
    if (!ReadFile((HANDLE)h, buf, (DWORD)len, &br, NULL)) return 0;
    return (unsigned)br;
}

unsigned usp_serial_write(usp_serial_t h, const unsigned char *buf, unsigned len) {
    DWORD bw = 0;
    if (!WriteFile((HANDLE)h, buf, (DWORD)len, &bw, NULL)) return 0;
    return (unsigned)bw;
}
