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

static char *serial_strdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *out = (char *)malloc(n);
    if (out) memcpy(out, s, n);
    return out;
}

static int is_com_prefix(const char *p) {
    return ((p[0] == 'C' || p[0] == 'c') &&
            (p[1] == 'O' || p[1] == 'o') &&
            (p[2] == 'M' || p[2] == 'm') &&
            (p[3] >= '0' && p[3] <= '9'));
}

static int extract_com_name(const char *friendly, char *port, int portsz) {
    const char *p = friendly;
    while (*p) {
        if (is_com_prefix(p)) {
            int len = 0;
            while (p[len] && len < portsz - 1 &&
                   p[len] != ')' && p[len] != '(' &&
                   p[len] != ' ' && p[len] != '\t') {
                port[len] = p[len];
                len++;
            }
            port[len] = '\0';
            return len > 0;
        }
        p++;
    }
    return 0;
}

static int get_port_name_from_registry(HDEVINFO devInfo,
                                       SP_DEVINFO_DATA *devData,
                                       char *port, int portsz) {
    HKEY key = SetupDiOpenDevRegKey(devInfo, devData, DICS_FLAG_GLOBAL, 0,
                                    DIREG_DEV, KEY_READ);
    if (key == INVALID_HANDLE_VALUE)
        return 0;

    DWORD type = REG_SZ;
    DWORD size = (DWORD)portsz;
    LONG rc = RegQueryValueExA(key, "PortName", NULL, &type,
                               (BYTE *)port, &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || type != REG_SZ || !is_com_prefix(port))
        return 0;
    port[portsz - 1] = '\0';
    return 1;
}

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
        char port[MAX_PORT_LEN] = {0};

        if (!get_port_name_from_registry(devInfo, &devData,
                                         port, sizeof(port))) {
            SetupDiGetDeviceRegistryPropertyA(
                devInfo, &devData, SPDRP_FRIENDLYNAME,
                NULL, (BYTE *)friendly, sizeof(friendly) - 1, NULL);
            extract_com_name(friendly, port, sizeof(port));
        }

        if (port[0]) {
            buf[count] = serial_strdup(port);
            if (!buf[count])
                break;
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

usp_serial_t usp_serial_open_ex(const char *port, int baud, unsigned buffer_size) {
    char path[MAX_PORT_LEN + 8];
    unsigned queue_size = usp_normalize_buffer_size(buffer_size);
    make_port_path(port, path, sizeof(path));

    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;

    SetupComm(h, (DWORD)queue_size, (DWORD)queue_size);

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

usp_serial_t usp_serial_open(const char *port, int baud) {
    return usp_serial_open_ex(port, baud, USP_DEFAULT_BUFFER_SIZE);
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

void usp_serial_set_buffer_size(usp_serial_t h, unsigned buffer_size) {
    unsigned queue_size = usp_normalize_buffer_size(buffer_size);
    if (h)
        SetupComm((HANDLE)h, (DWORD)queue_size, (DWORD)queue_size);
}
