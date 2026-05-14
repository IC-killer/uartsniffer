/*
 * serial_linux.c  --  Linux serial port implementation
 *
 * Uses POSIX termios.  Compile with -D_GNU_SOURCE.
 */

#include "uspy.h"

#ifndef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

/* ── port enumeration ────────────────────────────────────────────────────── */

int usp_serial_list(char **buf, int max) {
    int count = 0;

    /* Simplest approach: list /dev/ttyS* and /dev/ttyUSB* etc. */
    const char *patterns[] = {
        "/dev/ttyS", "/dev/ttyUSB", "/dev/ttyACM", "/dev/ttyAMA",
        NULL
    };

    for (int p = 0; patterns[p] && count < max; p++) {
        /* check numbered devices: /dev/ttyS0 … /dev/ttyS31 */
        for (int i = 0; i < 32 && count < max; i++) {
            char name[64];
            snprintf(name, sizeof(name), "%s%d", patterns[p], i);
            if (access(name, F_OK) == 0) {
                buf[count] = strdup(name);
                count++;
            }
        }
    }

    /* Also check /dev/serial/by-id for symlinks */
    DIR *d = opendir("/dev/serial/by-id");
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) && count < max) {
            if (ent->d_name[0] == '.') continue;
            char path[512];
            snprintf(path, sizeof(path), "/dev/serial/by-id/%s", ent->d_name);
            /* resolve symlink */
            char real[512];
            if (realpath(path, real)) {
                /* avoid duplicates – simple scan */
                int dup = 0;
                for (int i = 0; i < count; i++)
                    if (!strcmp(buf[i], real)) { dup = 1; break; }
                if (!dup) {
                    buf[count] = strdup(real);
                    count++;
                }
            }
        }
        closedir(d);
    }

    return count;
}

/* ── open / close ────────────────────────────────────────────────────────── */

usp_serial_t usp_serial_open(const char *port, int baud) {
    int fd = open(port, O_RDWR | O_NOCTTY | O_NDELAY);
    if (fd < 0) return NULL;

    /* set non-blocking (we poll with select in the forward loop) */
    fcntl(fd, F_SETFL, 0);

    struct termios tty;
    memset(&tty, 0, sizeof(tty));
    if (tcgetattr(fd, &tty) != 0) { close(fd); return NULL; }

    /* map baud rate integer to Bxxx constant */
    speed_t speed;
    switch (baud) {
        case 9600:    speed = B9600;    break;
        case 19200:   speed = B19200;   break;
        case 38400:   speed = B38400;   break;
        case 57600:   speed = B57600;   break;
        case 115200:  speed = B115200;  break;
        case 230400:  speed = B230400;  break;
        case 460800:  speed = B460800;  break;
        case 921600:  speed = B921600;  break;
        default:      speed = B9600;    break;
    }
    cfsetospeed(&tty, speed);
    cfsetispeed(&tty, speed);

    tty.c_cflag |= (CLOCAL | CREAD);
    tty.c_cflag &= ~PARENB;        /* no parity */
    tty.c_cflag &= ~CSTOPB;        /* 1 stop bit */
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |=  CS8;           /* 8 data bits */
    tty.c_cflag &= ~CRTSCTS;       /* no hardware flow control */

    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_iflag &= ~(IXON | IXOFF | IXANY);
    tty.c_oflag &= ~OPOST;

    /* read timeout: 0.1 s */
    tty.c_cc[VMIN]  = 0;
    tty.c_cc[VTIME] = 1;

    tcsetattr(fd, TCSANOW, &tty);
    return (usp_serial_t)(intptr_t)fd;
}

void usp_serial_close(usp_serial_t h) {
    if (h) close((int)(intptr_t)h);
}

/* ── read / write ────────────────────────────────────────────────────────── */

unsigned usp_serial_read(usp_serial_t h, unsigned char *buf, unsigned len) {
    int fd = (int)(intptr_t)h;
    ssize_t n = read(fd, buf, len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return 0;
    }
    return (unsigned)n;
}

unsigned usp_serial_write(usp_serial_t h, const unsigned char *buf, unsigned len) {
    int fd = (int)(intptr_t)h;
    ssize_t n = write(fd, buf, len);
    if (n < 0) return 0;
    return (unsigned)n;
}

#endif /* !_WIN32 */
