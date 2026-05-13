/*
 * watch_linux.c  --  Linux file-change watcher
 *
 * Uses inotify in a background thread.
 * Calls usp_watch_cb when the watched file is modified.
 */

#include "uspy.h"

#ifndef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/inotify.h>
#include <errno.h>

typedef struct {
    char            filepath[512];
    usp_watch_cb    callback;
    void           *cb_ctx;
    pthread_t       thread;
    volatile int    running;
} watch_ctx_t;

static void *watch_thread_proc(void *param) {
    watch_ctx_t *w = (watch_ctx_t *)param;
    int inotify_fd = inotify_init1(IN_NONBLOCK);
    if (inotify_fd < 0) {
        usp_err(YEL "[WATCH] inotify_init failed: %s\n" R, strerror(errno));
        return NULL;
    }

    int wd = inotify_add_watch(inotify_fd, w->filepath,
                               IN_MODIFY | IN_CLOSE_WRITE);
    if (wd < 0) {
        /* maybe watching a directory that contains the file? try dirname */
        /* For simplicity, watch the file directly – if it fails, report */
        usp_err(YEL "[WATCH] Cannot watch '%s': %s\n" R,
                w->filepath, strerror(errno));
        close(inotify_fd);
        return NULL;
    }

    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));

    while (w->running && !usp_should_quit()) {
        /* poll with timeout so we can check running flag */
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(inotify_fd, &fds);
        struct timeval tv = {0, 500000}; /* 500 ms */

        int ret = select(inotify_fd + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) break;
        if (ret == 0) continue;

        ssize_t n = read(inotify_fd, buf, sizeof(buf));
        if (n <= 0) continue;

        /* parse events */
        for (char *ptr = buf; ptr < buf + n; ) {
            struct inotify_event *ev = (struct inotify_event *)ptr;
            if (ev->mask & (IN_MODIFY | IN_CLOSE_WRITE)) {
                usleep(80000); /* 80ms debounce */
                if (w->callback)
                    w->callback(w->cb_ctx, w->filepath);
                /* drain remaining events for this burst */
                break;
            }
            ptr += sizeof(struct inotify_event) + ev->len;
        }
    }

    inotify_rm_watch(inotify_fd, wd);
    close(inotify_fd);
    return NULL;
}

usp_watcher_t usp_watch_start(const char *filepath,
                              usp_watch_cb cb, void *ctx) {
    watch_ctx_t *w = (watch_ctx_t *)calloc(1, sizeof(watch_ctx_t));
    if (!w) return NULL;
    snprintf(w->filepath, sizeof(w->filepath), "%s", filepath);
    w->callback = cb;
    w->cb_ctx   = ctx;
    w->running  = 1;
    if (pthread_create(&w->thread, NULL, watch_thread_proc, w) != 0) {
        free(w); return NULL;
    }
    return (usp_watcher_t)w;
}

void usp_watch_stop(usp_watcher_t h) {
    watch_ctx_t *w = (watch_ctx_t *)h;
    if (!w) return;
    w->running = 0;
    pthread_join(w->thread, NULL);
    free(w);
}

#endif /* !_WIN32 */
