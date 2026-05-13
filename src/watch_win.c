/*
 * watch_win.c  --  Windows file-change watcher
 *
 * Uses ReadDirectoryChangesW in a background thread.
 * Calls usp_watch_cb when the watched file is modified.
 */

#include "uspy.h"

#ifdef _WIN32

#include <windows.h>

typedef struct {
    char            filepath[512];
    char            filename[256];  /* just the filename part */
    usp_watch_cb    callback;
    void           *cb_ctx;
    HANDLE          hThread;
    volatile int    running;
} watch_ctx_t;

static DWORD WINAPI watch_thread_proc(LPVOID param) {
    watch_ctx_t *w = (watch_ctx_t *)param;

    /* extract directory from filepath */
    char watchDir[512];
    int dirLen = 0;
    {
        const char *p = w->filepath;
        int last = -1;
        for (int i = 0; p[i]; i++)
            if (p[i] == '\\' || p[i] == '/') last = i;
        if (last >= 0) {
            dirLen = last;
            snprintf(watchDir, sizeof(watchDir), "%.*s", dirLen, w->filepath);
        } else {
            snprintf(watchDir, sizeof(watchDir), ".");
        }
    }
    const char *cfgBase = w->filepath + (dirLen > 0 ? dirLen + 1 : 0);

    HANDLE hDir = CreateFileA(
        watchDir, FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);

    if (hDir == INVALID_HANDLE_VALUE) {
        usp_err(YEL "[WATCH] Cannot open dir '%s' (err %lu)\n" R,
                watchDir, GetLastError());
        return 0;
    }

    OVERLAPPED ov = {0};
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    BYTE notifBuf[4096];

    while (w->running && !usp_should_quit()) {
        ResetEvent(ov.hEvent);
        DWORD bytesRet = 0;
        BOOL ok = ReadDirectoryChangesW(
            hDir, notifBuf, sizeof(notifBuf), FALSE,
            FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
            &bytesRet, &ov, NULL);

        if (!ok && GetLastError() != ERROR_IO_PENDING) break;

        HANDLE waitHandles[1] = {ov.hEvent};
        DWORD wr = WaitForMultipleObjects(1, waitHandles, FALSE, 500);
        if (usp_should_quit() || !w->running) break;
        if (wr != WAIT_OBJECT_0) continue;

        GetOverlappedResult(hDir, &ov, &bytesRet, FALSE);

        int changed = 0;
        if (bytesRet > 0) {
            FILE_NOTIFY_INFORMATION *fni =
                (FILE_NOTIFY_INFORMATION *)notifBuf;
            for (;;) {
                if (fni->Action == FILE_ACTION_MODIFIED ||
                    fni->Action == FILE_ACTION_ADDED) {
                    char narrow[256] = {0};
                    WideCharToMultiByte(CP_ACP, 0, fni->FileName,
                                        fni->FileNameLength / sizeof(WCHAR),
                                        narrow, sizeof(narrow) - 1, NULL, NULL);
                    if (_stricmp(narrow, cfgBase) == 0) { changed = 1; break; }
                }
                if (!fni->NextEntryOffset) break;
                fni = (FILE_NOTIFY_INFORMATION *)
                    ((BYTE *)fni + fni->NextEntryOffset);
            }
        } else {
            changed = 1;
        }

        if (changed) {
            Sleep(80); /* debounce */
            if (w->callback)
                w->callback(w->cb_ctx, w->filepath);
        }
    }

    CloseHandle(ov.hEvent);
    CloseHandle(hDir);
    return 0;
}

usp_watcher_t usp_watch_start(const char *filepath,
                              usp_watch_cb cb, void *ctx) {
    watch_ctx_t *w = (watch_ctx_t *)calloc(1, sizeof(watch_ctx_t));
    if (!w) return NULL;
    snprintf(w->filepath, sizeof(w->filepath), "%s", filepath);
    w->callback = cb;
    w->cb_ctx   = ctx;
    w->running  = 1;
    w->hThread  = CreateThread(NULL, 0, watch_thread_proc, w, 0, NULL);
    if (!w->hThread) { free(w); return NULL; }
    return (usp_watcher_t)w;
}

void usp_watch_stop(usp_watcher_t h) {
    watch_ctx_t *w = (watch_ctx_t *)h;
    if (!w) return;
    w->running = 0;
    WaitForSingleObject(w->hThread, 3000);
    CloseHandle(w->hThread);
    free(w);
}

#endif /* _WIN32 */
