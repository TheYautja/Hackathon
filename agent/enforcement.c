#include "enforcement.h"
#include "audit.h"
#include "state.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32

#include <windows.h>
#include <tlhelp32.h>

#else

#include <pthread.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>

#endif

static volatile int g_monitor_running = 0;

#ifdef _WIN32
static HANDLE g_monitor_thread = NULL;
#else
static pthread_t g_monitor_thread;
#endif

#ifdef _WIN32

static int str_ieq(const char *a, const char *b)
{
    return _stricmp(a, b) == 0;
}

#else

#include <strings.h>

static int str_ieq(const char *a, const char *b)
{
    return strcasecmp(a, b) == 0;
}

#endif


int lab_enforcement_is_blocked(const char *exe_name)
{
    const lab_profile_t *profile = lab_state_active_profile();
    int i;

    if (!profile || !exe_name)
        return 0;

    /*
     * Allowed applications take precedence.
     */
    for (i = 0; i < profile->allowed_count; i++) {
        if (str_ieq(profile->allowed_apps[i], exe_name))
            return 0;
    }

    for (i = 0; i < profile->blocked_count; i++) {
        if (str_ieq(profile->blocked_apps[i], exe_name))
            return 1;
    }

    return 0;
}


#ifdef _WIN32

static void kill_process_by_name(const char *name)
{
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,
        0
    );

    PROCESSENTRY32 pe = {
        .dwSize = sizeof(pe)
    };

    if (snap == INVALID_HANDLE_VALUE)
        return;

    if (Process32First(snap, &pe)) {
        do {
            if (str_ieq(pe.szExeFile, name)) {
                HANDLE h = OpenProcess(
                    PROCESS_TERMINATE,
                    FALSE,
                    pe.th32ProcessID
                );

                if (h) {
                    if (TerminateProcess(h, 1)) {
                        lab_audit_log(
                            "PROCESS_BLOCKED",
                            "killed=%s pid=%lu",
                            name,
                            (unsigned long)pe.th32ProcessID
                        );
                    }

                    CloseHandle(h);
                }
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
}


static DWORD WINAPI monitor_thread(LPVOID unused)
{
    (void)unused;

    while (g_monitor_running) {
        const lab_profile_t *profile = lab_state_active_profile();
        int i;

        if (profile) {
            for (i = 0; i < profile->blocked_count; i++)
                kill_process_by_name(profile->blocked_apps[i]);
        }

        Sleep(2000);
    }

    return 0;
}


#else /* POSIX / Linux */


static void kill_process_by_name(const char *name)
{
    DIR *dir;
    struct dirent *entry;

    if (!name)
        return;

    dir = opendir("/proc");

    if (!dir)
        return;

    while ((entry = readdir(dir)) != NULL) {
        char path[256];
        char exe_path[512];
        char exe_name[256];
        long pid;

        /*
         * /proc entries containing processes are numeric.
         */
        if (sscanf(entry->d_name, "%ld", &pid) != 1)
            continue;

        if (pid <= 0)
            continue;

        snprintf(
            path,
            sizeof(path),
            "/proc/%ld/exe",
            pid
        );

        ssize_t len = readlink(
            path,
            exe_path,
            sizeof(exe_path) - 1
        );

        if (len <= 0)
            continue;

        exe_path[len] = '\0';

        /*
         * Extract executable filename.
         */
        const char *slash = strrchr(exe_path, '/');

        if (slash)
            snprintf(
                exe_name,
                sizeof(exe_name),
                "%s",
                slash + 1
            );
        else
            snprintf(
                exe_name,
                sizeof(exe_name),
                "%s",
                exe_path
            );

        if (!str_ieq(exe_name, name))
            continue;

        /*
         * Don't kill ourselves.
         */
        if ((pid_t)pid == getpid())
            continue;

        if (kill((pid_t)pid, SIGTERM) == 0) {
            lab_audit_log(
                "PROCESS_BLOCKED",
                "killed=%s pid=%ld",
                name,
                pid
            );
        }
    }

    closedir(dir);
}


static void *monitor_thread(void *unused)
{
    (void)unused;

    while (g_monitor_running) {
        const lab_profile_t *profile = lab_state_active_profile();
        int i;

        if (profile) {
            for (i = 0; i < profile->blocked_count; i++)
                kill_process_by_name(profile->blocked_apps[i]);
        }

        /*
         * Avoid a busy loop while still allowing reasonably
         * fast shutdown.
         */
        for (int i = 0; i < 20 && g_monitor_running; i++)
            usleep(100000);
    }

    return NULL;
}


#endif /* _WIN32 */


int lab_enforcement_apply(const lab_profile_t *profile)
{
    if (!profile)
        return -1;

    lab_audit_log(
        "ENFORCEMENT",
        "profile=%s blocked=%d allowed=%d",
        profile->name,
        profile->blocked_count,
        profile->allowed_count
    );

    return 0;
}


int lab_enforcement_start_monitor(void)
{
    if (g_monitor_running)
        return 0;

    g_monitor_running = 1;

#ifdef _WIN32

    g_monitor_thread = CreateThread(
        NULL,
        0,
        monitor_thread,
        NULL,
        0,
        NULL
    );

    if (!g_monitor_thread) {
        g_monitor_running = 0;
        return -1;
    }

#else

    if (pthread_create(
            &g_monitor_thread,
            NULL,
            monitor_thread,
            NULL) != 0) {

        g_monitor_running = 0;
        return -1;
    }

#endif

    return 0;
}


void lab_enforcement_stop_monitor(void)
{
    if (!g_monitor_running)
        return;

    g_monitor_running = 0;

#ifdef _WIN32

    if (g_monitor_thread) {
        WaitForSingleObject(
            g_monitor_thread,
            5000
        );

        CloseHandle(g_monitor_thread);
        g_monitor_thread = NULL;
    }

#else

    pthread_join(
        g_monitor_thread,
        NULL
    );

#endif
}
