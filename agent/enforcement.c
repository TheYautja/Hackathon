#include "enforcement.h"
#include "audit.h"
#include "state.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#endif

static volatile int g_monitor_running = 0;
static HANDLE g_monitor_thread = NULL;

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
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };

    if (snap == INVALID_HANDLE_VALUE)
        return;

    if (Process32First(snap, &pe)) {
        do {
            if (str_ieq(pe.szExeFile, name)) {
                HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (h) {
                    TerminateProcess(h, 1);
                    CloseHandle(h);
                    lab_audit_log("PROCESS_BLOCKED", "killed=%s pid=%lu",
                                  name, (unsigned long)pe.th32ProcessID);
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

#endif

int lab_enforcement_apply(const lab_profile_t *profile)
{
    if (!profile)
        return -1;

    lab_audit_log("ENFORCEMENT", "profile=%s blocked=%d allowed=%d",
                  profile->name, profile->blocked_count, profile->allowed_count);
    return 0;
}

int lab_enforcement_start_monitor(void)
{
#ifdef _WIN32
    if (g_monitor_running)
        return 0;

    g_monitor_running = 1;
    g_monitor_thread = CreateThread(NULL, 0, monitor_thread, NULL, 0, NULL);
    return g_monitor_thread ? 0 : -1;
#else
    return 0;
#endif
}

void lab_enforcement_stop_monitor(void)
{
#ifdef _WIN32
    g_monitor_running = 0;
    if (g_monitor_thread) {
        WaitForSingleObject(g_monitor_thread, 5000);
        CloseHandle(g_monitor_thread);
        g_monitor_thread = NULL;
    }
#endif
}
