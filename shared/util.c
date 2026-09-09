#include "util.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#define mkdir(path, mode) _mkdir(path)
#else
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#endif

static char g_data_dir[512];
static char g_baseline_dir[512];
static char g_log_path[512];
static char g_policy_path[512];
static int  g_paths_init = 0;

static void init_paths(void)
{
    if (g_paths_init)
        return;

#ifdef _WIN32
    const char *base = "C:\\ProgramData\\LabAgent";
#else
    const char *base = "/var/lib/labagent";
#endif

    snprintf(g_data_dir, sizeof(g_data_dir), "%s", base);
    snprintf(g_baseline_dir, sizeof(g_baseline_dir), "%s\\baseline", base);
    snprintf(g_log_path, sizeof(g_log_path), "%s\\audit.log", base);
    snprintf(g_policy_path, sizeof(g_policy_path), "%s\\policy.sealed", base);
    g_paths_init = 1;
}

const char *lab_data_dir(void)   { init_paths(); return g_data_dir; }
const char *lab_baseline_dir(void){ init_paths(); return g_baseline_dir; }
const char *lab_log_path(void)   { init_paths(); return g_log_path; }
const char *lab_policy_path(void){ init_paths(); return g_policy_path; }

uint64_t lab_now_unix(void)
{
#ifdef _WIN32
    FILETIME ft;
    ULARGE_INTEGER uli;
    GetSystemTimeAsFileTime(&ft);
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return (uli.QuadPart / 10000000ULL) - 11644473600ULL;
#else
    return (uint64_t)time(NULL);
#endif
}

uint64_t lab_monotonic_sec(void)
{
#ifdef _WIN32
    return (uint64_t)(GetTickCount64() / 1000ULL);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
#endif
}

void lab_sleep_ms(unsigned ms)
{
#ifdef _WIN32
    Sleep(ms);
#else
    usleep(ms * 1000);
#endif
}

int lab_mkdir_p(const char *path)
{
    char tmp[512];
    char *p;

    snprintf(tmp, sizeof(tmp), "%s", path);
    for (p = tmp + 1; *p; p++) {
        if (*p == '\\' || *p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = (*p == '\\') ? '\\' : '/';
        }
    }
    return mkdir(tmp, 0755) == 0 || 1; /* ok if exists */
}

int lab_get_hostname(char *buf, size_t len)
{
#ifdef _WIN32
    DWORD n = (DWORD)len;
    return GetComputerNameA(buf, &n) ? 0 : -1;
#else
    return gethostname(buf, len) == 0 ? 0 : -1;
#endif
}

int lab_get_agent_id(char *buf, size_t len)
{
    if (lab_get_hostname(buf, len) != 0)
        snprintf(buf, len, "lab-agent-unknown");
    return 0;
}
