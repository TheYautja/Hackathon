#include "reset.h"
#include "audit.h"
#include "state.h"
#include "util.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#include <tlhelp32.h>

static const char *g_keep_alive[] = {
    "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "labagent.exe", "dwm.exe", "fontdrvhost.exe", "sihost.exe",
    "taskhostw.exe", "RuntimeBroker.exe", NULL
};

static int should_keep(const char *name)
{
    int i;
    for (i = 0; g_keep_alive[i]; i++) {
        if (_stricmp(g_keep_alive[i], name) == 0)
            return 1;
    }
    return 0;
}

static void kill_non_whitelist(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };

    if (snap == INVALID_HANDLE_VALUE)
        return;

    if (Process32First(snap, &pe)) {
        do {
            if (!should_keep(pe.szExeFile)) {
                HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (h) {
                    TerminateProcess(h, 1);
                    CloseHandle(h);
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

static int get_user_folder(int csidl, char *out, size_t out_len)
{
    if (SHGetFolderPathA(NULL, csidl, NULL, SHGFP_TYPE_CURRENT, out) != S_OK)
        return -1;
    return 0;
}

static int mirror_directory(const char *src, const char *dst)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "robocopy \"%s\" \"%s\" /MIR /NFL /NDL /NJH /NJS /NC /NS /NP >nul",
             src, dst);
    return system(cmd) >= 0 ? 0 : -1;
}

static int ensure_baseline(const char *rel_dir, char *baseline_path, size_t len)
{
    char user_path[MAX_PATH];
    int csidl = -1;

    if (_stricmp(rel_dir, "Desktop") == 0)
        csidl = CSIDL_DESKTOPDIRECTORY;
    else if (_stricmp(rel_dir, "Downloads") == 0)
        csidl = CSIDL_PROFILE;
    else if (_stricmp(rel_dir, "Documents") == 0)
        csidl = CSIDL_PERSONAL;
    else
        return -1;

    if (csidl == CSIDL_PROFILE) {
        if (get_user_folder(CSIDL_PROFILE, user_path, sizeof(user_path)) != 0)
            return -1;
        strncat(user_path, "\\Downloads", sizeof(user_path) - strlen(user_path) - 1);
    } else {
        if (get_user_folder(csidl, user_path, sizeof(user_path)) != 0)
            return -1;
    }

    snprintf(baseline_path, len, "%s\\%s", lab_baseline_dir(), rel_dir);
    lab_mkdir_p(baseline_path);

    {
        char marker[MAX_PATH];
        snprintf(marker, sizeof(marker), "%s\\.initialized", baseline_path);
        if (GetFileAttributesA(marker) == INVALID_FILE_ATTRIBUTES) {
            mirror_directory(user_path, baseline_path);
            {
                FILE *f = fopen(marker, "w");
                if (f) fclose(f);
            }
            lab_audit_log("BASELINE_INIT", "dir=%s", rel_dir);
        }
    }

    return mirror_directory(baseline_path, user_path);
}

int lab_reset_run(const lab_profile_t *profile)
{
    int i;

    lab_state()->agent_status = LAB_STATUS_RESETTING;
    lab_audit_log("RESET_START", "profile=%s", profile ? profile->name : "none");

    BlockInput(TRUE);
    kill_non_whitelist();

    if (profile) {
        for (i = 0; i < profile->reset_dir_count; i++) {
            char baseline[MAX_PATH];
            ensure_baseline(profile->reset_dirs[i], baseline, sizeof(baseline));
        }
    } else {
        char baseline[MAX_PATH];
        ensure_baseline("Desktop", baseline, sizeof(baseline));
        ensure_baseline("Downloads", baseline, sizeof(baseline));
    }

    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        CloseClipboard();
    }

    BlockInput(FALSE);
    lab_state()->agent_status = LAB_STATUS_IDLE;
    lab_audit_log("RESET_COMPLETE", "ok");
    return 0;
}

#else

int lab_reset_run(const lab_profile_t *profile)
{
    (void)profile;
    lab_audit_log("RESET_START", "linux stub");
    lab_audit_log("RESET_COMPLETE", "ok");
    return 0;
}

#endif
