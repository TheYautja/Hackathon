#include "reset.h"
#include "audit.h"
#include "state.h"
#include "util.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
    HANDLE snap;
    PROCESSENTRY32 pe;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snap == INVALID_HANDLE_VALUE)
        return;

    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (Process32First(snap, &pe)) {
        do {
            if (!should_keep(pe.szExeFile)) {
                HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE,
                                       pe.th32ProcessID);

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
    if (SHGetFolderPathA(NULL, csidl, NULL,
                         SHGFP_TYPE_CURRENT, out) != S_OK)
        return -1;

    out[out_len - 1] = '\0';
    return 0;
}

static int mirror_directory(const char *src, const char *dst)
{
    char cmd[2048];

    snprintf(cmd, sizeof(cmd),
             "robocopy \"%s\" \"%s\" /MIR /NFL /NDL /NJH /NJS "
             "/NC /NS /NP >nul",
             src, dst);

    return system(cmd) >= 0 ? 0 : -1;
}

static int ensure_baseline(const char *rel_dir,
                           char *baseline_path,
                           size_t len)
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
        if (get_user_folder(CSIDL_PROFILE,
                            user_path,
                            sizeof(user_path)) != 0)
            return -1;

        strncat(user_path,
                "\\Downloads",
                sizeof(user_path) - strlen(user_path) - 1);
    } else {
        if (get_user_folder(csidl,
                            user_path,
                            sizeof(user_path)) != 0)
            return -1;
    }

    snprintf(baseline_path,
             len,
             "%s\\%s",
             lab_baseline_dir(),
             rel_dir);

    lab_mkdir_p(baseline_path);

    {
        char marker[MAX_PATH];

        snprintf(marker,
                 sizeof(marker),
                 "%s\\.initialized",
                 baseline_path);

        if (GetFileAttributesA(marker) == INVALID_FILE_ATTRIBUTES) {
            mirror_directory(user_path, baseline_path);

            FILE *f = fopen(marker, "w");
            if (f)
                fclose(f);

            lab_audit_log("BASELINE_INIT",
                          "dir=%s",
                          rel_dir);
        }
    }

    return mirror_directory(baseline_path, user_path);
}

int lab_reset_run(const lab_profile_t *profile)
{
    int i;

    lab_state()->agent_status = LAB_STATUS_RESETTING;

    lab_audit_log("RESET_START",
                  "profile=%s",
                  profile ? profile->name : "none");

    BlockInput(TRUE);

    kill_non_whitelist();

    if (profile) {
        for (i = 0; i < profile->reset_dir_count; i++) {
            char baseline[MAX_PATH];

            ensure_baseline(profile->reset_dirs[i],
                            baseline,
                            sizeof(baseline));
        }
    } else {
        char baseline[MAX_PATH];

        ensure_baseline("Desktop",
                        baseline,
                        sizeof(baseline));

        ensure_baseline("Downloads",
                        baseline,
                        sizeof(baseline));
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

#else /* POSIX / Linux */

#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>

static const char *g_keep_alive[] = {
    "systemd",
    "init",
    "bash",
    "sh",
    "labagent",
    "Xorg",
    "Xwayland",
    "xfce4-session",
    "xfwm4",
    "xfdesktop",
    "xfce4-panel",
    "thunar",
    "lightdm",
    NULL
};

static int should_keep(const char *name)
{
    int i;

    for (i = 0; g_keep_alive[i]; i++) {
        if (strcmp(g_keep_alive[i], name) == 0)
            return 1;
    }

    return 0;
}

static int get_process_name(pid_t pid,
                            char *name,
                            size_t name_len)
{
    char path[64];
    ssize_t n;

    snprintf(path,
             sizeof(path),
             "/proc/%ld/comm",
             (long)pid);

    FILE *f = fopen(path, "r");

    if (!f)
        return -1;

    if (!fgets(name, (int)name_len, f)) {
        fclose(f);
        return -1;
    }

    fclose(f);

    name[strcspn(name, "\r\n")] = '\0';

    n = (ssize_t)strlen(name);

    return n > 0 ? 0 : -1;
}

static void kill_non_whitelist(void)
{
    DIR *proc;
    struct dirent *entry;
    pid_t self = getpid();

    proc = opendir("/proc");

    if (!proc)
        return;

    while ((entry = readdir(proc)) != NULL) {
        char *end;
        long value;
        pid_t pid;
        char name[256];

        if (entry->d_name[0] < '0' ||
            entry->d_name[0] > '9')
            continue;

        errno = 0;
        value = strtol(entry->d_name, &end, 10);

        if (errno != 0 ||
            *end != '\0' ||
            value <= 0)
            continue;

        pid = (pid_t)value;

        /*
         * Never kill ourselves.
         */
        if (pid == self)
            continue;

        if (get_process_name(pid,
                             name,
                             sizeof(name)) != 0)
            continue;

        if (should_keep(name))
            continue;

        /*
         * Only request termination first.
         * Do not use SIGKILL here so applications have
         * a chance to clean themselves up.
         */
        if (kill(pid, SIGTERM) != 0) {
            /*
             * Processes can disappear between /proc
             * enumeration and kill().
             */
            if (errno != ESRCH && errno != EPERM) {
                lab_audit_log("RESET_KILL_FAILED",
                              "pid=%ld name=%s errno=%d",
                              (long)pid,
                              name,
                              errno);
            }
        }
    }

    closedir(proc);
}

static int path_join(char *out,
                     size_t out_len,
                     const char *a,
                     const char *b)
{
    int n;

    n = snprintf(out,
                 out_len,
                 "%s/%s",
                 a,
                 b);

    return (n < 0 || (size_t)n >= out_len) ? -1 : 0;
}

static int directory_exists(const char *path)
{
    DIR *dir = opendir(path);

    if (!dir)
        return 0;

    closedir(dir);
    return 1;
}

static int remove_directory_contents(const char *path)
{
    DIR *dir;
    struct dirent *entry;

    dir = opendir(path);

    if (!dir)
        return -1;

    while ((entry = readdir(dir)) != NULL) {
        char child[PATH_MAX];
        struct stat st;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        if (path_join(child,
                      sizeof(child),
                      path,
                      entry->d_name) != 0)
            continue;

        if (lstat(child, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            remove_directory_contents(child);
            rmdir(child);
        } else {
            unlink(child);
        }
    }

    closedir(dir);

    return 0;
}

static int copy_file(const char *src, const char *dst)
{
    FILE *in;
    FILE *out;
    unsigned char buffer[8192];
    size_t n;
    int error;

    in = fopen(src, "rb");
    if (!in)
        return -1;

    out = fopen(dst, "wb");
    if (!out) {
        fclose(in);
        return -1;
    }

    while ((n = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        if (fwrite(buffer, 1, n, out) != n) {
            fclose(in);
            fclose(out);
            return -1;
        }
    }

    error = ferror(in);

    fclose(in);
    fclose(out);

    return error ? -1 : 0;
}

static int mirror_directory(const char *src,
                            const char *dst)
{
    DIR *dir;
    struct dirent *entry;

    if (!directory_exists(src))
        return -1;

    lab_mkdir_p(dst);

    /*
     * Clear destination first.
     */
    remove_directory_contents(dst);

    dir = opendir(src);

    if (!dir)
        return -1;

    while ((entry = readdir(dir)) != NULL) {
        char source_path[PATH_MAX];
        char dest_path[PATH_MAX];
        struct stat st;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        if (path_join(source_path,
                      sizeof(source_path),
                      src,
                      entry->d_name) != 0)
            continue;

        if (path_join(dest_path,
                      sizeof(dest_path),
                      dst,
                      entry->d_name) != 0)
            continue;

        if (lstat(source_path, &st) != 0)
            continue;

        /*
         * Avoid recursively copying symlinks.
         */
        if (S_ISLNK(st.st_mode))
            continue;

        if (S_ISDIR(st.st_mode)) {
            lab_mkdir_p(dest_path);

            mirror_directory(source_path,
                             dest_path);
        } else if (S_ISREG(st.st_mode)) {
            copy_file(source_path,
                      dest_path);
        }
    }

    closedir(dir);

    return 0;
}

static int get_user_directory(const char *name,
                              char *out,
                              size_t out_len)
{
    const char *home = getenv("HOME");

    if (!home)
        return -1;

    return path_join(out,
                     out_len,
                     home,
                     name);
}

static int ensure_baseline(const char *rel_dir,
                           char *baseline_path,
                           size_t len)
{
    char user_path[PATH_MAX];
    char marker[PATH_MAX];

    if (strcmp(rel_dir, "Desktop") != 0 &&
        strcmp(rel_dir, "Downloads") != 0 &&
        strcmp(rel_dir, "Documents") != 0)
        return -1;

    if (get_user_directory(rel_dir,
                           user_path,
                           sizeof(user_path)) != 0)
        return -1;

    if (path_join(baseline_path,
                  len,
                  lab_baseline_dir(),
                  rel_dir) != 0)
        return -1;

    lab_mkdir_p(baseline_path);

    if (path_join(marker,
                  sizeof(marker),
                  baseline_path,
                  ".initialized") != 0)
        return -1;

    /*
     * First reset:
     *
     *     $HOME/Desktop
     *          ↓
     *     baseline/Desktop
     *
     * Later resets:
     *
     *     baseline/Desktop
     *          ↓
     *     $HOME/Desktop
     */
    if (access(marker, F_OK) != 0) {
        if (mirror_directory(user_path,
                             baseline_path) != 0) {
            lab_audit_log("BASELINE_INIT_FAILED",
                          "dir=%s",
                          rel_dir);
            return -1;
        }

        FILE *f = fopen(marker, "w");

        if (f)
            fclose(f);

        lab_audit_log("BASELINE_INIT",
                      "dir=%s",
                      rel_dir);
    }

    if (mirror_directory(baseline_path,
                         user_path) != 0) {
        lab_audit_log("RESET_DIR_FAILED",
                      "dir=%s",
                      rel_dir);
        return -1;
    }

    return 0;
}

static void clear_clipboard(void)
{
    /*
     * Linux does not have a universal clipboard API.
     *
     * Try xclip first, then xsel. These are optional.
     */
    if (system("command -v xclip >/dev/null 2>&1") == 0) {
        system("xclip -selection clipboard /dev/null "
               "2>/dev/null");
        return;
    }

    if (system("command -v xsel >/dev/null 2>&1") == 0) {
        system("xsel --clipboard --clear "
               "2>/dev/null");
    }
}

int lab_reset_run(const lab_profile_t *profile)
{
    int i;
    int result = 0;

    lab_state()->agent_status = LAB_STATUS_RESETTING;

    lab_audit_log("RESET_START",
                  "profile=%s",
                  profile ? profile->name : "none");

    kill_non_whitelist();

    if (profile) {
        for (i = 0; i < profile->reset_dir_count; i++) {
            char baseline[PATH_MAX];

            if (ensure_baseline(profile->reset_dirs[i],
                                baseline,
                                sizeof(baseline)) != 0) {
                result = -1;
            }
        }
    } else {
        char baseline[PATH_MAX];

        if (ensure_baseline("Desktop",
                            baseline,
                            sizeof(baseline)) != 0)
            result = -1;

        if (ensure_baseline("Downloads",
                            baseline,
                            sizeof(baseline)) != 0)
            result = -1;
    }

    clear_clipboard();

    lab_state()->agent_status = LAB_STATUS_IDLE;

    if (result == 0) {
        lab_audit_log("RESET_COMPLETE", "ok");
    } else {

        lab_audit_log("RESET_COMPLETE", "errors");

    }

    return result;

}

#endif

