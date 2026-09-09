#include "audit.h"
#include "enforcement.h"
#include "ipc.h"
#include "network.h"
#include "reset.h"
#include "state.h"
#include "policy.h"
#include "util.h"
#include <stdio.h>
#include <signal.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static int g_console_run = 1;

static BOOL WINAPI console_handler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) {
        g_console_run = 0;
        lab_state()->running = 0;
        return TRUE;
    }
    return FALSE;
}
#else
static volatile int g_console_run = 1;
static void sig_handler(int s) { (void)s; g_console_run = 0; lab_state()->running = 0; }
#endif

static int load_cached_policy(void)
{
    lab_sealed_policy_t sealed;
    lab_policy_t policy;
    lab_agent_state_t *st = lab_state();

    if (lab_policy_load_file(&sealed, lab_policy_path()) != 0)
        return -1;

    if (lab_policy_unseal(&policy, &sealed, st->hmac_key, sizeof(st->hmac_key)) != 0)
        return -1;

    return lab_state_apply_policy(&policy);
}

static void schedule_tick(void)
{
    lab_agent_state_t *st = lab_state();
    const char *scheduled;

    if (!st->policy_loaded)
        return;

    scheduled = lab_policy_profile_for_time(&st->policy);
    if (scheduled && strcmp(scheduled, st->active_profile) != 0)
        lab_state_switch_profile(scheduled);
}

int main(int argc, char **argv)
{
    const char *key_path = "keys/shared.key";
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
            key_path = argv[++i];
        else if (strcmp(argv[i], "--reset") == 0) {
            if (lab_state_init(key_path) != 0)
                return 1;
            load_cached_policy();
            return lab_reset_run(lab_state_active_profile());
        }
    }

    printf("LabAgent v0.1 — Orquestrador de Laboratorio\n");
    printf("ID: ");
    {
        char id[128];
        lab_get_agent_id(id, sizeof(id));
        printf("%s\n", id);
    }

    if (lab_state_init(key_path) != 0)
        return 1;

#ifdef _WIN32
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
#endif

    lab_mkdir_p(lab_data_dir());
    lab_mkdir_p(lab_baseline_dir());

    if (load_cached_policy() != 0)
        printf("[agent] nenhuma politica em cache — aguardando push do admin\n");

    lab_ipc_start();
    lab_network_start();
    lab_enforcement_start_monitor();

    lab_audit_log("AGENT_START", "ok");

    while (g_console_run && lab_state()->running) {
        schedule_tick();
        lab_sleep_ms(30000);
    }

    lab_enforcement_stop_monitor();
    lab_network_stop();
    lab_ipc_stop();
    lab_audit_log("AGENT_STOP", "ok");
    printf("[agent] encerrado\n");
    return 0;
}
