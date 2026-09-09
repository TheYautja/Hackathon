#include "state.h"
#include "audit.h"
#include "crypto.h"
#include "enforcement.h"
#include "util.h"
#include <stdio.h>
#include <string.h>

static lab_agent_state_t g_state;

lab_agent_state_t *lab_state(void)
{
    return &g_state;
}

int lab_state_init(const char *key_path)
{
    memset(&g_state, 0, sizeof(g_state));
    g_state.start_time = lab_monotonic_sec();
    g_state.agent_status = LAB_STATUS_IDLE;
    g_state.running = 1;

    lab_get_agent_id(g_state.agent_id, sizeof(g_state.agent_id));
    lab_get_hostname(g_state.hostname, sizeof(g_state.hostname));

    if (lab_load_key_file(g_state.hmac_key, sizeof(g_state.hmac_key), key_path) != 0) {
        fprintf(stderr, "[agent] chave HMAC nao encontrada: %s\n", key_path);
        return -1;
    }

    lab_mkdir_p(lab_data_dir());
    lab_mkdir_p(lab_baseline_dir());

    return 0;
}

int lab_state_apply_policy(const lab_policy_t *policy)
{
    const char *profile;

    if (!policy)
        return -1;

    g_state.policy = *policy;
    g_state.policy_loaded = 1;
    g_state.policy_seq = policy->seq;

    profile = lab_policy_profile_for_time(policy);
    if (!profile)
        profile = policy->default_profile;

    snprintf(g_state.active_profile, sizeof(g_state.active_profile), "%s", profile);
    lab_enforcement_apply(lab_state_active_profile());
    lab_audit_log("POLICY_APPLIED", "seq=%llu profile=%s",
                    (unsigned long long)policy->seq, g_state.active_profile);
    return 0;
}

int lab_state_switch_profile(const char *profile_id)
{
    if (!g_state.policy_loaded)
        return -1;

    if (!lab_policy_find_profile(&g_state.policy, profile_id))
        return -1;

    snprintf(g_state.active_profile, sizeof(g_state.active_profile), "%s", profile_id);
    lab_enforcement_apply(lab_state_active_profile());
    lab_audit_log("PROFILE_SWITCH", "profile=%s", profile_id);
    return 0;
}

const lab_profile_t *lab_state_active_profile(void)
{
    if (!g_state.policy_loaded)
        return NULL;
    return lab_policy_find_profile(&g_state.policy, g_state.active_profile);
}
