#ifndef LAB_AGENT_STATE_H
#define LAB_AGENT_STATE_H

#include "crypto.h"
#include "policy.h"
#include "protocol.h"
#include "util.h"

typedef struct {
    char agent_id[LAB_MAX_HOSTNAME];
    char hostname[LAB_MAX_HOSTNAME];
    char active_profile[LAB_MAX_PROFILE_ID];
    lab_policy_t policy;
    int  policy_loaded;
    uint64_t policy_seq;
    uint64_t start_time;
    uint64_t msg_seq;
    uint8_t hmac_key[LAB_HMAC_KEY_DEFAULT_LEN];
    uint8_t agent_status;
    int running;
} lab_agent_state_t;

lab_agent_state_t *lab_state(void);
int lab_state_init(const char *key_path);
int lab_state_apply_policy(const lab_policy_t *policy);
int lab_state_switch_profile(const char *profile_id);
const lab_profile_t *lab_state_active_profile(void);

#endif
