#ifndef LAB_ENFORCEMENT_H
#define LAB_ENFORCEMENT_H

#include "policy.h"

int lab_enforcement_apply(const lab_profile_t *profile);
int lab_enforcement_start_monitor(void);
void lab_enforcement_stop_monitor(void);
int lab_enforcement_is_blocked(const char *exe_name);

#endif
