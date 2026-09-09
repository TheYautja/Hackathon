#ifndef LAB_UTIL_H
#define LAB_UTIL_H

#include <stdint.h>

uint64_t lab_now_unix(void);
uint64_t lab_monotonic_sec(void);
void     lab_sleep_ms(unsigned ms);
int      lab_mkdir_p(const char *path);
int      lab_get_hostname(char *buf, size_t len);
int      lab_get_agent_id(char *buf, size_t len);
const char *lab_data_dir(void);
const char *lab_baseline_dir(void);
const char *lab_log_path(void);
const char *lab_policy_path(void);

#endif /* LAB_UTIL_H */
