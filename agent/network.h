#ifndef LAB_NETWORK_H
#define LAB_NETWORK_H

#include <stdint.h>

int lab_network_start(void);
void lab_network_stop(void);
int lab_network_handle_push(const uint8_t *payload, uint32_t len);

#endif
