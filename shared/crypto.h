#ifndef LAB_CRYPTO_H
#define LAB_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define LAB_SHA256_SIZE 32
#define LAB_HMAC_KEY_DEFAULT_LEN 32

int lab_random_bytes(uint8_t *buf, size_t len);
int lab_sha256(const uint8_t *data, size_t len, uint8_t out[LAB_SHA256_SIZE]);
int lab_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len,
                    uint8_t out[LAB_SHA256_SIZE]);
int lab_secure_compare(const uint8_t *a, const uint8_t *b, size_t len);
int lab_load_key_file(uint8_t *key, size_t key_len, const char *path);
int lab_save_key_file(const uint8_t *key, size_t key_len, const char *path);

#endif /* LAB_CRYPTO_H */
