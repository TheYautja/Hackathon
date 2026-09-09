#include "crypto.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fcntl.h>
#include <unistd.h>
#endif

int lab_random_bytes(uint8_t *buf, size_t len)
{
#ifdef _WIN32
    return BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
#endif
}

#ifdef _WIN32

int lab_sha256(const uint8_t *data, size_t len, uint8_t out[LAB_SHA256_SIZE])
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hash_len = 0, cb = 0;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (st != 0)
        return -1;

    st = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len,
                           sizeof(hash_len), &cb, 0);
    if (st != 0 || hash_len != LAB_SHA256_SIZE) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    st = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (st != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    st = BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0);
    if (st == 0)
        st = BCryptFinishHash(hHash, out, hash_len, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return st == 0 ? 0 : -1;
}

int lab_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len,
                    uint8_t out[LAB_SHA256_SIZE])
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hash_len = 0, cb = 0;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL,
                                     BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st != 0)
        return -1;

    st = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len,
                           sizeof(hash_len), &cb, 0);
    if (st != 0 || hash_len != LAB_SHA256_SIZE) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    st = BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, (ULONG)key_len, 0);
    if (st != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    st = BCryptHashData(hHash, (PUCHAR)data, (ULONG)data_len, 0);
    if (st == 0)
        st = BCryptFinishHash(hHash, out, hash_len, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return st == 0 ? 0 : -1;
}

#else

/* Minimal portable fallback — production Linux should use OpenSSL/libsodium */
#include "third_party/sha256.h"

int lab_sha256(const uint8_t *data, size_t len, uint8_t out[LAB_SHA256_SIZE])
{
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
    return 0;
}

int lab_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len,
                    uint8_t out[LAB_SHA256_SIZE])
{
    uint8_t kpad[64];
    uint8_t tk[LAB_SHA256_SIZE];
    size_t i;
    const uint8_t *k = key;
    size_t klen = key_len;

    if (klen > 64) {
        lab_sha256(key, klen, tk);
        k = tk;
        klen = LAB_SHA256_SIZE;
    }

    memset(kpad, 0, sizeof(kpad));
    memcpy(kpad, k, klen);

    for (i = 0; i < 64; i++)
        kpad[i] ^= 0x36;

    {
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, kpad, 64);
        sha256_update(&ctx, data, data_len);
        sha256_final(&ctx, out);
    }

    for (i = 0; i < 64; i++)
        kpad[i] ^= 0x36 ^ 0x5c;

    {
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, kpad, 64);
        sha256_update(&ctx, out, LAB_SHA256_SIZE);
        sha256_final(&ctx, out);
    }

    return 0;
}

#endif

int lab_secure_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    size_t i;

    if (!a || !b)
        return 0;

    for (i = 0; i < len; i++)
        diff |= a[i] ^ b[i];

    return diff == 0;
}

int lab_load_key_file(uint8_t *key, size_t key_len, const char *path)
{
    FILE *f = fopen(path, "rb");
    size_t n;

    if (!f)
        return -1;

    n = fread(key, 1, key_len, f);
    fclose(f);
    return n == key_len ? 0 : -1;
}

int lab_save_key_file(const uint8_t *key, size_t key_len, const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;

    if (fwrite(key, 1, key_len, f) != key_len) {
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}
