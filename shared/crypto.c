#include "crypto.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#else

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "third_party/sha256.h"

#endif


int lab_random_bytes(uint8_t *buf, size_t len)
{
    if (!buf && len != 0)
        return -1;

    if (len == 0)
        return 0;

#ifdef _WIN32

    /*
     * BCryptGenRandom takes an ULONG length, so don't allow
     * size_t -> ULONG truncation.
     */
    if (len > ULONG_MAX)
        return -1;

    return BCryptGenRandom(
        NULL,
        buf,
        (ULONG)len,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    ) == 0 ? 0 : -1;

#else

    int fd = open("/dev/urandom", O_RDONLY);

    if (fd < 0)
        return -1;

    size_t total = 0;

    while (total < len)
    {
        ssize_t n = read(fd, buf + total, len - total);

        if (n < 0)
        {
            if (errno == EINTR)
                continue;

            close(fd);
            return -1;
        }

        if (n == 0)
        {
            close(fd);
            return -1;
        }

        total += (size_t)n;
    }

    close(fd);

    return 0;

#endif
}


#ifdef _WIN32

int lab_sha256(
    const uint8_t *data,
    size_t len,
    uint8_t out[LAB_SHA256_SIZE]
)
{
    if ((!data && len != 0) || !out)
        return -1;

    if (len > ULONG_MAX)
        return -1;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;

    DWORD hash_len = 0;
    DWORD cb = 0;

    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0
    );

    if (st != 0)
        return -1;

    st = BCryptGetProperty(
        hAlg,
        BCRYPT_HASH_LENGTH,
        (PUCHAR)&hash_len,
        sizeof(hash_len),
        &cb,
        0
    );

    if (st != 0 || hash_len != LAB_SHA256_SIZE)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    st = BCryptCreateHash(
        hAlg,
        &hHash,
        NULL,
        0,
        NULL,
        0,
        0
    );

    if (st != 0)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    st = BCryptHashData(
        hHash,
        (PUCHAR)data,
        (ULONG)len,
        0
    );

    if (st == 0)
    {
        st = BCryptFinishHash(
            hHash,
            out,
            hash_len,
            0
        );
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return st == 0 ? 0 : -1;
}


int lab_hmac_sha256(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *data,
    size_t data_len,
    uint8_t out[LAB_SHA256_SIZE]
)
{
    if ((!key && key_len != 0) ||
        (!data && data_len != 0) ||
        !out)
    {
        return -1;
    }

    if (key_len > ULONG_MAX || data_len > ULONG_MAX)
        return -1;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;

    DWORD hash_len = 0;
    DWORD cb = 0;

    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
    );

    if (st != 0)
        return -1;

    st = BCryptGetProperty(
        hAlg,
        BCRYPT_HASH_LENGTH,
        (PUCHAR)&hash_len,
        sizeof(hash_len),
        &cb,
        0
    );

    if (st != 0 || hash_len != LAB_SHA256_SIZE)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    st = BCryptCreateHash(
        hAlg,
        &hHash,
        NULL,
        0,
        (PUCHAR)key,
        (ULONG)key_len,
        0
    );

    if (st != 0)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    st = BCryptHashData(
        hHash,
        (PUCHAR)data,
        (ULONG)data_len,
        0
    );

    if (st == 0)
    {
        st = BCryptFinishHash(
            hHash,
            out,
            hash_len,
            0
        );
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return st == 0 ? 0 : -1;
}


#else


int lab_sha256(
    const uint8_t *data,
    size_t len,
    uint8_t out[LAB_SHA256_SIZE]
)
{
    if ((!data && len != 0) || !out)
        return -1;

    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);

    return 0;
}


int lab_hmac_sha256(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *data,
    size_t data_len,
    uint8_t out[LAB_SHA256_SIZE]
)
{
    if ((!key && key_len != 0) ||
        (!data && data_len != 0) ||
        !out)
    {
        return -1;
    }

    uint8_t kpad[64];
    uint8_t tk[LAB_SHA256_SIZE];

    size_t i;

    const uint8_t *k = key;
    size_t klen = key_len;

    /*
     * HMAC-SHA256 uses a 64-byte block size.
     *
     * If the key is longer than the block size,
     * hash it first.
     */
    if (klen > sizeof(kpad))
    {
        if (lab_sha256(key, klen, tk) != 0)
            return -1;

        k = tk;
        klen = LAB_SHA256_SIZE;
    }

    memset(kpad, 0, sizeof(kpad));
    memcpy(kpad, k, klen);

    /*
     * inner = SHA256((K ^ ipad) || data)
     */
    for (i = 0; i < sizeof(kpad); i++)
        kpad[i] ^= 0x36;

    {
        SHA256_CTX ctx;

        sha256_init(&ctx);
        sha256_update(&ctx, kpad, sizeof(kpad));
        sha256_update(&ctx, data, data_len);
        sha256_final(&ctx, out);
    }

    /*
     * outer = SHA256((K ^ opad) || inner)
     *
     * Convert ipad -> opad.
     */
    for (i = 0; i < sizeof(kpad); i++)
        kpad[i] ^= 0x36 ^ 0x5c;

    {
        SHA256_CTX ctx;

        sha256_init(&ctx);
        sha256_update(&ctx, kpad, sizeof(kpad));
        sha256_update(&ctx, out, LAB_SHA256_SIZE);
        sha256_final(&ctx, out);
    }

    /*
     * Don't leave key material sitting around unnecessarily.
     */
    memset(kpad, 0, sizeof(kpad));
    memset(tk, 0, sizeof(tk));

    return 0;
}


#endif


int lab_secure_compare(
    const uint8_t *a,
    const uint8_t *b,
    size_t len
)
{
    if (!a || !b)
        return 0;

    uint8_t diff = 0;

    for (size_t i = 0; i < len; i++)
        diff |= a[i] ^ b[i];

    return diff == 0;
}


int lab_load_key_file(
    uint8_t *key,
    size_t key_len,
    const char *path
)
{
    if (!key || !path)
        return -1;

    FILE *f = fopen(path, "rb");

    if (!f)
        return -1;

    size_t total = 0;

    while (total < key_len)
    {
        size_t n = fread(
            key + total,
            1,
            key_len - total,
            f
        );

        if (n == 0)
            break;

        total += n;
    }

    /*
     * Make sure the file contains exactly the requested key.
     * Extra bytes indicate a malformed key file.
     */
    if (total != key_len)
    {
        fclose(f);
        memset(key, 0, key_len);
        return -1;
    }

    int extra = fgetc(f);

    fclose(f);

    if (extra != EOF)
    {
        memset(key, 0, key_len);
        return -1;
    }

    return 0;
}


int lab_save_key_file(
    const uint8_t *key,
    size_t key_len,
    const char *path
)
{
    if (!key || !path)
        return -1;

#ifdef _WIN32

    FILE *f = fopen(path, "wb");

#else

    /*
     * Keys should not be world-readable on POSIX systems.
     *
     * 0600 = owner read/write only.
     */
    int fd = open(
        path,
        O_WRONLY | O_CREAT | O_TRUNC,
        0600
    );

    if (fd < 0)
        return -1;

    FILE *f = fdopen(fd, "wb");

    if (!f)
    {
        close(fd);
        return -1;
    }

#endif

    if (fwrite(key, 1, key_len, f) != key_len)
    {
        fclose(f);
        return -1;
    }

    if (fclose(f) != 0)
        return -1;

    return 0;
}
