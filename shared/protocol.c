#include "protocol.h"
#include "crypto.h"
#include <stddef.h>
#include <string.h>
#include <time.h>

int lab_header_init(lab_msg_header_t *hdr, uint16_t type, uint64_t seq,
                    const uint8_t *nonce, uint32_t payload_len)
{
    if (!hdr)
        return -1;

    hdr->magic = LAB_MAGIC;
    hdr->version = LAB_PROTOCOL_VER;
    hdr->type = type;
    hdr->seq = seq;
    hdr->timestamp = (uint64_t)time(NULL);
    hdr->payload_len = payload_len;

    if (nonce)
        memcpy(hdr->nonce, nonce, LAB_NONCE_SIZE);
    else
        lab_random_bytes(hdr->nonce, LAB_NONCE_SIZE);

    memset(hdr->hmac, 0, LAB_HMAC_SIZE);
    return 0;
}

int lab_header_sign(lab_msg_header_t *hdr, const uint8_t *payload,
                    const uint8_t *hmac_key, size_t hmac_key_len)
{
    uint8_t body[LAB_MAX_PAYLOAD + 512];
    size_t hdr_copy_len = offsetof(lab_msg_header_t, hmac);
    size_t total;

    if (!hdr || !hmac_key || (hdr->payload_len > 0 && !payload))
        return -1;

    if (hdr_copy_len > sizeof(body))
        return -1;

    memcpy(body, hdr, hdr_copy_len);
    total = hdr_copy_len + hdr->payload_len;
    if (total > sizeof(body))
        return -1;

    if (hdr->payload_len > 0)
        memcpy(body + hdr_copy_len, payload, hdr->payload_len);
    return lab_hmac_sha256(hmac_key, hmac_key_len, body, total, hdr->hmac);
}

int lab_header_verify(const lab_msg_header_t *hdr, const uint8_t *payload,
                      const uint8_t *hmac_key, size_t hmac_key_len)
{
    uint8_t expected[LAB_HMAC_SIZE];
    uint8_t body[LAB_MAX_PAYLOAD + 512];
    size_t hdr_copy_len = offsetof(lab_msg_header_t, hmac);
    size_t total;

    if (!hdr || !hmac_key || (hdr->payload_len > 0 && !payload))
        return -1;

    if (hdr->magic != LAB_MAGIC || hdr->version != LAB_PROTOCOL_VER)
        return -1;

    if (hdr->payload_len > LAB_MAX_PAYLOAD)
        return -1;

    total = hdr_copy_len + hdr->payload_len;
    if (total > sizeof(body))
        return -1;

    memcpy(body, hdr, hdr_copy_len);
    if (hdr->payload_len > 0)
        memcpy(body + hdr_copy_len, payload, hdr->payload_len);

    if (lab_hmac_sha256(hmac_key, hmac_key_len, body, total, expected) != 0)
        return -1;

    return lab_secure_compare(expected, hdr->hmac, LAB_HMAC_SIZE) ? 0 : -1;
}

int lab_msg_pack(uint8_t *buf, size_t buf_len, const lab_msg_header_t *hdr,
                 const uint8_t *payload, size_t *out_len)
{
    size_t need = sizeof(lab_msg_header_t) + hdr->payload_len;

    if (!buf || !hdr || !out_len)
        return -1;
    if (need > buf_len)
        return -1;

    if (hdr->payload_len > LAB_MAX_PAYLOAD)
        return -1;

    memcpy(buf, hdr, sizeof(lab_msg_header_t));
    if (hdr->payload_len > 0 && payload)
        memcpy(buf + sizeof(lab_msg_header_t), payload, hdr->payload_len);

    *out_len = need;
    return 0;
}

int lab_msg_unpack(const uint8_t *buf, size_t buf_len, lab_msg_header_t *hdr,
                   const uint8_t **payload)
{
    if (!buf || !hdr || buf_len < sizeof(lab_msg_header_t))
        return -1;

    memcpy(hdr, buf, sizeof(lab_msg_header_t));

    if (hdr->magic != LAB_MAGIC || hdr->version != LAB_PROTOCOL_VER ||
        hdr->payload_len > LAB_MAX_PAYLOAD)
        return -1;

    if (sizeof(lab_msg_header_t) + hdr->payload_len > buf_len)
        return -1;

    if (payload)
        *payload = buf + sizeof(lab_msg_header_t);

    return 0;
}
