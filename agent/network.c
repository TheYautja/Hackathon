#include "network.h"
#include "crypto.h"
#include "audit.h"
#include "reset.h"
#include "state.h"
#include "protocol.h"
#include "policy.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

static SOCKET g_tcp_sock = INVALID_SOCKET;
static SOCKET g_udp_sock = INVALID_SOCKET;
static HANDLE g_net_thread = NULL;
static volatile int g_net_running = 0;

static int send_reply(SOCKET client, uint16_t type, const uint8_t *payload,
                      uint32_t plen)
{
    lab_msg_header_t hdr;
    uint8_t buf[LAB_MAX_PAYLOAD + 256];
    size_t outlen;
    lab_agent_state_t *st = lab_state();

    lab_header_init(&hdr, type, ++st->msg_seq, NULL, plen);
    lab_header_sign(&hdr, payload, st->hmac_key, sizeof(st->hmac_key));
    if (lab_msg_pack(buf, sizeof(buf), &hdr, payload, &outlen) != 0)
        return -1;

    return send(client, (const char *)buf, (int)outlen, 0) == (int)outlen ? 0 : -1;
}

int lab_network_handle_push(const uint8_t *payload, uint32_t len)
{
    lab_sealed_policy_t sealed;
    lab_policy_t policy;
    lab_agent_state_t *st = lab_state();

    if (len < sizeof(lab_sealed_policy_t))
        return -1;

    memcpy(&sealed, payload, sizeof(sealed));

    if (lab_policy_unseal(&policy, &sealed, st->hmac_key, sizeof(st->hmac_key)) != 0)
        return -1;

    if (st->policy_loaded && sealed.seq <= st->policy_seq) {
        lab_audit_log("POLICY_REJECT", "stale_seq=%llu current=%llu",
                      (unsigned long long)sealed.seq,
                      (unsigned long long)st->policy_seq);
        return -1;
    }

    if (lab_policy_save_file(&sealed, lab_policy_path()) != 0)
        return -1;
    if (lab_state_apply_policy(&policy) != 0)
        return -1;
    return 0;
}

static void handle_client(SOCKET client)
{
    uint8_t buf[LAB_MAX_PAYLOAD + 256];
    int n = recv(client, (char *)buf, sizeof(buf), 0);
    lab_msg_header_t hdr;
    const uint8_t *payload;
    lab_agent_state_t *st = lab_state();

    if (n < (int)sizeof(lab_msg_header_t))
        return;

    if (lab_msg_unpack(buf, (size_t)n, &hdr, &payload) != 0)
        return;

    if (lab_header_verify(&hdr, payload, st->hmac_key, sizeof(st->hmac_key)) != 0) {
        lab_audit_log("NET_REJECT", "HMAC invalido seq=%llu",
                      (unsigned long long)hdr.seq);
        return;
    }

    switch (hdr.type) {
    case LAB_MSG_PUSH_POLICY:
        if (lab_network_handle_push(payload, hdr.payload_len) == 0)
            send_reply(client, LAB_MSG_ACK, NULL, 0);
        else
            send_reply(client, LAB_MSG_ERROR, (uint8_t *)"POLICY", 6);
        break;

    case LAB_MSG_SWITCH_PROFILE:
        if (hdr.payload_len > 0) {
            char profile[LAB_MAX_PROFILE_ID];
            size_t plen = hdr.payload_len;
            if (plen >= sizeof(profile)) plen = sizeof(profile) - 1;
            memcpy(profile, payload, plen);
            profile[plen] = '\0';
            lab_state_switch_profile(profile);
        }
        send_reply(client, LAB_MSG_ACK, NULL, 0);
        break;

    case LAB_MSG_TRIGGER_RESET:
        lab_reset_run(lab_state_active_profile());
        send_reply(client, LAB_MSG_ACK, NULL, 0);
        break;

    case LAB_MSG_GET_STATUS:
    {
        lab_status_t status;
        memset(&status, 0, sizeof(status));
        snprintf(status.agent_id, sizeof(status.agent_id), "%s", st->agent_id);
        snprintf(status.hostname, sizeof(status.hostname), "%s", st->hostname);
        snprintf(status.active_profile, sizeof(status.active_profile), "%s", st->active_profile);
        status.status = st->agent_status;
        status.last_policy_seq = st->policy_seq;
        status.uptime_sec = lab_monotonic_sec() - st->start_time;
        send_reply(client, LAB_MSG_STATUS_REPLY, (uint8_t *)&status, sizeof(status));
        break;
    }

    default:
        send_reply(client, LAB_MSG_ERROR, (uint8_t *)"UNKNOWN", 7);
        break;
    }
}

static void send_announce(SOCKET udp, struct sockaddr_in *from)
{
    lab_announce_t ann;
    lab_msg_header_t hdr;
    uint8_t buf[512];
    size_t outlen;
    lab_agent_state_t *st = lab_state();

    memset(&ann, 0, sizeof(ann));
    snprintf(ann.agent_id, sizeof(ann.agent_id), "%s", st->agent_id);
    snprintf(ann.hostname, sizeof(ann.hostname), "%s", st->hostname);
    ann.tcp_port = LAB_TCP_PORT;
    lab_sha256(st->hmac_key, sizeof(st->hmac_key), ann.pubkey_hash);

    lab_header_init(&hdr, LAB_MSG_ANNOUNCE, ++st->msg_seq, NULL, sizeof(ann));
    lab_header_sign(&hdr, (uint8_t *)&ann, st->hmac_key, sizeof(st->hmac_key));
    lab_msg_pack(buf, sizeof(buf), &hdr, (uint8_t *)&ann, &outlen);
    sendto(udp, (const char *)buf, (int)outlen, 0,
           (struct sockaddr *)from, sizeof(*from));
}

static DWORD WINAPI network_thread(LPVOID unused)
{
    (void)unused;

    while (g_net_running) {
        fd_set rfds;
        struct timeval tv = { 1, 0 };
        FD_ZERO(&rfds);
        FD_SET(g_tcp_sock, &rfds);
        FD_SET(g_udp_sock, &rfds);

        if (select(0, &rfds, NULL, NULL, &tv) <= 0)
            continue;

        if (FD_ISSET(g_udp_sock, &rfds)) {
            uint8_t buf[512];
            struct sockaddr_in from;
            int fromlen = sizeof(from);
            int n = recvfrom(g_udp_sock, (char *)buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &fromlen);
            lab_msg_header_t hdr;
            const uint8_t *payload;

            if (n >= (int)sizeof(lab_msg_header_t) &&
                lab_msg_unpack(buf, (size_t)n, &hdr, &payload) == 0 &&
                hdr.type == LAB_MSG_DISCOVER) {
                send_announce(g_udp_sock, &from);
            }
        }

        if (FD_ISSET(g_tcp_sock, &rfds)) {
            SOCKET client = accept(g_tcp_sock, NULL, NULL);
            if (client != INVALID_SOCKET) {
                handle_client(client);
                closesocket(client);
            }
        }
    }
    return 0;
}

int lab_network_start(void)
{
    WSADATA wsa;
    struct sockaddr_in addr;
    lab_agent_state_t *st = lab_state();

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return -1;

    g_tcp_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    g_udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_tcp_sock == INVALID_SOCKET || g_udp_sock == INVALID_SOCKET)
        return -1;

    {
        int yes = 1;
        setsockopt(g_udp_sock, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(LAB_TCP_PORT);

    if (bind(g_tcp_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        return -1;
    listen(g_tcp_sock, SOMAXCONN);

    addr.sin_port = htons(LAB_UDP_DISCOVERY);
    bind(g_udp_sock, (struct sockaddr *)&addr, sizeof(addr));

    g_net_running = 1;
    g_net_thread = CreateThread(NULL, 0, network_thread, NULL, 0, NULL);

    lab_audit_log("NETWORK_START", "tcp=%d udp=%d id=%s",
                  LAB_TCP_PORT, LAB_UDP_DISCOVERY, st->agent_id);
    return g_net_thread ? 0 : -1;
}

void lab_network_stop(void)
{
    g_net_running = 0;
    if (g_net_thread) {
        WaitForSingleObject(g_net_thread, 5000);
        CloseHandle(g_net_thread);
        g_net_thread = NULL;
    }
    if (g_tcp_sock != INVALID_SOCKET) closesocket(g_tcp_sock);
    if (g_udp_sock != INVALID_SOCKET) closesocket(g_udp_sock);
    WSACleanup();
}

#else

int lab_network_start(void) { return 0; }
void lab_network_stop(void) {}
int lab_network_handle_push(const uint8_t *payload, uint32_t len)
{
    (void)payload; (void)len;
    return -1;
}

#endif
