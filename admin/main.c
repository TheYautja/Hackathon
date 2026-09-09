#include "crypto.h"
#include "policy.h"
#include "protocol.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

typedef struct {
    char agent_id[LAB_MAX_HOSTNAME];
    char hostname[LAB_MAX_HOSTNAME];
    char ip[64];
    uint16_t port;
    uint64_t last_seen;
} discovered_agent_t;

#define MAX_AGENTS 32
static discovered_agent_t g_agents[MAX_AGENTS];
static int g_agent_count = 0;
static uint8_t g_hmac_key[LAB_HMAC_KEY_DEFAULT_LEN];
static uint64_t g_seq = 1;

static int ws_init(void)
{
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    return 0;
#endif
}

static void ws_cleanup(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

static int tcp_connect(const char *ip, uint16_t port)
{
#ifdef _WIN32
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in addr;
    if (s == INVALID_SOCKET)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(s);
        return -1;
    }
    return (int)s;
#else
    (void)ip; (void)port;
    return -1;
#endif
}

static int send_msg(int sock, uint16_t type, const uint8_t *payload, uint32_t plen)
{
    lab_msg_header_t hdr;
    uint8_t buf[LAB_MAX_PAYLOAD + 256];
    size_t outlen;

    lab_header_init(&hdr, type, g_seq++, NULL, plen);
    lab_header_sign(&hdr, payload, g_hmac_key, sizeof(g_hmac_key));
    if (lab_msg_pack(buf, sizeof(buf), &hdr, payload, &outlen) != 0)
        return -1;

#ifdef _WIN32
    return send(sock, (const char *)buf, (int)outlen, 0) == (int)outlen ? 0 : -1;
#else
    return -1;
#endif
}

static int recv_msg(int sock, lab_msg_header_t *hdr, uint8_t *payload, size_t cap)
{
    uint8_t buf[LAB_MAX_PAYLOAD + 256];
#ifdef _WIN32
    int n = recv(sock, (char *)buf, sizeof(buf), 0);
#else
    int n = -1;
#endif
    const uint8_t *pl;
    if (n < (int)sizeof(lab_msg_header_t))
        return -1;
    if (lab_msg_unpack(buf, (size_t)n, hdr, &pl) != 0)
        return -1;
    if (lab_header_verify(hdr, pl, g_hmac_key, sizeof(g_hmac_key)) != 0)
        return -1;
    if (hdr->payload_len > cap)
        return -1;
    if (hdr->payload_len > 0)
        memcpy(payload, pl, hdr->payload_len);
    return (int)hdr->payload_len;
}

static void upsert_agent(const lab_announce_t *ann, const char *ip)
{
    int i;
    for (i = 0; i < g_agent_count; i++) {
        if (strcmp(g_agents[i].agent_id, ann->agent_id) == 0) {
            snprintf(g_agents[i].ip, sizeof(g_agents[i].ip), "%s", ip);
            g_agents[i].port = ann->tcp_port;
            g_agents[i].last_seen = lab_monotonic_sec();
            return;
        }
    }
    if (g_agent_count >= MAX_AGENTS)
        return;

    snprintf(g_agents[g_agent_count].agent_id, LAB_MAX_HOSTNAME, "%s", ann->agent_id);
    snprintf(g_agents[g_agent_count].hostname, LAB_MAX_HOSTNAME, "%s", ann->hostname);
    snprintf(g_agents[g_agent_count].ip, sizeof(g_agents[g_agent_count].ip), "%s", ip);
    g_agents[g_agent_count].port = ann->tcp_port;
    g_agents[g_agent_count].last_seen = lab_monotonic_sec();
    g_agent_count++;
}

static int cmd_discover(int timeout_sec)
{
#ifdef _WIN32
    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in broadcast;
    lab_msg_header_t hdr;
    uint8_t buf[256];
    size_t outlen;
    int i;

    if (udp == INVALID_SOCKET)
        return -1;

    {
        int yes = 1;
        setsockopt(udp, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
        DWORD tv = (DWORD)(timeout_sec * 1000);
        setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
    }

    lab_header_init(&hdr, LAB_MSG_DISCOVER, g_seq++, NULL, 0);
    lab_header_sign(&hdr, (const uint8_t *)"", g_hmac_key, sizeof(g_hmac_key));
    lab_msg_pack(buf, sizeof(buf), &hdr, NULL, &outlen);

    memset(&broadcast, 0, sizeof(broadcast));
    broadcast.sin_family = AF_INET;
    broadcast.sin_port = htons(LAB_UDP_DISCOVERY);
    broadcast.sin_addr.s_addr = INADDR_BROADCAST;

    for (i = 0; i < 3; i++)
        sendto(udp, (const char *)buf, (int)outlen, 0,
               (struct sockaddr *)&broadcast, sizeof(broadcast));

    while (1) {
        uint8_t rbuf[512];
        struct sockaddr_in from;
        int fromlen = sizeof(from);
        int n = recvfrom(udp, (char *)rbuf, sizeof(rbuf), 0,
                         (struct sockaddr *)&from, &fromlen);
        lab_msg_header_t rhdr;
        const uint8_t *payload;
        char ip[64];

        if (n <= 0)
            break;

        if (lab_msg_unpack(rbuf, (size_t)n, &rhdr, &payload) != 0)
            continue;
        if (rhdr.type != LAB_MSG_ANNOUNCE)
            continue;
        if (lab_header_verify(&rhdr, payload, g_hmac_key, sizeof(g_hmac_key)) != 0)
            continue;
        if (rhdr.payload_len < sizeof(lab_announce_t))
            continue;

        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
        upsert_agent((const lab_announce_t *)payload, ip);
    }

    closesocket(udp);

    printf("Agentes descobertos: %d\n", g_agent_count);
    for (i = 0; i < g_agent_count; i++)
        printf("  [%s] %s @ %s:%u\n", g_agents[i].agent_id,
               g_agents[i].hostname, g_agents[i].ip, g_agents[i].port);
    return 0;
#else
    (void)timeout_sec;
    printf("Discovery suportado apenas no Windows neste MVP.\n");
    return -1;
#endif
}

static discovered_agent_t *find_agent(const char *id)
{
    int i;
    for (i = 0; i < g_agent_count; i++) {
        if (strcmp(g_agents[i].agent_id, id) == 0 ||
            strcmp(g_agents[i].hostname, id) == 0 ||
            strcmp(g_agents[i].ip, id) == 0)
            return &g_agents[i];
    }
    return NULL;
}

static int cmd_push(const char *target, const char *policy_file)
{
    discovered_agent_t *agent;
    FILE *f;
    char json[LAB_MAX_PAYLOAD];
    lab_policy_t policy;
    lab_sealed_policy_t sealed;
    size_t n;
    int sock;
    lab_msg_header_t rhdr;
    uint8_t payload[64];

    agent = find_agent(target);
    if (!agent) {
        fprintf(stderr, "Agente nao encontrado: %s (use discover)\n", target);
        return -1;
    }

    f = fopen(policy_file, "r");
    if (!f) {
        fprintf(stderr, "Politica nao encontrada: %s\n", policy_file);
        return -1;
    }

    n = fread(json, 1, sizeof(json) - 1, f);
    json[n] = '\0';
    fclose(f);

    if (lab_policy_from_json(&policy, json) != 0) {
        fprintf(stderr, "JSON de politica invalido\n");
        return -1;
    }

    policy.issued_at = lab_now_unix();
    policy.valid_until = lab_now_unix() + 7 * 24 * 3600;
    policy.seq = lab_now_unix();

    if (lab_policy_seal(&sealed, &policy, g_hmac_key, sizeof(g_hmac_key)) != 0) {
        fprintf(stderr, "Falha ao assinar politica\n");
        return -1;
    }

    sock = tcp_connect(agent->ip, agent->port);
    if (sock < 0) {
        fprintf(stderr, "Falha ao conectar em %s:%u\n", agent->ip, agent->port);
        return -1;
    }

    if (send_msg(sock, LAB_MSG_PUSH_POLICY, (uint8_t *)&sealed, sizeof(sealed)) != 0) {
        closesocket(sock);
        return -1;
    }

    if (recv_msg(sock, &rhdr, payload, sizeof(payload)) >= 0 && rhdr.type == LAB_MSG_ACK)
        printf("Politica enviada para %s com sucesso (seq=%llu)\n",
               agent->agent_id, (unsigned long long)policy.seq);
    else
        printf("Resposta inesperada do agente %s\n", agent->agent_id);

#ifdef _WIN32
    closesocket(sock);
#endif
    return 0;
}

static int cmd_status(const char *target)
{
    discovered_agent_t *agent = find_agent(target);
    int sock;
    lab_msg_header_t rhdr;
    lab_status_t status;

    if (!agent) {
        fprintf(stderr, "Agente nao encontrado: %s\n", target);
        return -1;
    }

    sock = tcp_connect(agent->ip, agent->port);
    if (sock < 0)
        return -1;

    if (send_msg(sock, LAB_MSG_GET_STATUS, NULL, 0) != 0) {
        closesocket(sock);
        return -1;
    }

    if (recv_msg(sock, &rhdr, (uint8_t *)&status, sizeof(status)) >= 0 &&
        rhdr.type == LAB_MSG_STATUS_REPLY) {
        printf("Agente: %s (%s)\n", status.agent_id, status.hostname);
        printf("Perfil ativo: %s\n", status.active_profile);
        printf("Status: %u | Policy seq: %llu | Uptime: %llu s\n",
               status.status,
               (unsigned long long)status.last_policy_seq,
               (unsigned long long)status.uptime_sec);
    }

#ifdef _WIN32
    closesocket(sock);
#endif
    return 0;
}

static int cmd_switch(const char *target, const char *profile)
{
    discovered_agent_t *agent = find_agent(target);
    int sock;
    lab_msg_header_t rhdr;
    uint8_t payload[64];

    if (!agent)
        return -1;

    sock = tcp_connect(agent->ip, agent->port);
    if (sock < 0)
        return -1;

    send_msg(sock, LAB_MSG_SWITCH_PROFILE, (const uint8_t *)profile,
             (uint32_t)strlen(profile));
    recv_msg(sock, &rhdr, payload, sizeof(payload));
    printf("Perfil alterado para %s em %s\n", profile, agent->agent_id);

#ifdef _WIN32
    closesocket(sock);
#endif
    return 0;
}

static int cmd_reset(const char *target)
{
    discovered_agent_t *agent = find_agent(target);
    int sock;
    lab_msg_header_t rhdr;
    uint8_t payload[64];

    if (!agent)
        return -1;

    sock = tcp_connect(agent->ip, agent->port);
    if (sock < 0)
        return -1;

    send_msg(sock, LAB_MSG_TRIGGER_RESET, NULL, 0);
    recv_msg(sock, &rhdr, payload, sizeof(payload));
    printf("Reset disparado em %s\n", agent->agent_id);

#ifdef _WIN32
    closesocket(sock);
#endif
    return 0;
}

static void usage(const char *prog)
{
    printf("LabAdmin — Gestor de Agentes de Laboratorio\n\n");
    printf("Uso:\n");
    printf("  %s discover [--timeout N]\n", prog);
    printf("  %s push <agente> <policy.json>\n", prog);
    printf("  %s status <agente>\n", prog);
    printf("  %s switch <agente> <perfil>\n", prog);
    printf("  %s reset <agente>\n", prog);
    printf("  %s add <id> <ip> [porta]\n", prog);
    printf("\nOpcoes:\n");
    printf("  --key <path>   Chave HMAC compartilhada (default: keys/shared.key)\n");
}

static int cmd_add(const char *id, const char *ip, uint16_t port)
{
    if (g_agent_count >= MAX_AGENTS)
        return -1;
    snprintf(g_agents[g_agent_count].agent_id, LAB_MAX_HOSTNAME, "%s", id);
    snprintf(g_agents[g_agent_count].hostname, LAB_MAX_HOSTNAME, "%s", id);
    snprintf(g_agents[g_agent_count].ip, sizeof(g_agents[g_agent_count].ip), "%s", ip);
    g_agents[g_agent_count].port = port;
    g_agents[g_agent_count].last_seen = lab_monotonic_sec();
    g_agent_count++;
    printf("Agente adicionado: %s @ %s:%u\n", id, ip, port);
    return 0;
}

int main(int argc, char **argv)
{
    const char *key_path = "keys/shared.key";
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
            key_path = argv[++i];
    }

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (lab_load_key_file(g_hmac_key, sizeof(g_hmac_key), key_path) != 0) {
        fprintf(stderr, "Chave nao encontrada: %s\n", key_path);
        fprintf(stderr, "Execute: powershell scripts/genkeys.ps1\n");
        return 1;
    }

    ws_init();

    if (strcmp(argv[1], "discover") == 0) {
        int timeout = 3;
        for (i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc)
                timeout = atoi(argv[++i]);
        }
        cmd_discover(timeout);
    } else if (strcmp(argv[1], "push") == 0 && argc >= 4) {
        cmd_push(argv[2], argv[3]);
    } else if (strcmp(argv[1], "status") == 0 && argc >= 3) {
        cmd_status(argv[2]);
    } else if (strcmp(argv[1], "switch") == 0 && argc >= 4) {
        cmd_switch(argv[2], argv[3]);
    } else if (strcmp(argv[1], "reset") == 0 && argc >= 3) {
        cmd_reset(argv[2]);
    } else if (strcmp(argv[1], "add") == 0 && argc >= 4) {
        uint16_t port = LAB_TCP_PORT;
        if (argc >= 5)
            port = (uint16_t)atoi(argv[4]);
        cmd_add(argv[2], argv[3], port);
    } else {
        usage(argv[0]);
        ws_cleanup();
        return 1;
    }

    ws_cleanup();
    return 0;
}
