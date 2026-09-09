#include "ipc.h"
#include "audit.h"
#include "reset.h"
#include "state.h"
#include "protocol.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32

#include <windows.h>
#include <sddl.h>

static HANDLE g_ipc_thread = NULL;
static volatile int g_ipc_running = 0;

static void handle_ipc_message(const uint8_t *payload,
                               uint32_t len,
                               HANDLE pipe)
{
    lab_msg_header_t reply;
    uint8_t outbuf[512];
    size_t outlen;
    lab_agent_state_t *st = lab_state();

    if (len < 1)
        return;

    switch (payload[0])
    {
    case LAB_MSG_SWITCH_PROFILE:
        if (len > 1)
        {
            char profile[LAB_MAX_PROFILE_ID];
            size_t plen = len - 1;

            if (plen >= sizeof(profile))
                plen = sizeof(profile) - 1;

            memcpy(profile, payload + 1, plen);
            profile[plen] = '\0';

            lab_state_switch_profile(profile);
        }
        break;

    case LAB_MSG_TRIGGER_RESET:
        lab_reset_run(lab_state_active_profile());
        break;

    case LAB_MSG_GET_STATUS:
    {
        lab_status_t status;

        memset(&status, 0, sizeof(status));

        snprintf(status.agent_id, sizeof(status.agent_id),
                 "%s", st->agent_id);
        snprintf(status.hostname, sizeof(status.hostname),
                 "%s", st->hostname);
        snprintf(status.active_profile, sizeof(status.active_profile),
                 "%s", st->active_profile);

        status.status = st->agent_status;
        status.last_policy_seq = st->policy_seq;
        status.uptime_sec = lab_monotonic_sec() - st->start_time;

        lab_header_init(&reply,
                        LAB_MSG_STATUS_REPLY,
                        ++st->msg_seq,
                        NULL,
                        (uint32_t)sizeof(status));

        lab_header_sign(&reply,
                        (uint8_t *)&status,
                        st->hmac_key,
                        sizeof(st->hmac_key));

        lab_msg_pack(outbuf,
                     sizeof(outbuf),
                     &reply,
                     (uint8_t *)&status,
                     &outlen);

        WriteFile(pipe, outbuf, (DWORD)outlen, NULL, NULL);
        return;
    }

    default:
        lab_audit_log("IPC_UNKNOWN",
                      "type=%u",
                      payload[0]);
        break;
    }

    lab_header_init(&reply,
                    LAB_MSG_ACK,
                    ++st->msg_seq,
                    NULL,
                    0);

    lab_header_sign(&reply,
                    (const uint8_t *)"",
                    st->hmac_key,
                    sizeof(st->hmac_key));

    lab_msg_pack(outbuf,
                 sizeof(outbuf),
                 &reply,
                 NULL,
                 &outlen);

    WriteFile(pipe, outbuf, (DWORD)outlen, NULL, NULL);
}


static DWORD WINAPI ipc_thread(LPVOID unused)
{
    (void)unused;

    while (g_ipc_running)
    {
        SECURITY_ATTRIBUTES security_attributes;
        PSECURITY_DESCRIPTOR security_descriptor = NULL;
        HANDLE pipe;

        memset(&security_attributes, 0,
               sizeof(security_attributes));

        security_attributes.nLength =
            sizeof(security_attributes);

        if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
                "D:P(A;;GA;;;SY)(A;;GA;;;BA)",
                SDDL_REVISION_1,
                &security_descriptor,
                NULL))
        {
            Sleep(1000);
            continue;
        }

        security_attributes.lpSecurityDescriptor =
            security_descriptor;

        pipe = CreateNamedPipeA(
            LAB_IPC_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE |
            PIPE_READMODE_BYTE |
            PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            &security_attributes
        );

        LocalFree(security_descriptor);

        if (pipe == INVALID_HANDLE_VALUE)
        {
            Sleep(1000);
            continue;
        }

        if (ConnectNamedPipe(pipe, NULL) ||
            GetLastError() == ERROR_PIPE_CONNECTED)
        {
            uint8_t buf[LAB_MAX_PAYLOAD + 256];
            DWORD read = 0;

            if (ReadFile(pipe,
                         buf,
                         sizeof(buf),
                         &read,
                         NULL) &&
                read >= sizeof(lab_msg_header_t))
            {
                lab_msg_header_t hdr;
                const uint8_t *payload;
                lab_agent_state_t *st = lab_state();

                if (lab_msg_unpack(buf,
                                   read,
                                   &hdr,
                                   &payload) == 0 &&
                    lab_header_verify(
                        &hdr,
                        payload,
                        st->hmac_key,
                        sizeof(st->hmac_key)) == 0)
                {
                    handle_ipc_message(
                        payload,
                        hdr.payload_len,
                        pipe);
                }
                else
                {
                    lab_audit_log(
                        "IPC_REJECT",
                        "auth failed");
                }
            }
        }

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }

    return 0;
}


int lab_ipc_start(void)
{
    g_ipc_running = 1;

    g_ipc_thread = CreateThread(
        NULL,
        0,
        ipc_thread,
        NULL,
        0,
        NULL
    );

    return g_ipc_thread ? 0 : -1;
}


void lab_ipc_stop(void)
{
    g_ipc_running = 0;

    if (g_ipc_thread)
    {
        WaitForSingleObject(g_ipc_thread, 3000);
        CloseHandle(g_ipc_thread);
        g_ipc_thread = NULL;
    }
}


#else /* POSIX */


#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int g_ipc_sock = -1;
static pthread_t g_ipc_thread;
static volatile int g_ipc_running = 0;
static int g_ipc_thread_started = 0;


static int send_all(int sock, const uint8_t *buf, size_t len)
{
    size_t total = 0;

    while (total < len)
    {
        ssize_t n = send(sock,
                         buf + total,
                         len - total,
                         0);

        if (n < 0)
        {
            if (errno == EINTR)
                continue;

            return -1;
        }

        if (n == 0)
            return -1;

        total += (size_t)n;
    }

    return 0;
}


static void handle_ipc_message(const uint8_t *payload,
                               uint32_t len,
                               int client)
{
    lab_msg_header_t reply;
    uint8_t outbuf[512];
    size_t outlen;
    lab_agent_state_t *st = lab_state();

    if (len < 1)
        return;

    switch (payload[0])
    {
    case LAB_MSG_SWITCH_PROFILE:
        if (len > 1)
        {
            char profile[LAB_MAX_PROFILE_ID];
            size_t plen = len - 1;

            if (plen >= sizeof(profile))
                plen = sizeof(profile) - 1;

            memcpy(profile, payload + 1, plen);
            profile[plen] = '\0';

            lab_state_switch_profile(profile);
        }
        break;

    case LAB_MSG_TRIGGER_RESET:
        lab_reset_run(lab_state_active_profile());
        break;

    case LAB_MSG_GET_STATUS:
    {
        lab_status_t status;

        memset(&status, 0, sizeof(status));

        snprintf(status.agent_id,
                 sizeof(status.agent_id),
                 "%s",
                 st->agent_id);

        snprintf(status.hostname,
                 sizeof(status.hostname),
                 "%s",
                 st->hostname);

        snprintf(status.active_profile,
                 sizeof(status.active_profile),
                 "%s",
                 st->active_profile);

        status.status = st->agent_status;
        status.last_policy_seq = st->policy_seq;
        status.uptime_sec =
            lab_monotonic_sec() - st->start_time;

        lab_header_init(&reply,
                        LAB_MSG_STATUS_REPLY,
                        ++st->msg_seq,
                        NULL,
                        (uint32_t)sizeof(status));

        lab_header_sign(&reply,
                        (uint8_t *)&status,
                        st->hmac_key,
                        sizeof(st->hmac_key));

        if (lab_msg_pack(outbuf,
                         sizeof(outbuf),
                         &reply,
                         (uint8_t *)&status,
                         &outlen) == 0)
        {
            send_all(client, outbuf, outlen);
        }

        return;
    }

    default:
        lab_audit_log("IPC_UNKNOWN",
                      "type=%u",
                      payload[0]);
        break;
    }

    lab_header_init(&reply,
                    LAB_MSG_ACK,
                    ++st->msg_seq,
                    NULL,
                    0);

    lab_header_sign(&reply,
                    (const uint8_t *)"",
                    st->hmac_key,
                    sizeof(st->hmac_key));

    if (lab_msg_pack(outbuf,
                     sizeof(outbuf),
                     &reply,
                     NULL,
                     &outlen) == 0)
    {
        send_all(client, outbuf, outlen);
    }
}


static void *ipc_thread(void *unused)
{
    (void)unused;

    while (g_ipc_running)
    {
        int client = accept(g_ipc_sock, NULL, NULL);

        if (client < 0)
        {
            if (!g_ipc_running)
                break;

            if (errno == EINTR)
                continue;

            sleep(1);
            continue;
        }

        uint8_t buf[LAB_MAX_PAYLOAD + 256];

        size_t total = 0;

        while (total < sizeof(buf))
        {
            ssize_t n = recv(client,
                             buf + total,
                             sizeof(buf) - total,
                             0);

            if (n < 0)
            {
                if (errno == EINTR)
                    continue;

                break;
            }

            if (n == 0)
                break;

            total += (size_t)n;

            if (total >= sizeof(lab_msg_header_t))
                break;
        }

        if (total >= sizeof(lab_msg_header_t))
        {
            lab_msg_header_t hdr;
            const uint8_t *payload;
            lab_agent_state_t *st = lab_state();

            if (lab_msg_unpack(buf,
                               total,
                               &hdr,
                               &payload) == 0 &&
                lab_header_verify(
                    &hdr,
                    payload,
                    st->hmac_key,
                    sizeof(st->hmac_key)) == 0)
            {
                handle_ipc_message(
                    payload,
                    hdr.payload_len,
                    client);
            }
            else
            {
                lab_audit_log(
                    "IPC_REJECT",
                    "auth failed");
            }
        }

        close(client);
    }

    return NULL;
}


int lab_ipc_start(void)
{
    struct sockaddr_un addr;

    g_ipc_sock = socket(AF_UNIX,
                        SOCK_STREAM,
                        0);

    if (g_ipc_sock < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));

    addr.sun_family = AF_UNIX;

    /*
     * LAB_IPC_PIPE_NAME is a Windows pipe name,
     * so don't reuse it as a filesystem path.
     */
    snprintf(addr.sun_path,
             sizeof(addr.sun_path),
             "/tmp/laborchestrator.sock");

    unlink(addr.sun_path);

    if (bind(g_ipc_sock,
             (struct sockaddr *)&addr,
             sizeof(addr)) != 0)
    {
        close(g_ipc_sock);
        g_ipc_sock = -1;
        return -1;
    }

    /*
     * Only the owner may access the IPC socket.
     */
    chmod(addr.sun_path, 0600);

    if (listen(g_ipc_sock, 8) != 0)
    {
        unlink(addr.sun_path);
        close(g_ipc_sock);
        g_ipc_sock = -1;
        return -1;
    }

    g_ipc_running = 1;

    if (pthread_create(&g_ipc_thread,
                       NULL,
                       ipc_thread,
                       NULL) != 0)
    {
        g_ipc_running = 0;
        unlink(addr.sun_path);
        close(g_ipc_sock);
        g_ipc_sock = -1;
        return -1;
    }

    g_ipc_thread_started = 1;

    return 0;
}


void lab_ipc_stop(void)
{
    g_ipc_running = 0;

    /*
     * Closing the listening socket wakes accept().
     */
    if (g_ipc_sock >= 0)
    {
        shutdown(g_ipc_sock, SHUT_RDWR);
        close(g_ipc_sock);
        g_ipc_sock = -1;
    }

    if (g_ipc_thread_started)
    {
        pthread_join(g_ipc_thread, NULL);
        g_ipc_thread_started = 0;
    }

    unlink("/tmp/laborchestrator.sock");
}


#endif
