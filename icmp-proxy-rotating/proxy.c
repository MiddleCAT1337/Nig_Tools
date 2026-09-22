#define WIN32_LEAN_AND_MEAN
#include "proxy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define SOCKS5_VER           0x05
#define SOCKS5_AUTH_NONE     0x00
#define SOCKS5_CMD_CONNECT   0x01
#define SOCKS5_CMD_UDP_ASSOC 0x03
#define SOCKS5_ATYP_IPV4     0x01
#define SOCKS5_REP_SUCCESS   0x00

static int wait_socket(SOCKET sock, int timeout_ms, int write_ready)
{
    fd_set fds;
    struct timeval tv;
    int ret;

    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (write_ready)
        ret = select(0, NULL, &fds, NULL, &tv);
    else
        ret = select(0, &fds, NULL, NULL, &tv);
    return ret;
}

static int socket_connect_blocking(const struct sockaddr_in *addr, int timeout_ms)
{
    SOCKET sock;
    u_long mode = 1;
    int so_error = 0;
    int so_len = sizeof(so_error);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        return (int)INVALID_SOCKET;

    ioctlsocket(sock, FIONBIO, &mode);
    if (connect(sock, (const struct sockaddr *)addr, sizeof(*addr)) == 0)
        return (int)sock;

    if (WSAGetLastError() != WSAEWOULDBLOCK) {
        closesocket(sock);
        return (int)INVALID_SOCKET;
    }

    if (wait_socket(sock, timeout_ms, 1) <= 0) {
        closesocket(sock);
        return (int)INVALID_SOCKET;
    }

    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&so_error, &so_len) != 0 ||
        so_error != 0) {
        closesocket(sock);
        return (int)INVALID_SOCKET;
    }

    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);
    return (int)sock;
}

static int socks_recv_all(SOCKET sock, void *buf, int len, int timeout_ms)
{
    char *p = (char *)buf;
    int got = 0;

    while (got < len) {
        int n;
        if (wait_socket(sock, timeout_ms, 0) <= 0)
            return -1;
        n = recv(sock, p + got, len - got, 0);
        if (n <= 0)
            return -1;
        got += n;
    }
    return 0;
}

static int socks_send_all(SOCKET sock, const void *buf, int len, int timeout_ms)
{
    const char *p = (const char *)buf;
    int sent = 0;

    while (sent < len) {
        int n;
        if (wait_socket(sock, timeout_ms, 1) <= 0)
            return -1;
        n = send(sock, p + sent, len - sent, 0);
        if (n <= 0)
            return -1;
        sent += n;
    }
    return 0;
}

static int proxy_resolve_addr(const proxy_entry_t *proxy, struct sockaddr_in *out)
{
    struct addrinfo hints, *res = NULL;
    char port_str[8];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)proxy->port);

    if (getaddrinfo(proxy->host, port_str, &hints, &res) != 0 || res == NULL)
        return -1;

    memcpy(out, res->ai_addr, sizeof(*out));
    freeaddrinfo(res);
    return 0;
}

static int socks5_handshake(SOCKET sock, unsigned char cmd,
                            const struct sockaddr_in *target,
                            struct sockaddr_in *bind_out,
                            int timeout_ms, int *error_code)
{
    unsigned char req[10];
    unsigned char resp[4];
    unsigned char addr_buf[256];
    unsigned char rep;
    int need = 4;

    req[0] = SOCKS5_VER;
    req[1] = 1;
    req[2] = SOCKS5_AUTH_NONE;
    if (socks_send_all(sock, req, 3, timeout_ms) != 0) {
        if (error_code) *error_code = WSAETIMEDOUT;
        return -1;
    }
    if (socks_recv_all(sock, resp, 2, timeout_ms) != 0) {
        if (error_code) *error_code = WSAETIMEDOUT;
        return -1;
    }
    if (resp[0] != SOCKS5_VER || resp[1] != SOCKS5_AUTH_NONE) {
        if (error_code) *error_code = WSAECONNREFUSED;
        return -1;
    }

    req[0] = SOCKS5_VER;
    req[1] = cmd;
    req[2] = 0x00;
    req[3] = SOCKS5_ATYP_IPV4;
    memcpy(req + 4, &target->sin_addr, 4);
    memcpy(req + 8, &target->sin_port, 2);

    if (socks_send_all(sock, req, 10, timeout_ms) != 0) {
        if (error_code) *error_code = WSAETIMEDOUT;
        return -1;
    }

    if (socks_recv_all(sock, resp, 4, timeout_ms) != 0) {
        if (error_code) *error_code = WSAETIMEDOUT;
        return -1;
    }

    rep = resp[1];
    if (rep != SOCKS5_REP_SUCCESS) {
        if (error_code) *error_code = WSAECONNREFUSED;
        return -1;
    }

    switch (resp[3]) {
    case SOCKS5_ATYP_IPV4:
        need = 4 + 2;
        break;
    case 0x03:
        if (socks_recv_all(sock, addr_buf, 1, timeout_ms) != 0) {
            if (error_code) *error_code = WSAETIMEDOUT;
            return -1;
        }
        need = addr_buf[0] + 2;
        break;
    case 0x04:
        need = 16 + 2;
        break;
    default:
        if (error_code) *error_code = WSAEINVAL;
        return -1;
    }

    if (socks_recv_all(sock, addr_buf, need, timeout_ms) != 0) {
        if (error_code) *error_code = WSAETIMEDOUT;
        return -1;
    }

    if (bind_out && resp[3] == SOCKS5_ATYP_IPV4) {
        memset(bind_out, 0, sizeof(*bind_out));
        bind_out->sin_family = AF_INET;
        memcpy(&bind_out->sin_addr, addr_buf, 4);
        memcpy(&bind_out->sin_port, addr_buf + 4, 2);
    }

    return 0;
}

int proxy_resolve_default_path(char *out, size_t out_size)
{
    char exe_path[MAX_PATH];
    char *slash;
    size_t dir_len;

    if (GetModuleFileNameA(NULL, exe_path, MAX_PATH) == 0)
        return -1;

    slash = strrchr(exe_path, '\\');
    if (!slash)
        slash = strrchr(exe_path, '/');
    if (slash)
        *(slash + 1) = '\0';
    else
        exe_path[0] = '\0';

    dir_len = strlen(exe_path);
    if (dir_len + strlen(PROXY_FILE_NAME) + 1 >= out_size)
        return -1;

    memcpy(out, exe_path, dir_len + 1);
    strcat(out, PROXY_FILE_NAME);
    return 0;
}

static int parse_proxy_line(char *line, proxy_entry_t *entry)
{
    char *colon;
    long port;

    line[strcspn(line, "\r\n")] = '\0';
    while (*line == ' ' || *line == '\t')
        line++;
    if (*line == '\0' || *line == '#')
        return 0;

    colon = strrchr(line, ':');
    if (!colon)
        return 0;

    *colon = '\0';
    port = strtol(colon + 1, NULL, 10);
    if (port < 1 || port > 65535)
        return 0;

    if (strlen(line) >= PROXY_HOST_MAX)
        return 0;

    strncpy(entry->host, line, PROXY_HOST_MAX - 1);
    entry->host[PROXY_HOST_MAX - 1] = '\0';
    entry->port = (uint16_t)port;
    return 1;
}

int proxy_load(const char *path, proxy_list_t *list)
{
    FILE *fp;
    char line[256];
    proxy_entry_t *entries = NULL;
    size_t cap = 0;
    size_t count = 0;

    memset(list, 0, sizeof(*list));

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        proxy_entry_t entry;

        if (!parse_proxy_line(line, &entry))
            continue;

        if (count >= cap) {
            size_t new_cap = cap ? cap * 2 : 32;
            proxy_entry_t *new_entries =
                (proxy_entry_t *)realloc(entries, new_cap * sizeof(proxy_entry_t));
            if (!new_entries) {
                free(entries);
                fclose(fp);
                return -1;
            }
            entries = new_entries;
            cap = new_cap;
        }
        entries[count++] = entry;
    }

    fclose(fp);

    if (count == 0) {
        free(entries);
        return -1;
    }

    list->entries = entries;
    list->count   = count;
    list->index   = 0;
    return 0;
}

void proxy_free(proxy_list_t *list)
{
    if (list->entries) {
        free(list->entries);
        list->entries = NULL;
    }
    list->count = 0;
    list->index = 0;
}

const proxy_entry_t *proxy_current(const proxy_list_t *list)
{
    if (!list || list->count == 0)
        return NULL;
    return &list->entries[list->index];
}

int proxy_advance(proxy_list_t *list)
{
    size_t prev;

    if (!list || list->count == 0)
        return 1;

    prev = list->index;
    list->index = (list->index + 1) % list->count;
    return list->index <= prev && prev == list->count - 1;
}

int socks5_tcp_connect(const proxy_entry_t *proxy,
                       const struct sockaddr_in *target,
                       int timeout_ms, int *error_code)
{
    struct sockaddr_in proxy_addr;
    SOCKET sock;

    if (proxy_resolve_addr(proxy, &proxy_addr) != 0) {
        if (error_code) *error_code = WSAHOST_NOT_FOUND;
        return (int)INVALID_SOCKET;
    }

    sock = (SOCKET)socket_connect_blocking(&proxy_addr, timeout_ms);
    if (sock == INVALID_SOCKET) {
        if (error_code) *error_code = WSAECONNREFUSED;
        return (int)INVALID_SOCKET;
    }

    if (socks5_handshake(sock, SOCKS5_CMD_CONNECT, target, NULL,
                         timeout_ms, error_code) != 0) {
        closesocket(sock);
        return (int)INVALID_SOCKET;
    }

    return (int)sock;
}

int socks5_udp_open(const proxy_entry_t *proxy,
                    const struct sockaddr_in *target,
                    int timeout_ms,
                    socks5_udp_tunnel_t *tunnel,
                    int *error_code)
{
    struct sockaddr_in proxy_addr;
    SOCKET tcp_sock;
    SOCKET udp_sock;

    memset(tunnel, 0, sizeof(*tunnel));
    tunnel->target_addr = *target;

    if (proxy_resolve_addr(proxy, &proxy_addr) != 0) {
        if (error_code) *error_code = WSAHOST_NOT_FOUND;
        return -1;
    }

    tcp_sock = (SOCKET)socket_connect_blocking(&proxy_addr, timeout_ms);
    if (tcp_sock == INVALID_SOCKET) {
        if (error_code) *error_code = WSAECONNREFUSED;
        return -1;
    }

    if (socks5_handshake(tcp_sock, SOCKS5_CMD_UDP_ASSOC, target,
                         &tunnel->relay_addr, timeout_ms, error_code) != 0) {
        closesocket(tcp_sock);
        return -1;
    }

    if (tunnel->relay_addr.sin_addr.s_addr == 0 ||
        tunnel->relay_addr.sin_port == 0) {
        struct sockaddr_in local;
        int local_len = sizeof(local);
        if (getsockname(tcp_sock, (struct sockaddr *)&local, &local_len) == 0) {
            tunnel->relay_addr.sin_family = AF_INET;
            tunnel->relay_addr.sin_addr   = local.sin_addr;
            if (tunnel->relay_addr.sin_port == 0)
                tunnel->relay_addr.sin_port = htons(0);
        }
    }

    udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock == INVALID_SOCKET) {
        if (error_code) *error_code = (int)WSAGetLastError();
        closesocket(tcp_sock);
        return -1;
    }

    tunnel->udp_sock  = udp_sock;
    tunnel->tcp_ctrl  = tcp_sock;
    return 0;
}

void socks5_udp_close(socks5_udp_tunnel_t *tunnel)
{
    if (tunnel->udp_sock != INVALID_SOCKET && tunnel->udp_sock != 0) {
        closesocket(tunnel->udp_sock);
        tunnel->udp_sock = INVALID_SOCKET;
    }
    if (tunnel->tcp_ctrl != INVALID_SOCKET && tunnel->tcp_ctrl != 0) {
        closesocket(tunnel->tcp_ctrl);
        tunnel->tcp_ctrl = INVALID_SOCKET;
    }
}

static int build_udp_frame(const struct sockaddr_in *target,
                           const void *data, int data_len,
                           unsigned char *out, int out_cap)
{
    int frame_len = 10 + data_len;

    if (frame_len > out_cap)
        return -1;

    out[0] = 0x00;
    out[1] = 0x00;
    out[2] = 0x00;
    out[3] = SOCKS5_ATYP_IPV4;
    memcpy(out + 4, &target->sin_addr, 4);
    memcpy(out + 8, &target->sin_port, 2);
    memcpy(out + 10, data, (size_t)data_len);
    return frame_len;
}

int socks5_udp_send(socks5_udp_tunnel_t *tunnel,
                    const void *data, int len, int *error_code)
{
    unsigned char frame[512];
    int frame_len;

    frame_len = build_udp_frame(&tunnel->target_addr, data, len, frame, sizeof(frame));
    if (frame_len < 0) {
        if (error_code) *error_code = WSAEMSGSIZE;
        return -1;
    }

    if (sendto(tunnel->udp_sock, (const char *)frame, frame_len, 0,
               (struct sockaddr *)&tunnel->relay_addr,
               sizeof(tunnel->relay_addr)) == SOCKET_ERROR) {
        if (error_code) *error_code = (int)WSAGetLastError();
        return -1;
    }
    return 0;
}

int socks5_udp_recv(socks5_udp_tunnel_t *tunnel,
                    void *buf, int buf_len, int timeout_ms, int *error_code)
{
    unsigned char frame[512];
    struct sockaddr_in from;
    int from_len = sizeof(from);
    int n;
    int hdr_len;
    int data_len;

    u_long mode = 1;
    ioctlsocket(tunnel->udp_sock, FIONBIO, &mode);

    if (wait_socket(tunnel->udp_sock, timeout_ms, 0) <= 0) {
        if (error_code) *error_code = WSAETIMEDOUT;
        return -1;
    }

    n = recvfrom(tunnel->udp_sock, (char *)frame, sizeof(frame), 0,
                 (struct sockaddr *)&from, &from_len);
    if (n < 10) {
        if (error_code) *error_code = WSAETIMEDOUT;
        return -1;
    }

    if (frame[3] == SOCKS5_ATYP_IPV4)
        hdr_len = 10;
    else
        return -1;

    data_len = n - hdr_len;
    if (data_len > buf_len)
        data_len = buf_len;
    memcpy(buf, frame + hdr_len, (size_t)data_len);
    return data_len;
}
