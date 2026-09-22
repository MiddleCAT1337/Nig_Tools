#ifndef PROXY_H
#define PROXY_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stddef.h>
#include <stdint.h>

#define PROXY_HOST_MAX   64
#define PROXY_FILE_NAME  "verified_socks5.txt"
#define PROXY_CONNECT_TIMEOUT_MS  2000

typedef struct {
    char     host[PROXY_HOST_MAX];
    uint16_t port;
} proxy_entry_t;

typedef struct {
    proxy_entry_t *entries;
    size_t         count;
    size_t         index;
} proxy_list_t;

typedef struct {
    SOCKET             udp_sock;
    SOCKET             tcp_ctrl;
    struct sockaddr_in relay_addr;
    struct sockaddr_in target_addr;
} socks5_udp_tunnel_t;

int  proxy_resolve_default_path(char *out, size_t out_size);
int  proxy_load(const char *path, proxy_list_t *list);
void proxy_free(proxy_list_t *list);

const proxy_entry_t *proxy_current(const proxy_list_t *list);
int                  proxy_advance(proxy_list_t *list);

int socks5_tcp_connect(const proxy_entry_t *proxy,
                         const struct sockaddr_in *target,
                         int timeout_ms, int *error_code);

int socks5_udp_open(const proxy_entry_t *proxy,
                    const struct sockaddr_in *target,
                    int timeout_ms,
                    socks5_udp_tunnel_t *tunnel,
                    int *error_code);

void socks5_udp_close(socks5_udp_tunnel_t *tunnel);

int socks5_udp_send(socks5_udp_tunnel_t *tunnel,
                    const void *data, int len, int *error_code);

int socks5_udp_recv(socks5_udp_tunnel_t *tunnel,
                    void *buf, int buf_len, int timeout_ms, int *error_code);

#endif
