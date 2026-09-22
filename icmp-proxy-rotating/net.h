#ifndef NET_H
#define NET_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>

#include "proxy.h"

typedef enum {
    PROTO_TCP,
    PROTO_UDP
} proto_t;

typedef struct {
    uint64_t sent;
    uint64_t received;
    double   min_ms;
    double   max_ms;
    double   sum_ms;
} stats_t;

typedef struct {
    proto_t      proto;
    uint16_t     port;
    int          timeout_ms;
    proxy_list_t *proxies;
    int          max_proxy_attempts;
} probe_config_t;

typedef struct {
    int      ok;
    double   latency_ms;
    int      error_code;
    int      proxy_failed;
} probe_result_t;

typedef struct {
    proto_t proto;
    int     tcp_ok;
    int     udp_ok;
    int     udp_via_proxy;
    char    message[128];
} detect_result_t;

int  net_init(void);
void net_cleanup(void);

int  net_resolve(const char *host, uint16_t port, struct sockaddr_in *out);

probe_result_t net_probe_tcp(const struct sockaddr_in *addr, int timeout_ms);
probe_result_t net_probe_udp(const struct sockaddr_in *addr, int timeout_ms);

probe_result_t net_probe_tcp_via_proxy(const struct sockaddr_in *addr,
                                         const proxy_entry_t *proxy,
                                         int timeout_ms);
probe_result_t net_probe_udp_via_proxy(const struct sockaddr_in *addr,
                                         const proxy_entry_t *proxy,
                                         int timeout_ms);

probe_result_t net_probe_with_failover(const struct sockaddr_in *addr,
                                         proto_t proto,
                                         probe_config_t *cfg);

detect_result_t net_detect_proto(const struct sockaddr_in *addr,
                                  probe_config_t *cfg,
                                  int timeout_ms);

int  net_should_failover(const probe_result_t *result);

void stats_init(stats_t *s);
void stats_update(stats_t *s, const probe_result_t *r);

double timer_now_ms(void);

#endif
