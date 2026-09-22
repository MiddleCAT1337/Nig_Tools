#define WIN32_LEAN_AND_MEAN
#include "net.h"

#include <stdio.h>
#include <string.h>

static LARGE_INTEGER g_freq;

int net_init(void)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return -1;
    if (!QueryPerformanceFrequency(&g_freq))
        return -1;
    return 0;
}

void net_cleanup(void)
{
    WSACleanup();
}

double timer_now_ms(void)
{
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1000.0 / (double)g_freq.QuadPart;
}

int net_resolve(const char *host, uint16_t port, struct sockaddr_in *out)
{
    struct addrinfo hints, *res = NULL;
    char port_str[8];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || res == NULL)
        return -1;

    memcpy(out, res->ai_addr, sizeof(struct sockaddr_in));
    freeaddrinfo(res);
    out->sin_port = htons(port);
    return 0;
}

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

probe_result_t net_probe_tcp(const struct sockaddr_in *addr, int timeout_ms)
{
    probe_result_t result = {0};
    SOCKET sock;
    u_long mode = 1;
    double start;
    int so_error = 0;
    int so_len = sizeof(so_error);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        result.error_code = (int)WSAGetLastError();
        return result;
    }

    start = timer_now_ms();
    ioctlsocket(sock, FIONBIO, &mode);

    if (connect(sock, (const struct sockaddr *)addr, sizeof(*addr)) == 0) {
        result.ok = 1;
        result.latency_ms = timer_now_ms() - start;
        closesocket(sock);
        return result;
    }

    if (WSAGetLastError() != WSAEWOULDBLOCK) {
        result.error_code = (int)WSAGetLastError();
        closesocket(sock);
        return result;
    }

    if (wait_socket(sock, timeout_ms, 1) <= 0) {
        result.error_code = WSAETIMEDOUT;
        closesocket(sock);
        return result;
    }

    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&so_error, &so_len) != 0) {
        result.error_code = (int)WSAGetLastError();
        closesocket(sock);
        return result;
    }

    if (so_error != 0) {
        result.error_code = so_error;
        closesocket(sock);
        return result;
    }

    result.ok = 1;
    result.latency_ms = timer_now_ms() - start;
    closesocket(sock);
    return result;
}

probe_result_t net_probe_udp(const struct sockaddr_in *addr, int timeout_ms)
{
    probe_result_t result = {0};
    SOCKET sock;
    u_long mode = 1;
    double start;
    char probe = 0;
    char buf[64];
    int ret;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        result.error_code = (int)WSAGetLastError();
        return result;
    }

    if (connect(sock, (const struct sockaddr *)addr, sizeof(*addr)) != 0) {
        result.error_code = (int)WSAGetLastError();
        closesocket(sock);
        return result;
    }

    start = timer_now_ms();
    ioctlsocket(sock, FIONBIO, &mode);

    if (send(sock, &probe, 1, 0) == SOCKET_ERROR) {
        int err = (int)WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            result.error_code = err;
            closesocket(sock);
            return result;
        }
    }

    ret = wait_socket(sock, timeout_ms, 0);
    if (ret > 0) {
        if (recv(sock, buf, sizeof(buf), 0) != SOCKET_ERROR) {
            result.ok = 1;
            result.latency_ms = timer_now_ms() - start;
            closesocket(sock);
            return result;
        }
    }

    {
        int so_error = 0;
        int so_len = sizeof(so_error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&so_error, &so_len) == 0) {
            if (so_error == WSAECONNREFUSED || so_error == WSAEHOSTUNREACH ||
                so_error == WSAENETUNREACH) {
                result.error_code = so_error;
                closesocket(sock);
                return result;
            }
        }
    }

    result.ok = 1;
    result.latency_ms = timer_now_ms() - start;
    closesocket(sock);
    return result;
}

probe_result_t net_probe_tcp_via_proxy(const struct sockaddr_in *addr,
                                         const proxy_entry_t *proxy,
                                         int timeout_ms)
{
    probe_result_t result = {0};
    (void)timeout_ms;
    SOCKET sock;
    double start;
    int err = 0;

    start = timer_now_ms();
    sock = (SOCKET)socks5_tcp_connect(proxy, addr, PROXY_CONNECT_TIMEOUT_MS, &err);
    if (sock == INVALID_SOCKET) {
        result.proxy_failed = 1;
        result.error_code = err ? err : WSAECONNREFUSED;
        return result;
    }

    result.ok = 1;
    result.latency_ms = timer_now_ms() - start;
    closesocket(sock);
    return result;
}

probe_result_t net_probe_udp_via_proxy(const struct sockaddr_in *addr,
                                         const proxy_entry_t *proxy,
                                         int timeout_ms)
{
    probe_result_t result = {0};
    socks5_udp_tunnel_t tunnel;
    double start;
    char probe = 0;
    char buf[64];
    int err = 0;
    int n;

    if (socks5_udp_open(proxy, addr, PROXY_CONNECT_TIMEOUT_MS, &tunnel, &err) != 0) {
        result.proxy_failed = 1;
        result.error_code = err ? err : WSAECONNREFUSED;
        return result;
    }

    start = timer_now_ms();

    if (socks5_udp_send(&tunnel, &probe, 1, &err) != 0) {
        result.proxy_failed = 1;
        result.error_code = err;
        socks5_udp_close(&tunnel);
        return result;
    }

    n = socks5_udp_recv(&tunnel, buf, sizeof(buf), timeout_ms, &err);
    if (n > 0) {
        result.ok = 1;
        result.latency_ms = timer_now_ms() - start;
        socks5_udp_close(&tunnel);
        return result;
    }

    if (err == WSAETIMEDOUT) {
        result.error_code = WSAETIMEDOUT;
        socks5_udp_close(&tunnel);
        return result;
    }

    result.ok = 1;
    result.latency_ms = timer_now_ms() - start;
    socks5_udp_close(&tunnel);
    return result;
}

int net_should_failover(const probe_result_t *result)
{
    if (result->proxy_failed)
        return 1;
    if (result->error_code == WSAETIMEDOUT)
        return 1;
    return 0;
}

probe_result_t net_probe_with_failover(const struct sockaddr_in *addr,
                                         proto_t proto,
                                         probe_config_t *cfg)
{
    probe_result_t result = {0};
    int attempts = 0;
    int max_attempts;

    if (!cfg->proxies || cfg->proxies->count == 0) {
        result.error_code = WSAEINVAL;
        return result;
    }

    max_attempts = cfg->max_proxy_attempts;
    if (max_attempts <= 0 || (size_t)max_attempts > cfg->proxies->count)
        max_attempts = (int)cfg->proxies->count;

    while (attempts < max_attempts) {
        const proxy_entry_t *proxy = proxy_current(cfg->proxies);

        if (proto == PROTO_UDP)
            result = net_probe_udp_via_proxy(addr, proxy, cfg->timeout_ms);
        else
            result = net_probe_tcp_via_proxy(addr, proxy, cfg->timeout_ms);

        if (result.ok)
            return result;

        if (!net_should_failover(&result))
            return result;

        proxy_advance(cfg->proxies);
        attempts++;
    }

    return result;
}

void stats_init(stats_t *s)
{
    memset(s, 0, sizeof(*s));
    s->min_ms = -1.0;
}

void stats_update(stats_t *s, const probe_result_t *r)
{
    s->sent++;
    if (!r->ok)
        return;

    s->received++;
    s->sum_ms += r->latency_ms;

    if (s->min_ms < 0.0 || r->latency_ms < s->min_ms)
        s->min_ms = r->latency_ms;
    if (r->latency_ms > s->max_ms)
        s->max_ms = r->latency_ms;
}

static int port_in_list(uint16_t port, const uint16_t *list)
{
    int i;
    for (i = 0; list[i] != 0; i++) {
        if (list[i] == port)
            return 1;
    }
    return 0;
}

static proto_t heuristic_proto(uint16_t port)
{
    static const uint16_t udp_ports[] = {53, 67, 68, 123, 161, 500, 514, 1194, 4500, 0};
    static const uint16_t tcp_ports[] = {21, 22, 23, 25, 80, 443, 3306, 3389, 8080, 0};

    if (port_in_list(port, udp_ports))
        return PROTO_UDP;
    if (port_in_list(port, tcp_ports))
        return PROTO_TCP;
    return PROTO_TCP;
}

detect_result_t net_detect_proto(const struct sockaddr_in *addr,
                                  probe_config_t *cfg,
                                  int timeout_ms)
{
    detect_result_t dr;
    probe_result_t tcp_res;
    probe_result_t udp_res;
    uint16_t port = ntohs(addr->sin_port);
    int saved_timeout;

    memset(&dr, 0, sizeof(dr));

    if (cfg && cfg->proxies && cfg->proxies->count > 0) {
        saved_timeout = cfg->timeout_ms;
        cfg->timeout_ms = timeout_ms;

        tcp_res = net_probe_with_failover(addr, PROTO_TCP, cfg);
        udp_res = net_probe_with_failover(addr, PROTO_UDP, cfg);

        cfg->timeout_ms = saved_timeout;
        dr.udp_via_proxy = !udp_res.proxy_failed;
    } else {
        tcp_res = net_probe_tcp(addr, timeout_ms);
        udp_res = net_probe_udp(addr, timeout_ms);
        dr.udp_via_proxy = 1;
    }

    dr.tcp_ok = tcp_res.ok;
    dr.udp_ok = udp_res.ok;

    if (tcp_res.ok && !udp_res.ok) {
        dr.proto = PROTO_TCP;
        snprintf(dr.message, sizeof(dr.message), "Detected: TCP (port open)");
    } else if (udp_res.ok && !tcp_res.ok) {
        dr.proto = PROTO_UDP;
        snprintf(dr.message, sizeof(dr.message), "Detected: UDP (TCP closed)");
    } else if (tcp_res.ok && udp_res.ok) {
        dr.proto = PROTO_TCP;
        snprintf(dr.message, sizeof(dr.message), "Detected: TCP (both responded)");
    } else if (!dr.udp_via_proxy) {
        dr.proto = PROTO_TCP;
        snprintf(dr.message, sizeof(dr.message),
                 "UDP unavailable via proxy, using TCP");
    } else {
        dr.proto = heuristic_proto(port);
        if (dr.proto == PROTO_UDP)
            snprintf(dr.message, sizeof(dr.message),
                     "Detection inconclusive, using UDP (port hint)");
        else
            snprintf(dr.message, sizeof(dr.message),
                     "Detection inconclusive, using TCP");
    }
    return dr;
}
