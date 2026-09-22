#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <windows.h>

#include "net.h"
#include "proxy.h"
#include "ui.h"

#define DETECT_TIMEOUT_MS          800
#define PING_TIMEOUT_MS            200
#define PING_INTERVAL_MS           100
#define DETECT_MAX_PROXY_ATTEMPTS  10

int main(void)
{
    char host[256];
    char proxy_path[MAX_PATH];
    uint16_t port;
    struct sockaddr_in addr;
    detect_result_t detect;
    stats_t stats;
    probe_config_t cfg;
    proxy_list_t proxies;
    uint64_t seq = 0;
    int proxy_loaded = 0;

    ui_init();
    ui_print_banner();

    if (!ui_read_target(host, sizeof(host), &port)) {
        ui_print_error("Invalid IP or port.");
        ui_cleanup();
        return 1;
    }

    if (net_init() != 0) {
        ui_print_error("Failed to initialize Winsock.");
        ui_cleanup();
        return 1;
    }

    if (proxy_resolve_default_path(proxy_path, sizeof(proxy_path)) != 0 ||
        proxy_load(proxy_path, &proxies) != 0) {
        ui_print_error("Could not load verified_socks5.txt next to executable.");
        net_cleanup();
        ui_cleanup();
        return 1;
    }
    proxy_loaded = 1;

    if (net_resolve(host, port, &addr) != 0) {
        ui_print_error("Could not resolve target host.");
        proxy_free(&proxies);
        net_cleanup();
        ui_cleanup();
        return 1;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.proto               = PROTO_TCP;
    cfg.port                = port;
    cfg.timeout_ms          = PING_TIMEOUT_MS;
    cfg.proxies             = &proxies;
    cfg.max_proxy_attempts  = (int)proxies.count;

    ui_print_proxy_info(proxy_current(&proxies), proxies.count);

    ui_detect_begin();
    cfg.max_proxy_attempts = DETECT_MAX_PROXY_ATTEMPTS;
    detect = net_detect_proto(&addr, &cfg, DETECT_TIMEOUT_MS);
    cfg.max_proxy_attempts = (int)proxies.count;
    ui_detect_end(&detect);

    if (!detect.udp_via_proxy && detect.proto == PROTO_UDP)
        detect.proto = PROTO_TCP;

    cfg.proto = detect.proto;

    ui_install_ctrl_handler();
    stats_init(&stats);
    ui_print_probe_header();
    ui_print_probe_hint();

    while (ui_is_running()) {
        probe_result_t result;
        const proxy_entry_t *proxy_before;

        seq++;
        proxy_before = proxy_current(&proxies);
        result = net_probe_with_failover(&addr, detect.proto, &cfg);

        if (proxy_current(&proxies) != proxy_before)
            ui_print_proxy_switch(proxy_current(&proxies));

        stats_update(&stats, &result);
        ui_print_probe(seq, host, port, detect.proto, proxy_current(&proxies), &result);

        if (!ui_is_running())
            break;

        Sleep(PING_INTERVAL_MS);
    }

    ui_print_probe_footer();
    ui_print_summary(&stats, host, port, detect.proto);
    if (proxy_loaded)
        proxy_free(&proxies);
    net_cleanup();
    ui_cleanup();
    return 0;
}
