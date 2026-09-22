#ifndef UI_H
#define UI_H

#include <stddef.h>
#include "net.h"
#include "proxy.h"

void ui_init(void);
void ui_cleanup(void);

int  ui_is_running(void);
void ui_request_stop(void);
void ui_install_ctrl_handler(void);

void ui_print_banner(void);
int  ui_read_target(char *host, size_t host_size, uint16_t *port);
void ui_print_target_box(const char *host, uint16_t port);

void ui_print_proxy_info(const proxy_entry_t *proxy, size_t total);
void ui_print_proxy_switch(const proxy_entry_t *proxy);

void ui_detect_begin(void);
void ui_detect_end(const detect_result_t *detect);

void ui_print_probe_header(void);
void ui_print_probe_hint(void);
void ui_print_probe_footer(void);
void ui_print_probe(uint64_t seq, const char *host, uint16_t port,
                    proto_t proto, const proxy_entry_t *proxy,
                    const probe_result_t *result);
void ui_print_summary(const stats_t *stats, const char *host, uint16_t port, proto_t proto);
void ui_print_error(const char *msg);

#endif
