#define WIN32_LEAN_AND_MEAN
#include "ui.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define ANSI_RESET       "\033[0m"
#define ANSI_PURPLE      "\033[38;5;141m"
#define ANSI_PURPLE_LITE "\033[38;5;183m"
#define ANSI_PURPLE_DIM  "\033[38;5;97m"
#define ANSI_WHITE       "\033[97m"
#define ANSI_DIM         "\033[38;5;245m"
#define ANSI_RED         "\033[38;5;203m"
#define ANSI_GREEN       "\033[38;5;120m"
#define ANSI_CYAN        "\033[38;5;117m"
#define ANSI_YELLOW      "\033[38;5;221m"

#define BOX_INNER_W      50
#define DISCORD_URL      "https://discord.gg/dtWQTZwJQe"

static int g_running = 1;
static int g_use_ansi = 0;
static HANDLE g_console = INVALID_HANDLE_VALUE;

static volatile LONG g_spin_active = 0;
static HANDLE g_spin_thread = NULL;

static BOOL WINAPI ctrl_handler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) {
        g_running = 0;
        return TRUE;
    }
    return FALSE;
}

static void enable_vt(void)
{
    DWORD mode = 0;
    HANDLE h_in;

    g_console = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_console == INVALID_HANDLE_VALUE)
        return;

    if (GetConsoleMode(g_console, &mode)) {
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        if (SetConsoleMode(g_console, mode))
            g_use_ansi = 1;
    }

    h_in = GetStdHandle(STD_INPUT_HANDLE);
    if (h_in != INVALID_HANDLE_VALUE && GetConsoleMode(h_in, &mode)) {
        mode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
        SetConsoleMode(h_in, mode);
    }

    SetConsoleTextAttribute(g_console, FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
}

static void ui_box_top(int w)
{
    int i;

    printf(ANSI_PURPLE_DIM "╔" ANSI_RESET);
    for (i = 0; i < w; i++)
        printf(ANSI_PURPLE_DIM "═" ANSI_RESET);
    printf(ANSI_PURPLE_DIM "╗\n" ANSI_RESET);
}

static void ui_box_top_titled(int w, const char *title)
{
    int title_len = (int)strlen(title);
    int left_fill, right_fill, total_fill;
    int i;

    printf(ANSI_PURPLE_DIM "╔" ANSI_RESET);
    total_fill = w - title_len - 2;
    if (total_fill < 4)
        total_fill = 4;
    left_fill = total_fill / 2;
    right_fill = total_fill - left_fill;

    for (i = 0; i < left_fill; i++)
        printf(ANSI_PURPLE_DIM "═" ANSI_RESET);
    printf(ANSI_PURPLE_LITE " %s " ANSI_RESET, title);
    for (i = 0; i < right_fill; i++)
        printf(ANSI_PURPLE_DIM "═" ANSI_RESET);
    printf(ANSI_PURPLE_DIM "╗\n" ANSI_RESET);
}

static void ui_box_bot(int w)
{
    int i;

    printf(ANSI_PURPLE_DIM "╚" ANSI_RESET);
    for (i = 0; i < w; i++)
        printf(ANSI_PURPLE_DIM "═" ANSI_RESET);
    printf(ANSI_PURPLE_DIM "╝\n" ANSI_RESET);
}

static int utf8_display_len(const char *s)
{
    int n = 0;

    while (*s) {
        if (((unsigned char)*s & 0xC0) != 0x80)
            n++;
        s++;
    }
    return n;
}

static void ui_box_mid_plain(int w, const char *content)
{
    int len = utf8_display_len(content);
    int pad_right;
    int i;

    if (len > w)
        len = w;

    printf(ANSI_PURPLE_DIM "║" ANSI_RESET);
    fwrite(content, 1, strlen(content), stdout);
    pad_right = w - len;
    for (i = 0; i < pad_right; i++)
        printf(" ");
    printf(ANSI_PURPLE_DIM "║" ANSI_RESET "\n");
}

static void ui_box_mid_colored(int w, const char *content, const char *color)
{
    int len = utf8_display_len(content);
    int pad_right;
    int i;

    if (len > w)
        len = w;

    printf(ANSI_PURPLE_DIM "║" ANSI_RESET);
    printf("%s%s%s", color, content, ANSI_RESET);
    pad_right = w - len;
    for (i = 0; i < pad_right; i++)
        printf(" ");
    printf(ANSI_PURPLE_DIM "║" ANSI_RESET "\n");
}

static DWORD WINAPI spin_proc(LPVOID unused)
{
    const char *frames = "|/-\\";
    int frame = 0;
    int first = 1;
    char line[128];

    (void)unused;

    while (InterlockedCompareExchange(&g_spin_active, 0, 0) != 0) {
        snprintf(line, sizeof(line), "  %c Analyzing TCP/UDP on target...",
                 frames[frame % 4]);
        if (!first)
            printf("\033[1A\033[2K");
        ui_box_mid_plain(BOX_INNER_W, line);
        fflush(stdout);
        first = 0;
        frame++;
        Sleep(80);
    }
    return 0;
}

void ui_init(void)
{
    COORD buf;

    setvbuf(stdout, NULL, _IONBF, 0);
    SetConsoleTitleA("Destroy PINGER");
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    system("color 07");
    enable_vt();

    buf.X = 120;
    buf.Y = 40;
    SetConsoleScreenBufferSize(g_console, buf);
}

void ui_cleanup(void)
{
    if (g_console != INVALID_HANDLE_VALUE)
        SetConsoleTextAttribute(g_console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf(ANSI_RESET "\n");
}

void ui_install_ctrl_handler(void)
{
    SetConsoleCtrlHandler(ctrl_handler, TRUE);
}

int ui_is_running(void)
{
    return g_running;
}

void ui_request_stop(void)
{
    g_running = 0;
}

static void print_discord_line(void)
{
    printf("\n");
    printf(ANSI_DIM "        " ANSI_RESET);
    printf(ANSI_PURPLE_LITE "◈" ANSI_RESET);
    printf(ANSI_DIM "  Discord: " ANSI_RESET);
    printf(ANSI_CYAN "%s" ANSI_RESET, DISCORD_URL);
    printf(ANSI_DIM "  " ANSI_RESET);
    printf(ANSI_PURPLE_LITE "◈" ANSI_RESET);
    printf("\n\n");
}

void ui_print_banner(void)
{
    static const char *pinger[] = {
        "██████╗ ██╗███╗   ██╗ ██████╗ ███████╗██████╗",
        "██╔══██╗██║████╗  ██║██╔════╝ ██╔════╝██╔══██╗",
        "██████╔╝██║██╔██╗ ██║██║  ███╗█████╗  ██████╔╝",
        "██╔═══╝ ██║██║╚██╗██║██║   ██║██╔══╝  ██╔══██╗",
        "██║     ██║██║ ╚████║╚██████╔╝███████╗██║  ██║",
        "╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝"
    };
    int i;

    printf("\n");
    ui_box_top(BOX_INNER_W);
    ui_box_mid_plain(BOX_INNER_W, "");
    for (i = 0; i < 6; i++)
        ui_box_mid_colored(BOX_INNER_W, pinger[i], ANSI_PURPLE_LITE);
    ui_box_mid_plain(BOX_INNER_W, "");
    ui_box_bot(BOX_INNER_W);
    print_discord_line();
}

static int parse_port_input(const char *s, uint16_t *out)
{
    long val;
    char *end;

    val = strtol(s, &end, 10);
    if (*end != '\0' || val < 1 || val > 65535)
        return 0;
    *out = (uint16_t)val;
    return 1;
}

int ui_read_target(char *host, size_t host_size, uint16_t *port)
{
    char port_buf[32];

    printf(ANSI_PURPLE "  ▸ IP    : " ANSI_RESET);
    fflush(stdout);

    if (!fgets(host, (int)host_size, stdin))
        return 0;
    host[strcspn(host, "\r\n")] = '\0';
    if (host[0] == '\0')
        return 0;

    printf(ANSI_PURPLE "  ▸ PORT  : " ANSI_RESET);
    fflush(stdout);

    if (!fgets(port_buf, sizeof(port_buf), stdin))
        return 0;
    port_buf[strcspn(port_buf, "\r\n")] = '\0';
    if (!parse_port_input(port_buf, port))
        return 0;

    ui_print_target_box(host, *port);
    return 1;
}

void ui_print_target_box(const char *host, uint16_t port)
{
    char line[128];

    ui_box_top_titled(BOX_INNER_W, "TARGET CONFIG");
    snprintf(line, sizeof(line), "  ▸ IP    : %s", host);
    ui_box_mid_plain(BOX_INNER_W, line);
    snprintf(line, sizeof(line), "  ▸ PORT  : %u", (unsigned)port);
    ui_box_mid_plain(BOX_INNER_W, line);
    ui_box_bot(BOX_INNER_W);
    printf("\n");
}

void ui_print_proxy_info(const proxy_entry_t *proxy, size_t total)
{
    char line[128];

    if (!proxy)
        return;

    ui_box_top_titled(BOX_INNER_W, "PROXY CONFIG");
    snprintf(line, sizeof(line), "  ▸ SOCKS5 : %s:%u", proxy->host, (unsigned)proxy->port);
    ui_box_mid_plain(BOX_INNER_W, line);
    snprintf(line, sizeof(line), "  ▸ Loaded : %zu proxies (failover enabled)", total);
    ui_box_mid_plain(BOX_INNER_W, line);
    ui_box_bot(BOX_INNER_W);
    printf("\n");
}

void ui_print_proxy_switch(const proxy_entry_t *proxy)
{
    char line[128];

    if (!proxy)
        return;

    snprintf(line, sizeof(line), "  ▸ Switched proxy → %s:%u",
             proxy->host, (unsigned)proxy->port);
    printf(ANSI_YELLOW "%s\n" ANSI_RESET, line);
}

void ui_detect_begin(void)
{
    InterlockedExchange(&g_spin_active, 1);
    ui_box_top_titled(BOX_INNER_W, "PROTOCOL SCAN");
    g_spin_thread = CreateThread(NULL, 0, spin_proc, NULL, 0, NULL);
}

void ui_detect_end(const detect_result_t *detect)
{
    char line[128];
    const char *proto_str = (detect->proto == PROTO_UDP) ? "UDP" : "TCP";

    InterlockedExchange(&g_spin_active, 0);
    if (g_spin_thread) {
        WaitForSingleObject(g_spin_thread, INFINITE);
        CloseHandle(g_spin_thread);
        g_spin_thread = NULL;
        printf("\033[1A\033[2K");
    }

    snprintf(line, sizeof(line), "  %s — %.32s", proto_str, detect->message);
    ui_box_mid_colored(BOX_INNER_W, line, ANSI_WHITE);
    ui_box_bot(BOX_INNER_W);
    printf("\n");
}

void ui_print_probe_header(void)
{
    printf(ANSI_PURPLE_DIM);
    printf("  ┌──────┬─────────────────────┬──────┬───────────┬────────┬──────────────────┐\n");
    printf("  │" ANSI_WHITE "  #   " ANSI_PURPLE_DIM "│" ANSI_WHITE "  TARGET             " ANSI_PURPLE_DIM "│" ANSI_WHITE " PROTO" ANSI_PURPLE_DIM "│" ANSI_WHITE "  LATENCY  " ANSI_PURPLE_DIM "│" ANSI_WHITE " STATUS " ANSI_PURPLE_DIM "│" ANSI_WHITE "  PROXY            " ANSI_PURPLE_DIM "│\n");
    printf("  ├──────┼─────────────────────┼──────┼───────────┼────────┼──────────────────┤\n");
    printf(ANSI_RESET);
}

void ui_print_probe_hint(void)
{
    printf(ANSI_DIM "  ▸ Press Ctrl+C to stop\n\n" ANSI_RESET);
}

void ui_print_probe_footer(void)
{
    printf(ANSI_PURPLE_DIM);
    printf("  └──────┴─────────────────────┴──────┴───────────┴────────┴──────────────────┘\n");
    printf(ANSI_RESET);
}

void ui_print_probe(uint64_t seq, const char *host, uint16_t port,
                    proto_t proto, const proxy_entry_t *proxy,
                    const probe_result_t *result)
{
    char target[32];
    char proxy_str[32];
    const char *proto_str = (proto == PROTO_UDP) ? "UDP" : "TCP";
    const char *status_color;
    char status[16];
    char latency[16];

    snprintf(target, sizeof(target), "%s:%u", host, (unsigned)port);
    if ((int)strlen(target) > 21)
        target[21] = '\0';

    if (proxy) {
        char host_short[16];
        strncpy(host_short, proxy->host, sizeof(host_short) - 1);
        host_short[sizeof(host_short) - 1] = '\0';
        snprintf(proxy_str, sizeof(proxy_str), "%s:%u",
                 host_short, (unsigned)proxy->port);
    } else {
        strncpy(proxy_str, "---", sizeof(proxy_str) - 1);
        proxy_str[sizeof(proxy_str) - 1] = '\0';
    }
    if ((int)strlen(proxy_str) > 18)
        proxy_str[18] = '\0';

    if (result->ok) {
        snprintf(latency, sizeof(latency), "%.2fms", result->latency_ms);
        strncpy(status, "OK", sizeof(status) - 1);
        status[sizeof(status) - 1] = '\0';
        status_color = ANSI_GREEN;
    } else if (result->error_code == WSAETIMEDOUT || result->error_code == 0) {
        strncpy(latency, "---", sizeof(latency) - 1);
        latency[sizeof(latency) - 1] = '\0';
        strncpy(status, "TIMEOUT", sizeof(status) - 1);
        status[sizeof(status) - 1] = '\0';
        status_color = ANSI_RED;
    } else {
        snprintf(latency, sizeof(latency), "---");
        snprintf(status, sizeof(status), "ERR %d", result->error_code);
        status_color = ANSI_RED;
    }

    printf(ANSI_PURPLE_DIM "  │" ANSI_RESET);
    printf(ANSI_PURPLE "%6llu" ANSI_PURPLE_DIM "│" ANSI_RESET,
           (unsigned long long)seq);
    printf(ANSI_WHITE "%-21s" ANSI_PURPLE_DIM "│" ANSI_RESET, target);
    printf(ANSI_YELLOW "%-6s" ANSI_PURPLE_DIM "│" ANSI_RESET, proto_str);
    printf(ANSI_CYAN "%11s" ANSI_PURPLE_DIM "│" ANSI_RESET, latency);
    printf("%s%-8s" ANSI_PURPLE_DIM "│" ANSI_RESET, status_color, status);
    printf(ANSI_DIM "%-18s" ANSI_PURPLE_DIM "│\n" ANSI_RESET, proxy_str);
}

void ui_print_summary(const stats_t *stats, const char *host, uint16_t port, proto_t proto)
{
    const char *proto_str = (proto == PROTO_UDP) ? "UDP" : "TCP";
    double loss = 0.0;
    double avg = 0.0;
    char line[128];

    if (stats->sent > 0)
        loss = 100.0 * (double)(stats->sent - stats->received) / (double)stats->sent;
    if (stats->received > 0)
        avg = stats->sum_ms / (double)stats->received;

    printf("\n");
    ui_box_top_titled(BOX_INNER_W, "SESSION SUMMARY");
    snprintf(line, sizeof(line), "  Target   %s:%u  [%s]", host, (unsigned)port, proto_str);
    ui_box_mid_plain(BOX_INNER_W, line);
    snprintf(line, sizeof(line), "  Sent %5llu   Received %5llu   Loss %5.1f%%",
             (unsigned long long)stats->sent,
             (unsigned long long)stats->received,
             loss);
    ui_box_mid_plain(BOX_INNER_W, line);
    if (stats->received > 0) {
        snprintf(line, sizeof(line), "  Latency  min %6.2fms  avg %6.2fms  max %6.2fms",
                 stats->min_ms, avg, stats->max_ms);
        ui_box_mid_plain(BOX_INNER_W, line);
    } else {
        ui_box_mid_colored(BOX_INNER_W, "  Latency  (no successful probes)", ANSI_DIM);
    }
    ui_box_bot(BOX_INNER_W);
    printf("\n");
}

void ui_print_error(const char *msg)
{
    char line[128];

    snprintf(line, sizeof(line), "  Error: %s", msg);
    ui_box_top_titled(BOX_INNER_W, "ERROR");
    ui_box_mid_colored(BOX_INNER_W, line, ANSI_RED);
    ui_box_bot(BOX_INNER_W);
    printf("\n");
}
