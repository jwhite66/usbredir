/* usbredirtestserver.c simple usb network redirection test client (guest).

   Copyright (C) 2015 Jeremy White, based on the usbredirserver, which is
   Copyright 2010-2011 Red Hat, Inc.

   Red Hat Authors:
   Hans de Goede <hdegoede@redhat.com>

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/wait.h>

#include "usbredirparser.h"

/* Macros to go from an endpoint address to an index for our ep array */
#define EP2I(ep_address) (((ep_address & 0x80) >> 3) | (ep_address & 0x0f))
#define I2EP(i) (((i & 0x10) << 3) | (i & 0x0f))

#define TESTSERVER_VERSION "usbredirtestserver " PACKAGE_VERSION

static void usbredirtestserver_hello(void *priv, struct usb_redir_hello_header *h);
static void usbredirtestserver_reset(void *priv);
static void usbredirtestserver_get_configuration(void *priv, uint64_t id);
static void usbredirtestserver_set_configuration(void *priv, uint64_t id,
    struct usb_redir_set_configuration_header *set_configuration);
static void usbredirtestserver_set_alt_setting(void *priv, uint64_t id,
    struct usb_redir_set_alt_setting_header *set_alt_setting);
static void usbredirtestserver_get_alt_setting(void *priv, uint64_t id,
    struct usb_redir_get_alt_setting_header *get_alt_setting);
static void usbredirtestserver_control_packet(void *priv, uint64_t id,
    struct usb_redir_control_packet_header *control_packet,
    uint8_t *data, int data_len);
static void usbredirtestserver_bulk_packet(void *priv, uint64_t id,
    struct usb_redir_bulk_packet_header *bulk_packet,
    uint8_t *data, int data_len);
static void usbredirtestserver_iso_packet(void *priv, uint64_t id,
    struct usb_redir_iso_packet_header *iso_packet,
    uint8_t *data, int data_len);
static void usbredirtestserver_interrupt_packet(void *priv, uint64_t id,
    struct usb_redir_interrupt_packet_header *interrupt_packet,
    uint8_t *data, int data_len);

static int verbose = usbredirparser_info; /* 2 */
static int running = 1;

typedef struct {
    struct usb_redir_control_packet_header ctrl;
    unsigned char *data;
    int data_len;
} expect_ctrl_t;

#define MAX_LABELS  10
#define BUFFER_SIZE 65536
typedef struct {
    char buffer[BUFFER_SIZE];
    int fd;
    int read_into;
    int read_from;
    int prompted;

    char *labels[MAX_LABELS];
    int label_positions[MAX_LABELS];
} command_buffer_t;

static command_buffer_t *new_command_buffer(char *fname);
static int command_buffer_read(command_buffer_t *cmd);
static char * command_buffer_get(command_buffer_t *cmd);
static void free_command_buffer(command_buffer_t *cmd);

typedef struct {
    int id;
    int fd;
    command_buffer_t *cmd;
    struct usbredirparser *parser;
    struct usb_redir_interface_info_header interface_info;
    struct usb_redir_ep_info_header ep_info;
    struct usb_redir_device_connect_header device_connect;
    expect_ctrl_t *expect_ctrl;
} private_info_t;

static const struct option longopts[] = {
    { "port", required_argument, NULL, 'p' },
    { "verbose", required_argument, NULL, 'v' },
    { "script", required_argument, NULL, 's' },
    { "help", no_argument, NULL, 'h' },
    { NULL, 0, NULL, 0 }
};

static void usbredirtestserver_log(void *priv, int level, const char *msg)
{
    if (level <= verbose)
        fprintf(stderr, "%s\n", msg);
}

static int usbredirtestserver_read(void *priv, uint8_t *data, int count)
{
    private_info_t *info = (private_info_t *) priv;

    int r = read(info->fd, data, count);
    if (r < 0) {
        if (errno == EAGAIN)
            return 0;
        return -1;
    }
    if (r == 0) { /* Server disconnected */
        fprintf(stderr, "read(%d) returns 0; closing.\n", info->fd);
        close(info->fd);
        info->fd = -1;
    }
    return r;
}

static int usbredirtestserver_write(void *priv, uint8_t *data, int count)
{
    private_info_t *info = (private_info_t *) priv;

    int r = write(info->fd, data, count);
    if (r < 0) {
        if (errno == EAGAIN)
            return 0;
        if (errno == EPIPE) { /* Server disconnected */
            fprintf(stderr, "write(%d) returns EPIPE; closing.\n", info->fd);
            close(info->fd);
            info->fd = -1;
            return 0;
        }
        return -1;
    }
    return r;
}

static void usage(int exit_code, char *argv0)
{
    fprintf(exit_code? stderr:stdout,
        "Usage: %s [-p|--port <port>] [-v|--verbose <0-3>] [-s|--script <script-file>] <server>\n",
        argv0);
    exit(exit_code);
}

static void usbredirtestserver_cmdline_parse(private_info_t *info, char *buf);


static void run_main_loop(private_info_t *info)
{
    fd_set readfds, writefds;
    int n, nfds;
    struct timeval tv;

    printf("device %d connected, fd %d\n", info->id, info->fd);
    printf("running %d\n", running);

    while (running && info->fd != -1) {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);

        if (info->cmd->fd != -1)
            FD_SET(info->cmd->fd, &readfds);

        FD_SET(info->fd, &readfds);
        if (usbredirparser_has_data_to_write(info->parser)) {
            FD_SET(info->fd, &writefds);
        }
        nfds = info->fd + 1;
        if (info->cmd->fd > info->fd)
            nfds = info->cmd->fd + 1;

        tv.tv_sec = 0;
        tv.tv_usec = 1000;
        n = select(nfds, &readfds, &writefds, NULL, &tv);
        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("select");
            break;
        }

        if ( (info->cmd->fd != -1 && FD_ISSET(info->cmd->fd, &readfds))) {
            if (command_buffer_read(info->cmd) < 0)
                break;
        }

        while (! info->expect_ctrl) {
            char *command = command_buffer_get(info->cmd);
            if (! command)
                break;
            usbredirtestserver_cmdline_parse(info, command);
            free(command);
        }

        if (FD_ISSET(info->fd, &readfds)) {
            if (usbredirparser_do_read(info->parser)) {
                break;
            }
        }
        if (FD_ISSET(info->fd, &writefds)) {
            if (usbredirparser_do_write(info->parser)) {
                break;
            }
        }

    }
    if (info->fd != -1) {
        close(info->fd);
        info->fd = -1;
    }
    printf("device %d closed\n", info->id);
}

void run_one_device(int fd, char *script_file, int id)
{
    private_info_t private_info;
    struct usbredirparser *parser;
    int parser_flags = usbredirparser_fl_usb_host;
    uint32_t caps[USB_REDIR_CAPS_SIZE] = { 0, };
    int flags;

    memset(&private_info, 0, sizeof(private_info));

    private_info.cmd = new_command_buffer(script_file);
    if (! private_info.cmd)
        exit(-1);

    flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        perror("fcntl F_GETFL");
        exit(-1);
    }
    flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (flags == -1) {
        perror("fcntl F_SETFL O_NONBLOCK");
        exit(-1);
    }

    parser = usbredirparser_create();
    if (!parser) {
        exit(-1);
    }

    private_info.fd = fd;
    private_info.parser = parser;
    private_info.id = id++;

    parser->priv = &private_info;

    parser->log_func = usbredirtestserver_log;
    parser->read_func = usbredirtestserver_read;
    parser->write_func = usbredirtestserver_write;
    parser->hello_func = usbredirtestserver_hello;
    parser->reset_func = usbredirtestserver_reset;
    parser->control_packet_func = usbredirtestserver_control_packet;
    parser->bulk_packet_func = usbredirtestserver_bulk_packet;
    parser->iso_packet_func = usbredirtestserver_iso_packet;
    parser->interrupt_packet_func = usbredirtestserver_interrupt_packet;
    parser->get_configuration_func = usbredirtestserver_get_configuration;
    parser->set_configuration_func = usbredirtestserver_set_configuration;
    parser->set_alt_setting_func = usbredirtestserver_set_alt_setting;
    parser->get_alt_setting_func = usbredirtestserver_get_alt_setting;

/*
    TODO: These functions are what the host program also supports
    parser->start_iso_stream_func = usbredirtestserver_start_iso_stream;
    parser->stop_iso_stream_func = usbredirtestserver_stop_iso_stream;
    parser->start_interrupt_receiving_func =
        usbredirtestserver_start_interrupt_receiving;
    parser->stop_interrupt_receiving_func =
        usbredirtestserver_stop_interrupt_receiving;
    parser->alloc_bulk_streams_func = usbredirtestserver_alloc_bulk_streams;
    parser->free_bulk_streams_func = usbredirtestserver_free_bulk_streams;
    parser->cancel_data_packet_func = usbredirtestserver_cancel_data_packet;
    parser->filter_reject_func = usbredirtestserver_filter_reject;
    parser->filter_filter_func = usbredirtestserver_filter_filter;
    parser->device_disconnect_ack_func =
        usbredirtestserver_device_disconnect_ack;
    parser->start_bulk_receiving_func =
        usbredirtestserver_start_bulk_receiving;
    parser->stop_bulk_receiving_func =
        usbredirtestserver_stop_bulk_receiving;
*/

    /* TODO - usbredirserver can do this; not sure if we want to..
    if (flags & usbredirhost_fl_write_cb_owns_buffer) {
        parser_flags |= usbredirparser_fl_write_cb_owns_buffer;
    } */

    usbredirparser_caps_set_cap(caps, usb_redir_cap_connect_device_version);
    usbredirparser_caps_set_cap(caps, usb_redir_cap_filter);
    usbredirparser_caps_set_cap(caps, usb_redir_cap_device_disconnect_ack);
    usbredirparser_caps_set_cap(caps, usb_redir_cap_ep_info_max_packet_size);
    usbredirparser_caps_set_cap(caps, usb_redir_cap_64bits_ids);
    usbredirparser_caps_set_cap(caps, usb_redir_cap_32bits_bulk_length);
    usbredirparser_caps_set_cap(caps, usb_redir_cap_bulk_receiving);
    usbredirparser_caps_set_cap(caps, usb_redir_cap_bulk_streams);

    usbredirparser_init(parser, TESTSERVER_VERSION, caps, USB_REDIR_CAPS_SIZE,
                    parser_flags);

    run_main_loop(&private_info);

    usbredirparser_destroy(parser);

    exit(!running);
}


int main(int argc, char *argv[])
{
    int o;
    char *endptr;
    int port = 4000;
    int server_fd, client_fd;
    int on = 1;
    struct sockaddr_in serveraddr;
    int id = 0;
    char *script_file = NULL;

    while ((o = getopt_long(argc, argv, "hp:s:v:", longopts, NULL)) != -1) {
        switch (o) {
        case 'p':
            port = strtol(optarg, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "Inalid value for --port: '%s'\n", optarg);
                usage(1, argv[0]);
            }
            break;
        case 'v':
            verbose = strtol(optarg, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "Inalid value for --verbose: '%s'\n", optarg);
                usage(1, argv[0]);
            }
            break;
        case 's':
            script_file = strdup(optarg);
            if (access(script_file, R_OK)) {
                fprintf(stderr, "Cannot read %s\n", script_file);
                usage(1, argv[0]);
            }
            break;
        case '?':
        case 'h':
            usage(o == '?', argv[0]);
            break;
        }
    }

    if (optind != argc) {
        fprintf(stderr, "Excess non option arguments\n");
        usage(1, argv[0]);
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Error creating socket");
        exit(1);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
        perror("Error setsockopt(SO_REUSEADDR) failed");
        exit(1);
    }

    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port   = htons(port);
    serveraddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) {
        fprintf(stderr, "Error binding port %d: %s\n", port, strerror(errno));
        exit(1);
    }

    if (listen(server_fd, 1)) {
        perror("Error listening");
        exit(1);
    }

    while (running) {
        int status;
        fd_set readfds;
        int nfds;
        struct timeval tv;

        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);

        nfds = server_fd + 1;

        tv.tv_sec = 0;
        tv.tv_usec = 1000;
        if (select(nfds, &readfds, NULL, NULL, &tv) < 0) {
            perror("select");
            break;
        }

        if (FD_ISSET(server_fd, &readfds)) {
            client_fd = accept(server_fd, NULL, 0);
            if (client_fd == -1) {
                if (errno == EINTR) {
                    continue;
                }
                perror("accept");
                break;
            }

            id++;
            if (fork() == 0)
                run_one_device(client_fd, script_file, id);
            else
                close(client_fd);
        }

    }


    exit(0);
}

static void usbredirtestserver_cmdline_help(void)
{
    printf("Avaiable commands:\n"
        "interface n <val>:<class>:<subclass>:<protocol>\n"
        "endpoint n <type>:<interval>:<interface>:<max_packet_size>:<max_streams>\n"
        "device <speed>:<class>:<subclass>:<protocol>:<vendor>:<product>:<bcd>\n"
        "ctrl <endpoint>:<request>:<request_type>:<value>:<index>:<length> [data]\n"
        "expect ctrl ...\n"
        "kill\n"
        "quit\n"
        "help\n");
}

static int parse_ctrl(char *buf, struct usb_redir_control_packet_header *ctrl,
                        unsigned char **data, int *data_len)
{
    int pos1 = 0;
    int pos2 = 0;
    int i;

    memset(ctrl, 0, sizeof(*ctrl));
    *data_len = 0;
    *data = NULL;

    if (7 != sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hx:%hx:%hx %n",
                &ctrl->endpoint,
                &ctrl->request,
                &ctrl->requesttype,
                &ctrl->status,
                &ctrl->value,
                &ctrl->index,
                &ctrl->length,
                &pos1)) {
        fprintf(stderr, "Error scanning '%s'\n", buf);
        return -1;
    }

    *data = malloc(strlen(buf + pos1) + 1);
    if (!*data) {
        fprintf(stderr, "Out of memory allocating %d!\n", strlen(buf + pos1) + 1);
        return -2;
    }
    memset(*data, 0, strlen(buf + pos1) + 1);

    for (i = 0; i < ctrl->length; i++) {
        if (sscanf(buf + pos1, "%hhx %n", (*data) + i, &pos2) != 1) {
            break;
        }
        pos1 += pos2;
    }
    *data_len = i;
    if (i == 0) {
        free(*data);
        *data = NULL;
    }

    return 0;
}

static void usbredirtestserver_cmdline_ctrl(private_info_t *info, char *buf)
{
    unsigned char *data;
    int data_len;

    struct usb_redir_control_packet_header control_packet;

    if (parse_ctrl(buf, &control_packet, &data, &data_len)) {
        fprintf(stderr, "Unable to parse ctrl; closing.\n");
        close(info->fd);
        info->fd = -1;
        return;
    }

    usbredirparser_send_control_packet(info->parser, info->id, &control_packet,
                                       data, data_len);
    if (data)
        free(data);
    printf("Sent control packet with id: %u\n", info->id);
    info->id++;
}

static void expect_ctrl(private_info_t *info, char *buf)
{
    if (info->expect_ctrl) {
        fprintf(stderr, "Warning: discarding previous expect_ctrl\n");
        if (info->expect_ctrl->data)
            free(info->expect_ctrl->data);
        free(info->expect_ctrl);
    }

    info->expect_ctrl = malloc(sizeof(*info->expect_ctrl));
    if (parse_ctrl(buf, &info->expect_ctrl->ctrl,
            &info->expect_ctrl->data, &info->expect_ctrl->data_len) < 0) {
        free(info->expect_ctrl);
        info->expect_ctrl = NULL;
    }
}

static void usbredirtestserver_cmdline_expect(private_info_t *info, char *buf)
{
    if (strlen(buf) >= 5 && memcmp(buf, "ctrl ", 5) == 0)
        expect_ctrl(info, buf + 5);

    else
        fprintf(stderr, "Error: we can only expect ctrl at the moment.\n");
}

static void usbredirtestserver_cmdline_device(private_info_t *info, char *buf)
{
    int i;

    memset(&info->device_connect, 0, sizeof(info->device_connect));
    if (7 != sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hx:%hx:%hx",
        &info->device_connect.speed,
        &info->device_connect.device_class,
        &info->device_connect.device_subclass,
        &info->device_connect.device_protocol,

        &info->device_connect.vendor_id,
        &info->device_connect.product_id,
        &info->device_connect.device_version_bcd)) {
            fprintf(stderr, "Error: incorrect device specification.\n");
            fprintf(stderr, "Provide speed:class:subclass:protocol:vendor:product:bcdver\n");
            fprintf(stderr, "All as hex strings.\n");
            return;
    }


    usbredirparser_send_interface_info(info->parser, &info->interface_info);
    usbredirparser_send_ep_info(info->parser, &info->ep_info);
    usbredirparser_send_device_connect(info->parser, &info->device_connect);
}

static void usbredirtestserver_cmdline_endpoint(private_info_t *info, char *buf)
{
    int i;
    uint8_t type;
    uint8_t interval;
    uint8_t interface;
    uint16_t max_packet_size;
    uint32_t max_streams;

    memset(&info->device_connect, 0, sizeof(info->device_connect));
    if (6 != sscanf(buf, "%d %hhx:%hhx:%hhx:%hx:%x",
        &i, &type, &interval, &interface, &max_packet_size, &max_streams)) {
            fprintf(stderr, "Error: incorrect endpoint specification.\n");
            fprintf(stderr, "Provide type:interval:interface:max_packet_size:max_streams");
            fprintf(stderr, "All as hex strings.\n");
            return;
    }

    if (i >= 0 && i < 32) {
        info->ep_info.type[i] = type;
        info->ep_info.interval[i] = interval;
        info->ep_info.interface[i] = interface;
        info->ep_info.max_packet_size[i] = max_packet_size;
        info->ep_info.max_streams[i] = max_streams;
    }
}

static void usbredirtestserver_cmdline_interface(private_info_t *info, char *buf)
{
    int i;
    uint8_t interface;
    uint8_t class;
    uint8_t subclass;
    uint8_t protocol;

    memset(&info->device_connect, 0, sizeof(info->device_connect));
    if (5 != sscanf(buf, "%d %hhx:%hhx:%hhx:%hhx",
        &i, &interface, &class, &subclass, &protocol)) {
            fprintf(stderr, "Error: incorrect interface specification.\n");
            fprintf(stderr, "Provide value:class:subclass:protocol");
            fprintf(stderr, "All as hex strings.\n");
            return;
    }

    if (i >= 0 && i < 32) {
        if (info->interface_info.interface_count < (i + 1))
            info->interface_info.interface_count = i + 1;
        info->interface_info.interface[i] = interface;
        info->interface_info.interface_class[i] = class;
        info->interface_info.interface_subclass[i] = subclass;
        info->interface_info.interface_protocol[i] = protocol;
    }
}


static void usbredirtestserver_cmdline_parse(private_info_t *info, char *buf)
{
    char *p;
    int len;

    if (strlen(buf) == 0 || buf[0] == '#')
        return;

    /* Compute length of first token */
    for (p = buf; *p && *p != ' ' && *p != '\t'; p++)
        ;
    len = p - buf;

    /* Point at the next token */
    for (; *p && (*p == ' ' || *p == '\t'); p++)
        ;

    if (len == 0)
        return;

    if (len <= 4) {
        if (!memcmp(buf, "help", len)) {
            usbredirtestserver_cmdline_help();
            return;
        } else if (!memcmp(buf, "quit", len)) {
            running = 0;
            close(info->fd);
            info->fd = -1;
            printf("Quit requested\n");
            return;
        } else if (!memcmp(buf, "kill", len)) {
            close(info->fd);
            info->fd = -1;
            printf("Terminated this device\n");
            return;
        } else if (!memcmp(buf, "ctrl", len)) {
            usbredirtestserver_cmdline_ctrl(info, p);
            return;
        }
    }

    if (len <= 6 && !memcmp(buf, "device", len)) {
        usbredirtestserver_cmdline_device(info, p);
        return;
    }

    if (len <= 6 && !memcmp(buf, "expect", len)) {
        usbredirtestserver_cmdline_expect(info, p);
        return;
    }

    if (len <= 8 && !memcmp(buf, "endpoint", len)) {
        usbredirtestserver_cmdline_endpoint(info, p);
        return;
    }

    if (len <= 9 && !memcmp(buf, "interface", len)) {
        usbredirtestserver_cmdline_interface(info, p);
        return;
    }

    printf("unknown command: '%s', type 'help' for help\n", buf);
}

#define TODO_IMPLEMENT printf("Error: %s unimplemented.\n", __FUNCTION__)
static void usbredirtestserver_hello(void *priv, struct usb_redir_hello_header *h)
{
#define TODO_IMPLEMENT printf("Error: %s unimplemented.\n", __FUNCTION__)
    // TODO - issue a connect?
}


static void usbredirtestserver_reset(void *priv)
{
    TODO_IMPLEMENT;
}

static void usbredirtestserver_get_configuration(void *priv, uint64_t id)
{
    private_info_t *info = (private_info_t *) priv;

    printf("get_configuration request %"PRIu64"; sending config 0\n", id);

    struct usb_redir_configuration_status_header status;

    status.status = usb_redir_success;
    status.configuration = 0;

    usbredirparser_send_configuration_status(info->parser, id, &status);
}

static void usbredirtestserver_set_configuration(void *priv, uint64_t id,
    struct usb_redir_set_configuration_header *set_config)
{
    private_info_t *info = (private_info_t *) priv;
    struct usb_redir_configuration_status_header status;
    printf("set_configuration request %"PRIu64"; config %d\n", id,
        set_config->configuration);

    status.status = usb_redir_success;
    status.configuration = set_config->configuration;

    // TODO - we must send the ep_info and interface_info
    //       before the status, at least according to the console
    //usbredirhost_send_interface_n_ep_info(host);
    usbredirparser_send_configuration_status(info->parser, id, &status);
}

static void usbredirtestserver_set_alt_setting(void *priv, uint64_t id,
    struct usb_redir_set_alt_setting_header *set_alt_setting)
{
    private_info_t *info = (private_info_t *) priv;
    struct usb_redir_alt_setting_status_header status;

    status.status = usb_redir_success,
    status.interface = set_alt_setting->interface;
    status.alt = set_alt_setting->alt; /* TODO no clue... */

    usbredirparser_send_alt_setting_status(info->parser, id, &status);
}

static void usbredirtestserver_get_alt_setting(void *priv, uint64_t id,
    struct usb_redir_get_alt_setting_header *get_alt_setting)
{
    private_info_t *info = (private_info_t *) priv;
    struct usb_redir_alt_setting_status_header status;
    status.status = usb_redir_success,
    status.interface = get_alt_setting->interface;
    status.alt = 0; /* TODO no clue... */
    usbredirparser_send_alt_setting_status(info->parser, id, &status);
}


static void check_expect_ctrl(private_info_t *info,
            struct usb_redir_control_packet_header *ctrl,
            uint8_t *data, int data_len)
{
    int i;

    if (ctrl->endpoint != info->expect_ctrl->ctrl.endpoint ||
        ctrl->request  != info->expect_ctrl->ctrl.request  ||
        ctrl->requesttype  != info->expect_ctrl->ctrl.requesttype  ||
        ctrl->status  != info->expect_ctrl->ctrl.status  ||
        ctrl->value  != info->expect_ctrl->ctrl.value  ||
        ctrl->index  != info->expect_ctrl->ctrl.index  ||
        ctrl->length  != info->expect_ctrl->ctrl.length) {
        fprintf(stderr, "Error: incoming control does not match expected.\n");
        return;
    }

    if (data_len != info->expect_ctrl->data_len) {
        fprintf(stderr, "Error: incoming control data_len %d does not match expected %d.\n",
                data_len, info->expect_ctrl->data_len);
        return;
    }

    for (i = 0; i < data_len; i++) {
        if (data[i] != info->expect_ctrl->data[i]) {
            fprintf(stderr, "Error: incoming data[%d] value %x does not match expected %x.\n",
                i, data[i], info->expect_ctrl->data[i]);
            return;
        }
    }

    if (info->expect_ctrl->data)
        free(info->expect_ctrl->data);
    free(info->expect_ctrl);
    info->expect_ctrl = NULL;
}

static void usbredirtestserver_control_packet(void *priv, uint64_t id,
    struct usb_redir_control_packet_header *control_packet,
    uint8_t *data, int data_len)
{
    private_info_t *info = (private_info_t *) priv;
    int i;
    printf("Control packet id: %"PRIu64", status: %d - %x:%x:%x:%x:%x:%x:%x",
            id, control_packet->status,
            control_packet->endpoint,
            control_packet->request,
            control_packet->requesttype,
            control_packet->status,
            control_packet->value,
            control_packet->index,
            control_packet->length);

    if (data_len) {
        printf(", data:");
    }
    for (i = 0; i < data_len; i++) {
        printf(" %02X", (unsigned int)data[i]);
    }
    printf("\n");

    if (info->expect_ctrl) {
        check_expect_ctrl(info, control_packet, data, data_len);
        info->id = id;
    }

    usbredirparser_free_packet_data(info->parser, data);
}

static void usbredirtestserver_bulk_packet(void *priv, uint64_t id,
    struct usb_redir_bulk_packet_header *bulk_packet,
    uint8_t *data, int data_len)
{
    printf("Bulk packet id %"PRIu64"\n", id);
}

static void usbredirtestserver_iso_packet(void *priv, uint64_t id,
    struct usb_redir_iso_packet_header *iso_packet,
    uint8_t *data, int data_len)
{
    printf("ISO packet id %"PRIu64"\n", id);
}

static void usbredirtestserver_interrupt_packet(void *priv, uint64_t id,
    struct usb_redir_interrupt_packet_header *interrupt_packet,
    uint8_t *data, int data_len)
{
    printf("Interrupt packet id %"PRIu64"\n", id);
}

/* Functions to track and manage a command buffer.
   This complexity is largely the result of a desire to have
   a 'goto' command */
static command_buffer_t *new_command_buffer(char *script_file)
{
    command_buffer_t *cmd = malloc(sizeof(*cmd));
    if (!cmd)
        return NULL;

    memset(cmd, 0, sizeof(*cmd));
    if (script_file) {
        cmd->fd = open(script_file, O_RDONLY);
        if (cmd->fd < 0) {
            perror("open script");
            free(cmd);
            return NULL;
        }
    }
    else
        cmd->fd = STDIN_FILENO;

    return cmd;
}

static int command_buffer_read(command_buffer_t *cmd)
{
    int rc;
    if (cmd->fd == -1)
        return 0;

    if (cmd->read_into >= sizeof(cmd->buffer) - 1) {
        /* Our buffer is full... */
        fprintf(stderr, "Error: buffer full.\n;");
        exit(-3);
    }

    if (cmd->fd == STDIN_FILENO && ! cmd->prompted) {
        printf("> ");
        fflush(stdout);
        cmd->prompted = 1;
    }

    rc = read(cmd->fd, cmd->buffer + cmd->read_into, sizeof(cmd->buffer) - cmd->read_into - 1);
    if (rc < 0)
        return rc;

    if (rc == 0)
        cmd->fd = -1;

    cmd->read_into += rc;

    return rc;
}

static int intercept_goto_and_labels(command_buffer_t *cmd, char *command)
{
    int i;

    if (command[0] == ':') {
        for (i = 0; i < MAX_LABELS; i++)
            if (! cmd->labels[i]) {
                cmd->labels[i] = strdup(command + 1);
                cmd->label_positions[i] = cmd->read_from;
                return 1;
            }
            /* If we already have this label, ignore it. */
            else if (strcmp(cmd->labels[i], command + 1) == 0)
                return 1;
    }

    if (strlen(command) > 5 && memcmp(command, "goto ", 5) == 0) {
        for (i = 0; i < MAX_LABELS; i++)
            if (cmd->labels[i] && strcmp(cmd->labels[i], command + 5) == 0) {
                cmd->read_from = cmd->label_positions[i];
                return 1;
            }

    }

    return 0;
}

static char *command_buffer_get(command_buffer_t *cmd)
{
    char *p;
    char *ret;
    int len;

    if (cmd->read_from >= cmd->read_into)
        return NULL;

    p = strchr(cmd->buffer + cmd->read_from, '\n');
    if (!p && cmd->fd == -1)
        p = cmd->buffer + cmd->read_into;

    if (!p)
        return NULL;

    len = p - (cmd->buffer + cmd->read_from);

    ret = malloc(len + 1);
    if (! ret)
        return NULL;

    memcpy(ret, cmd->buffer + cmd->read_from, len);
    ret[len] = 0;
    cmd->prompted = 0;
    cmd->read_from += len + 1;

    if (intercept_goto_and_labels(cmd, ret)) {
        free(ret);
        return command_buffer_get(cmd);
    }

    return ret;
}

static void free_command_buffer(command_buffer_t *cmd)
{
    int i;
    for (i = 0; i < MAX_LABELS; i++)
        if (cmd->labels[i])
            free(cmd->labels[i]);
    free(cmd);
}
