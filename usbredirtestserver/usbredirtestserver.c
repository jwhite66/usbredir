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
    int id;
    int fd;
    int cmd_fd;
    struct usbredirparser *parser;
} private_info_t ;

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
    char buf[1024];
    int pos = 0;
    fd_set readfds, writefds;
    int n, nfds;
    struct timeval tv;
    int closed = 0;

    printf("device %d connected\n", info->id);

    if (info->cmd_fd == STDIN_FILENO)
        printf("%d> ", info->id); fflush(stdout);

    while (running && info->fd != -1) {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);

        if (! closed)
            FD_SET(info->cmd_fd, &readfds);

        FD_SET(info->fd, &readfds);
        if (usbredirparser_has_data_to_write(info->parser)) {
            FD_SET(info->fd, &writefds);
        }
        nfds = info->fd + 1;
        if (info->cmd_fd > info->fd)
            nfds = info->cmd_fd + 1;

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

        if (!closed && FD_ISSET(info->cmd_fd, &readfds)) {
            char *p;
            int rc;
            rc = read(info->cmd_fd, buf + pos, sizeof(buf) - pos);
printf("JPW read rc %d\n", rc);

            if (rc == 0)
                closed++;

            if (rc < 0)
                break;

            pos += rc;

            while (pos > 0) {
                p = strchr(buf, '\n');
                if (!p)
                    p = buf + pos;
                if (p) {
                    *p = '\0';
                    usbredirtestserver_cmdline_parse(info, buf);
                    pos -= (p - buf + 1);
                    memmove(buf, p + 1, sizeof(buf) - pos);
                    if (info->cmd_fd == STDIN_FILENO)
                        printf("%d> ", info->id); fflush(stdout);
                }
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

    if (script_file) {
        private_info.cmd_fd = open(script_file, O_RDONLY);
        if (private_info.cmd_fd < 0) {
            perror("open script");
            exit(-2);
        }
    }
    else
        private_info.cmd_fd = STDIN_FILENO;

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

    /* TODO - usbredirserver can do this; not sure if we want to...
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

    while ((o = getopt_long(argc, argv, "hp:s:", longopts, NULL)) != -1) {
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

        if (waitpid(-1, &status, WNOHANG)) {
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                printf("Child exited abnormally; stopping.\n");
                break;
            }
        }
    }


    exit(0);
}

static void usbredirtestserver_cmdline_help(void)
{
    printf("Avaiable commands:\n"
        "ctrl <endpoint> <request> <request_type> <value> <index> <length> [data]\n"
        "device\n"
        "kill\n"
        "quit\n"
        "help\n");
}

static void usbredirtestserver_cmdline_ctrl(private_info_t *info, char *buf)
{
    struct usb_redir_control_packet_header control_packet;
    char *arg, *endptr = NULL;
    uint8_t *data = NULL;
    int data_len;
    char *dup = strdup(buf);

    arg = strtok(dup, " \t\n");
    if (arg) {
        control_packet.endpoint = strtol(arg, &endptr, 0);
    }
    if (!arg || *endptr != '\0') {
        printf("Missing or invalid endpoint\n");
        goto out;
    }

    arg = strtok(NULL, " \t\n");
    if (arg) {
        control_packet.request = strtol(arg, &endptr, 0);
    }
    if (!arg || *endptr != '\0') {
        printf("Missing or invalid request\n");
        goto out;
    }

    arg = strtok(NULL, " \t\n");
    if (arg) {
        control_packet.requesttype = strtol(arg, &endptr, 0);
    }
    if (!arg || *endptr != '\0') {
        printf("Missing or invalid request type\n");
        goto out;
    }

    arg = strtok(NULL, " \t\n");
    if (arg) {
        control_packet.value = strtol(arg, &endptr, 0);
    }
    if (!arg || *endptr != '\0') {
        printf("Missing or invalid value\n");
        goto out;
    }

    arg = strtok(NULL, " \t\n");
    if (arg) {
        control_packet.index = strtol(arg, &endptr, 0);
    }
    if (!arg || *endptr != '\0') {
        printf("Missing or invalid index\n");
        goto out;
    }

    arg = strtok(NULL, " \t\n");
    if (arg) {
        control_packet.length = strtol(arg, &endptr, 0);
    }
    if (!arg || *endptr != '\0') {
        printf("Missing or invalid length\n");
        goto out;
    }

    if (!(control_packet.endpoint & 0x80)) {
        int i;

        data = malloc(control_packet.length);
        if (!data) {
            fprintf(stderr, "Out of memory!\n");
            close(info->fd);
            info->fd= -1;
            goto out;
        }

        for (i = 0; i < control_packet.length; i++) {
            arg = strtok(NULL, " \t\n");
            if (arg) {
                data[i] = strtol(arg, &endptr, 0);
            }
            if (!arg || *endptr != '\0') {
                printf("Missing or invalid data byte(s)\n");
                free(data);
                goto out;
            }
        }
        data_len = control_packet.length;
    } else {
        data_len = 0;
    }
    usbredirparser_send_control_packet(info->parser, info->id, &control_packet,
                                       data, data_len);
    if (data)
        free(data);
    printf("Sent control packet with id: %u\n", info->id);
    info->id++;
out:
    free(dup);
}

static void usbredirtestserver_cmdline_device(private_info_t *info, char *buf)
{
    struct usb_redir_interface_info_header interface_info;
    struct usb_redir_ep_info_header ep_info;
    struct usb_redir_device_connect_header device_connect;
    int i;

    memset(&device_connect, 0, sizeof(device_connect));
    if (7 != sscanf(buf, "%hhx:%hhx:%hhx:%hhx %hx:%hx:%hx",
        &device_connect.speed,
        &device_connect.device_class,
        &device_connect.device_subclass,
        &device_connect.device_protocol,

        &device_connect.vendor_id,
        &device_connect.product_id,
        &device_connect.device_version_bcd)) {
            fprintf(stderr, "Error: incorrect device specification.\n");
            fprintf(stderr, "Provide speed:class:subclass:protocol ");
            fprintf(stderr, " vendor:product:bcdver\n");
            fprintf(stderr, "All as hex strings.\n");
            return;
    }

    memset(&interface_info, 0, sizeof(interface_info));

    interface_info.interface_count = 4;
    for (i = 0; i < 4; i++) {
        interface_info.interface[i] = i;
        interface_info.interface_class[i] = device_connect.device_class;
        interface_info.interface_subclass[i] = device_connect.device_subclass;
        interface_info.interface_protocol[i] = device_connect.device_protocol;
    }

    memset(&ep_info, 0, sizeof(ep_info));
    ep_info.type[0] = 0;
    ep_info.type[1] = 0 | 0x80;
    ep_info.type[2] = 2;
    ep_info.type[3] = 2 | 0x80;
    for (i = 0; i < 4; i++) {
        ep_info.interval[i] = 1; /* TODO */
        ep_info.interface[i] = i; /* TODO */
        ep_info.max_packet_size[i] = 64;
        ep_info.max_streams[i] = 0; /* TODO */
    }

    usbredirparser_send_interface_info(info->parser, &interface_info);
    usbredirparser_send_ep_info(info->parser, &ep_info);
    usbredirparser_send_device_connect(info->parser, &device_connect);

}

static void usbredirtestserver_cmdline_parse(private_info_t *info, char *buf)
{
    char *p;
    int len;

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


static void usbredirtestserver_control_packet(void *priv, uint64_t id,
    struct usb_redir_control_packet_header *control_packet,
    uint8_t *data, int data_len)
{
    private_info_t *info = (private_info_t *) priv;
    int i;
    printf("Control packet id: %"PRIu64", status: %d", id,
           control_packet->status);

    if (data_len) {
        printf(", data:");
    }
    for (i = 0; i < data_len; i++) {
        printf(" %02X", (unsigned int)data[i]);
    }
    printf("\n");
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
