#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>

void usage(const char *argv0)
{
    fprintf(stderr, "%s: Connect a remote USB device to the usbredir kernel module.\n", argv0);
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s devid < server port | --socket file > ] [--attach attach]\n", argv0);
    fprintf(stderr, "where devid is a unique identifier for this connection, server:port\n");
    fprintf(stderr, "is the address of a TCP server that is listening, waiting to export a USBREDIR device.\n");
    fprintf(stderr, "If you specify --socket, then you need to supply the name of a  UNIX domain socket.\n");
}

int connect_tcp(char *server, char *port)
{
    struct addrinfo hints, *res, *rp;
    int rc;
    int s;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;

    /* get all possible addresses */
    rc = getaddrinfo(server, port, &hints, &res);
    if (rc < 0)
    {

        fprintf(stderr, "Error resolving %s:%s\n", server, port);
        return -1;
    }

    for (rp = res; rp; rp = rp->ai_next)
    {
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s < 0)
        {
            perror("socket");
            return -2;
        }

        if (connect(s, rp->ai_addr, rp->ai_addrlen) == 0)
            break;

    }

    if (! rp)
    {
        fprintf(stderr, "Error: unable to connect.\n");
        return -3;
    }

    freeaddrinfo(res);

    return s;
}

int connect_unix(char *fname)
{
    int s;
    struct sockaddr_un addr;

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0)
    {
        perror("socket");
        return s;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, fname, sizeof(addr.sun_path)-1);

    if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) != 0)
    {
        perror("connect");
        return -1;
    }

    return s;
}

int main(int argc, char *argv[])
{
        int s;
        int fd;
        int i;
        char buf[256 + 8];
        char *attach_file = "/sys/bus/platform/drivers/usbredir/attach";
        char *devid = NULL;
        char *server = NULL;
        char *port = NULL;
        int socket = 0;


        /* Poor man's argument parsing */
        for (i = 1; i < argc; i++)
        {
            if (strcmp(argv[i], "--attach") == 0)
            {
                if (i == (argc - 1))
                {
                    fprintf(stderr, "Error: you must supply a path to the sysfs attach file.\n");
                    exit(1);
                }
                i++;
                attach_file = argv[i];
                break;
            }
            else if (strcmp(argv[i], "--socket") == 0)
            {
                if (i == (argc - 1))
                {
                    fprintf(stderr, "Error: you must supply a path to the socket.\n");
                    exit(1);
                }
                server = argv[++i];
                socket = 1;
                continue;
            }
            else if (!devid)
                devid = argv[i];
            else if (!server)
                server = argv[i];
            else if (!port)
                port = argv[i];
            else
            {
                fprintf(stderr, "Error: too many arguments.\n");
                usage(argv[0]);
                exit(1);
            }
        }

        if (!devid || (socket && !server) || (!socket && (!server || !port)))
        {
            fprintf(stderr, "Error: specify device id, and then server and port or --socket\n");
            usage(argv[0]);
            exit(1);
        }

        if (socket)
            s = connect_unix(server);
        else
            s = connect_tcp(server, port);

        if (s < 0)
            exit(s);

        fd = open(attach_file, O_WRONLY);
        if (fd == -1)
        {
            fprintf(stderr, "Could not write to %s\n", attach_file);
            exit(1);
        }

        snprintf(buf, sizeof(buf), "%d %s", s, devid);
        if (write(fd, buf, strlen(buf)) < 0)
        {
            fprintf(stderr, "Attach of '%s' to kernel failed\n", buf);
            exit(1);
        }
        close(fd);

        return 0;
}
