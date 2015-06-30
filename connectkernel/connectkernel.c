#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>

void usage(const char *argv0)
{
    fprintf(stderr, "%s: Connect a remote USB device to the usbredir kernel module.\n", argv0);
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s devid server port [--attach attach]\n", argv0);
    fprintf(stderr, "where devid is a unique identifier for this connection, server:port\n");
    fprintf(stderr, "is the address of a TCP server that is listening, waiting to export a USBREDIR device.\n");
    fprintf(stderr, "Generally, you invoke %s to connect to a usbredirserver process.\n", argv0);
}


int main(int argc, char *argv[])
{
	struct addrinfo hints, *res, *rp;
        int rc;
        int s;
        int fd;
        int i;
        char buf[256 + 8];
        char *attach_file = "/sys/bus/platform/drivers/usbredir/attach";
        char *devid = NULL;
        char *server = NULL;
        char *port = NULL;


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

        if (!devid || !server || !port)
        {
            fprintf(stderr, "Error: specify device id, server and port\n");
            usage(argv[0]);
            exit(1);
        }

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;

	/* get all possible addresses */
	rc = getaddrinfo(server, port, &hints, &res);
	if (rc < 0)
        {

            fprintf(stderr, "Error resolving %s:%s\n", server, port);
            exit(1);
        }

	for (rp = res; rp; rp = rp->ai_next)
        {
            s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (s < 0)
            {
                perror("socket");
                exit(2);
            }

            rc = connect(s, rp->ai_addr, rp->ai_addrlen);
            if (rc == 0)
                break;

        }

        if (! rp)
        {
            fprintf(stderr, "Error: unable to connect.\n");
            exit(3);
        }

	freeaddrinfo(res);

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
