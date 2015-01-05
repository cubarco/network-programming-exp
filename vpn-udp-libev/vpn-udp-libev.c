#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <ev.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_tun.h>
#include <net/if.h>

#define MTU 1464
#define BUFFSIZE MTU
#define MODE_SERVER 0
#define MODE_CLIENT 1

#define PERROR(s) do {perror(s); exit(1);} while (0)

typedef struct args {
    int mode;
    int port;
    int mtu;
    char *remote_addr_str;
} args_t;

typedef struct ctx {
    int local_fd;
    int tun_fd;
    int mode;
    socklen_t remote_addr_len;
    char *buf;
    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;
} ctx_t;

struct ctx ctx_v;
struct args args_v;

static int make_socket_non_blocking (int sfd)
{
    int flags, s;
    flags = fcntl (sfd, F_GETFL, 0);
    if (flags == -1) {
        PERROR("fcntl");
        return -1;
    }
    flags |= O_NONBLOCK;
    s = fcntl (sfd, F_SETFL, flags);
    if (s == -1) {
        PERROR("fcntl");
        return -1;
    }
    return 0;
}

static void local_udp_init()
{
    ctx_v.buf = malloc(BUFFSIZE);
    ctx_v.mode = args_v.mode;
    ctx_v.local_fd = socket(AF_INET, SOCK_DGRAM, 0);
    make_socket_non_blocking(ctx_v.local_fd);
    if (ctx_v.mode == MODE_SERVER){
        bzero(&ctx_v.local_addr, sizeof(ctx_v.local_addr));
        ctx_v.local_addr.sin_family = AF_INET;
        ctx_v.local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        ctx_v.local_addr.sin_port = htons(args_v.port);
        bind(ctx_v.local_fd, (struct sockaddr*)&ctx_v.local_addr,
                sizeof(ctx_v.local_addr));
    } else if (ctx_v.mode == MODE_CLIENT) {
        bzero(&ctx_v.remote_addr, sizeof(ctx_v.remote_addr));
        ctx_v.remote_addr.sin_family = AF_INET;
        ctx_v.remote_addr.sin_addr.s_addr = inet_addr(args_v.remote_addr_str);
        ctx_v.remote_addr.sin_port = htons(args_v.port);
        ctx_v.remote_addr_len = sizeof(ctx_v.remote_addr);
    }
}

static void local_tun_init()
{
    struct ifreq ifr;
    int fd;
    if ( (ctx_v.tun_fd = open("/dev/net/tun", O_RDWR)) < 0)
        PERROR("tun open");
    make_socket_non_blocking(ctx_v.tun_fd);
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "tun%d", IFNAMSIZ);
    ifr.ifr_flags = IFF_TUN;
    if (ioctl(ctx_v.tun_fd, TUNSETIFF, &ifr) < 0)
        PERROR("tun ioctl");
    ifr.ifr_mtu = args_v.mtu == 0 ? MTU : args_v.mtu;
    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (ioctl(fd, SIOCSIFMTU, &ifr) < 0)
        PERROR("tun ioctl");
}

static void signal_cb(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
            case SIGINT:
            case SIGTERM:
                ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

static void tun_cb(EV_P_ ev_io *w, int revents)
{
    bzero(ctx_v.buf, BUFFSIZE);
    read(ctx_v.tun_fd, ctx_v.buf, BUFFSIZE);
    if (ctx_v.remote_addr_len != 0)
        sendto(ctx_v.local_fd, ctx_v.buf, BUFFSIZE, 0,
                (struct sockaddr*)&ctx_v.remote_addr, ctx_v.remote_addr_len);
}

static void udp_cb(EV_P_ ev_io *w, int revents)
{
    bzero(ctx_v.buf, BUFFSIZE);
    recvfrom(ctx_v.local_fd, ctx_v.buf, BUFFSIZE, 0,
            (struct sockaddr*)&ctx_v.remote_addr, &ctx_v.remote_addr_len);
    write(ctx_v.tun_fd, ctx_v.buf, BUFFSIZE);
}

static void usage(char *cmd)
{
    fprintf(stderr, "server: %s -s -p PORT [-m MTU]\n", cmd);
    fprintf(stderr, "client: %s -c SERVER_ADDRESS -p PORT [-m MTU]\n", cmd);
    exit(1);
}

int main(int argc, char **argv)
{
    int opt;
    struct ev_loop *loop = EV_DEFAULT;
    ev_signal sigint_watcher;
    ev_signal sigterm_watcher;
    ev_io tun_watcher;
    ev_io local_udp_watcher;

    if (argc < 3)
        usage(argv[0]);

    bzero(&ctx_v, sizeof(ctx_t));
    bzero(&args_v, sizeof(args_t));
    while ((opt = getopt(argc, argv, "shc:p:m:")) != -1) {
        switch (opt) {
            case 's':
                args_v.mode = MODE_SERVER;
                printf("server mode\n");
                break;
            case 'c':
                args_v.mode = MODE_CLIENT;
                args_v.remote_addr_str = strdup(optarg);
                printf("client mode\n");
                break;
            case 'p':
                args_v.port = atoi(optarg);
                break;
            case 'm':
                args_v.mtu = atoi(optarg);
                break;
            case 'h':
            default:
                usage(argv[0]);
        }
    }

    local_udp_init();
    local_tun_init();

    ev_io_init(&tun_watcher, tun_cb, ctx_v.tun_fd, EV_READ);
    ev_io_init(&local_udp_watcher, udp_cb, ctx_v.local_fd, EV_READ);
    ev_io_start(EV_A_ &tun_watcher);
    ev_io_start(EV_A_ &local_udp_watcher);

    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_A_ &sigint_watcher);
    ev_signal_start(EV_A_ &sigterm_watcher);
    ev_unref(EV_A);
    ev_unref(EV_A);

    ev_run(EV_A_ 0);

    return 0;
}
