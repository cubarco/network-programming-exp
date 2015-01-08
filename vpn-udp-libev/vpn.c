#include "common.h"
#include "vpn.h"
#include "crypto.h"
#include "compress.h"

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
    struct addrinfo hints;
    struct addrinfo *res;
    struct sockaddr_in *v4_addr;
    struct sockaddr_in6 *v6_addr;
    char *addr_str;
    bzero(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    if (ctx_v.mode == MODE_SERVER) {
        v6_addr = (struct sockaddr_in6 *)&ctx_v.local_addr;
        v4_addr = (struct sockaddr_in *)&ctx_v.local_addr;
        addr_str = args_v.local_addr_str;
    } else {
        v6_addr = (struct sockaddr_in6 *)&ctx_v.remote_addr;
        v4_addr = (struct sockaddr_in *)&ctx_v.remote_addr;
        addr_str = args_v.remote_addr_str;
    }
    if (0 != (result = getaddrinfo(addr_str, NULL, &hints, &res))) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
        exit(1);
    }
    ctx_v.local_fd = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (res->ai_family == AF_INET) {
        v4_addr->sin_family = AF_INET;
        inet_aton(addr_str, &v4_addr->sin_addr);
        v4_addr->sin_port = htons(args_v.port);
        ctx_v.remote_addr_len = sizeof(struct sockaddr_in);
        if (ctx_v.mode == MODE_SERVER)
            bind(ctx_v.local_fd, (struct sockaddr *)&ctx_v.local_addr,
                    sizeof(struct sockaddr_in));
    } else if (res->ai_family == AF_INET6) {
        v6_addr->sin6_family = AF_INET6;
        inet_pton(AF_INET6, addr_str, &v6_addr->sin6_addr);
        v6_addr->sin6_port = htons(args_v.port);
        ctx_v.remote_addr_len = sizeof(struct sockaddr_in6);
        if (ctx_v.mode == MODE_SERVER)
            bind(ctx_v.local_fd, (struct sockaddr *)&ctx_v.local_addr,
                    sizeof(struct sockaddr_in6));
    }
}

static void local_tun_init()
{
    struct ifreq ifr;
    int fd;
    if ( (ctx_v.tun_fd = open("/dev/net/tun", O_RDWR) ) < 0)
        PERROR("tun open");
    make_socket_non_blocking(ctx_v.tun_fd);
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "tun%d", IFNAMSIZ);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(ctx_v.tun_fd, TUNSETIFF, &ifr) < 0)
        PERROR("tun ioctl");
    ifr.ifr_mtu = ctx_v.mtu;
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
    if ((result = read(ctx_v.tun_fd, ctx_v.buf, BUFFSIZE)) < 0) {
        perror("read from tunnel");
        return;
    }
    if (args_v.uselzo) {
        result = compress(ctx_v.buf, ctx_v.comp_buf, result);
        result = crypto_encrypt(ctx_v.comp_buf, ctx_v.crypto_buf, result);
    } else
        result = crypto_encrypt(ctx_v.buf, ctx_v.crypto_buf, result);
    if (-1 == result)
        return;
    sendto(ctx_v.local_fd, ctx_v.crypto_buf, result, 0,
            (struct sockaddr*)&ctx_v.remote_addr, ctx_v.remote_addr_len);
}

static void udp_cb(EV_P_ ev_io *w, int revents)
{
    result = recvfrom(ctx_v.local_fd, ctx_v.buf, BUFFSIZE, 0,
                        (struct sockaddr*)&ctx_v.temp_remote_addr,
                            &ctx_v.remote_addr_len);
    if (result < 0) {
        perror("recvfrom");
        return;
    }
    result = crypto_decrypt(ctx_v.buf, ctx_v.crypto_buf, result);
    if (-1 == result)
        return;

    ctx_v.remote_addr = ctx_v.temp_remote_addr;
    if (args_v.uselzo) {
        result = decompress(ctx_v.crypto_buf, ctx_v.comp_buf, result);
        write(ctx_v.tun_fd, ctx_v.comp_buf, result);
    } else
        write(ctx_v.tun_fd, ctx_v.crypto_buf, result);

}

static void usage(char *cmd)
{
    fprintf(stderr, "server: %s -s LOCAL_ADDRESS -p PORT -k PASSWORD [-C] [-m MTU]\n", cmd);
    fprintf(stderr, "client: %s -c SERVER_ADDRESS -p PORT -k PASSWORD [-C] [-m MTU]\n", cmd);
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

    bzero(&ctx_v, sizeof(ctx_t));
    bzero(&args_v, sizeof(args_t));
    while ((opt = getopt(argc, argv, "hCs:c:p:k:m:")) != -1) {
        switch (opt) {
            case 's':
                args_v.mode = MODE_SERVER;
                args_v.local_addr_str = strdup(optarg);
                fprintf(stderr, "server mode\n");
                break;
            case 'c':
                args_v.mode = MODE_CLIENT;
                args_v.remote_addr_str = strdup(optarg);
                fprintf(stderr, "client mode\n");
                break;
            case 'p':
                args_v.port = atoi(optarg);
                break;
            case 'm':
                args_v.mtu = atoi(optarg);
                break;
            case 'k':
                args_v.pwd = strdup(optarg);
                break;
            case 'C':
                args_v.uselzo = 1;
                fprintf(stderr, "lzo compression enabled\n");
                break;
            case 'h':
            default:
                usage(argv[0]);
        }
    }
    if (args_v.mode == -1 || !args_v.port || !args_v.pwd)
        usage(argv[0]);

    ctx_v.buf = malloc(BUFFSIZE);
    ctx_v.crypto_buf = malloc(BUFFSIZE);
    ctx_v.comp_buf = malloc(BUFFSIZE);
    ctx_v.mode = args_v.mode;
    ctx_v.mtu = args_v.mtu == 0 ? MTU : args_v.mtu;
    if (-1 == crypto_init(args_v.pwd))
        exit(1);
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
