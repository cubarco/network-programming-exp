#ifndef VPN_H
#define VPN_H
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

/* 1492(Ethernet) - 20(IPv4) - 8(UDP) - 16(SSL trailing) */
#define MTU 1448
#define BUFFSIZE 1500
#define MODE_SERVER 0
#define MODE_CLIENT 1

#define PERROR(s) do {perror(s); exit(1);} while (0)

typedef struct args {
    int mode;
    int port;
    int mtu;
    char *pwd;
    char *remote_addr_str;
} args_t;

typedef struct ctx {
    int local_fd;
    int tun_fd;
    int mode;
    int mtu;
    socklen_t remote_addr_len;
    unsigned char *buf;
    unsigned char *crypto_buf;
    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;
} ctx_t;

struct ctx ctx_v;
struct args args_v;

int result;

#endif
