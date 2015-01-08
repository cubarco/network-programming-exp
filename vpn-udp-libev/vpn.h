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
#include <netdb.h>

/* 1492(Ethernet) - 20(IPv4) - 8(UDP) - 16(SSL trailing) - 6(lzo) */
#define MTU 1442
#define BUFFSIZE 1500
#define MODE_SERVER 1 
#define MODE_CLIENT 2

#define PERROR(s) do {perror(s); exit(1);} while (0)

typedef struct args {
    int mode;
    int port;
    int mtu;
    int uselzo;
    char *pwd;
    char *local_addr_str;
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
    unsigned char *comp_buf;
    struct sockaddr_storage local_addr;
    struct sockaddr_storage remote_addr;
    struct sockaddr_storage temp_remote_addr;
} ctx_t;

struct ctx ctx_v;
struct args args_v;

int result;

#endif
