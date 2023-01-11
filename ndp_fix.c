#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <net/if_dl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <assert.h>
#include <time.h>

// Note: most common usages of the packet library break strict-aliasing, so we do it by hand

#define PACK_UINT16BE(a, b) ((uint16_t)(a) << 8 | (uint16_t)(b))

struct ndpfix_Context {
    int sock;
};

struct OCChecksum {
    uint32_t checksum;
    uint8_t leftOver;
    int hasLeftOver;
};

enum LogLevel {
    LOG_INFO,
    LOG_ERR
};

static void hexDump(FILE *out, const uint8_t *data, size_t size);

static void valog(enum LogLevel level, const char *fmt, va_list args) {
    FILE *out = stderr;
    time_t curTime;
    struct tm timeForm;
    time(&curTime);
    localtime_r(&curTime, &timeForm);
    fprintf(
        out,
        "[%d-%d-%d %d:%02d:%02d]",
        timeForm.tm_year + 1900,
        timeForm.tm_mon + 1,
        timeForm.tm_mday,
        timeForm.tm_hour,
        timeForm.tm_min,
        timeForm.tm_sec
    );
    switch (level) {
        case LOG_INFO: fprintf(out, " [INFO] "); break;
        case LOG_ERR: fprintf(out, " [ERR] "); break;
        default: abort();
    }
    vfprintf(out, fmt, args);
    fprintf(out, "\n");
}
static void log(enum LogLevel level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    valog(level, fmt, args);
    va_end(args);
}

static inline void OCChecksum_init(struct OCChecksum *chk) {
    chk->checksum = 0;
    chk->hasLeftOver = 0;
}

static void OCChecksum_update(struct OCChecksum *chk, const uint8_t *data, size_t size) {
    if (chk->hasLeftOver && size > 0) {
        chk->hasLeftOver = 0;
        chk->checksum += PACK_UINT16BE(chk->leftOver, data[0]);
        size--;
        data++;
    }
    size_t i;
    for (i = 0; i + 1 < size; i += 2) {
        chk->checksum += PACK_UINT16BE(data[i], data[i + 1]);
    }
    if (i == size - 1) {
        assert(!chk->hasLeftOver);
        chk->hasLeftOver = 1;
        chk->leftOver = data[size - 1];
    } else {
        assert(i == size);
    }
}

static uint16_t OCChecksum_getChecksum(const struct OCChecksum *chk) {
    uint32_t ret = chk->checksum;
    if (chk->hasLeftOver) {
        ret += chk->leftOver;
    }
    while (ret & 0xffff0000) ret = (ret >> 16) + (ret & 0xffff);
    return (uint16_t) ~ret;
}

static uint16_t calculateICMPv6Checksum(const uint8_t *srcAddr, const uint8_t *destAddr, uint8_t type, uint8_t code, const uint8_t *msg, size_t msgSize) {
    struct OCChecksum checksum;
    size_t payloadSize = msgSize + 4;
    uint8_t header[] = {type, code, 0, 0};
    uint8_t payloadSizeData[] = {(uint8_t)(payloadSize >> 24), (uint8_t)(payloadSize >> 16), (uint8_t)(payloadSize >> 8), (uint8_t) payloadSize};
    uint8_t nextHeader[] = {0, 0, 0, 58};
    OCChecksum_init(&checksum);
    OCChecksum_update(&checksum, srcAddr, 16);
    OCChecksum_update(&checksum, destAddr, 16);
    OCChecksum_update(&checksum, payloadSizeData, sizeof payloadSizeData);
    OCChecksum_update(&checksum, nextHeader, sizeof nextHeader);
    OCChecksum_update(&checksum, header, sizeof header);
    OCChecksum_update(&checksum, msg, msgSize);
    return OCChecksum_getChecksum(&checksum);
}

static int ndpfix_Context_init(struct ndpfix_Context *ctx) {
    ctx->sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (ctx->sock < 0) {
        return -1;
    }
    int hopLimit = 255; // required for neighbor advertisement packets
    if (setsockopt(ctx->sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hopLimit, sizeof hopLimit) < 0) {
        close(ctx->sock);
        return -1;
    }

    return 0;
}
static void ndpfix_Context_free(struct ndpfix_Context *ctx) {
    close(ctx->sock);
}
static int ndpfix_Context_handleNDP(struct ndpfix_Context *ctx, const struct sockaddr_in6 *addrFrom, const uint8_t *msg, size_t msgSize) {
    uint8_t targetAddr[16];
    memcpy(targetAddr, msg + 4, 16);

    {
        char addrFromName[100], targetAddrName[100];
        assert(NULL != inet_ntop(AF_INET6, &addrFrom->sin6_addr, addrFromName, sizeof addrFromName));
        assert(NULL != inet_ntop(AF_INET6, targetAddr, targetAddrName, sizeof targetAddrName));
        log(LOG_INFO, "solicitation from %s, target %s", addrFromName, targetAddrName);
    }
    // if (msgSize > 20) {
    //     const uint8_t *options = msg + 20;
    //     fprintf(stdout, "link addr: ");
    //     for (int i = 0; i < 8; i++) {
    //         fprintf(stdout, "%x ", options[i]);
    //     }
    //     fprintf(stdout, "\n");
    // }
    struct ifaddrs *ifAddrs = NULL;
    if (getifaddrs(&ifAddrs) == -1) {
        log(LOG_ERR, "failed to get interface info: %s", strerror(errno));
        return -1;
    }
    const char *ifName = NULL;
    for (struct ifaddrs *n = ifAddrs; n; n = n->ifa_next) {
        if (n->ifa_addr->sa_family == AF_INET6 && !memcmp(targetAddr, &((struct sockaddr_in6 *) n->ifa_addr)->sin6_addr, sizeof targetAddr)) {
            ifName = n->ifa_name;
            break;
        }
    }
    if (ifName == NULL) {
        return 0;
    }
    uint8_t macAddr[6];
    int foundMacAddr = 0;
    for (struct ifaddrs *n = ifAddrs; n; n = n->ifa_next) {
        if (n->ifa_addr->sa_family == AF_LINK && !strcmp(ifName, n->ifa_name)) {
            memcpy(macAddr, LLADDR((struct sockaddr_dl *) n->ifa_addr), sizeof macAddr);
            foundMacAddr = 1;
            break;
        }
    }
    freeifaddrs(ifAddrs);
    if (!foundMacAddr) {
        log(LOG_ERR, "MAC address not found for %s", ifName);
        return -1;
    }

    uint8_t type = ND_NEIGHBOR_ADVERT, code = 0;
    uint8_t replyHeader[32] = {type, code, 0, 0, 0x60, 0, 0, 0};
    uint8_t replyOption[8] = {2, 1};
    memcpy(replyOption + 2, macAddr, sizeof macAddr);
    memcpy(replyHeader + 8, targetAddr, sizeof targetAddr);
    memcpy(replyHeader + 24, replyOption, sizeof replyOption);
    uint16_t checksum = calculateICMPv6Checksum(targetAddr, (const uint8_t *) &addrFrom->sin6_addr, type, code, replyHeader + 4, sizeof replyHeader - 4);
    replyHeader[2] = (uint8_t)(checksum >> 8);
    replyHeader[3] = (uint8_t) checksum;

    if (sendto(ctx->sock, replyHeader, sizeof replyHeader, 0, (const struct sockaddr *) addrFrom, sizeof *addrFrom) < 0) {
        log(LOG_ERR, "failed to send packet: %s", strerror(errno));
        return -1;
    } else {
        log(LOG_INFO, "sent neighbor advertisement, if name %s, MAC address: %02x:%02x:%02x:%02x:%02x:%02x", ifName, macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);
        return 0;
    }
}

static void hexDump(FILE *out, const uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        fprintf(out, "%x ", data[i]);
    }
}

int main(int argc, const char *argv[]) {
    struct ndpfix_Context ctx;
    if (ndpfix_Context_init(&ctx) < 0) {
        log(LOG_ERR, "failed to create context: %s", strerror(errno));
        return -1;
    }

    uint8_t buffer[8192];
    ssize_t size;

    log(LOG_INFO, "start listening for packets");
    while (1) {
        struct sockaddr_in6 addrFrom;
        socklen_t len = sizeof addrFrom;
        if ((size = recvfrom(ctx.sock, buffer, sizeof buffer, 0, (struct sockaddr *) &addrFrom, &len)) > 0) {
            if (addrFrom.sin6_family == AF_INET6) {
                assert(len == sizeof addrFrom);
                uint8_t *rawAddr = (uint8_t *) &addrFrom.sin6_addr;
                uint8_t type = buffer[0];
                uint8_t code = buffer[1];
                uint16_t chksum = PACK_UINT16BE(buffer[2], buffer[3]);
                const uint8_t *msg = buffer + 4;
                size_t msgSize = size - 4;
                if ((rawAddr[0] & 0xe0) == 0x20) {
                    if (type == ND_NEIGHBOR_SOLICIT && code == 0) {
                        ndpfix_Context_handleNDP(&ctx, &addrFrom, msg, msgSize);
                    }
                }
            }
        }
    }

    ndpfix_Context_free(&ctx);
    return 0;
}