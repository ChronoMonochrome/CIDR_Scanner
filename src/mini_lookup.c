#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

struct __attribute__((packed)) dns_header {
    unsigned short id;
    unsigned char rd :1;
    unsigned char tc :1;
    unsigned char aa :1;
    unsigned char opcode :4;
    unsigned char qr :1;
    unsigned char rcode :4;
    unsigned char cd :1;
    unsigned char ad :1;
    unsigned char z :1;
    unsigned char ra :1;
    unsigned short q_count;
    unsigned short ans_count;
    unsigned short auth_count;
    unsigned short add_count;
};

void format_name(unsigned char *dns, char *host) {
    int lock = 0;
    char temp[256];
    strncpy(temp, host, 255);
    strcat(temp, ".");
    for (int i = 0; i < (int)strlen(temp); i++) {
        if (temp[i] == '.') {
            *dns++ = i - lock;
            for (; lock < i; lock++) *dns++ = temp[lock];
            lock++;
        }
    }
    *dns++ = '\0';
}

int main(int argc, char *argv[]) {
    if (argc < 3) return printf("Usage: %s <host> <dns>\n", argv[0]), 1;

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct timeval tv = {2, 0}; // 2 second timeout
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dest = { .sin_family = AF_INET, .sin_port = htons(53), .sin_addr.s_addr = inet_addr(argv[2]) };

    unsigned char buf[512];
    memset(buf, 0, 512); // Initial clear

    srand(time(NULL));
    unsigned short sent_id = htons(rand() % 65535);

    struct dns_header *dns = (struct dns_header *)buf;
    dns->id = sent_id;
    dns->rd = 1;
    dns->q_count = htons(1);
    dns->add_count = htons(1);

    unsigned char *qname = &buf[sizeof(struct dns_header)];
    format_name(qname, argv[1]);
    int qname_len = strlen((char *)qname) + 1;

    unsigned short *qinfo = (unsigned short *)&buf[sizeof(struct dns_header) + qname_len];
    *qinfo++ = htons(1); // Type A
    *qinfo++ = htons(1); // Class IN

    // EDNS0
    unsigned char *opt = (unsigned char *)qinfo;
    *opt++ = 0;
    *(unsigned short*)opt = htons(41); opt += 2;
    *(unsigned short*)opt = htons(4096); opt += 2;
    memset(opt, 0, 6); opt += 6;

    int packet_size = (unsigned char*)opt - buf;
    sendto(sockfd, buf, packet_size, 0, (struct sockaddr *)&dest, sizeof(dest));

    // CRITICAL FIX: Clear buffer before receiving
    memset(buf, 0, 512);
    
    int len = recvfrom(sockfd, buf, 512, 0, NULL, NULL);

    // CRITICAL FIX: Only process if we actually received data
    if (len <= 0) {
        printf("No response from %s (Check network or IP)\n", argv[2]);
        close(sockfd);
        return 1;
    }

    struct dns_header *res = (struct dns_header *)buf;

    // CRITICAL FIX: Verify the ID matches our request
    if (res->id != sent_id) {
        printf("Received packet with mismatched ID. Ignoring.\n");
        close(sockfd);
        return 1;
    }

    int ans_count = ntohs(res->ans_count);
    unsigned char *reader = &buf[sizeof(struct dns_header) + qname_len + 4];

    for (int i = 0; i < ans_count; i++) {
        if ((*reader & 0xC0) == 0xC0) reader += 2; 
        else { while (*reader != 0) reader++; reader++; }
        
        unsigned short type = ntohs(*(unsigned short *)reader); reader += 2;
        reader += 2; // class
        reader += 4; // ttl
        unsigned short rdlen = ntohs(*(unsigned short *)reader); reader += 2;
        
        if (type == 1 && rdlen == 4) {
            struct in_addr addr; memcpy(&addr, reader, 4);
            printf("Address: %s\n", inet_ntoa(addr));
        }
        reader += rdlen;
    }

    close(sockfd);
    return 0;
}
