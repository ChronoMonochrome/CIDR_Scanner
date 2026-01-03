#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <math.h>
#include <time.h>
#include <getopt.h>
#include <pthread.h>
#include <stdatomic.h>

#define DNS_QR 0x8000
#define DNS_RD 0x0100

// Global configuration and counters
atomic_uint total_probes = 0;      // Actual probes sent
atomic_uint traversal_idx = 0;     // Logic counter to maintain resume consistency
atomic_uint found_count = 0;
uint32_t global_range_size = 0;
uint32_t resume_at = 0;            // The -p flag value
int thread_count = 8;              // Adjustable via -t

typedef struct {
    uint32_t start_ip;
    uint32_t count;
    uint32_t global_offset;        // Where this thread's chunk starts in the global index
} thread_args_t;

struct __attribute__((packed)) dns_header {
    unsigned short id, flags, q_count, ans_count, auth_count, add_count;
};

void print_help(char *prog) {
    printf("Usage: %s [OPTIONS] <CIDR>\n\n", prog);
    printf("Options:\n");
    printf("  -l, --linear         Enable exhaustive linear search (default: bisection)\n");
    printf("  -p, --probe NUM      Resume scanning starting from probe number NUM\n");
    printf("  -t, --threads NUM    Number of threads for linear scan (default: 8)\n");
    printf("  -h, --help           Show this help message\n\n");
    printf("Example:\n");
    printf("  %s -l -p 12000000 158.160.0.0/16\n", prog);
}

void format_dns_name(unsigned char *dns, char *host) {
    int lock = 0;
    char copy[256];
    strncpy(copy, host, 255);
    strcat(copy, ".");
    for (int i = 0; i < (int)strlen(copy); i++) {
        if (copy[i] == '.') {
            *dns++ = i - lock;
            for (; lock < i; lock++) *dns++ = copy[lock];
            lock++;
        }
    }
    *dns++ = '\0';
}

void print_progress(uint32_t current, uint32_t total) {
    int width = 40;
    float ratio = (float)current / total;
    int pos = width * ratio;
    printf("\r[");
    for (int i = 0; i < width; i++) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %d%% (Probe Index: %u | Found: %u)", (int)(ratio * 100), current, atomic_load(&found_count));
    fflush(stdout);
}

int dns_probe(int sockfd, uint32_t server_ip) {
    // Resume logic: check if we should skip this probe
    uint32_t current_idx = atomic_fetch_add(&traversal_idx, 1);
    if (current_idx < resume_at) return 0;

    unsigned char buf[512];
    unsigned short sent_id = (unsigned short)(rand() % 65535);
    memset(buf, 0, 512);

    struct dns_header *dns = (struct dns_header *)buf;
    dns->id = htons(sent_id);
    dns->flags = htons(DNS_RD);
    dns->q_count = htons(1);
    dns->add_count = htons(1);

    unsigned char *qname = &buf[sizeof(struct dns_header)];
    format_dns_name(qname, "google.com");
    int qname_len = strlen((char *)qname) + 1;

    unsigned short *qinfo = (unsigned short *)&buf[sizeof(struct dns_header) + qname_len];
    *qinfo++ = htons(1); *qinfo++ = htons(1);

    unsigned char *opt = (unsigned char *)qinfo;
    *opt++ = 0;
    *(unsigned short*)opt = htons(41); opt += 2;
    *(unsigned short*)opt = htons(4096); opt += 2;
    memset(opt, 0, 6); opt += 6;

    struct sockaddr_in dest = { .sin_family = AF_INET, .sin_port = htons(53), .sin_addr.s_addr = htonl(server_ip) };
    sendto(sockfd, buf, (unsigned char*)opt - buf, 0, (struct sockaddr *)&dest, sizeof(dest));

    atomic_fetch_add(&total_probes, 1);

    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    int len = recvfrom(sockfd, buf, 512, 0, (struct sockaddr *)&from_addr, &from_len);

    if (len >= (int)sizeof(struct dns_header)) {
        struct dns_header *res = (struct dns_header *)buf;
        if (from_addr.sin_addr.s_addr == htonl(server_ip) && 
            ntohs(res->id) == sent_id && (ntohs(res->flags) & DNS_QR)) {
            int rcode = ntohs(res->flags) & 0x000F;
            if (rcode == 0 || rcode == 3) {
                atomic_fetch_add(&found_count, 1);
                return 1;
            }
        }
    }
    return 0;
}

void* linear_worker(void* args) {
    thread_args_t* t_args = (thread_args_t*)args;
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct timeval tv = {1, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // To keep logic identical, we must use the global index inside the loop
    for (uint32_t i = 0; i < t_args->count; i++) {
        uint32_t current_ip = t_args->start_ip + i;
        if (dns_probe(sockfd, current_ip)) {
            struct in_addr addr; addr.s_addr = htonl(current_ip);
            printf("\r[ALIVE] %-15s (Index: %u)\n", inet_ntoa(addr), atomic_load(&traversal_idx) - 1);
        }
        if (atomic_load(&traversal_idx) % 50 == 0) 
            print_progress(atomic_load(&traversal_idx), global_range_size);
    }
    close(sockfd);
    return NULL;
}

void bisection_search(int sockfd, uint32_t start_ip, int mask) {
    if (mask > 32) return;
    uint32_t range_size = (uint32_t)pow(2, 32 - mask);
    uint32_t test_ip = start_ip + (range_size / 2);

    if (dns_probe(sockfd, test_ip)) {
        struct in_addr addr; addr.s_addr = htonl(test_ip);
        printf("\r[FOUND] %-15s (Index: %u | Depth: /%d)\n", inet_ntoa(addr), atomic_load(&traversal_idx) - 1, mask);
    }
    
    if (mask < 32) {
        bisection_search(sockfd, start_ip, mask + 1);
        bisection_search(sockfd, start_ip + (range_size / 2), mask + 1);
    }
}

int main(int argc, char *argv[]) {
    int linear_mode = 0;
    static struct option long_options[] = {
        {"linear",  no_argument,       0, 'l'},
        {"probe",   required_argument, 0, 'p'},
        {"threads", required_argument, 0, 't'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "lp:t:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'l': linear_mode = 1; break;
            case 'p': resume_at = strtoul(optarg, NULL, 10); break;
            case 't': thread_count = atoi(optarg); break;
            case 'h': print_help(argv[0]); return 0;
            default: return 1;
        }
    }

    if (optind >= argc || !strchr(argv[optind], '/')) {
        print_help(argv[0]); return 1;
    }

    srand(time(NULL));
    char *cidr = strdup(argv[optind]);
    char *ip_part = strtok(cidr, "/");
    int mask = atoi(strtok(NULL, "/"));
    uint32_t start_ip = ntohl(inet_addr(ip_part));
    global_range_size = (uint32_t)pow(2, 32 - mask);

    if (linear_mode) {
        pthread_t threads[thread_count];
        thread_args_t args[thread_count];
        uint32_t chunk_size = global_range_size / thread_count;

        printf("Linear Scan: %s/%d (%u IPs) | Resume Index: %u | Threads: %d\n", 
               ip_part, mask, global_range_size, resume_at, thread_count);

        for (int i = 0; i < thread_count; i++) {
            args[i].start_ip = start_ip + (i * chunk_size);
            args[i].count = (i == thread_count - 1) ? (global_range_size - (i * chunk_size)) : chunk_size;
            // Note: In linear mode, threads process distinct IPs. 
            // The traversal_idx will be updated atomically as they go.
            pthread_create(&threads[i], NULL, linear_worker, &args[i]);
        }
        for (int i = 0; i < thread_count; i++) pthread_join(threads[i], NULL);
        print_progress(global_range_size, global_range_size);
    } else {
        int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        struct timeval tv = {1, 0};
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        printf("Bisection Search: %s/%d | Resume Index: %u\n", ip_part, mask, resume_at);
        bisection_search(sockfd, start_ip, mask);
        close(sockfd);
    }

    printf("\nScan Finished. Probes sent this session: %u\n", atomic_load(&total_probes));
    free(cidr);
    return 0;
}
