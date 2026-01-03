#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <getopt.h>

// Global Counters & Config
atomic_uint traversal_idx = 0;   // Logical position in the scan tree
atomic_uint actual_probes = 0;    // Physical packets sent this session
uint32_t resume_limit = 0;        // Value from -p
int global_max_mask = 30;         // Value from -m

typedef struct {
    uint32_t start_ip;
    int initial_mask;
    int thread_id;
} thread_data_t;

void print_help(char *name) {
    printf("Usage: %s [OPTIONS] <CIDR>\n\n", name);
    printf("Options:\n");
    printf("  -p, --probe NUM     Resume scan from probe index NUM\n");
    printf("  -m, --mask NUM      Set max depth mask (default: 30)\n");
    printf("  -t, --threads NUM   Set number of worker threads (default: nproc*512)\n");
    printf("  -h, --help          Show this help menu\n\n");
    printf("Example:\n");
    printf("  %s -p 12000000 0.0.0.0/1\n", name);
}

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int ping_check(int sockfd, uint32_t ip, int thread_id) {
    // Resume Logic: Increment traversal index regardless of whether we send a packet
    uint32_t current_idx = atomic_fetch_add(&traversal_idx, 1);
    if (current_idx < resume_limit) return 0; 

    char packet[64];
    struct icmp *icmp = (struct icmp *)packet;
    struct sockaddr_in dest_addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(ip) };

    memset(packet, 0, sizeof(packet));
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_id = htons(getpid() + thread_id);
    icmp->icmp_seq = htons(current_idx % 65535); 
    icmp->icmp_cksum = checksum(packet, sizeof(packet));

    sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    atomic_fetch_add(&actual_probes, 1);

    unsigned char recv_buf[128];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    while (1) {
        int len = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from_addr, &from_len);
        if (len <= 0) return 0;

        struct ip *ip_hdr = (struct ip *)recv_buf;
        int ip_hdr_len = ip_hdr->ip_hl << 2;
        struct icmp *icmp_res = (struct icmp *)(recv_buf + ip_hdr_len);

        if (icmp_res->icmp_type == ICMP_ECHOREPLY && 
            from_addr.sin_addr.s_addr == dest_addr.sin_addr.s_addr &&
            icmp_res->icmp_id == htons(getpid() + thread_id)) {
            return 1;
        }
    }
}

void find_active_ranges(int sockfd, uint32_t start_ip, int mask, int thread_id) {
    if (mask > global_max_mask) return;

    uint32_t range_size = (uint32_t)pow(2, 32 - mask);
    uint32_t middle_ip = start_ip + (range_size / 2);

    // Get current index once to use for both logic and display
    uint32_t current_idx = atomic_load(&traversal_idx);

    // Only update the progress line every 1000 probes to keep the UI clean
    if (current_idx >= resume_limit && current_idx % 1000 == 0) {
        struct in_addr current_view;
        current_view.s_addr = htonl(middle_ip);
        // \r to return to start, then enough spaces at the end to clear old data
        printf("\33[2K\r[Probes: %-10u] Testing: %-15s/%-2d   ", 
               current_idx, inet_ntoa(current_view), mask);
        fflush(stdout);
    }

    if (ping_check(sockfd, middle_ip, thread_id)) {
        struct in_addr addr;
        addr.s_addr = htonl(start_ip);
        // The leading \n pushes the progress line up so [FOUND] gets its own line
        printf("\n[FOUND] %-15s/%-2d (at index %u)\n", inet_ntoa(addr), mask, current_idx);
        return; 
    }

    if (mask < global_max_mask) {
        find_active_ranges(sockfd, start_ip, mask + 1, thread_id);
        find_active_ranges(sockfd, start_ip + (range_size / 2), mask + 1, thread_id);
    }
}

void* thread_wrapper(void* arg) {
    thread_data_t* data = (thread_data_t*)arg;
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    struct timeval tv = {0, 350000}; 
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    find_active_ranges(sockfd, data->start_ip, data->initial_mask, data->thread_id);
    
    close(sockfd);
    return NULL;
}

int main(int argc, char *argv[]) {
    int nproc = sysconf(_SC_NPROCESSORS_ONLN) * 512;
    
    static struct option long_options[] = {
        {"probe",   required_argument, 0, 'p'},
        {"mask",    required_argument, 0, 'm'},
        {"threads", required_argument, 0, 't'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:m:t:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p': resume_limit = strtoul(optarg, NULL, 10); break;
            case 'm': global_max_mask = atoi(optarg); break;
            case 't': nproc = atoi(optarg); break;
            case 'h': print_help(argv[0]); return 0;
            default: return 1;
        }
    }

    if (optind >= argc) {
        print_help(argv[0]);
        return 1;
    }

    char *cidr_input = strdup(argv[optind]);
    char *ip_part = strtok(cidr_input, "/");
    char *mask_part = strtok(NULL, "/");
    if (!mask_part) { printf("Error: Invalid CIDR\n"); return 1; }
    
    int initial_mask = atoi(mask_part);
    uint32_t start_ip = ntohl(inet_addr(ip_part));

    int split_bits = (int)ceil(log2(nproc));
    int thread_mask = initial_mask + split_bits;
    uint32_t subrange_size = (uint32_t)pow(2, 32 - thread_mask);

    printf("Starting Scan: %s/%d (Threads: %d, Max Mask: /%d)\n", ip_part, initial_mask, nproc, global_max_mask);
    if (resume_limit > 0) printf("Resuming from index: %u\n", resume_limit);

    pthread_t threads[nproc];
    thread_data_t t_data[nproc];

    for (int i = 0; i < nproc; i++) {
        t_data[i].start_ip = start_ip + (i * subrange_size);
        t_data[i].initial_mask = thread_mask;
        t_data[i].thread_id = i;
        pthread_create(&threads[i], NULL, thread_wrapper, &t_data[i]);
    }

    for (int i = 0; i < nproc; i++) pthread_join(threads[i], NULL);

    printf("\nScan complete. Probes sent: %u\n", atomic_load(&actual_probes));
    free(cidr_input);
    return 0;
}
