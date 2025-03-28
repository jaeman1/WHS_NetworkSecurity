#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#define SNAP_LEN 1518  // 최대 캡처 길이

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    printf("\nEthernet Header:\n");
    printf("   Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
           eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("   Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
           eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    // IP 헤더
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    printf("\nIP Header:\n");
    printf("   Src IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("   Dst IP: %s\n", inet_ntoa(ip_header->ip_dst));

    // TCP 프로토콜인지 확인
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));

        printf("\nTCP Header:\n");
        printf("   Src Port: %d\n", ntohs(tcp_header->source));
        printf("   Dst Port: %d\n", ntohs(tcp_header->dest));

        // 메시지 데이터 출력 (적절한 길이로 제한)
        const u_char *payload = packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4) + (tcp_header->doff * 4);
        int payload_size = header->caplen - (payload - packet);

        printf("\nMessage (Payload):\n");
        if (payload_size > 0) {
            for (int i = 0; i < (payload_size < 50 ? payload_size : 50); i++) {  // 최대 50바이트만 출력
                printf("%c", isprint(payload[i]) ? payload[i] : '.');
            }
            printf("\n");
        } else {
            printf("   No Payload\n");
        }
    } else {
        printf("   Non-TCP packet, skipping...\n");
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];  // 에러 메시지 저장용
    pcap_t *handle;

    // 디바이스 설정
    char *device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }
    printf("Using device: %s\n", device);

    // 디바이스 열기
    handle = pcap_open_live(device, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return 1;
    }

    // 패킷 캡처
    pcap_loop(handle, 10, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
