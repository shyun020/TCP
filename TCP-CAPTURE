#include <pcap.h>              // libpcap 라이브러리를 사용하기 위한 헤더
#include <stdio.h>             // 표준 입출력 함수 사용을 위한 헤더
#include <arpa/inet.h>         // 인터넷 주소를 다루는 함수 사용을 위한 헤더
#include <netinet/in.h>        // 인터넷 주소 구조체 사용을 위한 헤더
#include <netinet/ip.h>        // IP 헤더 정의를 위한 헤더
#include <netinet/tcp.h>       // TCP 헤더 정의를 위한 헤더
#include <net/ethernet.h>      // 이더넷 헤더 정의를 위한 헤더

// 패킷 캡처 시 호출될 콜백 함수 선언
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];  // 에러 메시지를 저장할 버퍼
    char *device = pcap_lookupdev(errbuf);  // 캡처할 네트워크 장치 이름 검색
    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);  // 장치를 찾지 못한 경우 오류 메시지 출력
        return(2);
    }
    printf("Device: %s\n", device);  // 사용할 네트워크 장치 출력

    pcap_t *handle;
    // 선택한 장치를 이용해 패킷 캡처를 위한 핸들 생성. 패킷을 캡처할 최대 크기(BUFSIZ), 프로모스큐어스 모드 설정(1), 타임아웃 값 설정(1000ms)
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);  // 핸들 생성 실패 시 오류 메시지 출력
        return(2);
    }

    // TCP 패킷만 필터링하기 위한 BPF 프로그램 컴파일
    struct bpf_program fp;       // 필터 구조체
    char filter_exp[] = "tcp";   // 적용할 필터 (TCP 패킷만 캡처)
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));  // 필터 컴파일 실패 시 오류 메시지 출력
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));  // 필터 설정 실패 시 오류 메시지 출력
        return(2);
    }

    // 무한 루프에서 패킷 캡처 시작, 캡처된 패킷마다 got_packet 콜백 함수 호출
    pcap_loop(handle, 0, got_packet, NULL);

    pcap_close(handle);  // 캡처 핸들 종료
    return(0);
}

// 캡처된 패킷을 처리하는 콜백 함수
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;  // 이더넷 헤더 포인터
    eth_header = (struct ether_header *) packet;  // 패킷에서 이더넷 헤더 위치 찾기
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {  // IP 패킷인지 확인
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));  // IP 헤더 위치 계산
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));  // TCP 헤더 위치 계산

        // 이더넷 헤더 정보 출력
        printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x, ", eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
        printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

        // IP 헤더 정보 출력
        printf("Src IP: %s, ", inet_ntoa(ip_header->ip_src));
        printf("Dst IP: %s\n", inet_ntoa(ip_header->ip_dst));

        // TCP 헤더 정보 출력
        printf("Src port: %d, ", ntohs(tcp_header->th_sport));
        printf("Dst port: %d\n", ntohs(tcp_header->th_dport));

        // 페이로드 길이 계산 및 출력
        int ip_header_len = ip_header->ip_hl * 4;  // IP 헤더 길이
        int tcp_header_len = tcp_header->th_off * 4;  // TCP 헤더 길이
        int payload_len = ntohs(ip_header->ip_len) - (ip_header_len + tcp_header_len);  // 페이로드 길이 계산
        if (payload_len > 0) {
            printf("Payload (%d bytes)\n", payload_len);  // 페이로드 존재 시 길이 출력
        } else {
            printf("No Payload\n");  // 페이로드 없음
        }
    }
}
