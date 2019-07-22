#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

struct ethernet_header{
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
};

struct ip_header{
    uint8_t vhl;    // version + header_length
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_ip[4];
    uint8_t dest_ip[4];
};

struct tcp_header{
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t hlen_res;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

void print_usage(){
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

void print_mac(uint8_t * mac){
    for(int i=0; i<6; i++){
        printf("%02x", *(mac+i));
        if(i != 5) printf(":");
    }
    putchar('\n');
}

void print_ip(uint8_t * ip){
    for(int i=0; i<4; i++){
        printf("%d", *(ip+i));
        if(i != 3) printf(".");
    }
    putchar('\n');
}

void print_port(uint16_t port){
    printf("%d\n", ntohs(port));
}

void print_tcp_data(uint8_t * data, int length){
    for(int i=0; i < length; i++){
        printf("%02x ", *(data+i));
        // 10 char print
        if(i == 9) break;
    }
    putchar('\n');
}

int main(int argc, char * argv[]){

    //structure pointer declare
    pcap_pkthdr* header;
    ethernet_header* eth;
    ip_header* ip;
    tcp_header* tcp;
    const u_char* packet;

    if(argc != 2){
        print_usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL){
        fprintf(stderr, "Counln't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    // packet analysis
    while(true){
        //packet capture
        int res = pcap_next_ex(handle, &header, &packet);

        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;
        /*
            printf("%d\n", PCAP_ERROR);	  #define PCAP_ERROR -1
            printf("%d\n", PCAP_ERROR_BREAK); #define PCAP_ERROR_BREAK -2
        */

        // ethernet section
        eth = (ethernet_header *)packet;

        // ethernet print
        printf("Dst mac > ");
        print_mac(eth->dest_mac);
        printf("Src mac > ");
        print_mac(eth->src_mac);

        // ip protocol check
        if(ntohs(eth->type) == 0x0800){
            // ip sector
            int ip_offset = sizeof(struct ethernet_header);
            ip = (ip_header *)(packet + sizeof(struct ethernet_header));
            int total_length = ntohs(ip->total_length);
            int ip_header_length = (ip->vhl & 0x0F) * 4;

            // ip print
            printf("Dst ip > ");
            print_ip(ip->dest_ip);
            printf("Src ip > ");
            print_ip(ip->src_ip);

            // tcp protocol check
            if(ip->protocol == 0x06){
                // tcp sector
                int tcp_offset = ip_offset + ip_header_length;
                tcp = (tcp_header *)(packet + tcp_offset);

                // port print
                printf("Dst port > ");
                print_port(tcp->dest_port);
                printf("Src port > ");
                print_port(tcp->src_port);


                int tcp_header_length = (tcp->hlen_res & 0xF0) >> 2;
                int data_offset = ip_header_length + tcp_header_length;
                // data_offset is Offset of data from ip_header

                // data check
                if(total_length == data_offset){
                    printf("No data!!\n");
                }else{
                    int data_length = total_length - data_offset;
                    print_tcp_data((uint8_t *)(packet + ip_offset + data_offset), data_length);
                }

            }else{
                printf("This is not TCP protocol\n");
            }
        }else{
            printf("This is not IP protocol\n");
        }
        putchar('\n');
    }
    pcap_close(handle);
    return 0;
}
