//John Tunisi, Lawrence L. O'Boyle II, Lucas Braun

#include <cstdio>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <utility>
#include <vector>
#include <algorithm>
using namespace std;

struct sort_by_second{
	bool operator()(const std::pair<pair<u_int32_t,u_int32_t>, int>&l, const std::pair<pair<u_int32_t,u_int32_t>, int>&r){
		return l.second > r.second;
	}
};

//counters
double EII=0,  IEEE802_3=0;
double icmp=0, tcp=0, udp=0, other=0, sum=0;
double ipv4=0, ipv6=0, arp=0, loopback=0, other_data=0, total_data=0;
pair <u_int32_t, u_int32_t> ipv4_pair;	
vector<pair<u_int32_t, u_int32_t> > ipv4list;	
pair <u_int32_t, u_int32_t> tcp_pair;	
vector<pair<u_int32_t, u_int32_t> > tcplist;	
pair <u_int32_t, u_int32_t> udp_pair;	
vector<pair<u_int32_t, u_int32_t> > udplist;	

void print_ethernet_header(const u_char *, const struct pcap_pkthdr *, int);
void print_tcp_packet(const u_char *, int);
bool ipv4_packet(const u_char *, int);
void count_ip_percent(const u_char *, int);



void process_packet(u_char *junk, const struct pcap_pkthdr *h, const u_char *bytes){
	printf("Packet length: %d\n", h->len);
	print_ethernet_header(bytes, h, 500);
	print_tcp_packet(bytes, 500);
	count_ip_percent(bytes, 500);



}

int main(int argc, char *argv[]){
	
	if(argc != 2){
		fprintf(stderr, "Usage: %s <pcapfile>\n", argv[0]);
		return 1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr = pcap_open_offline(argv[1], errbuf);
	
	if(descr == NULL){
		fprintf(stderr, "pcap_open_offline(): %s\n", errbuf);
		return 1;
	}

	pcap_loop(descr, 500, process_packet, NULL);




	printf("Percent IEEE 802.3 : %f%\n", 100*(IEEE802_3/(500)));
	printf("Percent Ethernet II : %f%\n", 100*(EII/(500)));
	printf(" | -TotalData: %f\n", total_data);
	printf(" | -IPv4 Data: %f, %f%\n", ipv4, 100*(ipv4/total_data));
	printf(" | -IPv6 Data: %f, %f%\n", ipv6, 100*(ipv6/total_data));
	printf(" | -ARP Data : %f, %f%\n", arp, 100*(arp/total_data));
	printf(" | -Loopback Data: %f, %f%\n", loopback, 100*(loopback/total_data));
	printf(" | -Other Data: %f, %f%\n", other_data, 100*(other_data/total_data));
	printf(" | -ICMP : %f%\n", 100*(icmp/sum));
	printf(" | -TCP  : %f%\n", 100*(tcp/sum));
	printf(" | -UDP  : %f%\n", 100*(udp/sum));
	printf(" | -Other: %f%\n", 100*(other/sum));

	vector<pair<pair<u_int32_t, u_int32_t>, int > > ipv4counts,
							tcpcounts,
							udpcounts;	
	std::sort(ipv4list.begin(), ipv4list.end());
	std::sort(tcplist.begin(), tcplist.end());
	std::sort(udplist.begin(), udplist.end());

	for(int i=0; i<ipv4list.size(); i++){
		if(ipv4counts.size()==0 || ipv4list[i]!=ipv4counts.back().first){
			ipv4counts.push_back(make_pair(ipv4list[i], 1));
		}
		else{
			int temp = ipv4counts.back().second;
			ipv4counts.pop_back();
			ipv4counts.push_back(make_pair(ipv4list[i],temp+1));
		}
	}
	for(int i=0; i<ipv4counts.size(); i++){
		printf("%u/%u counted %i (%f%)\n", ipv4counts[i].first.first, ipv4counts[i].first.second, ipv4counts[i].second, (double)ipv4counts[i].second/ipv4list.size()*100);
	}

	for(int i=0; i<tcplist.size(); i++){
		if(tcpcounts.size()==0 || tcplist[i]!=tcpcounts.back().first){
			tcpcounts.push_back(make_pair(tcplist[i], 1));
		}
		else{
			int temp = tcpcounts.back().second;
			tcpcounts.pop_back();
			tcpcounts.push_back(make_pair(tcplist[i],temp+1));
		}
	}
	printf("------------TCP COUNTS------------\n");
	std::sort(tcpcounts.begin(), tcpcounts.end(), sort_by_second());
	for(int i=0; i<5; i++){
		printf("%u/%u counted %i (%f%)\n", tcpcounts[i].first.first, tcpcounts[i].first.second, tcpcounts[i].second, (double)tcpcounts[i].second/500 /*tcplist.size()*/ *100);
	}

	for(int i=0; i<udplist.size(); i++){
		if(udpcounts.size()==0 || udplist[i]!=udpcounts.back().first){
			udpcounts.push_back(make_pair(udplist[i], 1));
		}
		else{
			int temp = udpcounts.back().second;
			udpcounts.pop_back();
			udpcounts.push_back(make_pair(udplist[i],temp+1));
		}
	}
	printf("------------UDP COUNTS------------\n");
	std::sort(udpcounts.begin(), udpcounts.end(), sort_by_second());
	for(int i=0; i<5; i++){
		printf("%u/%u counted %i (%f%)\n", udpcounts[i].first.first, udpcounts[i].first.second, udpcounts[i].second, (double)udpcounts[i].second/500 /*udplist.size )*/ *100);
	}

	return 0;
}

void print_ethernet_header(const u_char *Buffer, const struct pcap_pkthdr *h, int Size){
  const struct ether_header *ethernet;
  ethernet = (struct ether_header*)(Buffer);

  u_short ethertype = ntohs(ethernet->ether_type);

  if(ethertype == ETHERTYPE_IP	){
    ipv4 += h->len;  

  //1536 = 0x0600
  if(h->len <= 1536){
    EII++;
  }
  else{
    IEEE802_3++;
  }
}else{

  switch(ethertype){

  case ETHERTYPE_IPV6:
    ipv6 += h->len;
    break;

  case ETHERTYPE_ARP:
    arp += h->len;
    break;

  case ETHERTYPE_LOOPBACK:
    loopback += h->len;
    break;

  default:
    other_data += h->len;
    break;
}

}
  total_data = ipv4+ipv6+arp+loopback+other_data;

	if( h->len <1536){
  printf(" | -EtherType: (%#.4x)\n", ethertype);
}
}

void print_tcp_packet(const u_char *Buffer, int Size){
  unsigned short iphdrlen;

  struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
  
  iphdrlen = iph->ihl * 4;

  struct tcphdr *tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

  int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

  printf(" | -Source Port : %u\n", ntohs(tcph->source));
  printf(" | -Destination Port : %u\n", ntohs(tcph->dest));
}


bool ipv4_packet(const u_char *Buffer, int Size){

  struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));

  if(iph->version == 4){
    return true;
  }
  return false;
}

void count_ip_percent(const u_char *Buffer, int Size){

	struct iphdr *iph = (struct iphdr*)(Buffer +sizeof(struct ethhdr));

        struct tcphdr *tcph = (struct tcphdr*) (Buffer + sizeof(ether_header)+sizeof(struct ip));
        struct udphdr *udph = (struct udphdr*) (Buffer + sizeof(ether_header)+sizeof(struct ip));

	sum++;
	if(ipv4_packet){
	  switch(iph->protocol){

	  case 1: //icmp
	    icmp++;
	    break;

	  case 6: //tcp
	    tcp++;
	    tcp_pair=make_pair(/*iph->saddr, iph->daddr*/tcph->source, tcph->dest);
	    tcplist.push_back(tcp_pair);
	    break;

	  case 17: //udp
	    udp++;
	    udp_pair=make_pair(/*iph->saddr, iph->daddr*/ udph->source, udph->dest);
	    udplist.push_back(udp_pair);
	    break;

	  default:
	    other++;
	    break;
	  }
	}
	ipv4_pair = make_pair(iph->saddr, iph->daddr);
	ipv4list.push_back(ipv4_pair);

}
