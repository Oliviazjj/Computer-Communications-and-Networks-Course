#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <math.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <time.h>


#define MAX_STR_LEN 100
#define MAX_OVERALL_TIME_SIZE 3000
#define MAX_TIME_SIZE 20
#define MAX_HOPS 1000

struct outgoing{
	short id;
	// windows
	int seq_num;
	// linux
	short int sport;
	short int dport;
	struct timeval ts;
};
int tmp_fragment;
char src[MAX_STR_LEN];  
char ult_dst[MAX_STR_LEN];
int fragments=0;
int routers_count=0;
int outgoing_count=0;
int first_id=0;
int last_frag=0;
int first_time_flag=1;
int rtt_router_count=0;
struct outgoing times[MAX_HOPS];
struct router{
	char ip_addr[MAX_STR_LEN];
	struct timeval ts;	
	double rtt[MAX_STR_LEN];
	int num_rtt;
};
struct router routers[MAX_HOPS];

struct fragment{
	int number_packet;
	int offset;

};
struct fragment fragment_list[MAX_HOPS];
const char *timestamp_string(struct timeval ts)
{
	static char timestamp_string_buf[256];

	sprintf(timestamp_string_buf, "%d.%06d",
		(int) ts.tv_sec, (int) ts.tv_usec);

	return timestamp_string_buf;
}
double timeval_to_double(struct timeval time) {
	
	return time.tv_sec*1000+time.tv_usec/1000;
}
int dump_packet(const unsigned char *packet, unsigned int capture_len, struct router routers[MAX_HOPS], int protocols[MAX_STR_LEN],struct timeval ts, struct outgoing times[MAX_HOPS]){
	struct ip *ip;
	unsigned int IP_header_len;
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);
	ip=(struct ip*)packet;
	if(capture_len < sizeof(struct ip)) {
		printf("IP is incorrect.");
		exit(1) ;
	}
	IP_header_len = ip->ip_hl * 4;
	packet += IP_header_len;
	capture_len -= IP_header_len;
	if(capture_len < IP_header_len) {
		printf("IP header is incorrect.");
		exit(1) ;
	}
	analyze_packet(ip,packet,routers,protocols,ts,times);
	
	return 0;


}

int analyze_packet(struct ip *ip, const unsigned char *packet, struct router routers[MAX_HOPS], int protocols[MAX_STR_LEN],struct timeval ts, struct outgoing times[MAX_HOPS]){
	struct icmphdr *icmp;
	struct udphdr *udp;
	uint16_t port;
	unsigned short temp,id,offset;
	int mf;
	//get ID
	temp = ip->ip_id;
	id=(temp>>8)| (temp<<8);
	
	//packet is ICMP
	if(ip->ip_p==1){
		icmp=(struct icmphdr*) packet;

		//add protocol
		 protocols[ip->ip_p]++;
		
		//Packet time out
		if(icmp->type==11){
			//add intermediate router to list
			int has_same_connection=0;
			int i;		
			for(i=0;i<routers_count;i++){
				if(strcmp(routers[i].ip_addr,inet_ntoa(ip->ip_src))==0){
					has_same_connection=1;
				}
			}
			if(has_same_connection==0){
				strcpy(routers[routers_count].ip_addr,inet_ntoa(ip->ip_src));
				routers[routers_count++].ts=ts; 
			}
			//receive packet   calculate RTT
			for(i=0;i<outgoing_count;i++){
				if(times[i].seq_num==icmp->un.echo.sequence){	
					routers[routers_count].rtt[routers[rtt_router_count].num_rtt]=timeval_to_double(ts)-timeval_to_double(times[i].ts);
					routers[routers_count].num_rtt++;
				}
			} 
		//first packet sent in trace route
		}else if((icmp->type==8)&&(ip->ip_ttl==1)&&(first_id==0)){
			//set source and ultimate destination address
			strcpy(ult_dst ,inet_ntoa(ip->ip_dst));
			strcpy(src,inet_ntoa(ip->ip_src));
			//record time packet was sent
			times[outgoing_count].id=ip->ip_id;
			times[outgoing_count].seq_num=icmp->un.echo.sequence;
			times[outgoing_count++].ts=ts;
			//set ID of first packet
			temp=ip->ip_id;
			first_id=(temp>>8)|(temp<<8);
			//Get MF flag value
			mf=(ip->ip_off & 0x0020 >>5);
			if(mf==1){
				printf("add a fragment 111");
			}
		
		//packet is outgoing,record time sent*/
		}else if(icmp->type==8){
			//record time packet was sent
			times[outgoing_count].id=ip->ip_id;
			times[outgoing_count].seq_num=icmp->un.echo.sequence;
			times[outgoing_count++].ts=ts;
		//packet signifiers that the destination has been reached
		}else if((icmp->type==0)| (icmp->type==3)){
			int has_same_connection=0;
			int i;		
			for(i=0;i<routers_count;i++){
				if(strcmp(routers[i].ip_addr,inet_ntoa(ip->ip_src))==0){
					has_same_connection=1;
				}
			}
			if(has_same_connection==0){
				strcpy(routers[routers_count].ip_addr,inet_ntoa(ip->ip_src));
				routers[routers_count].ts=ts; 
				routers[routers_count++].num_rtt=0;
				 
			}
			return 0;	
		}
	//packet is UDP
	}else if(ip->ip_p==17){
		
		struct udphdr *udp;
		udp=(struct udphdr *)packet;
		temp = ip->ip_id;
		id=(temp>>8)| (temp<<8);
		if((ip->ip_ttl==1)&&(first_time_flag==1)){
			strcpy(ult_dst, inet_ntoa(ip->ip_dst));
			strcpy(src,inet_ntoa(ip->ip_src));
			temp=ip->ip_id;
			first_time_flag=0;
			protocols[ip->ip_p]++;
		}
		 if(first_id==id){

			temp = ip->ip_off & 0xFF1F;
			offset=(temp>>8)|(temp<<8);
			mf=(ip->ip_off & 0x0020 >>5);		
			fragment_list[tmp_fragment].number_packet++;
			fragment_list[tmp_fragment].offset = offset*8;

						
		}else{
			
			first_id=id;
			fragment_list[fragments].number_packet=0;
			fragment_list[fragments].offset=0;
			tmp_fragment=fragments;
			fragments++	;
		}
		int i;
		int is_same_connection=0;
		for(i=0; i<outgoing_count;i++){
			if(times[i].sport=ntohs(udp->uh_sport)&&(times[i].dport=ntohs(udp->uh_dport))){
				is_same_connection=1;
				routers[routers_count].rtt[routers[rtt_router_count].num_rtt]=timeval_to_double(ts)-timeval_to_double(times[i].ts);
				routers[routers_count].num_rtt++;
			}
		}
		if(is_same_connection==0){
			times[outgoing_count].sport=ntohs(udp->uh_sport);
			times[outgoing_count++].dport=ntohs(udp->uh_dport);
		}
	}	

			





	
}
void calculateAvgRTT(struct router router_test){
	int i;	
	double sum=0.0;
	double dev=0.0;
	double d;
	for(i=0; i<router_test.num_rtt; i++){
		sum+=router_test.rtt[i];
		
	}
	double avg=sum/router_test.num_rtt;
	double square;
	for(i=0; i<router_test.num_rtt; i++){
		d=timeval_to_double(router_test.ts)-avg;
		square+=d*d;
	}
	dev=sqrt(square/router_test.num_rtt);

	printf("The avg RRT between %s and %s is: %f ms, the s.d. is: %f ms \n", src,router_test.ip_addr,avg,dev);


}

void print_results(struct router routers[MAX_HOPS],int protocols[MAX_STR_LEN] ,struct outgoing times[MAX_HOPS] ){
	printf("The IP address of the source node:%s\n", src);
	printf("The IP address of ultimate destination node:%s\n", ult_dst);
	//print intermediate routers
	printf("The IP address of the intermediate destination node:\n");
	int i;	
	for(i=0;i<routers_count;i++){
		printf("router %d: %s\n",i+1,routers[i].ip_addr);
	}
	printf("\nThe values in the protocol field of IP headers:\n");
	for(i=0; i<MAX_STR_LEN; i++){
		if(protocols[i]>0){
			if(i==1){printf("1: ICMP\n");}
			else if(i==17){printf("17: UDP\n");}
		}
	}
	printf("\n");
	int tmp_counter=0;
	int last_offset=0;
	for(i=0;i<fragments;i++){
		if(fragment_list[i].number_packet!=0){
			tmp_counter++;
			last_offset=fragment_list[i].offset;
			printf("The number of fragments created from the original datagram is: %d\n",tmp_counter);
			printf("The offset of the last fragment is: %d\n",last_offset);
			printf("\n");
		}
	}	
	
	for(i=0; i<routers_count; i++){
		calculateAvgRTT(routers[i]);
	}	
	
}


int main(int argc, char *argv[]){
	pcap_t *pcap;
	char err_buff[PCAP_ERRBUF_SIZE];
	const unsigned char *packet;
	struct pcap_pkthdr header;
	struct router routers[MAX_HOPS];
	struct outgoing times[MAX_HOPS];
	int protocols [MAX_STR_LEN];
	if(argc < 2)
	{
		printf("Usage: <trace_file>\n");
		exit(1);
	}

	pcap = pcap_open_offline(argv[1], err_buff);
	if(pcap==NULL)
	{
		printf("Error: could not read file: %s\n",err_buff);
		exit(1);
	}

	while((packet=pcap_next(pcap,&header)) != NULL)
	{

		if(dump_packet(packet, header.caplen, routers, protocols, header.ts, times)){
			break;
		}
	}
	print_results(routers, protocols, times);
	return 0;
}
