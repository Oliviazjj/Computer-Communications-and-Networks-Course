#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <time.h>
#define MAX_STR_LEN 1000
#define MAX_NUM_CONNECTION 2000
unsigned int count = 0;				/*packet counter*/
unsigned int count_connection=0;			/*connection counter*/
unsigned int count_reset=0;			/*reset counter*/
unsigned int count_complete=0;			/*complete connection counter*/
double standard_time=0;
double min_time_duration=0;
double total_time_duration=0;
double max_time_duration=0;
int minRTT=0;
int totalRTT=0;
int maxRTT=0;
int min_numPackets=0;
int total_numPackets=0;
int max_numPackets=0;
int min_window=0;
int total_window=0;
int max_window=0;

struct TCP_hdr {
	short	th_sport;		/* source port number*/
	short	th_dport;		/* destination port number*/
	unsigned int th_seq;		/*sequence number*/
	unsigned int th_ack;		/*acknowledgement number*/
	char th_offx2;		/*data offset, rsvd*/
	#define TH_OFF(th)		(((th)->th_offx2 & 0xf0) >> 4)
	char th_flags;		/*flags*/
	short th_win;			/*window*/
	short	uh_sum;			/* datagram checksum */
	short th_urp;			/*urgent pointer*/
};
struct item{
	char src_ip[MAX_STR_LEN];
	char dst_ip[MAX_STR_LEN];
	unsigned short int src_port;
	unsigned short int dst_port;
	int seq_num,ack_num;
	char flag;
	int window;
	char used;
	int data_bytes;
	double start_time;

};
struct round_trip{
	int seq_num;
	struct timeval time;
};

struct connection{
	char ip_src[MAX_STR_LEN];      /*the ip of source*/
	char ip_dst[MAX_STR_LEN];	/*the ip of destination*/
	unsigned short int port_src;
	unsigned short int port_dst;
	int syn_count;			/*the counter of syn*/
	int fin_count;
	int rst_count;
	double starting_time;
	double ending_time;
	double duration;
	int num_packet_src;
	int num_packet_dst;
	int num_total_packets;
	int cur_data_len_src;
	int cur_data_len_dst;
	int cur_total_data_len;
	int max_win_size;
	int min_win_size;
	double sum_win_size;
	struct round_trip rtt_ary_src[MAX_NUM_CONNECTION/4];
	int rtt_ary_src_len;
	struct round_trip rtt_ary_dst[MAX_NUM_CONNECTION/4];
	int rtt_ary_dst_len;
	int is_set;
};

const char *timestamp_string(struct timeval ts)
{
	static char timestamp_string_buf[256];

	sprintf(timestamp_string_buf, "%d.%06d",
		(int) ts.tv_sec, (int) ts.tv_usec);

	return timestamp_string_buf;
}

void problem_pkt(struct timeval ts, const char *reason)
{
	fprintf(stderr, "%s: %s\n", timestamp_string(ts), reason);
}

void too_short(struct timeval ts, const char *truncated_hdr)
{
	fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
		timestamp_string(ts), truncated_hdr);
}
struct item items[MAX_NUM_CONNECTION];
struct connection c[MAX_NUM_CONNECTION];
void parse_packet(const unsigned char *packet, struct timeval ts,
			unsigned int capture_len)
{
	struct ip *ip;
	struct TCP_hdr *tcp;
	unsigned int IP_header_length;
	unsigned captured = capture_len;
	/* For simplicity, we assume Ethernet encapsulation. */
	if (capture_len < sizeof(struct ether_header))
		{
		/* We didn't even capture a full Ethernet header, so we
		 * can't analyze this any further.
		 */
		too_short(ts, "Ethernet header");
		exit(1);
		}

	/* Skip over the Ethernet header. */
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);
	ip = (struct ip*) packet;
	IP_header_length = ip->ip_hl * 4;	/* ip_hl is in 4-byte words */

	if (capture_len < IP_header_length)
		{ /* didn't capture the full IP header including options */
		too_short(ts, "IP header with options");
		exit(1);
		}

	if (ip->ip_p != IPPROTO_TCP)
		{
		problem_pkt(ts, "non-TCP packet");
		exit(1);
		}

	/* Skip over the IP header to get to the UDP header. */
	packet += IP_header_length;
	capture_len -= IP_header_length;

	if (capture_len < sizeof(struct TCP_hdr))
		{
		too_short(ts, "TCP header");
		exit(1);
		}

	tcp = (struct TCP_hdr*) packet;
	int size_tcp = TH_OFF(tcp)*4;
	int data = captured - sizeof(struct ether_header) - IP_header_length - size_tcp;


	static char timestamp_string_buf[256];
	sprintf(timestamp_string_buf, "%d.%06d",(int)ts.tv_sec,(int)ts.tv_usec);
	double t = atof(timestamp_string_buf);
	if(!standard_time){
		standard_time=t;
	}
	/*obtain IP addresses and stored as char[]*/
	char *addr =inet_ntoa(ip->ip_src);
	strcpy(items[count].src_ip, addr);
	int size=strlen(items[count].src_ip);
	items[count].src_ip[size] = '\0';
	addr = inet_ntoa(ip->ip_dst);
	strcpy(items[count].dst_ip,addr);
	size=strlen(items[count].dst_ip);
	items[count].dst_ip[size] = '\0';
	items[count].src_port = ntohs(tcp->th_sport);
	items[count].dst_port = ntohs(tcp->th_dport);
	items[count].seq_num = ntohl(tcp->th_seq);
	items[count].ack_num = ntohl(tcp->th_ack);
	items[count].flag=(unsigned int)tcp->th_flags;
	items[count].window = ntohs(tcp->th_win);
	items[count].used=0;
	items[count].data_bytes = data;
	items[count].start_time=t;
	count++;


}


void check_connection(){
	c[0].min_win_size=-1;
	c[0].max_win_size=-1;
	int i;
	for(i=0; i<count; i++){
		if(items[i].used==0){
			int j;
			for(j=i; j<count; j++){
				
				if((items[i].src_port == items[j].src_port && items[i].dst_port == items[j].dst_port && !strcmp(items[i].dst_ip, items[j].dst_ip) && !strcmp(items[i].src_ip, items[j].src_ip) && items[j].used == 0)||(items[i].dst_port == items[j].src_port && items[i].src_port == items[j].dst_port && !strcmp(items[i].src_ip, items[j].dst_ip)&& !strcmp(items[i].dst_ip, items[j].src_ip)&&items[j].used == 0)){
					items[j].used=1;
					strcpy(c[count_connection].ip_dst,items[i].dst_ip);
					strcpy(c[count_connection].ip_src,items[i].src_ip);
					c[count_connection].port_src=items[i].src_port;
					c[count_connection].port_dst=items[i].dst_port;
					c[count_connection].num_total_packets++;
					c[count_connection].cur_total_data_len+=items[j].data_bytes;
					c[count_connection].starting_time=items[i].start_time-standard_time;
					c[count_connection].ending_time=items[j].start_time-standard_time;
					if(items[j].flag & TH_FIN){
        					c[count_connection].fin_count++;
					}
    					if( items[j].flag & TH_SYN){
       						c[count_connection].syn_count++;
						
		
					}
					if (items[j].flag & TH_RST){
						c[count_connection].rst_count++;
						count_reset++;
					}	
					

					if(c[count_connection].max_win_size==-1){
						c[count_connection].max_win_size=items[j].window;
					}
					else if(c[count_connection].max_win_size<items[j].window){				
						c[count_connection].max_win_size=items[j].window;
					}
					if(c[count_connection].min_win_size==-1){
						c[count_connection].min_win_size=items[j].window;
					}
					else if(c[count_connection].min_win_size>items[j].window){				
						c[count_connection].min_win_size=items[j].window;
					}
					c[count_connection].sum_win_size+=items[j].window;

					/*same src port & dst port*/
					if(items[i].src_port == items[j].src_port && items[i].dst_port == items[j].dst_port ){
						c[count_connection].num_packet_src++;
						c[count_connection].cur_data_len_src+=items[j].data_bytes;	
						c[count_connection].rtt_ary_src_len++;
					
					}


					/*opposite port */
					if(items[i].dst_port == items[j].src_port && items[i].src_port == items[j].dst_port ){
						c[count_connection].num_packet_dst++;
						c[count_connection].cur_data_len_dst+=items[j].data_bytes;
						c[count_connection].rtt_ary_dst_len++;
						
					}
				}
				
			}
			count_connection++;
			c[count_connection].min_win_size=-1;
			c[count_connection].max_win_size=-1;
		}

	}


	/************************************A Part*********************************/
    	printf("A) Total number of connections: %d\n", count_connection);
	printf("---------------------------------------------------------------------\n");




	/************************************B Part*********************************/
	printf("B) Connections' details:\n\n");
	int k;
			/*set all of the variables into the corresponding value of the first connection*/
	int flag_packets=0;
   	for(k=0; k<count_connection; k++){
        	printf("Connection %d:\n",k+1);
        	printf("Source Address: %s\n",c[k].ip_src);
        	printf("Destination Address: %s\n",c[k].ip_dst);
        	printf("Source Port: %d\n",c[k].port_src);
        	printf("Destination Port: %d\n",c[k].port_dst);
		printf("Status: S%dF%d\n",c[k].syn_count,c[k].fin_count);
		if((c[k].syn_count==1&&c[k].fin_count==1)||(c[k].syn_count==2&&c[k].fin_count==2)||(c[k].syn_count==2&&c[k].fin_count==1)){
        		printf("Start time: %.3f\n", c[k].starting_time);
        		printf("Ending time: %.3f\n", c[k].ending_time);
			c[k].duration=c[k].ending_time-c[k].starting_time;
        		printf("Duration: %.3f\n",c[k].duration);
        		printf("Number of Packet from Source: %d\n",c[k]. num_packet_src);
        		printf("Number of Packet from Destination:  %d\n",c[k]. num_packet_dst);
        		c[k].num_total_packets=c[k].num_packet_src+c[k]. num_packet_dst;
        		printf("Total Number of Packets:  %d\n",c[k].num_total_packets);
			
			if(flag_packets==0){
				flag_packets=1;
				min_numPackets=c[0].num_total_packets;
				max_numPackets=c[0].num_total_packets;
				min_window=c[0].min_win_size;
				max_window=c[0].max_win_size;
				min_time_duration=c[0].duration;
				
				minRTT;
				maxRTT;	
			}
			if(min_numPackets>c[k].num_total_packets){
				min_numPackets=c[k].num_total_packets;
			}
			total_numPackets+=c[k].num_total_packets;
			if(max_numPackets<c[k].num_total_packets){
				max_numPackets=c[k].num_total_packets;
			}
			if(min_window>c[k].min_win_size){
				min_window=c[k].min_win_size;
			}
			total_window+=c[k].sum_win_size;
			if(max_window<c[k].max_win_size){
				max_window=c[k].max_win_size;
			}
			if(min_time_duration>c[k].duration){
				min_time_duration=c[k].duration;
			}
			total_time_duration+=c[k].duration;
			if(max_time_duration<c[k].duration){
				max_time_duration=c[k].duration;
			}
        		printf("Number of data bytes sent from Source to Destination:  %d\n", c[k]. cur_data_len_src);
        		printf("Number of data bytes sent from Destination to Source:  %d\n", c[k]. cur_data_len_dst);
        		c[k].cur_total_data_len=c[k]. cur_data_len_src+c[k]. cur_data_len_dst;
        		printf("Total number of data bytes: %d\n", c[k].cur_total_data_len);
			count_complete++;
		}
        	printf("END\n");
		printf("--------------------------------\n");		



		
		


    	}


	/************************************C Part*********************************/

	printf("C) General\n\n");		
	printf("Total number of complete TCP connections: %d\n", count_complete);
	printf("Number of reset TCP connections:  %d\n", count_reset);
	printf("Number of TCP connections that were still open when the trace capture ended: %d\n", count_connection-count_complete );
	printf("---------------------------------------------------------------------\n");

	/************************************D Part*********************************/

	
	printf("\n(D) Complete TCP connections:\n\n"); 
				printf("Minimum time durations: %.3f\n",min_time_duration); 
				printf("Mean time durations: %.3f\n",total_time_duration/count_complete);
				printf("Maximum time durations: %.3f\n\n",max_time_duration); 
				printf("Minimum RTT values including both send/received: %d\n",minRTT);
				printf("Mean RTT values including both send/received: %d\n",totalRTT/count_connection);
				printf("Maximum RTT values including both send/received: %d\n\n",maxRTT);
				printf("Minimum number of packets including both send/received: %d\n",min_numPackets);
				printf("Mean number of packets including both send/received: %d\n",total_numPackets/count_complete);
				printf("Maximum number of packets including both send/received: %d\n\n",max_numPackets);
				printf("Minimum receive window sizes including both send/received: %d\n",min_window),
				printf("Mean receive window sizes including both send/received: %d\n",total_window/count);
				printf("Maximum receive window sizes including both send/received: %d\n",max_window); 
				printf("--------------------------------------------------------\n");


}



int main(int argc, char *argv[]){
	struct pcap_pkthdr header;
  	const unsigned char *packet;
	if(argc !=2){
		printf("Error: Program requires one argument, the trace file\n");
		exit(1);
	}
	pcap_t *pcap;
   	char errbuf[PCAP_ERRBUF_SIZE];
	pcap = pcap_open_offline(argv[1],errbuf);
	if(pcap == NULL){
		printf("Couldn't open pcap file %s\n", errbuf);
		exit(1);
	}
	while((packet = pcap_next(pcap, &header)) != NULL){
		parse_packet(packet, header.ts, header.caplen);
	} 
	check_connection();
	
	return 0;





}




