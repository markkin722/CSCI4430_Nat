/*
 * nftest.c
 * - demo program of netfilter_queue
 * - Patrick P. C. Lee
 *
 * - To run it, you need to be in root
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include "checksum.h"
#include "checksum.c"

extern "C" {
	#include <linux/netfilter.h>     /* Defines verdicts (NF_ACCEPT, etc) */
	#include <libnetfilter_queue/libnetfilter_queue.h>
}

/*
 * Callback function installed to netfilter queue
 */
static int Callback(nfq_q_handle* myQueue, struct nfgenmsg* msg, 
		nfq_data* pkt, void *cbData) {
	unsigned int id = 0;
	nfqnl_msg_packet_hdr *header;
	
	printf("pkt recvd: ");
	if ((header = nfq_get_msg_packet_hdr(pkt))) {
		id = ntohl(header->packet_id);
		printf("  id: %u\n", id);
		printf("  hw_protocol: %u\n", ntohs(header->hw_protocol));		
		printf("  hook: %u\n", header->hook);
	}

	// print the timestamp (PC: seems the timestamp is not always set)
	struct timeval tv;
	if (!nfq_get_timestamp(pkt, &tv)) {
		printf("  timestamp: %lu.%lu\n", tv.tv_sec, tv.tv_usec);
	} else {
		printf("  timestamp: nil\n");
	}

	// Print the payload; in copy meta mode, only headers will be
	// included; in copy packet mode, whole packet will be returned.
	printf(" payload: ");
	unsigned char *pktData;
	int len = nfq_get_payload(pkt, (char**)&pktData);

	/*1. check the protocol of pkt (TCP/UDP) */
	struct ip* ip_hdr = (struct ip*)pktData;

	if (ip_hdr->ip_p == IPPROTO_TCP) {
		struct tcphdr* tcp_hdr = (struct tcphdr*)((unsigned char*)pktData + (ip_hdr->ip_hl << 2));
		printf("It is TCP protocol.\n");
		//a. accept with translation
		// recalculate the checksum 

		//b. accept without translation
		// recalculate the checksum

	} else if (ip_hdr->ip_p == IPPROTO_UDP) {
		struct udphdr* udp_hdr = (struct udphdr*)((unsigned char*)pktData + (ip_hdr->ip_hl << 2));
		printf("It is UDP protocol.\n");

		//c. accept with translation
		// recalculate the checksum 

		//d. accept without translation
		// recalculate the checksum

	} else if (ip_hdr->ip_p == IPPROTO_ICMP){
		printf("It is ICMP protocol.%02x\n", ip_hdr->ip_p);
		printf("pktchecksum.%d\n", ip_hdr->ip_sum);
		printf("ipchecksum.%d\n", ip_checksum((unsigned char*) ip_hdr));
		printf("DROPPED.\n");
		//Drop it
		return nfq_set_verdict(myQueue, id, NF_DROP, 0, NULL);
	} else {
		printf("They are other protocol.\n");
		printf("DROPPED.\n");
		return nfq_set_verdict(myQueue, id, NF_DROP, 0, NULL);
	}

	if (len > 0) {
		for (int i=0; i<len; ++i) {
			printf("%02x ", pktData[i]);
		}
	}
	printf("\n");
	
	// add a newline at the end
	printf("\n");
	
	// For this program we'll always accept the packet...
	return nfq_set_verdict(myQueue, id, NF_ACCEPT, 0, NULL);

	// end Callback
}

/*
 * Main program
 */
int main(int argc, char **argv) {
	struct nfq_handle *nfqHandle;
	struct nfq_q_handle *myQueue;
	struct nfnl_handle *netlinkHandle;
	char pub_ip[20];
	char int_ip[20];
	int sub_mask;
	
	int fd, res;
	char buf[4096];
	
	if(argc != 4){
		printf("usage:sudo ./nftest <public ip> <internal ip> <subnet mask>\n");
		exit(0);
	}	
	
	strcpy(pub_ip,argv[1]);
	strcpy(int_ip, argv[2]);
	sub_mask = atoi(argv[3]);

	printf("public ip: %s\n", pub_ip);
	printf("internal ip: %s\n", int_ip);
	printf("subnet mask: %d\n", sub_mask);

	// Get a queue connection handle from the module
	if (!(nfqHandle = nfq_open())) {
		fprintf(stderr, "Error in nfq_open()\n");
		exit(-1);
	}

	// Unbind the handler from processing any IP packets 
	// (seems to be a must)
	if (nfq_unbind_pf(nfqHandle, AF_INET) < 0) {
		fprintf(stderr, "Error in nfq_unbind_pf()\n");
		exit(1);
	}

	// Bind this handler to process IP packets...
	if (nfq_bind_pf(nfqHandle, AF_INET) < 0) {
		fprintf(stderr, "Error in nfq_bind_pf()\n");
		exit(1);
	}

	// Install a callback on queue 0
	if (!(myQueue = nfq_create_queue(nfqHandle,  0, &Callback, NULL))) {
		fprintf(stderr, "Error in nfq_create_queue()\n");
		exit(1);
	}

	// Turn on packet copy mode
	if (nfq_set_mode(myQueue, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "Could not set packet copy mode\n");
		exit(1);
	}

	netlinkHandle = nfq_nfnlh(nfqHandle);
	fd = nfnl_fd(netlinkHandle);

	while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) {
		// I am not totally sure why a callback mechanism is used
		// rather than just handling it directly here, but that
		// seems to be the convention...
		nfq_handle_packet(nfqHandle, buf, res);
		// end while receiving traffic
	}

	nfq_destroy_queue(myQueue);

	nfq_close(nfqHandle);

	return 0;

	// end main
}
