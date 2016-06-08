/**
 * \file sniffer.c
 * \brief Contains the callback for packets captured by libpcap
 * \date May 18, 2016
 * 
 * This file contains an array defining the radiotap header fields requirements
 * in terms of memory alignment and the size of each field.<br>
 * It also contains the callback called by pcap when a packet is captured.
 * This callback decodes the content of the packet by successively converting the
 * packet pointer to a corresponding header and moving along to the next header.<br>
 * Two fuctions are also declared for printing the packet's payload in hex and ascii 
 * format.
 */

#include "sniffer.h"
#include "http-client.h"
//#define PRINT_INFO(x)	puts(x);
#define PRINT_INFO(x)	
#define PRINT_DEBUG(x) puts(x);

char debugBuffer[1024] = {0};

/**
 * \brief Array containing the alignment requirements and content length of all radiotap header fields
 * 
 * Each element of the array corresponds to a radiotap header field (see ::ieee80211_radiotap_type).<br>
 * It stored the alignment requirement and total length of each field.
 */
const struct radiotap_align_size radiotap_field_sizes[] = {		
	{ 8, 8 },	/* [IEEE80211_RADIOTAP_TSFT] = 0 */
	{ 1, 1 },	/* [IEEE80211_RADIOTAP_FLAGS] = 1 */
	{ 1, 1 },	/* [IEEE80211_RADIOTAP_RATE] = 2 */
	{ 2, 4 },	/* [IEEE80211_RADIOTAP_CHANNEL] = 3 */        
	{ 2, 2 },	/* [IEEE80211_RADIOTAP_FHSS] = 4 */ 
	{ 1, 1 },	/* [IEEE80211_RADIOTAP_DBM_ANTSIGNAL] = 5 */            
	{ 1, 1 },	/* [IEEE80211_RADIOTAP_DBM_ANTNOISE] = 6 */             
	{ 2, 2 },	/* [IEEE80211_RADIOTAP_LOCK_QUALITY] = 7 */             
	{ 2, 2 },	/* [IEEE80211_RADIOTAP_TX_ATTENUATION] = 8 */           
	{ 2, 2 },	/* [IEEE80211_RADIOTAP_DB_TX_ATTENUATION] = 9 */        
	{ 1, 1 },	/* [IEEE80211_RADIOTAP_DBM_TX_POWER] = 10 */            
	{ 1, 1 },	/* [IEEE80211_RADIOTAP_ANTENNA] = 11 */                 
	{ 1, 1 },	/* [IEEE80211_RADIOTAP_DB_ANTSIGNAL] = 12 */            
	{ 1, 1 },	/* [IEEE80211_RADIOTAP_DB_ANTNOISE] = 13 */             
	{ 2, 2 },	/* [IEEE80211_RADIOTAP_RX_FLAGS] = 14 */                
	{ 2, 2 },	/* [IEEE80211_RADIOTAP_TX_FLAGS] = 15 */                
	{ 1, 1 },	/* [IEEE80211_RADIOTAP_RTS_RETRIES] = 16 */             
	{ 1, 1 },	/* [IEEE80211_RADIOTAP_DATA_RETRIES] = 17 */            
	{ 0, 0 },	/* Unofficial, used by FreeBSD [IEEE80211_RADIOTAP_XCHANNEL] = 18 */                
	{ 1, 3 },	/* [IEEE80211_RADIOTAP_MCS] = 19 */                     
	{ 4, 8 },	/* [IEEE80211_RADIOTAP_AMPDU_STATUS] = 20 */            
	{ 2, 12 }	/* [IEEE80211_RADIOTAP_VHT] = 21 */                     
	
	/*
	* add more here as they are defined in		
	* include/net/ieee80211_radiotap.h		
	*/		
};

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
	static unsigned long long count = 0;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct ieee80211_radiotap_header * rtap_head;	/* Radiotap header */
	const struct ieee80211_header * eh;		/* 80211 (ethernet) header */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const unsigned char *payload;                    /* Packet payload */

	/* Size of the different parts of the packet */
	int size_radiotap;
	int size_ip;
	int size_tcp;
	int size_payload;

	const unsigned char * mac;
	 __attribute__((__unused__)) const unsigned char *mac_receive;	/* Sender's and receiver's MAC addresses */
	unsigned long present_flags;	/* it_present flags to decode */
	int offset = 0;
	char rssi[3] = {0};

	const unsigned char * ptrPacket = packet;	/* Pointer used to go through the packet and decode it */
	
	int field, idFlag = 0, idRssi = 0;	/* Counters used to decode it_present flags */

	count++;
	
	debugBuffer[0] = 0;

	/* First in the packet, we have the radio header */
	rtap_head = (struct ieee80211_radiotap_header *) ptrPacket;

	/* Get length of the radiotap header */
	size_radiotap = (int) rtap_head->it_len[0] + 256 * (int) rtap_head->it_len[1];
	/* Move past the radiotap header */
	ptrPacket += size_radiotap;
	/* Get a pointer to the ieee80211 header */
	eh = (struct ieee80211_header *) (ptrPacket);
	/* Move past the ieee80211 header */
	ptrPacket += sizeof(struct ieee80211_header);

	/* Only parse big packets (more likely to be ip packets) */
	if ((eh->frame_control & 0x03) == 0x01 && header->len > 300) {
		sprintf( debugBuffer+strlen(debugBuffer), "Packet n°%llu\n\r", count);
		mac = (unsigned char*)eh->source_addr;

		mac_receive = (unsigned char*)eh->recipient;
		
		offset = 16;	/* size of the radiotap header */
		
		/* Loop through the present flags from the radiotap header */
		do {
			/* Read flag into 32-bit value */
			present_flags = *(((u_char*)rtap_head->it_present)+(idFlag*4)) | 
				*(((u_char*)rtap_head->it_present)+(idFlag*4+1))<<8 |
				*(((u_char*)rtap_head->it_present)+(idFlag*4+2))<<16 | 
				*(((u_char*)rtap_head->it_present)+(idFlag*4+3))<<24;
// 			printf("present_flags flag : %hhx %hhx %hhx %hhx\n\r", present_flags, present_flags>>8, present_flags>>16, present_flags>>24);
				
			
			for(field = IEEE80211_RADIOTAP_TSFT; field <= IEEE80211_RADIOTAP_VHT; field++) {
				/* For each field, check if it is present */
				if(present_flags & (1 << field)) {
					/* If the field is present but misaligned, we add a padding to the offset */
					if((offset % radiotap_field_sizes[field].align) != 0) {
						/* Compute size of the misalignment */
						offset += radiotap_field_sizes[field].align - 
							(offset % radiotap_field_sizes[field].align);
					}
					
					/* For RSSI fields, store their values in the corresponding array */
					if(field == IEEE80211_RADIOTAP_DBM_ANTSIGNAL) {
						rssi[idRssi++] = *((unsigned char *) rtap_head + offset) - 0x100;
					}
						
					/* Add the field content length to the offset */
					offset += radiotap_field_sizes[field].size;
				}
			}
			idFlag++;
		}while(present_flags & (1 << IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE));	/* IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE indicates that another 32-bit flag is present */
		
		if(offset != size_radiotap) {
			PRINT_DEBUG(debugBuffer);
			printf("Strange header detected !\n\rHeader size smaller than offset\n\r");
			print_payload(ptrPacket, size_radiotap);
			return;
		}
		printf(" Header OK : \n\r");
		print_payload(ptrPacket, size_radiotap);
		
		sprintf( debugBuffer+strlen(debugBuffer), "rssi[0] = %d, rssi[1] = %d, rssi[2] = %d\n\r", rssi[0], rssi[1], rssi[2]);

		// 		printf("Sequence control : %d\n\r", eh->sequence_control);
		sprintf( debugBuffer+strlen(debugBuffer), "%d bytes -- %02X:%02X:%02X:%02X:%02X:%02X -- offset : %d\n",
				size_radiotap, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], offset);

		/* After ieee80211 header, there is the Logical Link Control header */
		 __attribute__((__unused__)) llcsnaphdr * logic = (llcsnaphdr*) (ptrPacket);
		ptrPacket += sizeof(llcsnaphdr);

		/* After logic Link control, there is IP header */
		ip = (struct sniff_ip*)(ptrPacket);

		/* Get the size of the IP header and check it is less than 20 */
		size_ip = IP_HL(ip)*4;
		if (size_ip < 20) {
			PRINT_INFO(debugBuffer);
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return;
		}

		/* Only send packet when packet is for the server */
		if(ip->ip_dst.s_addr == inet_addr(HOST)) {
			/* Send request to the server */
			send_request(inet_ntoa(ip->ip_src),rssi[0],rssi[1],rssi[2]);
			
			/* print source and destination IP addresses */
			sprintf( debugBuffer+strlen(debugBuffer), "       From: %s\n", inet_ntoa(ip->ip_src));
			sprintf( debugBuffer+strlen(debugBuffer), "         To: %s\n", inet_ntoa(ip->ip_dst));

			/* determine protocol */	
			switch(ip->ip_p) {
				case IPPROTO_TCP:
					sprintf( debugBuffer+strlen(debugBuffer), "   Protocol: TCP\n");
					break;
				case IPPROTO_UDP:
					sprintf( debugBuffer+strlen(debugBuffer), "   Protocol: UDP\n");
					PRINT_INFO(debugBuffer);
					return;
				case IPPROTO_ICMP:
					sprintf( debugBuffer+strlen(debugBuffer), "   Protocol: ICMP\n");
					PRINT_INFO(debugBuffer);
					return;
				case IPPROTO_IP:
					sprintf( debugBuffer+strlen(debugBuffer), "   Protocol: IP\n");
					PRINT_INFO(debugBuffer);
					return;
				default:
					sprintf( debugBuffer+strlen(debugBuffer), "   Protocol: unknown\n");
					PRINT_INFO(debugBuffer);
					return;
			}

			/*
			 *  OK, this packet is TCP.
			 */

			/* define/compute tcp header offset */
			ptrPacket += size_ip;
			tcp = (struct sniff_tcp*)(ptrPacket);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				sprintf( debugBuffer+strlen(debugBuffer), "   * Invalid TCP header length: %u bytes\n", size_tcp);
				PRINT_INFO(debugBuffer);
				return;
			}
			
			/* Print source and destination ports */
			sprintf( debugBuffer+strlen(debugBuffer), "   Src port: %d\n", ntohs(tcp->th_sport));
			sprintf( debugBuffer+strlen(debugBuffer), "   Dst port: %d\n", ntohs(tcp->th_dport));

			/* Define/compute tcp payload (segment) offset */
			ptrPacket += size_tcp;
			payload = ptrPacket;

			/* Compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

			/*
			 * Print payload data; it might be binary, so don't just
			 * treat it as a string.
			 */
			if (size_payload > 0) {
				sprintf( debugBuffer+strlen(debugBuffer), "   Payload (%d bytes):\n", size_payload);
				PRINT_INFO(debugBuffer);
				print_payload(payload, size_payload);
			}
			
			if(rssi[0] == 0 || rssi[1] == 0 || rssi[2] == 0) {
				sprintf( debugBuffer+strlen(debugBuffer), "RSSI : %d, %d, %d\n\r", rssi[0], rssi[1], rssi[2]);
				PRINT_INFO(debugBuffer);
				while(1) {}
			}
			
		}
	}
}

void print_hex_ascii_line(const unsigned char *payload, int len, int offset)
{
	int i;
	int gap;
	const unsigned char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");
}

void print_payload(const unsigned char *payload, int len)
{
	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const unsigned char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
}
