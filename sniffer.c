#include "sniffer.h"
#include <semaphore.h>
#include "http-client.h"

sem_t synchro;


/* Callback for packet captured */
void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
	static unsigned long long count = 0;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct ieee80211_radiotap_header * rtap_head;	/* Radiotap header */
	const struct ieee80211_header * eh;		/* 80211 (ethernet) header */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const unsigned char *payload;                    /* Packet payload */

	int size_radiotap;
	int size_ip;
	int size_tcp;
	int size_payload;

	const unsigned char * mac, *mac_receive;
	unsigned char first_flags;
	int offset = 0;
	char rssi;

	const unsigned char * ptrPacket = packet;	/* Pointer used to go through the packet and decode it */

	count++;

	/* First in the packet, we have the radio header */
	rtap_head = (struct ieee80211_radiotap_header *) ptrPacket;

	/* Get length of the radiotap header */
	size_radiotap = (int) rtap_head->it_len[0] + 256 * (int) rtap_head->it_len[1];
	/* Go after radiotap header */
	ptrPacket += size_radiotap;
	/* ieee802 (ethernet) header after radiotap header */
	eh = (struct ieee80211_header *) (ptrPacket);
	ptrPacket += sizeof(struct ieee80211_header);

	/* Only get big packets (more likely to be ip packets) */
	if ((eh->frame_control & 0x03) == 0x01 && header->len > 300) {
		printf("Packet n°%llu\n\r", count);
		mac = (unsigned char*)eh->source_addr;

		mac_receive = (unsigned char*)eh->recipient;
		first_flags = rtap_head->it_present[0];
		offset = 8;	/* size of the radiotap header */

		offset += 8;

		offset += ((first_flags & 0x01) == 0x01) ? 8 : 0 ;	/* IEEE80211_RADIOTAP_TSFT */
		offset += ((first_flags & 0x02) == 0x02) ? 1 : 0 ; /* IEEE80211_RADIOTAP_FLAGS */


		offset += 1; /* Whatever the IEEE80211_RADIOTAP_RATE flag is, we need to add one to the offset */
		// 		offset += ((first_flags & 0x04) == 0x04) ? 1 : 0 ; /* IEEE80211_RADIOTAP_RATE */

		// 		printf("channel : %d - %d\n\r", *((unsigned short *) rtap_head + offset), *((unsigned short *) rtap_head + offset+2));


		offset += ((first_flags & 0x08) == 0x08) ? 4 : 0 ; /* IEEE80211_RADIOTAP_CHANNEL */
		offset += ((first_flags & 0x10) == 0x10) ? 2 : 0 ; /* IEEE80211_RADIOTAP_FHSS */
		rssi = *((unsigned char *) rtap_head + offset) - 0x100;

		// 		printf("Sequence control : %d\n\r", eh->sequence_control);
		printf("%d bytes -- %02X:%02X:%02X:%02X:%02X:%02X -- RSSI: %d dBm, offset : %d\n",
				size_radiotap, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], (int)rssi, offset);
// 		printf("receive : %02X:%02X:%02X:%02X:%02X:%02X\n\r", mac_receive[0], mac_receive[1], mac_receive[2], mac_receive[3], mac_receive[4], mac_receive[5]);
		//}

// 		printf("caplen of pcap_pkthdr :%d\n\r", header->caplen);
// 		printf("len of pcap_pkthdr :%d\n\r", header->len);

// 		printf("EH -> control : %x\n\r", eh->frame_control);
// 		printf("EH -> duration: %x\n\r", eh->frame_duration);
// 		printf("EH -> seq: %x\n\r", eh->sequence_control);

		/* After ieee80211 header, there is the Logical Link Control header */
		llcsnaphdr * logic = (llcsnaphdr*) (ptrPacket);
		ptrPacket += sizeof(llcsnaphdr);

// 		printf("logic -> dsap = %x\n\r", logic->dsap);
// 		printf("logic -> dsap = %x\n\r", logic->ssap);

		/* After logic Link control, there is IP header */
		ip = (struct sniff_ip*)(ptrPacket);

		size_ip = IP_HL(ip)*4;
		if (size_ip < 20) {
			//printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return;
		}
		
		/* Only send packet when packet is for the server */
		if(ip->ip_dst.s_addr == inet_addr(HOST)) {
			/* Send request to the server */
			send_request(inet_ntoa(ip->ip_src),rssi);
			

			/* print source and destination IP addresses */
			printf("       From: %s\n", inet_ntoa(ip->ip_src));
			printf("         To: %s\n", inet_ntoa(ip->ip_dst));

			/* determine protocol */	
			switch(ip->ip_p) {
				case IPPROTO_TCP:
					printf("   Protocol: TCP\n");
					break;
				case IPPROTO_UDP:
					printf("   Protocol: UDP\n");
					return;
				case IPPROTO_ICMP:
					printf("   Protocol: ICMP\n");
					return;
				case IPPROTO_IP:
					printf("   Protocol: IP\n");
					return;
				default:
					printf("   Protocol: unknown\n");
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
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}

			printf("   Src port: %d\n", ntohs(tcp->th_sport));
			printf("   Dst port: %d\n", ntohs(tcp->th_dport));

			/* define/compute tcp payload (segment) offset */
			ptrPacket += size_tcp;
			payload = ptrPacket;

			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

			/*
			* Print payload data; it might be binary, so don't just
			* treat it as a string.
			*/
			if (size_payload > 0) {
				printf("   Payload (%d bytes):\n", size_payload);
				print_payload(payload, size_payload);
			}
		}
}
return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
	void
print_hex_ascii_line(const unsigned char *payload, int len, int offset)
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

	return;
}


/*
 * print packet payload data (avoid printing binary data)
 */
	void
print_payload(const unsigned char *payload, int len)
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

	return;
}
