#include "sniffer.h"
#include <semaphore.h>


sem_t synchro;


/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	struct ieee80211_radiotap_header * rtap_head;
	struct ieee80211_header * eh;
	u_char * mac, *mac_receive;
	u_char first_flags;
	int offset = 0;
	char rssi;
	struct rtapdata * rtap_data;

	count++;
	
	
	rtap_head = (struct ieee80211_radiotap_header *) packet;
	

	
	 int len = (int) rtap_head->it_len[0] + 256 * (int) rtap_head->it_len[1];
	 
	
    eh = (struct ieee80211_header *) (packet + len);
	
    if ((eh->frame_control & 0x03) == 0x01) {
			
 		printf("\nPacket number %d:\n", count-1);

	printf("Length of radiotap header : %d\n\r", len);
	printf("it_present[0] : 0x%x\n\r", rtap_head->it_present[0]);
	printf("it_present[1] : 0x%x\n\r", rtap_head->it_present[1]);
	printf("it_present[2] : 0x%x\n\r", rtap_head->it_present[2]);
	printf("it_present[3] : 0x%x\n\r", rtap_head->it_present[3]);
	 
	
	
		mac = eh->source_addr;
		mac_receive = eh->recipient;
		first_flags = rtap_head->it_present[0];
		offset = 8;	/* size of the radiotap header */
		
		offset += 8;
		
		offset += ((first_flags & 0x01) == 0x01) ? 8 : 0 ;	/* IEEE80211_RADIOTAP_TSFT */
		offset += ((first_flags & 0x02) == 0x02) ? 1 : 0 ; /* IEEE80211_RADIOTAP_FLAGS */
		
		
		
		offset += ((first_flags & 0x04) == 0x04) ? 1 : 0 ; /* IEEE80211_RADIOTAP_RATE */
		
		printf("channel : %d - %d\n\r", *((unsigned short *) rtap_head + offset), *((unsigned short *) rtap_head + offset+2));

		
		offset += ((first_flags & 0x08) == 0x08) ? 4 : 0 ; /* IEEE80211_RADIOTAP_CHANNEL */
		offset += ((first_flags & 0x10) == 0x10) ? 2 : 0 ; /* IEEE80211_RADIOTAP_FHSS */
		rssi = *((char *) rtap_head + offset) - 0x100;
		printf("Sequence control : %d\n\r", eh->sequence_control);
		printf("%d bytes -- %02X:%02X:%02X:%02X:%02X:%02X -- RSSI: %d dBm\n",
		       len, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], (int)rssi);
		printf("receive : %02X:%02X:%02X:%02X:%02X:%02X\n\r", mac_receive[0], mac_receive[1], mac_receive[2], mac_receive[3], mac_receive[4], mac_receive[5]);
	//}
	
	/*
	printf("Frame control : %d\n\r", eh->frame_control);
    if ((eh->frame_control & 0x03) == 0x01) {
		printf("--------RADIOTAP HEADER FOUND -------\n\r");
      mac = eh->source_addr;
	  printf("FROM : %s\n\r", mac);
      first_flags = rtap_head->it_present[0];
      offset = 8;
      offset += ((first_flags & 0x01) == 0x01) ? 8 : 0 ;
      offset += ((first_flags & 0x02) == 0x02) ? 1 : 0 ;
      offset += ((first_flags & 0x04) == 0x04) ? 1 : 0 ;
      offset += ((first_flags & 0x08) == 0x08) ? 4 : 0 ;
      offset += ((first_flags & 0x10) == 0x10) ? 2 : 0 ;
      rssi = *((char *) rtap_head + offset) - 0x100;
      //printf("%d bytes -- %02X:%02X:%02X:%02X:%02X:%02X -- RSSI: %d dBm\n",
      //       len, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], (int) rssi);
      // We got some message issued by a terminal (FromDS=0,ToDS=1)
//       sem_wait(&synchro);
//       if ((dev_info = find_mac(rssi_list, mac)) == NULL) {
// 	dev_info = add_element(&rssi_list, mac);
//       }
//       clear_outdated_values(&dev_info->measurements);
//       add_value(&dev_info->measurements, (int) rssi);
//       sem_post(&synchro);
    }

	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

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
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
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
return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

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
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

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
