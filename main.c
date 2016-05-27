#include <pcap.h>
#include <stdio.h>
#include "sniffer.h"



int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	//char filter_exp[] = "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";	/* The filter expression */
	char filter_exp[] = "ether host **MAC**";
	
	char wirelessInterface[] = "wlan0";
	
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	
	int i;

	/* Define the device */
	/*dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}*/
	/* Find the properties for the device */
	/*if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}*/
	/* Open the session in promiscuous mode */
	
	handle = pcap_open_live(wirelessInterface, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	
		printf("rfmon ? %d\n\r", pcap_can_set_rfmon(handle));
	
	
	
	printf("pcap data link : %d\n\r", pcap_datalink(handle));
	//do {
	
// 	for(i = 0; i < 10; i++) {
// 		/* Grab a packet */
// 		packet = pcap_next(handle, &header);
// 		/* Print its length */
// 		printf("Jacked a packet with length of [%d]\n", header.len);
// 		/*if(header.len > 0)
// 			puts(packet);
// 		*/
// 	}
	//}while(header.len == 0);
	
	pcap_loop(handle, 200, got_packet, NULL);
	
	
	/* And close the session */
	pcap_close(handle);
	return(0);
}
