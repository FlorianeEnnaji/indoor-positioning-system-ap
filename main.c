#include <pcap.h>
#include <stdio.h>
#include "sniffer.h"


int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	//char filter_exp[] = "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";	/* The filter expression */
	char filter_exp[30] = "";	/* Capture filter */
	/* 
	 * MAC address to filter on.
	 * Used to check string format of the argument 
	 */
	char filterMac[6];	

	char wirelessInterface[] = "wlan0";	/* Capturing interface */

	bpf_u_int32 net = PCAP_NETMASK_UNKNOWN;		/* Our IP */	
	printf("Capturing packets on %s\n\r", wirelessInterface);
	/* Check if there is an argument */
	if(argc > 1) {
		/* Check if the argument is a valid MAC address */
		printf("Capturing packets on %s\n\r", wirelessInterface);

		if(sscanf(argv[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&filterMac[0],&filterMac[1],&filterMac[2],
					&filterMac[3],&filterMac[4],&filterMac[5]) == 6) {
			printf("Filtering on %s\n\r", argv[1]);
			sprintf(filter_exp, "ether host %s", argv[1]);
		}
		else {
			printf("The argument is NOT a MAC address.\n\r");
			return -1;
		}
	}


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
		fprintf(stderr, "Couldn't open device %s: %s\n", wirelessInterface, errbuf);
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

	printf("pcap data link : %d\n\r", pcap_datalink(handle));

	pcap_loop(handle, 500, got_packet, NULL);


	/* And close the session */
	pcap_close(handle);
	return(0);
}

