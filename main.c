/**
 * \file main.c
 * \brief File containing the main function
 * \date May 18, 2016
 * 
 * This file contains the entry point of the program.
 * It uses pcaplib to open the wireless interface and set the callback for 
 * captured packets.
 */
#include <pcap.h>
#include <stdio.h>
#include "sniffer.h"

/**
 * \brief Entry point of the program
 * 
 * \param argc : Number of command line arguments used when the program was
 * launched
 * \param argv : Array containing the command line arguments
 * 		An optional first argument can be used to filter packet coming from or 
 * to a specific MAC address
 */
int main(int argc, char *argv[])
{
	pcap_t *handle;		/* Pcap session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[30] = "";	/* Capture filter */
	/* 
	 * MAC address to filter on.
	 * Used to check string format of the argument
	 */
	char filterMac[6];	

	char wirelessInterface[] = "wlan0";	/* Capturing interface */

	bpf_u_int32 net = PCAP_NETMASK_UNKNOWN;		/* Netmask used for compiling filter */	
	
	printf("Capturing packets on %s\n\r", wirelessInterface);
	
	/* Check if there is an argument */
	if(argc > 1) {
		/* Check if the argument is a valid MAC address */		
		if(sscanf(argv[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&filterMac[0],&filterMac[1],&filterMac[2],
					&filterMac[3],&filterMac[4],&filterMac[5]) == 6) {
			printf("Filtering on %s\n\r", argv[1]);
			sprintf(filter_exp, "ether host %s", argv[1]);
		}
		else {
			printf("The argument is NOT a valid MAC address.\n\r");
			printf("You can either use a proper MAX address formatted as \
				XX:XX:XX:XX:XX:XX as an argument to filter on that address, \
				or remove it completely to capture all packets\n\r");
			return -1;
		}
	}

	/* Define the device (not used) */
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
	/* Compile the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	/* Apply the filter to the current session */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	/* 
	 * Set got_packet to be the callback for each packet captured by pcaplib 
	 * The second parameter (0) means that we want to capture packets undefinitely.
	 */
	pcap_loop(handle, 0, got_packet, NULL);

	/* And close the session */
	pcap_close(handle);
	return(0);
}

