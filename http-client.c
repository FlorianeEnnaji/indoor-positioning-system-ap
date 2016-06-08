/**
 * \file http-client.c
 * \brief Contains functions used to build and send HTTP requests
 * \date May 28, 2016
 * 
 * This file contains some functions used to build and send HTTP requests
 * to the server
 */
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#include "http-client.h"


void send_request(const char *ipSrc, const int rssi1, const int rssi2, const int rssi3)
{
	/* Integers used to store return codes of socket functions */
	int sock, rv, cc, tmpres;
	/* Buffer for storing content sent by the server in response to an request */
	char msg_r[MAX_ANSWER_SIZE] = "";
	/* Server's IP address */
	char *host=HOST;
	/* Port on which the server is listening */
	char *port = PORT;
	/* Page to which the requests have to be sent */
	char *page = PAGE;
	/* String of the query */
	char * query;
	/* Format of the query, used in sprintf */
	char *req_format = "DeviceIp=%s&RSSI=%04d,%04d,%04d&RSSI_mW=%.10f,%.10f,%.10f\0";
	/* Total request to be sent to the server */
	char *req;
	
	/* RSSI values in mW */
	double rssi_mW[3] = {0};
	
	/* Store informations about the host for the socket functions */
	struct addrinfo hints, *infos;

	/* Convert dBm to mW */
	rssi_mW[0] = pow(10,(rssi1/10.));
	rssi_mW[1] = pow(10,(rssi2/10.));
	rssi_mW[2] = pow(10,(rssi3/10.));
	
	/* Allocate memory for storing the request */
	req = (char*) malloc(strlen(req_format)-2+strlen(ipSrc)+1-(3*5)+3*15);
	/* Format the request using the function's parameters */
	sprintf(req, req_format, ipSrc, rssi1, rssi2, rssi3, rssi_mW[0], rssi_mW[1], rssi_mW[2]);
	
	puts(req);
	
	/* Setup hints for socket stream */
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;

	/* Convert host and port to usable data structure for socket functions */
	if ( (rv = getaddrinfo(host, port, &hints, &infos)) != 0)
	{
		fprintf(stderr, "tcp listen error for %s, %s, %s", host, port, gai_strerror(rv));
	}
	/* Open socket */
	if( (sock = socket(infos->ai_family, infos->ai_socktype, infos->ai_protocol)) == -1)
	{
		printf("socket creation error : %d\n\r", sock);
		return;
// 		exit(1);
	}
	/* Connect to the server */
	if( (cc = connect(sock, infos->ai_addr, infos->ai_addrlen)) == -1)
	{
		printf("socket connection error : %d\n\r", cc);
		printf("Packet was not sent\n\r");
		return;
// 		exit(1);
	}
	/* Build the HTTP request */
	query = build_post_query(host, page, req);

	/* Send the query to the server */
	int sent = 0;
	while(sent < strlen(query))
	{
		tmpres = send(sock, query+sent, strlen(query)-sent, 0);
		if(tmpres == -1){
			printf("Can't send query");
			exit(1);
		}
		sent += tmpres;
	}

	/* Store response into buffer */
	recv(sock, msg_r, sizeof(msg_r), MSG_PEEK);

	// 	printf("message received : %s\n", msg_r);

	/* Close the socket */
	close(sock);
	/* Free allocated memory */
	free(req);
	free(query);
	freeaddrinfo(infos);
}

char * build_get_query(const char *host, const char *page)
{
	char *query;
	const char *getpage = page;
	/* Template for the request */
	char *tpl = "GET /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n";
	if(getpage[0] == '/'){
		getpage = getpage + 1;
		//     fprintf(stderr,"Removing leading \"/\", converting %s to %s\n", page, getpage);
	}
	/* 
	 * Allocate memory for storing the complete query.
	 * -5 is to consider the %s %s %s in tpl and the ending \0 
	 */
	query = (char *)malloc(strlen(host)+strlen(getpage)+strlen(USERAGENT)+strlen(tpl)-5);
	/* Format the query using template and function's parameters */
	sprintf(query, tpl, getpage, host, USERAGENT);
	return query;
}

char * build_post_query(const char *host, const char *page, const char *content)
{
	char *query;
	const char *getpage = page;
	int size = strlen(content);
	/* Template for the request */
	char *tpl = "POST /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s";

	if(getpage[0] == '/'){
		getpage = getpage + 1;
		//     fprintf(stderr,"Removing leading \"/\", converting %s to %s\n", page, getpage);
	}
	/* 
	 * Allocate memory for storing the complete query.
	 * -5 is to consider the %s %s %s in tpl and the ending \0 
	 */
	query = (char *)malloc(strlen(host)+strlen(getpage)+strlen(USERAGENT)+strlen(tpl)+size-5);
	/* Format the query using template and function's parameters */
	sprintf(query, tpl, getpage, host, USERAGENT, size, content);
	return query;
}
