#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include "http-client.h"


void send_request(const char *ipSrc, const int rssi1, const int rssi2, const int rssi3)
{
	int sock, rv, cc;
	char msg_r[TAILLEMAX] = "", *port = PORT, *host=HOST;
	char * get;
	int tmpres;
	char *req_format = "DeviceIp=%s&RSSI=%03d,%03d,%03d\0";
	char *req;
	struct addrinfo hints, *infos;

	//printf("req ?\n\r");
	req = (char*) malloc(strlen(req_format)-9+strlen(ipSrc)+30);
	sprintf(req, req_format, ipSrc, rssi1, rssi2, rssi3);
	//printf("rssi : %03d\n", rssi);
	//printf("req = %s\n\r", req);
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;

	if ( (rv = getaddrinfo(host, port, &hints, &infos)) != 0)
	{
		fprintf(stderr, "tcp listen error for %s, %s, %s", host, port, gai_strerror(rv));
	}

	if( (sock = socket(infos->ai_family, infos->ai_socktype, infos->ai_protocol)) == -1)
	{
		perror("socket creation error : ");
	}

	if( (cc = connect(sock, infos->ai_addr, infos->ai_addrlen)) == -1)
	{
		perror("socket connection error : ");
	}

	get = build_post_query(host, "/api/AP-measure",req);
	// 	printf("message sent : %s\n", get);

	//Send the query to the server
	int sent = 0;
	while(sent < strlen(get))
	{
		tmpres = send(sock, get+sent, strlen(get)-sent, 0);
		if(tmpres == -1){
			perror("Can't send query");
			exit(1);
		}
		sent += tmpres;
	}

	//send(sock, msg_e, strlen(msg_e), MSG_PEEK);

	recv(sock, msg_r, sizeof(msg_r), MSG_PEEK);

	// 	printf("message received : %s\n", msg_r);

	close(sock);
	free(req);
	free(get);
	freeaddrinfo(infos);
}

char * build_get_query(const char *host, const char *page)
{
	char *query;
	const char *getpage = page;
	char *tpl = "GET /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n";
	if(getpage[0] == '/'){
		getpage = getpage + 1;
		//     fprintf(stderr,"Removing leading \"/\", converting %s to %s\n", page, getpage);
	}
	// -5 is to consider the %s %s %s in tpl and the ending \0
	query = (char *)malloc(strlen(host)+strlen(getpage)+strlen(USERAGENT)+strlen(tpl)-5);
	sprintf(query, tpl, getpage, host, USERAGENT);
	return query;
}

char * build_post_query(const char *host, const char *page, const char *content)
{
	char *query;
	const char *getpage = page;
	int size = strlen(content);
	char *tpl = "POST /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s";

	if(getpage[0] == '/'){
		getpage = getpage + 1;
		//     fprintf(stderr,"Removing leading \"/\", converting %s to %s\n", page, getpage);
	}
	// -5 is to consider the %s %s %s in tpl and the ending \0
	query = (char *)malloc(strlen(host)+strlen(getpage)+strlen(USERAGENT)+strlen(tpl)+size-5);
	sprintf(query, tpl, getpage, host, USERAGENT, size, content);
	return query;
}
