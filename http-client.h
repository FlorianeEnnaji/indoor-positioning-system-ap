#ifndef __HTTTP_CLIENT_H__
#define __HTTTP_CLIENT_H__

#define TAILLEMAX 400

#define HOST "192.168.1.200"
#define PAGE "/"
#define PORT "8090"
#define USERAGENT "HTMLGET 1.1"

void send_request(const char *ipSrc, const int rssi1, const int rssi2, const int rssi3);
char *build_get_query(const char *host, const char *page);
char * build_post_query(const char *host, const char *page, const char *content);

#endif
