/**
 * \file http-client.h
 * \brief Contains function definitions and constants used for sending http requests
 * \date May 28, 2016
 * 
 * This file contains a series of constants and function definitions used for
 * building and sending HTTP requests to the server.
 */
#ifndef __HTTTP_CLIENT_H__
#define __HTTTP_CLIENT_H__

/** \brief IP of the server */
#define HOST "192.168.1.233"
/** \brief Port used by the server to receive requests */
#define PORT "8090"
/** \brief Page on the server to which we need to send the requests */
#define PAGE "/api/AP-measure"
/** \brief User agent used when building requests */
#define USERAGENT "HTMLGET 1.1"
/** \brief Size of the buffer used to store http answer to requests */
#define MAX_ANSWER_SIZE 400

/**
 * \brief Send an HTTP request to the server
 * 
 * Send an HTTP request to the server containing the IP of the captured packet
 * and the three RSSI values retrieved from the radiotap header.
 * 
 * \param ipSrc : IP address of the captured packet's sender
 * \param rssi1-3 : RSSI values retrieved from the radiotap header
 * \return void
 */
void send_request(const char *ipSrc, const int rssi1, const int rssi2, const int rssi3);

/**
 * \brief Build an HTTP GET request
 * 
 * \param host : ip address of the server to which the request will be sent
 * \param page : page to request
 * \return pointer to the content returned by the server
 */
char * build_get_query(const char *host, const char *page);

/**
 * \brief Build an HTTP POST request
 * 
 * \param host : ip address of the server to which the request will be sent
 * \param page : page to which the request will be sent
 * \param content : content of the request (as a url encoded string)
 * \return pointer to the content returned by the server
 */
char * build_post_query(const char *host, const char *page, const char *content);

#endif
