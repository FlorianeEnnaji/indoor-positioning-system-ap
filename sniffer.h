/**
 * \file sniffer.h
 * \brief Contains definitions of structs and 
 * functions used for analyzing captured packets
 * \date May 18, 2016
 * 
 * This file contains a series of struct and function definitions
 * used for analyzing the packets captured by pcaplib.
 */

#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/**
 * \brief IP header 
 * 
 * Content of the IP header, used to decode the frame.
 */
struct sniff_ip {
	u_char ip_vhl;		/**< Field containing two values : IP version << 4 | header length >> 2 */
	u_char ip_tos;		/**< Type of service */
	u_short ip_len;		/**< Total IP datagram length */
	u_short ip_id;		/**< Identification */
	u_short ip_off;		/**< Fragment offset field */
#define IP_RF 0x8000		/* Teserved fragment flag */
#define IP_DF 0x4000		/* Dont fragment flag */
#define IP_MF 0x2000		/* More fragments flag */
#define IP_OFFMASK 0x1fff	/* Mask for fragmenting bits */
	u_char ip_ttl;		/**< Time to live */
	u_char ip_p;		/**< Transport layer protocol */
	u_short ip_sum;		/**< Header checksum */
	struct in_addr ip_src;	/**< Source IP address */
	struct in_addr ip_dst;	/**< Destination IP address */
};

/** 
 * Retrieve header length from ip_vhl field 
 * \param ip : ip_vhl field from IP header
 */
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
/** 
 * Retrieve IP version from ip_vhl field 
 * \param ip : ip_vhl field from IP header
 */
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/** Define tcp_seq as an alias of unsigned integer */
typedef u_int tcp_seq;

/**
 * \brief TCP header 
 * 
 * Content of the TCP header, used to decode the frame.
 */
struct sniff_tcp {
	u_short th_sport;	/**< Source port */
	u_short th_dport;	/**< Destination port */
	tcp_seq th_seq;		/**< Sequence number */
	tcp_seq th_ack;		/**< Acknowledgement number */
	u_char th_offx2;	/**< Data offset and reserved bits */
	/** Retrieve offset from th_offx2 field */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;	/**< Flags */
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/**< Window */
	u_short th_sum;		/**< Checksum */
	u_short th_urp;		/**< Urgent pointer */
};

/**
 * \brief IEEE 802.11 header
 * 
 * Content of the ieee 802.11 header, used to decode the frame.
 */
struct ieee80211_header
{
	u_short frame_control;	/**< Frame control flags */
	u_short frame_duration;	/**< Duration */
	u_char recipient[6];	/**< Receiver MAC address */
	u_char source_addr[6];	/**< Transmitter MAC address */
	u_char address3[6];		/**< Destination MAC address */
	u_short sequence_control;	/**< Sequence number */
	u_short qos_control;		/**< Qos control */
};

/**
 * \brief Logic-link Control 
 * 
 * Content of the logic layer control, used to decode the frame.
 */
typedef struct llcsnaphdr
{
	uint8_t dsap;	/**< Destination Service Access Point */
	uint8_t ssap;	/**< Source Service Access Point */
	uint8_t ctrl;	/**< Control byte */
	uint8_t oui[3];	/**< Organizationally unique identifier */
	uint16_t type;	/**< Type */
} llcsnaphdr;

/**
 * \brief Radiotap header
 * 
 * Fixed part of the radiotap header. <br>
 * Used to decode the rest of the radiotap header using it_present flags.
 */
struct ieee80211_radiotap_header
{
	u_char it_version;	/**< Header revision */
	u_char it_pad;		/**< Header pad */
	u_char it_len[2];	/**< Header length (little endian) */
	u_char it_present[4];	/**< Present flags */
};

/**
 * \brief Radiotap header content flags
 * 
 * Flags contained in it_present field of the radiotap header
 */
enum ieee80211_radiotap_type {
	/**
	 * Data type : __le64   <br>
	 * Unit : microseconds
	 *
	 * Value in microseconds of the MAC's 64-bit 802.11 Time <br>
	 * Synchronization Function timer when the first bit of the <br>
	 * MPDU arrived at the MAC. For received frames, only.
	 */
	IEEE80211_RADIOTAP_TSFT = 0,
	/**
	 * Data type : u8<br>
	 * Unit : bitmap
	 * 
	 * Properties of transmitted and received frames. See flags
	 * defined below.
	 */
	IEEE80211_RADIOTAP_FLAGS = 1,
	/**
	 * Data type : u8 <br>
	 * Unit : 500kb/s
	 *
	 * Tx/Rx data rate
	 */
	IEEE80211_RADIOTAP_RATE = 2,
	/**
	 * Data type : 2 x __le16<br>
	 * Unit : MHz, bitmap
	 *
	 * Tx/Rx frequency in MHz, followed by flags (see below).
	 */
	IEEE80211_RADIOTAP_CHANNEL = 3,
	/**
	 * Data type : __le16
	 *
	 * For frequency-hopping radios, the hop set (first byte)
	 * and pattern (second byte).
	 */
	IEEE80211_RADIOTAP_FHSS = 4,
	/**
	 * Data type : s8<br>
	 * Unit : decibels from one milliwatt (dBm)
	 *
	 * RF signal power at the antenna, decibel difference from
	 */
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	/**
	 * Data type : s8<br>
	 * Unit : decibels from one milliwatt (dBm)
	 * 
	 * RF noise power at the antenna, decibel difference from one
	 * milliwatt.
	 */
	IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	/**
	 * Data type : __le16
	 * 
	 * Quality of Barker code lock. Unitless. Monotonically 
	 * nondecreasing with "better" lock strength. Called "Signal 
	 * Quality" in datasheets.  (Is there a standard way to measure
	 * this?)
	 */
	IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	/**
	 * Data type : __le16
	 * 
	 * Transmit power expressed as unitless distance from max
	 * power set at factory calibration.  0 is max power.
	 * Monotonically nondecreasing with lower power levels.
	 */
	IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	/**
	 * Data type : __le16<br>
	 * Unit : decibels (dB)
	 * 
	 * Transmit power expressed as decibel distance from max power
	 * set at factory calibration.  0 is max power.  Monotonically
	 * nondecreasing with lower power levels.
	 */
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	/**
	 * Data type : s8<br>
	 * Unit : decibels from one milliwatt (dBm)
	 * 
	 * Transmit power expressed as dBm (decibels from a 1 milliwatt
	 * reference). This is the absolute power level measured at
	 * the antenna port.
	 */
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	/**
	 * Data type : u8<br>
	 * Unit : bitmap
	 * 
	 * Unitless indication of the Rx/Tx antenna for this packet.
	 * The first antenna is antenna 0.
	 */
	IEEE80211_RADIOTAP_ANTENNA = 11,
	/**
	 * Data type : u8<br>
	 * Unit : decibel (dB)
	 * 
	 * RF signal power at the antenna, decibel difference from an
	 * arbitrary, fixed reference.
	 */
	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	/**
	 * Data type : u8<br>
	 * Unit : decibel (dB)
	 * 
	 * RF noise power at the antenna, decibel difference from an 
	 * arbitrary, fixed reference point.
	 */
	IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	/**
	 * Data type : __le16<br>
	 * Unit : bitmap
	 * 
	 * Properties of received frames. See flags defined below.
	 */
	IEEE80211_RADIOTAP_RX_FLAGS = 14,
	/**
	 * Data type : __le16<br>
	 * Unit : bitmap
	 * 
	 * Properties of transmitted frames. See flags defined below.
	 */
	IEEE80211_RADIOTAP_TX_FLAGS = 15,
	/**
	 * Data type : u8<br>
	 * Unit : data
	 * 
	 * Number of rts retries a transmitted frame used.
	 */
	IEEE80211_RADIOTAP_RTS_RETRIES = 16,
	/**
	 * Data type : u8<br>
	 * Unit : data
	 * 
	 * Number of unicast retries a transmitted frame used.
	 */
	IEEE80211_RADIOTAP_DATA_RETRIES = 17,
	IEEE80211_RADIOTAP_XCHANNEL = 18,	/**< Unofficial, supported by BSD */
	/**
	 * Data type : u8, u8, u8<br>
	 * 
	 * Contains a bitmap of known fields/flags, the flags, and
	 * the MCS index.
	 */
	IEEE80211_RADIOTAP_MCS = 19,
	/**
	 * Data type : u32, u16, u8, u8
	 * 
	 * Contains the AMPDU information for the subframe.
	 */
	IEEE80211_RADIOTAP_AMPDU_STATUS = 20,
	/**
	 * Data type : u16, u8, u8, u8[4], u8, u8, u16
	 * 
	 * Contains VHT information about this frame.
	 */
	IEEE80211_RADIOTAP_VHT = 21,

	/* valid in every it_present bitmap, even vendor namespaces */
	IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE = 29,	/**< Radiotap namespace next */
	IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30,	/**< Vendor namespace next */
	IEEE80211_RADIOTAP_EXT = 31					/**< Ext */
};

/**
 * \brief Alignment requirements and size of the radiotap header field
 * 
 * Each radiotap header field has an alignment requirement linked to the type
 * of variable stored in the field. Sometimes a field can contain several variables
 * of different types. Size is then use to know the total size of the field.
 */
struct radiotap_align_size {		
	uint8_t align;		/**< Alignment requirement (in bytes) */
	uint8_t size;		/**< Total length of the field (in bytes) */
};

/**
 * \brief Callback for captured packet
 * 
 * If the packet is bigger than 300 bytes, we start decoding its content by moving
 * from the packet pointer and casting it to the different type of headers contained
 * in the packet.<br>
 * To decode the packet, we move along the radiotap header using an offset calculated
 * using the it_present flags and the fields alignment requirements.<br>
 * We retrieve the RSSI (IEEE80211_RADIOTAP_DBM_ANTSIGNAL) values from the header.<br>
 * Using the radiotap header size, we continue to parse the rest of the packet with the 
 * Logic layer header, and the IP header.<br>
 * If the packet contains an IP header, we read the destination IP and only go forward if
 * the packet is targeted to the server. Then we check the upper layer protocol. If it is
 * TCP, we continue parsing the TCP header using the corresponding struct. Finally, we
 * print the content of the TCP payload. 
 * 
 * \param args : arguments sent to the callback function by pcaplib
 * \param header : pcap header containing the timestamp, and size of the captured packet
 * \param packet : pointer to the start of the packet
 * \return void
 */
void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

/**
 * \brief Print packet payload data (avoid printing binary data)
 * 
 * Format and display the packet's payload by calling print_hex_ascii_line
 * 
 * \param payload : pointer to the packet's TCP payload
 * \param len : size of the payload
 * \return void
 */
void print_payload(const unsigned char *payload, int len);

/**
 * \brief Print data in rows of 16 bytes: offset   hex   ascii
 * 
 * Format and display the packet's TCP payload in three columns : the offset from start 
 * of the payload, the content in hex and the content in ASCII.
 * 
 * \param payload : pointer to the start of the packet's TCP payload
 * \param len : length of the data we want to print of the same line
 * \param offset : specify which portion of the payload we want to print
 * \return void
 */
void print_hex_ascii_line(const unsigned char *payload, int len, int offset);

#endif
