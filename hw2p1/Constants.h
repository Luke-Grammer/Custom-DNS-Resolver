// Constants.h
// CSCE 463-500
// Luke Grammer
// 9/24/19

#pragma once

#define MISC_ERROR     -2

#define DNS_INET        1 
#define MAX_ATTEMPTS    3
#define TIMEOUT_SECONDS 10
#define DNS_PORT        53   
#define MAX_DNS_SIZE    512

#define DNS_OK          0
#define DNS_FORMAT      1
#define DNS_SERVERFAIL  2
#define DNS_ERROR       3
#define DNS_NOTIMPL     4
#define DNS_REFUSED     5

#define DNS_A       1	  /* name -> IP */
#define DNS_NS      2	  /* name server */
#define DNS_CNAME	5	  /* canonical name */
#define DNS_PTR     12	  /* IP -> name */
#define DNS_HINFO   13	  /* host info/SOA */
#define DNS_MX      15	  /* mail exchange */
#define DNS_AAAA    28
#define DNS_AXFR    252	  /* request for zone transfer */
#define DNS_ANY     255	  /* all records */
