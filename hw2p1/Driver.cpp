// Driver.cpp
// CSCE 463-500
// Luke Grammer
// 9/24/19

#include "pch.h"

#define _CRTDBG_MAP_ALLOC  
#include <stdlib.h>  
#include <crtdbg.h> // libraries to check for memory leaks

#pragma comment(lib, "ws2_32.lib")

using namespace std;

int main(int argc, char** argv)
{
	// debug flag to check for memory leaks
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF); 
	
	DWORD host_ip = NULL, server_ip = NULL;
	DNSResolver resolver;

	// make sure command line arguments are valid
	if (argc != 3)
	{
		(argc < 3) ? printf("too few arguments") : printf("too many arguments");
		printf("\nusage: Driver.exe <Hostname or IP> <DNS Server IP>\n");
		return(EXIT_FAILURE);
	}

	server_ip = inet_addr(argv[2]);
	if (server_ip == INADDR_NONE)
	{
		printf("error: address of local DNS server is not a valid IP address\n");
		return(EXIT_FAILURE);
	}

	host_ip = inet_addr(argv[1]);
	int result = 0;
	// host is not a valid IP, do a forward DNS lookup
	if (host_ip == INADDR_NONE)
		result = resolver.ResolveDNS(DNS_A, argv[1], server_ip);
	// host is a valid IP, do reverse lookup
	else
		result = resolver.ResolveDNS(DNS_PTR, argv[1], server_ip);
	
	return result;
}
