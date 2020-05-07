#pragma once

/*
 * The DNSResolver class is designed to be able to issue recursive queries to a 
 * specified DNS server, as well as parse and print the response.
 */
class DNSResolver
{
	SOCKET sock;
	struct sockaddr_in remote;
	struct in_addr server_addr;
	USHORT curr_id;
	char* packet = NULL;

	// Beginning and end time points for timer implementation
	std::chrono::time_point<std::chrono::high_resolution_clock> start_time, stop_time;

	// Simple function that prints an error message given as an argument and returns the constant value -1.
	// If a true boolean is included as the last argument, print the result of WSAGetLastError() as well.
	int printAndReturn(const char* msg, bool wsa);
	
	// Create valid Type A query string based on supplied hostname string (e.x. www.google.com -> 3www6google3com0)
	// Returns the dynamically allocated formatted query string of NULL in the event of an error
	char* FormatTypeAQuery(char* lookup_string);
	
	// Create valid Type PTR query string based on supplied IP string (e.x. 192.168.2.1 -> 1.2.168.192.in-addr.arpa)
	// Returns the dynamically allocated formatted query string of NULL in the event of an error
	char* FormatTypePTRQuery(char* lookup_string);
	
	// Create and return basic recursive DNS query header
	DNSHeader CreateDNSHeader();
	
	// Initialize a valid DNS Query packet given the type of query (A or PTR) and the lookup string.
	// Also take in the packet_size (initially 0) and modify it to reflect the final size of the 
	// formatted DNS packet.
	void CreateDNSQueryPacket(DWORD query_type, char* lookup, int& packet_size);

	// Send DNS query to connected server through UDP socket.
	// Returns -1 to indicate a problem sending the packet, or -2 to indicate that 
	// the packet has not been correctly allocated.
	int SendDNSQuery(DWORD packet_size);

	// Attempts to receive a UDP packet response into character buffer buf. 
	// If a response is successfully read, return number of bytes read and 
	// return the buffer that was passed in by reference.
	// The timeout is set to 10 seconds by default.
	// Returns -1 if there was a network error recieving the packet, or 
	// -2 to indicate that the received packet did not originate from the 
	// originally contacted server.
	int ReceiveDNSQuery(char buf[]);

	// Takes a DNS response from the server as a character buffer in addition to the 
	// size of the response and validates the response against the original packet. 
	// If response is successfully validated, parse the DNS answers and print the results.
	// Prints a message and returns -1 in case of failure or 0 for success.
	int ValidateAndParseResponse(char* buf, int response_size);

	// Print N resource records from a given buffer with starting location given by cursor. 
	// Additionally, advance cursor by the amount advanced. 
	// Returns -1 in case an error was encountered or 0 if successful.
	int PrintResourceRecords(USHORT num_records, char* buf, char*& cursor, int response_size);

	// Gets an IPv4 address starting from the position indicated by cursor 
	// from the buffer starting at position 'start'. The total size of the 
	// buffer is indicated by response_size. In addition, advance the cursor
	// by the number of characters read. Return the buffer of characters read
	// or null if an error is encountered.
	char* GetIPv4Address(char*& cursor, char* start, int response_size);

	// Checks the byte indicated by cursor in a buffer to see if the cursor needs 
	// to jump to another offset in the buffer. Continues jumping and checking the 
	// current position until an end position is found or 10 jumps are made 
	// (indicating a jump loop). Returns an updated cursor to the corresponding 
	// buffer offset and a status flag indicating if a jump was made. returns null
	// in case of failure.
	char* SafeJump(char* cursor, char* buf, int response_size, bool& jumped, int jump_count);

	// Gets a string corresponsing to a host name starting from the position 
	// indicated by cursor from the buffer starting at position 'start'. The 
	// total size of the buffer is indicated by response_size. In addition, 
	// advance the cursor by the number of characters read. Return the buffer 
	// of characters read or null if an error is encountered.
	char* GetName(char*& cursor, char* start, int response_size);
	
public:

	// Basic constructor for the DNS resolver class Initializes WinSock and opens and binds a UDP socket
	DNSResolver();
	
	// Destructor cleans up winsock and closes socket
	~DNSResolver();
	
	// Function to format, send, and parse a DNS query and display the resulting information. 
	// If an error is encountered, prints a message and gracefully terminates program execution.
	int ResolveDNS(DWORD type, char* lookup, DWORD server_ip);
};