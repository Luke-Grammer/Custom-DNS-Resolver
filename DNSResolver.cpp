// DNSResolver.cpp
// CSCE 463-500
// Luke Grammer
// 9/24/19

#include "pch.h"

// Basic constructor for the DNS resolver class Initializes WinSock and opens and binds a UDP socket
DNSResolver::DNSResolver()
{
	WSADATA wsa_data;
	WORD w_ver_requested;
	struct sockaddr_in local;
	memset(&local, 0, sizeof(local));

	// Initialize WinSock
	w_ver_requested = MAKEWORD(2, 2);
	if (WSAStartup(w_ver_requested, &wsa_data) != 0) {
		printf("  ++ program error: WSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		exit(EXIT_FAILURE);
	}

	// Open a UDP socket
	sock = socket(AF_INET, SOCK_DGRAM, NULL);
	if (sock == INVALID_SOCKET)
	{
		printf("  ++ program error: socket() generated error %d\n", WSAGetLastError());
		WSACleanup();
		exit(EXIT_FAILURE);
	}

	// Bind socket to local machine
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(0);

	if (bind(sock, (struct sockaddr*) &local, sizeof(local)) == SOCKET_ERROR)
	{
		printf("  ++ program error: bind() generated error %d\n", WSAGetLastError());
		WSACleanup();
		exit(EXIT_FAILURE);
	}

	// Set up address for local DNS server
	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_port = htons(DNS_PORT);

	srand( (unsigned) time(NULL));
	curr_id = (rand() % 65535) + 1;
}

// Destructor cleans up winsock and closes socket
DNSResolver::~DNSResolver()
{
	if (packet != NULL)
		free(packet);
	closesocket(sock);
	WSACleanup();
}

// Simple function that prints an error message given as an argument and returns the constant value -1.
// If a true boolean is included as the last argument, print the result of WSAGetLastError() as well.
int DNSResolver::printAndReturn(const char* msg, bool wsa = false)
{
	printf("%s ", msg);
	if (wsa)
		printf("%d", WSAGetLastError());
	printf("\n");
	return -1;
}

// Create valid Type A query string based on supplied hostname string (e.x. www.google.com -> 3www6google3com0)
// Returns the dynamically allocated formatted query string of NULL in the event of an error
char* DNSResolver::FormatTypeAQuery(char* lookup_string)
{
	UCHAR counter = 0;
	DWORD start_index = 0;

	// Allocate memory for the formatted query string
	char* query_string = (char*) malloc(strlen(lookup_string) + 2);
	if (query_string == NULL)
		return NULL;

	// Find the next '.' in the lookup string and update the query string with the number of characters found
	for (unsigned i = 0; i < strlen(lookup_string); i++)
	{
		if (lookup_string[i] == '.')
		{
			query_string[start_index] = counter;
			memcpy(query_string + start_index + 1, lookup_string + start_index, (size_t) i - start_index);
			start_index = i + 1;
				counter = 0;
			continue;
		}
		counter++;
	}

	/*
	 * Update the last size indicator to be equal to the number of characters 
	 * left in the lookup string, copy characters and null terminate the query string
	 *
	 * Warning C6386 because we're writing to a string with size 
	 * strlen(lookup_string) + 2 bytes but 2 bytes might be written.
	 * This will not cause buffer overrun because strlen(lookup_string) >= 0
	 */ 
	query_string[start_index] = counter;
	memcpy(query_string + start_index + 1, lookup_string + start_index, strlen(lookup_string) - start_index);
	query_string[strlen(lookup_string) + 1] = 0;

	return query_string;
}

// Create valid Type PTR query string based on supplied IP string (e.x. 192.168.2.1 -> 1.2.168.192.in-addr.arpa)
// Returns the dynamically allocated formatted query string of NULL in the event of an error
char* DNSResolver::FormatTypePTRQuery(char* lookup_string)
{
	// Allocate memory for the formatted query string
	char* temp_query_string = (char*)malloc(strlen(lookup_string) + 14);
	if (temp_query_string == NULL)
		return NULL;

	// Reverse IP of lookup string and copy it to temporary query string
	DWORD rev_ip = inet_addr(lookup_string);
	rev_ip = htonl(rev_ip);
	struct in_addr lookup_addr;
	lookup_addr.s_addr = rev_ip;
	memcpy(temp_query_string, inet_ntoa(lookup_addr), strlen(lookup_string));

	// Append ".in-addr.arpa" to temporary query string
	char append_string[] = ".in-addr.arpa\0";
	for (int i = 0; i < 14; i++)
		temp_query_string[strlen(lookup_string) + i] = append_string[i];

	// Print query and get the query string with explicit sizes in place of the '.' character
	printf("Query   : %s, ", temp_query_string);
	char* query_string = FormatTypeAQuery(temp_query_string);
	// Free temporary query string
	free(temp_query_string);

	return query_string;
}

// Create and return basic recursive DNS query header
DNSHeader DNSResolver::CreateDNSHeader()
{
	DNSHeader header;
	header.ID         = htons(curr_id);
	header.QR         = 0;
	header.opcode     = 0;
	header.AA         = 0;
	header.TC         = 0;
	header.RD         = 1;
	header.RA         = 0;
	header.reserved   = 0;
	header.result     = 0;
	header.questions  = htons(1);
	header.answers    = 0;
	header.authority  = 0;
	header.additional = 0;
	return header;
}

// Initialize a valid DNS Query packet given the type of query (A or PTR) and the lookup string.
// Also take in the packet_size (initially 0) and modify it to reflect the final size of the 
// formatted DNS packet.
void DNSResolver::CreateDNSQueryPacket(DWORD query_type, char* lookup, int &packet_size)
{
	// Create query header
	DNSHeader pheader = CreateDNSHeader();
	QueryHeader qheader;
	qheader.qClass = htons(1);
	qheader.qType = (query_type == DNS_A) ? htons(DNS_A) : htons(DNS_PTR);

	// Print information and get formatted lookup string
	printf("Lookup  : %s\n", lookup);
	char* formatted_lookup = (query_type == DNS_A) ? FormatTypeAQuery(lookup) : FormatTypePTRQuery(lookup);
	if (formatted_lookup == NULL)
		return;

	// Calculate size of packet
	packet_size = (DWORD) strlen(formatted_lookup) + 1 + sizeof(DNSHeader) + sizeof(QueryHeader);
	packet = (char*) malloc(packet_size);
	if (packet == NULL)
		return;

	if (query_type == DNS_A)
		printf("Query   : %s, ", lookup);
	printf("type %d, TXID 0x%.4X\n", query_type, ntohs(pheader.ID));
	
	/*
	 * Copy header and query into the allocated packet
	 *
	 * Warning C6386 because we're copying 'sizeof(DNSHeader)' bytes but writable size is 'packet_size' bytes.
	 * This is not an issue for reasonable lookup string lengths because packet_size is strictly > sizeof(DNSHeader) 
	 */ 
	memcpy(packet, &pheader, sizeof(DNSHeader));
	memcpy(packet + sizeof(DNSHeader), formatted_lookup, strlen(formatted_lookup) + 1);
	memcpy(packet + sizeof(DNSHeader) + strlen(formatted_lookup) + 1, &qheader, sizeof(QueryHeader));
	free(formatted_lookup);
}

// Send DNS query to connected server through UDP socket.
// Returns -1 to indicate a problem sending the packet, or -2 to indicate that 
// the packet has not been correctly allocated.
int DNSResolver::SendDNSQuery(DWORD packet_size)
{
	if (packet == NULL)
		return MISC_ERROR;

	int result;
	result = sendto(sock, packet, packet_size, NULL, (struct sockaddr*) & remote, sizeof(remote));
	return result;
}

// Attempts to receive a UDP packet response into character buffer buf. 
// If a response is successfully read, return number of bytes read and 
// return the buffer that was passed in by reference.
// The timeout is set to 10 seconds by default.
// Returns -1 if there was a network error recieving the packet, or 
// -2 to indicate that the received packet did not originate from the 
// originally contacted server.
int DNSResolver::ReceiveDNSQuery(char buf[])
{
	// set timeout
	struct timeval timeout;
	timeout.tv_sec = TIMEOUT_SECONDS;
	timeout.tv_usec = 0;

	fd_set fd;
	FD_ZERO(&fd);
	FD_SET(sock, &fd);
	
	// create address struct for responder
	struct sockaddr_in response_addr;
	int response_size = sizeof(response_addr);
		
	int ret = 0;
	ret = select(0, &fd, NULL, NULL, &timeout);
	if (ret > 0)
	{
		// attempt to get response from server
		int packet_size = recvfrom(sock, buf, MAX_DNS_SIZE, 0, (struct sockaddr*) &response_addr, &response_size);
		if (packet_size == 0)
			return SOCKET_ERROR;
		if (response_addr.sin_addr.s_addr != remote.sin_addr.s_addr || response_addr.sin_port != remote.sin_port)
			return MISC_ERROR;

		return packet_size;
	}
	else if (ret == 0)
		return 0;
	else
		return SOCKET_ERROR;
}

// Takes a DNS response from the server as a character buffer in addition to the 
// size of the response and validates the response against the original packet. 
// If response is successfully validated, parse the DNS answers and print the results.
// Prints a message and returns -1 in case of failure or 0 for success.
int DNSResolver::ValidateAndParseResponse(char* buf, int response_size)
{
	// check to make sure response size is at least as large as the fixed DNS header
	if (response_size < sizeof(DNSHeader))
		return printAndReturn("  ++ invalid reply: smaller than fixed header");

	DNSHeader response = *(DNSHeader*)buf;
	DNSHeader original = *(DNSHeader*)packet;

	// get number of responses from the response packet
	USHORT num_questions = ntohs(response.questions);
	USHORT num_answers = ntohs(response.answers);
	USHORT num_authority = ntohs(response.authority);
	USHORT num_additional = ntohs(response.additional);

	// check for TXID mismatch
	if (ntohs(original.ID) != ntohs(response.ID))
	{
		printf("  ++ invalid reply: TXID mismatch, sent %.4X, received %.4X", ntohs(original.ID), ntohs(response.ID));
		return printAndReturn("");
	}

	// check response code
	if (ntohs(response.result) == DNS_OK)
		printf("  succeeded with Rcode = %d\n", response.result);
	else
	{
		printf("  failed with Rcode = %d", response.result);
		return printAndReturn("");
	}

	char* cursor = buf + sizeof(DNSHeader);
	char* name = NULL;

	// Loop through questions
	if (num_questions > 0)
		printf("------------ [questions] ----------\n");
	for (int i = 0; i < num_questions; i++)
	{
		// check if we reached end of packet in the middle of processing queries
		if (cursor >= buf + response_size)
			return printAndReturn("  ++ invalid section: not enough records");

		// get the query text
		name = GetName(cursor, buf, response_size);
		if (name == NULL)
			return printAndReturn("");

		// check to make sure there is space for the query header in the packet
		if (cursor + sizeof(QueryHeader) > buf + response_size)
			return printAndReturn("  ++ invalid record: truncated fixed query header");

		// get query header information, print, and advance cursor
		QueryHeader query = *(QueryHeader*)cursor;
		printf("\t%s type %d class %d\n", name, (int) ntohs(query.qType), (int) ntohs(query.qClass));
		cursor += sizeof(QueryHeader);
	}

	// loop through answers and print results
	if (num_answers > 0)
		printf("------------ [answers] ----------\n");
	if (PrintResourceRecords(num_answers, buf, cursor, response_size) < 0)
		return printAndReturn("");

	// loop through authority and print results
	if (num_authority > 0)
		printf("------------ [authority] ----------\n");
	if (PrintResourceRecords(num_authority, buf, cursor, response_size) < 0)
		return printAndReturn("");

	// loop through additional and print results
	if (num_additional > 0)
		printf("------------ [additional] ----------\n");
	if (PrintResourceRecords(num_additional, buf, cursor, response_size) < 0)
		return printAndReturn("");
	return 0;
}

// Print N resource records from a given buffer with starting location given by cursor. 
// Additionally, advance cursor by the amount advanced. 
// Returns -1 in case an error was encountered or 0 if successful.
int DNSResolver::PrintResourceRecords(USHORT num_records, char* buf, char* &cursor, int response_size)
{
	// loop through all records of a given type
	for (int i = 0; i < num_records; i++)
	{
		// check if we reached end of packet in the middle of processing responses 
		if (cursor >= buf + response_size)
			return printAndReturn("\n  ++ invalid section: not enough records");

		// get the query text the response is for
		char* name = GetName(cursor, buf, response_size);
		if (name == NULL)
			return printAndReturn("");

		// check to make sure there is at least enough room in the packet for a RR header
		if (cursor + sizeof(ResourceRecord) > buf + response_size)
			return printAndReturn("\n  ++ invalid record: truncated fixed RR header");

		ResourceRecord record = *(ResourceRecord*)cursor;
		USHORT record_type = ntohs(record.rType);

		// check to make sure RR header size and length field does not indicate content past the packet boundary
		if (cursor + sizeof(ResourceRecord) + ntohs(record.rLength) > buf + response_size)
			return printAndReturn("\n  ++ invalid record: RR value length beyond packet");

		// check record type, skip if unrecognized
		char type_indicator[6] = "";
		if (record_type == DNS_A || record_type == DNS_PTR || record_type == DNS_CNAME || record_type == DNS_NS)
			printf("\t%s ", name);
		if (record_type == DNS_A)
			strcpy_s(type_indicator, 6, "A");
		else if (record_type == DNS_PTR)
			strcpy_s(type_indicator, 6, "PTR");
		else if (record_type == DNS_CNAME)
			strcpy_s(type_indicator, 6, "CNAME");
		else if (record_type == DNS_NS)
			strcpy_s(type_indicator, 6, "NS");
		else
		{
			cursor += sizeof(ResourceRecord) + ntohs(record.rLength);
			continue;
		}

		// advance past RR header
		cursor += sizeof(ResourceRecord);

		// if the record type is A, read an IPv4 address. Otherwise, read a hostname.
		if (record_type == DNS_A)
		{
			name = GetIPv4Address(cursor, buf, response_size);
			if (name == NULL)
				return printAndReturn("");
		}
		else
		{
			name = GetName(cursor, buf, response_size);
			if (name == NULL)
				return printAndReturn("");
		}

		// print record information
		if (record_type == DNS_A || record_type == DNS_PTR || record_type == DNS_CNAME || record_type == DNS_NS)
			printf("%s %s TTL = %d\n", type_indicator, name, ntohl(record.rTTL));
	}
	return 0;
}

// Gets an IPv4 address starting from the position indicated by cursor 
// from the buffer starting at position 'start'. The total size of the 
// buffer is indicated by response_size. In addition, advance the cursor
// by the number of characters read. Return the buffer of characters read
// or null if an error is encountered.
char* DNSResolver::GetIPv4Address(char*& cursor, char* start, int response_size)
{
	static char ip_buf[MAX_DNS_SIZE];
	if (cursor + sizeof(DWORD) > start + response_size)
	{
		printf("\n  ++ invalid record: truncated name");
		return NULL;
	}
	
	// get 4 byte address from cursor and copy into buffer
	struct in_addr addr;
	addr.s_addr = *(DWORD*)cursor;
	strcpy_s(ip_buf, MAX_DNS_SIZE, inet_ntoa(addr));

	cursor += sizeof(DWORD);
	return ip_buf;
}

// Checks the byte indicated by cursor in a buffer to see if the cursor needs 
// to jump to another offset in the buffer. Continues jumping and checking the 
// current position until an end position is found or 10 jumps are made 
// (indicating a jump loop). Returns an updated cursor to the corresponding 
// buffer offset and a status flag indicating if a jump was made. returns null
// in case of failure.
char* DNSResolver::SafeJump(char* cursor, char* buf, int response_size, bool &jumped, int jump_count)
{
	char* temp_cursor = cursor;
	// make sure there is enough space to read the current byte of the cursor
	if (cursor >= buf + response_size)
	{
		printf("\n  ++ invalid record: truncated name");
		return NULL;
	}

	// check jump count for loop
	if (jump_count >= 10)
	{
		printf("\n  ++ invalid record: jump loop");
		return NULL;
	}

	// see if jump is necessary
	if ((UCHAR)* cursor >= 0xC0)
	{
		// set flag and make sure the jump offset is inside the boundary of the packet
		jumped = true;
		if (cursor + 1 >= buf + response_size)
		{
			printf("\n  ++ invalid record: truncated jump offset");
			return NULL;
		}

		// calculate jump offset and advance the cursor
		USHORT first_byte_of_offset = ((((UCHAR) *(cursor)) ^ (0xC0)) << 8);
		UCHAR second_byte_of_offset = (UCHAR) *(cursor + 1);
		USHORT jump_offset = first_byte_of_offset + second_byte_of_offset;
		temp_cursor = buf + jump_offset;

		// check range of the updated cursor to make sure it is in a valid position in the 
		// packet
		if (temp_cursor < buf + sizeof(DNSHeader))
		{
			if (temp_cursor < buf)
			{
				printf("\n  ++ invalid record: jump beyond packet boundary");
				return NULL;
			}
			else
			{
				printf("\n  ++ invalid record: jump into fixed header");
				return NULL;
			}
		}
		else if (temp_cursor >= buf + response_size)
		{
			printf("\n  ++ invalid record: jump beyond packet boundary");
			return NULL;
		}

		// check to see if another jump needs to be made at the current position
		temp_cursor = SafeJump(temp_cursor, buf, response_size, jumped, ++jump_count);
	}
	return temp_cursor;
}

// Gets a string corresponsing to a host name starting from the position 
// indicated by cursor from the buffer starting at position 'start'. The 
// total size of the buffer is indicated by response_size. In addition, 
// advance the cursor by the number of characters read. Return the buffer 
// of characters read or null if an error is encountered.
char* DNSResolver::GetName(char* &cursor, char* start, int response_size)
{
	bool jumped = false;
	static char name_buf[MAX_DNS_SIZE];
	char* temp_cursor = cursor;
	int chars_read = 0;

	// check packet to make sure next byte can be read
	if(cursor >= start + response_size)
	{
		printf("\n  ++ invalid record: truncated name");
		return NULL;
	}

	// while the end of the name has not been reached
	while (*temp_cursor != 0)
	{
		// jump if necessary
		temp_cursor = SafeJump(temp_cursor, start, response_size, jumped, 0);
		if (temp_cursor == NULL)
			return NULL;

		// get the number of bytes to read in the next section 
		int num_chars = *temp_cursor;
		chars_read++;

		// advance the temporary cursor and the current cursor if necessary
		if (temp_cursor < start + response_size)
		{
			temp_cursor++;
			if (!jumped)
				cursor++;
		}
		else
		{
			printf("\n  ++ invalid record: truncated name");
			return NULL;
		}

		// while there are still more characters to read in the current section
		while (num_chars > 0)
		{
			// collect the character in the output buffer and advance the cursor
			name_buf[chars_read - 1] = *temp_cursor;
			chars_read++;
			if (temp_cursor < start + response_size)
			{
				temp_cursor++;
				if (!jumped)
					cursor++;
			}
			else
			{
				printf("\n  ++ invalid record: truncated name");
				return NULL;
			}
			num_chars--;
		}

		// check if unexpectedly reached EOF
		if (temp_cursor >= start + response_size)
		{
			printf("\n  ++ invalid record: truncated name");
			return NULL;
		}

		// Add dot or null terminator to end of current output buffer after complete section has been collected
		if (*temp_cursor != 0)
			name_buf[chars_read - 1] = '.';
		else
			name_buf[chars_read - 1] = 0;
	}
	if (jumped)
		cursor++;

	cursor++;
	return name_buf;
}

// Function to format, send, and parse a DNS query and display the resulting information. 
// If an error is encountered, prints a message and gracefully terminates program execution.
int DNSResolver::ResolveDNS(DWORD query_type, char* lookup, DWORD server_ip)
{
	// Finish setting up remote for UDP communication with local DNS server
	server_addr.s_addr = server_ip;
	remote.sin_addr = server_addr;

	// Create properly formatted DNS query packet to send to server
	int packet_size = 0;
	int result = 0;
	CreateDNSQueryPacket(query_type, lookup, packet_size);
	if (packet == NULL)
		return printAndReturn("  ++ program error: failed to create DNS query packet due to malloc failure");
	printf("Server  : %s\n", inet_ntoa(server_addr));
	printf("********************************\n");
	
	char buf[MAX_DNS_SIZE];

	// Attempt to send/receive DNS query N times
	for (int i = 0; i < MAX_ATTEMPTS; i++)
	{
		// Start timer, attempt to send/receive DNS packet
		printf("Attempt %d with %d bytes... ", i, packet_size);
		start_time = std::chrono::high_resolution_clock::now();
		result = SendDNSQuery(packet_size);
		if (result == SOCKET_ERROR)
			return printAndReturn("send encountered socket error", true);
		else if (result == MISC_ERROR)
			return printAndReturn("\n  ++ program error: attempted to send null packet");
		result = ReceiveDNSQuery(buf);
		stop_time = std::chrono::high_resolution_clock::now();

		// check response from receive
		if (result > 0)
		{
			printf("response in %lld ms with %d bytes\n",
				std::chrono::duration_cast<std::chrono::milliseconds>
				(stop_time - start_time).count(), result);
			break;
		}
		else if (result == 0)
		{
			printf("timeout in %lld ms\n",
				std::chrono::duration_cast<std::chrono::milliseconds>
				(stop_time - start_time).count());
		}
		else if (result == SOCKET_ERROR)
			return printAndReturn("receive encountered socket error", true);
		else if (result == MISC_ERROR)
			return printAndReturn("  ++ invalid reply: response not received on the same IP/port as requested server");
	}
	if (result == 0)
		return printAndReturn("  ++ no reply: no response from server");

	// check to make sure response size is at least as large as the fixed DNS header
	if (result < sizeof(DNSHeader))
		return printAndReturn("\n  ++ invalid reply: smaller than fixed header");

	// form DNSHeader from result to print response information
	DNSHeader response = *(DNSHeader*)buf;

	printf("  TXID 0x%.4X, flags 0x%.2X%.2X, questions %d, answers %d, authority %d, additional %d\n",
		ntohs(response.ID), (UCHAR)buf[2], (UCHAR)buf[3], ntohs(response.questions),
		ntohs(response.answers), ntohs(response.authority), ntohs(response.additional));

	// validate content of response packet and parse/print result records
	if (ValidateAndParseResponse(buf, result) != 0)
		return printAndReturn("");

	return 0;
}
