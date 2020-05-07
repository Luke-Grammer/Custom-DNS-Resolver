#pragma once

#pragma pack(push, 1)
// Struct to hold DNS header information
struct DNSHeader 
{
	USHORT ID = 0;
	USHORT RD	    : 1;
	USHORT TC		: 1;
	USHORT AA		: 1;
	USHORT opcode   : 4;
	USHORT QR		: 1;
	USHORT result   : 4;
	USHORT reserved : 3;
	USHORT RA       : 1;
	USHORT questions;
	USHORT answers;
	USHORT authority;
	USHORT additional;
};

// Struct to hold DNS query header
struct QueryHeader 
{
	USHORT qType;
	USHORT qClass;
};

// Struct to hold DNS Resource Record header
struct ResourceRecord
{
	USHORT rType;
	USHORT rClass;
	UINT   rTTL;
	USHORT rLength;
};
#pragma pack(pop)