﻿module ip;

import std.conv;

alias uint ip_v4;
alias ubyte[16] ip_v6;


struct Ip4Packet{
	align (1):
	union{
		ubyte ip_version;
		ubyte header_length;
	}
	ubyte services_field;
	ushort total_length;
	ushort identification;
	union{
		ubyte flags;
		ushort fragment_offset;
	}
	ubyte time_to_live;
	ubyte protocol;
	ushort header_checksum;
	uint source;
	uint dest;
}


ushort checksum_head_ip4(ubyte *data, uint length){
	uint tmp = 0;
	for(int i=0; i<length; i+=2){
		tmp += (data[i]<<8) + data[i+1];
	}
	auto p1 = tmp >> 16;
	auto p2 = tmp & 0x0ffff;
	return cast(ushort) (~ (p1+p2) );
}

unittest{
	ubyte[] test = cast(ubyte[])x"4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7";
	assert(test.length==20);
	auto rs = checksum_head_ip4(cast(ubyte*)test.ptr, 20);
	assert(rs==0xb861);
}


auto parseIpHex(const char[] s){
	ip_v4 ip;
	string tmp = s.idup;
	for(int i=0; i<4; i++){
		string str = tmp[0 .. 2];
		ip |= (parse!ubyte(str, 16))<<(8*i);
		if(tmp.length>2) tmp = tmp[2 .. $];
	}
	return ip;
}

unittest{
	auto ip = parseIpHex("0102000A");
	writefln("ip: %s", ip);
	import std.socket: InternetAddress;
	assert(ip == InternetAddress.parse("10.0.2.1"));
}
