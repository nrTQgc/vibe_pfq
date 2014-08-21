
interface IpNetwork{
	ubyte[] getPayloadUdp(ubyte[] buffer);
	ubyte[] fillUdpPacket(ubyte[] buffer, size_t payload_len, ip_v4 src, ushort src_port, ip_v4 dest, ushort dst_port);
}

alias ubyte[6] mac_type;
enum mac_type NO_MAC = [0];
alias uint ip_v4;
alias ubyte[16] ip_v6;

struct EthernetPacket{
	align (1):
	mac_type dest;
	mac_type src;
	ushort type;
}

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

struct UdpIp4Packet{
	align (1):
	ushort src_port;
	ushort dst_port;
	ushort length;
	ushort checksum;
}

struct NetDev{
	string name;
	mac_type mac;
	ip_v4 ip;
	ip_v6 ip6;
	string hostname;

	mac_type gateway_mac;
	ip_v4 gateway_ip;
	ip_v4 net_mask;
	mac_type[ip_v4] arp_table;

	this(ip_v4 _net_mask, ip_v4 _gateway_ip){
		net_mask = _net_mask;
		gateway_ip = _gateway_ip;
	}

	bool is_ip_local(ip_v4 ip){
		ip_v4 net = gateway_ip & net_mask;
		return ((ip ^ net) & net_mask) == 0;
	}

	unittest{
		auto n = NetDev();
		n.net_mask = 0x00FFFFFF;
		n.gateway_ip = 0x0102000A;
		assert(n.is_ip_local(0x0102000A));
		assert(n.is_ip_local(0x0802000A));
		assert(!n.is_ip_local(0x0802000B));
	}
}

version(linux){
	import std.socket: InternetAddress;
	import std.stdio;
	import std.exception;
	import std.array;
	import std.string;
	import std.algorithm;
	import core.sys.posix.sys.ioctl;
	import core.sys.posix.sys.socket;
	import core.sys.posix.arpa.inet;
	import core.sys.posix.netinet.in_;
	import core.stdc.string;
	import core.sys.posix.netdb;
	import std.conv;

	alias InternetAddress.parse parseIpDot;

	void main(){
		auto net = new LinuxIpNetwork();
		writefln("dev: %s", net.network[0].gateway_ip);
		writefln("dev: %s", net.network[1].gateway_ip);
	}

	class LinuxIpNetwork: IpNetwork{
		private{
			NetDev[] network;

			this(NetDev[] network){
				this.network = network;
			}
		}
		enum MultiCastNet = NetDev(parseIpHex("224.0.0.0"), uint.max);
		enum BroadCastNet = NetDev(parseIpHex("255.255.255.255"), uint.max);
		enum LocalhostNet = NetDev(parseIpHex("127.0.0.0"), uint.max);

		this(){
			network = detect();
			fillArp(network);
			fillGatewayInfo(network);
		}

		override ubyte[] getPayloadUdp(ubyte[] buffer){
			return buffer[(EthernetPacket.sizeof + Ip4Packet.sizeof + UdpIp4Packet.sizeof) .. $];
		}

		override ubyte[] fillUdpPacket(ubyte[] buffer, size_t _payload_len, ip_v4 src, ushort src_port, ip_v4 dest, ushort dst_port){
			assert(_payload_len<=ushort.max);
			ushort payload_len = cast(ushort)_payload_len;
			mac_type dest_mac, src_mac;
			NetDev *cur;
			//todo support: 0.0.0.0 as source, multicat, broadcast, ...
			foreach(NetDev dev; network){
				if(dev.is_ip_local(dest)){
					dest_mac = dev.arp_table[dest];
				}
				if(dev.ip == src){
					src_mac = dev.mac;
					cur = &dev;
				}
			}
			if(dest_mac == NO_MAC && cur!=null){
				dest_mac = cur.gateway_mac;
			}

			EthernetPacket *pck = cast(EthernetPacket*)buffer.ptr;

			pck.src = src_mac;
			pck.dest = dest_mac;
			pck.type = htons(0x0800);
			ubyte[] ip_raw = buffer[EthernetPacket.sizeof .. $];
			Ip4Packet* ip = cast(Ip4Packet*)ip_raw;
			static assert(Ip4Packet.sizeof==20);
			ip.ip_version = 0x45; //version 4 and header length 20 
			ip.services_field = 0;
			ip.total_length = htons(cast(ushort)(payload_len + 20 + 8));
			ip.identification = 0;//?todo?
			ip.flags = 0x02; //don't fragment
			ip.fragment_offset = 0;
			ip.time_to_live = 0x40;
			ip.protocol = 0x11;
			ip.source = htonl(src);
			ip.dest = htonl(dest);
			ip.header_checksum = 0;
			ip.header_checksum = htons(checksum_head_ip4(cast(ubyte*)ip, 20));

			ubyte[] udp_raw = ip_raw[Ip4Packet.sizeof .. $];
			UdpIp4Packet* udp = cast(UdpIp4Packet*)udp_raw;
			static assert(UdpIp4Packet.sizeof==8);
			udp.dst_port = htons(dst_port);
			udp.src_port = htons(src_port);
			udp.length = htons(cast(ushort)(UdpIp4Packet.sizeof + payload_len));
			ubyte[] data = udp_raw[UdpIp4Packet.sizeof .. $];
			enforce(data.length >= payload_len);
			udp.checksum = 0;//todo
			return buffer[0 .. (EthernetPacket.sizeof + Ip4Packet.sizeof + UdpIp4Packet.sizeof + payload_len)];
		}

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


	unittest{
		NetDev dev = NetDev();
		dev.name = "test";
		dev.mac = [0,1,2,3,4,1];
		dev.ip = parseIpDot("10.0.2.30");
		dev.hostname = "test.host";
		
		dev.gateway_mac = [0,1,2,3,4,2];
		dev.gateway_ip = parseIpDot("10.0.2.1");
		dev.net_mask = parseIpDot("10.0.2.0"); 
		auto localIp = parseIpDot("10.0.2.2");
		auto globalIp = parseIpDot("8.8.8.8");
		dev.arp_table[localIp] = [0,1,2,3,4,3];

		auto net = new LinuxIpNetwork([dev]);
		ubyte[] buffer = new ubyte[2048];
		ubyte[] payload = new ubyte[1024];
		net.fillUdpPacket(buffer, payload.length, dev.ip, 2000, localIp, 8000);
		assert(buffer[0 .. 6] == dev.arp_table[localIp]);
		buffer = buffer[6 .. $];
		assert(buffer[0 .. 6] == dev.mac);
		buffer = buffer[6 .. $];
		assert(*(cast(ushort*)(buffer[0 .. 2].ptr)) == htons(0x0800));
		buffer = buffer[2 .. $];
		assert(buffer[0] == 0x45);
		buffer = buffer[1 .. $];

		buffer[] = 0;
		net.fillUdpPacket(buffer, payload.length, dev.ip, 2000, globalIp, 8000);
		assert(buffer[0 .. 6] == dev.gateway_mac);
	}
/*
 * Port from  https://raw.githubusercontent.com/ajrisi/lsif/master/lsif.c
 */
	struct ifreq {
		char ifr_name[IFNAMSIZ]; /* Interface name */
		union {
			sockaddr ifr_addr;
			sockaddr ifr_dstaddr;
			sockaddr ifr_broadaddr;
			sockaddr ifr_netmask;
			sockaddr ifr_hwaddr;
			short	       ifr_flags;
			int	       ifr_ifindex;
			int	       ifr_metric;
			int	       ifr_mtu;
			ifmap    ifr_map;
			char	       ifr_slave[IFNAMSIZ];
			char	       ifr_newname[IFNAMSIZ];
			char *	       ifr_data;
		};
	};

	struct ifmap {
		ulong mem_start;
		ulong mem_end;
		ushort base_addr; 
		ubyte irq;
		ubyte dma;
		ubyte port;
		/* 3 bytes spare */
	};

	struct ifconf {
		int		      ifc_len; /* size of buffer */
		union {
			char *	      ifc_buf; /* buffer address */
			ifreq * ifc_req; /* array of structures */
		};
	};

	enum NI_MAXHOST = 1025;
	enum NI_MAXSERV = 32;
	enum IFNAMSIZ   = 16;

	char* get_ip_str(sockaddr *sa, char *s, int maxlen)
	{
		switch(sa.sa_family) {
			case AF_INET:
				inet_ntop(AF_INET, &((cast(sockaddr_in *)sa).sin_addr), s, maxlen);
				break;
				
			case AF_INET6:
				inet_ntop(AF_INET6, &((cast(sockaddr_in6 *)sa).sin6_addr), s, maxlen);
				break;
				
			default:
				strncpy(s, "Unknown AF", maxlen);
				return null;
		}
		return s;
	}

	NetDev[] detect()
	{
		NetDev[] rs;
		char            buf[8192];
		/* Get a socket handle. */
		int sck = socket(AF_INET, SOCK_DGRAM, 0);
		if(sck < 0) {
			throw new Exception("socket");
		}
		/* Query available interfaces. */
		ifconf ifc = ifconf(buf.length, buf.ptr);
		if(ioctl(sck, SIOCGIFCONF, &ifc) < 0) {
			throw new Exception("ioctl(SIOCGIFCONF)");
		}
		/* Iterate through the list of interfaces. */
		ifreq* ifr = ifc.ifc_req;
		auto nInterfaces = ifc.ifc_len / ifreq.sizeof; 
		char hostname[NI_MAXHOST];
		for(int i = 0; i < nInterfaces; i++) {
			NetDev tmp;
			ifreq* item = &ifr[i];
			tmp.name = item.ifr_name[0 .. item.ifr_name.indexOf('\0')].idup;
			/* Show the device name and IP address */
			sockaddr * addr = &(item.ifr_addr);
			socklen_t salen;
			switch(addr.sa_family) {
				case AF_INET:
					salen = sockaddr_in.sizeof;
					memcpy(&tmp.ip, &(cast(sockaddr_in *)addr).sin_addr, salen);
					break;
				case AF_INET6:
					salen = sockaddr_in6.sizeof;
					memcpy(tmp.ip6.ptr, &(cast(sockaddr_in6 *)addr).sin6_addr, salen);
					break;
				default:
					salen = 0;
			}
			/* the call to get the mac address changes what is stored in the
	           item, meaning that we need to determine the hostname now */
			hostname[] = 0;
			getnameinfo(addr, salen, hostname.ptr, hostname.length, null, 0, NI_NAMEREQD);
			tmp.hostname = hostname[0 .. hostname.indexOf('\0')].idup;

			/* Lots of different ways to get the ethernet address */
			/* Linux */
			/* Get the MAC address */
			if(ioctl(sck, SIOCGIFHWADDR, item) < 0) {
				throw new Exception("ioctl(SIOCGIFHWADDR)");
			}
			memcpy(tmp.mac.ptr, &item.ifr_hwaddr.sa_data, tmp.mac.length);

			rs ~= tmp;
		}
		return rs;
	}

	static auto parseMac(const char[] s){
		import std.conv;
		mac_type mac;
		string tmp = s.idup;
		for(int i=0; i<6; i++){
			string str = tmp[0 .. 2];
			mac[i] = parse!ubyte(str, 16);
			if(tmp.length>3) tmp = tmp[3 .. $];
		}
		return mac;
	}

	unittest{
		auto mac = parseMac("00:08:ca:e6:7e:57");
		writefln("mac: %s", mac);
		assert(parseMac("00:08:ca:e6:7e:57") == cast(ubyte[])x"0008cae67e57");
	}

	void fillArp(NetDev[] devices){
		auto arpTable = File("/proc/net/arp");
		scope(exit) arpTable.close;
		arpTable.readln;
		foreach(dev; devices){
			mac_type[ip_v4] empty;
			dev.arp_table = empty;
		}

		foreach(line; arpTable.byLine){
			auto a = line.split();
			if(a[3]=="00:00:00:00:00:00") continue;
			auto devName = a[5];
			auto idx = devices.countUntil!((a,b) => a.name == b)(devName);
			auto mac = parseMac(a[3]);
			auto ip = parseIpDot(a[0]);
			devices[idx].arp_table[ip] = mac;
		}
	}

	void fillGatewayInfo(NetDev[] devices){
		auto routeTable = File("/proc/net/route");
		scope(exit) routeTable.close;
		routeTable.readln;
		foreach(line; routeTable.byLine){
			auto a = line.split();
			if(a.length==0) continue;
			auto devName = a[0];
			auto gatewayIp4 = a[2];
			auto flags = parse!uint(a[3]);
			auto strMask = a[7];
			if( (flags&1) == 0){
				//unusable;
				continue;
			}
			auto idx = devices.countUntil!((a,b) => a.name == b)(devName);
			if(flags&2){
				//gateway
				devices[idx].gateway_ip = parseIpHex(gatewayIp4);
			}else if (strMask != "00000000"){
				devices[idx].net_mask = parseIpHex(strMask);
			}
		}
	}

	static auto parseIpHex(const char[] s){
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

	static mac_type resolveMacByArp(NetDev[] network, ip_v4 ip){
		foreach(net; network){
			if( ip in net.arp_table ) 
				return net.arp_table[ip];
		}
		return NO_MAC;
	}
}