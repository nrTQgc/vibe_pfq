
interface IpNetwork{
}

alias ubyte[6] mac_type;
enum mac_type NO_MAC = [0];
alias uint ip_v4;
alias ubyte[16] ip_v6;

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
}

version(linux){

	import std.stdio;
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

	void main(){
		auto net = new LinuxIpNetwork();
		writefln("dev: %s", net.network[0].gateway_ip);
		writefln("dev: %s", net.network[1].gateway_ip);
	}

	class LinuxIpNetwork: IpNetwork{
		private{
			NetDev[] network;
		}

		this(){
			network = detect();
			fillArp(network);
			fillGatewayInfo(network);
		}

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
		import std.socket: InternetAddress;
		foreach(line; arpTable.byLine){
			auto a = line.split();
			if(a[3]=="00:00:00:00:00:00") continue;
			auto devName = a[5];
			auto idx = devices.countUntil!((a,b) => a.name == b)(devName);
			auto mac = parseMac(a[3]);
			auto ip = InternetAddress.parse(a[0]);
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
				devices[idx].gateway_ip = parseIp(gatewayIp4);
			}else if (strMask != "00000000"){
				devices[idx].net_mask = parseIp(strMask);
			}
		}
	}

	static auto parseIp(const char[] s){
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
		auto ip = parseIp("0102000A");
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