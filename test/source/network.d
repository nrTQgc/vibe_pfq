module network;

import ip;
import ethernet;
import udp;
import core.sys.posix.arpa.inet;
import std.exception;

mac_type resolveMacByArp(NetDev[] network, ip_v4 ip){
	foreach(net; network){
		if( ip in net.arp_table ) 
			return net.arp_table[ip];
	}
	return NO_MAC;
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



interface NetworkConf{
	NetDev[] getConfig();
}

interface IpNetwork{
	ubyte[] getPayloadUdp(ubyte[] buffer);
	ubyte[] fillUdpPacket(ubyte[] buffer, size_t payload_len, ip_v4 src, ushort src_port, ip_v4 dest, ushort dst_port);
}





class DefaultIpNetwork: IpNetwork{
	private{
		NetDev[] network;
		

	}
	enum MultiCastNet = NetDev(parseIpHex("224.0.0.0"), uint.max);
	enum BroadCastNet = NetDev(parseIpHex("255.255.255.255"), uint.max);
	enum LocalhostNet = NetDev(parseIpHex("127.0.0.0"), uint.max);

	this(NetDev[] network){
		this.network = network;
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






