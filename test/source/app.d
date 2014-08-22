
import std.stdio;

import ethernet;
import ip;
import udp;
import network;
import linux_net;

void main(){
	NetworkConf configurator = new LinuxNetworkConf();

	auto net = new DefaultIpNetwork(configurator.getConfig());
	//writefln("dev: %s", net.network[0].gateway_ip);
	//writefln("dev: %s", net.network[1].gateway_ip);
}


