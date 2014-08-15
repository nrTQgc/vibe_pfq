import vibe.appmain;
import vibe.core.core;
import vibe.core.log;
import vibe.core.net;

import core.time;

shared static this()
{
	runTask({
		auto udp_listener = listenUDP(1234);
		for (int i =0; true; i++) {
			auto pack = udp_listener.recv();
			if(i%10_000==0) logInfo("Got packets count: %s", i);
		}
	});

}