import vibe.d;
import std.datetime;
// nc -l 127.0.0.1 1234  -u  >/dev/null
void main()
{
	// returns false if a help screen has been requested and displayed (--help)
	if (!finalizeCommandLineOptions())
		return;
	//lowerPrivileges();

	//setLogLevel(LogLevel.trace);
	runTask({
		scope (exit) exitEventLoop();

		try{
			logInfo("start send udp packets");
			auto payload = new ubyte[500];//cast(ubyte[])"Hello, World!\r\n";//
			import vibe.core.drivers.libpfq: PFQUDPConnection;
			auto udp_sender =  listenUDP(0xc2d5);
			if(auto pfqCon = cast(PFQUDPConnection)udp_sender){
				//pfqCon.batchSize = 1000;
			}else{
				logError("No pfq connection :(");
			}
			//udp_sender.connect("127.0.0.1", 1234);
			udp_sender.connect("10.0.2.251", 1234);


			StopWatch sw;
			enum n = 1;
			enum udp_count = 10_000;
			TickDuration[n] times;
			TickDuration last = TickDuration.from!"seconds"(0);
			foreach(i; 0..n)
			{
				logInfo("attempt: %s", i);
				sw.start(); //start/resume mesuring.
				for(int k=0; k<udp_count; k++){
					//sleep(dur!"msecs"(1));
					yield();
					uint* ptr = (cast(uint*)payload.ptr);
					*ptr = k;
					udp_sender.send(payload);
					/*if(auto pfqCon = cast(PFQUDPConnection)udp_sender){
						auto err = pfqCon.getLastPFQError();
						if(err!="NULL") logInfo("error: %s, %s", err);
					}*/
				}

				sw.stop();  //stop/pause measuring.
				//Return value of peek() after having stopped are the always same.
				logInfo("%s times done, lap time: %s[ms], speed: %s", (i + 1) * udp_count, sw.peek().msecs, (1000.0f*(i + 1) * udp_count/sw.peek().msecs));
				times[i] = sw.peek() - last;
				last = sw.peek();
			}
			real sum = 0;
			// To know the number of seconds,
			// use properties of TickDuration.
			// (seconds, msecs, usecs, hnsecs)
			foreach(t; times)
				sum += t.msecs;
			if(auto pfqCon = cast(PFQUDPConnection)udp_sender){
				logInfo("Average time: %s msecs; error: %s", sum/n, pfqCon.getLastPFQError());
			}else{
				logInfo("Average time: %s msecs", sum/n);
			}

		}catch(Exception e){
			logError("%s", e);
		}
	});
	logInfo("runEventLoop");
	runEventLoop();
}

