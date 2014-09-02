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
			auto payload = new ubyte[16];//cast(ubyte[])"Hello, World!\r\n";//
			auto udp_sender =  listenUDP(0xc2d5);
			//udp_sender.connect("127.0.0.1", 1234);
			//udp_sender.connect("10.0.2.2", 1234);
			udp_sender.connect("192.168.56.1", 1234);


			StopWatch sw;
			enum n = 1;
			enum udp_count = 1_000;
			TickDuration[n] times;
			TickDuration last = TickDuration.from!"seconds"(0);
			foreach(i; 0..n)
			{
				logInfo("attempt: %s", i);
				sw.start(); //start/resume mesuring.
				for(int k=1; k<udp_count; k++){
					//sleep(dur!"msecs"(1));
					//yield();
					uint* ptr = (cast(uint*)payload.ptr);
					*ptr = k;
					udp_sender.send(payload);
					//logInfo("sent;  %s", k);
				}


				sw.stop();  //stop/pause measuring.
				//Return value of peek() after having stopped are the always same.
				logInfo("%s times done, lap time: %s[ms], speed: %s", (i + 1) * udp_count, sw.peek().msecs, (1000.0f*(i + 1) * udp_count/sw.peek().msecs));
				times[i] = sw.peek() - last;
				last = sw.peek();
				logInfo("yield <-");
				yield();
				logInfo("yield ->");
			}
			real sum = 0;
			// To know the number of seconds,
			// use properties of TickDuration.
			// (seconds, msecs, usecs, hnsecs)
			foreach(t; times)
				sum += t.msecs;
			logInfo("Average time: %s msecs", sum/n);

		}catch(Throwable e){
			logError("%s", e);
		}
	});
	logInfo("runEventLoop");
	runEventLoop();
}

/+ todo
/* set the thread affinity. */
static int setaffinity(pthread_t me, int i) {
    cpuset_t cpumask;

    if (i == -1)
        return 0;

    /* Set thread affinity affinity. */
    CPU_ZERO(&cpumask);
    CPU_SET(i, &cpumask);

    if (pthread_setaffinity_np(me, sizeof(cpuset_t), &cpumask) != 0) {
        D("Unable to set affinity");
        return 1;
    }
    return 0;
}
+/