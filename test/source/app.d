import std.stdio;
import std.string;
import std.conv;
import std.exception;

import core.sys.posix.fcntl;
import core.sys.posix.unistd;
import core.sys.posix.sys.ioctl;
import core.sys.posix.net.if_;
import core.sys.posix.unistd;
import core.sys.posix.sys.mman;


int main(string[] args){
	string s = "Hello";
	writefln("%s = %s", s, cast(byte[])s);
	string ethernetIf = "eth1";
	
	int fd = open("/dev/netmap", O_RDWR);
	if(fd == -1){
		writefln("Can't open /dev/netmap");
		return -1;
	}
	scope(exit) close(fd);

	writefln("open netmap fd: %s", fd);
	nmreq req;
	req.nr_version = NETMAP_API;
	req.nr_flags = NR_REG_NIC_SW;

	req.nr_name[] = 0;
	req.nr_name[0 .. ethernetIf.length] = ethernetIf;

	/* optionally import info from parent */
	//todo

	writefln("try ioctl; nmreq: %s, %s", req, NIOCREGIF);

	if(auto rs = ioctl(fd, NIOCREGIF, &req)){
		writefln("Can't switch to netmap mode: %s", rs);
		return -1;
	}

	writefln("Switch to netmap mode: ok; nmreq: %s", req);

	const(netmap_if*) p = cast(const(netmap_if*))mmap(null, req.nr_memsize, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
	if(p==null){
		writefln("mmap call failed!");
		return -1;
	}
	scope(exit)	munmap(cast(void*)p, req.nr_memsize);
	writefln("mmap pointer: %s", p);

	netmap_if *nifp = NETMAP_IF(p, req.nr_offset);
	writefln("nifp: %s", *nifp);
	netmap_ring *rx = NETMAP_RXRING(nifp, 0);
	netmap_ring *tx = NETMAP_TXRING(nifp, 1);
	//todo zerocopy = zerocopy && (pa->mem == pb->mem);
	writefln("RX: %s", *rx);
	writefln("TX: %s", *tx);
	pollfd pfd[1];
	pfd[0].fd = fd;
	pfd[0].events |= POLLIN;
	/*pfd[1].fd = fd;
	pfd[1].events |= POLLOUT;*/
	while(true){
		int pollRs = poll(pfd.ptr, pfd.length, 10000);
		writefln("poll rs: %s", pollRs);
		//process_rings(rx, tx, 100, "test");
		for(; pollRs>0; pollRs--){
			writefln("rx.cur: %s, , tx.cur: %s", rx.cur, tx.cur);
			netmap_slot* rs = rx.slot.ptr + rx.head + rx.cur;

			auto buf = NETMAP_BUF(rx, rs.buf_idx);
			writefln("buf: %s", buf);

			auto data = buf[0 .. rs.len];
			writefln("Len: %s; Data: %s", rs.len, data);

			netmap_slot* ts = tx.slot.ptr + tx.head + tx.cur;
			ts.len = rs.len;
			uint32_t pkt = ts.buf_idx;
			ts.buf_idx = rs.buf_idx;
			rs.buf_idx = pkt;
			/* report the buffer change. */
			ts.flags |= NS_BUF_CHANGED;
			rs.flags |= NS_BUF_CHANGED;
			//ioctl(fd, NIOCTXSYNC, null);
			//netmap_ring txring = NETMAP_TXRING(nifp, di);

			rx.cur = nm_ring_next(rx, rx.cur);
			tx.cur = nm_ring_next(tx, tx.cur);
			//ioctl(fd, NIOCTXSYNC, null);
		}

	}
	//return 0;
}

/*
 * Same prototype as pcap_inject(), only need to cast.
 */
static int
	nm_inject(nm_desc *d, const void *buf, ushort size)
{
	uint c, n = d.last_tx_ring - d.first_tx_ring + 1;
	
	for (c = 0; c < n ; c++) {
		/* compute current ring to use */
		netmap_ring *ring;
		uint32_t i, idx;
		ushort ri = cast(ushort)(d.cur_tx_ring + c);
		
		if (ri > d.last_tx_ring)
			ri = d.first_tx_ring;
		ring = NETMAP_TXRING(d.nifp, ri);
		if (nm_ring_empty(ring)) {
			continue;
		}
		i = ring.cur;
		idx = ring.slot[i].buf_idx;
		ring.slot[i].len = size;
		nm_pkt_copy(buf, cast(void*)NETMAP_BUF(ring, idx), size);
		d.cur_tx_ring = ri;
		ring.head = ring.cur = nm_ring_next(ring, i);
		return size;
	}
	return 0; /* fail */
}

/+auto nr_flags = NR_REG_ALL_NIC;
	nm_desc d;
	if (nr_flags ==  NR_REG_SW) { /* host stack */
		d.first_tx_ring = d.last_tx_ring = d.req.nr_tx_rings;
		d.first_rx_ring = d.last_rx_ring = d.req.nr_rx_rings;
	} else if (nr_flags ==  NR_REG_ALL_NIC) { /* only nic */
		d.first_tx_ring = 0;
		d.first_rx_ring = 0;
		d.last_tx_ring = cast(ushort)(d.req.nr_tx_rings - 1);
		d.last_rx_ring = cast(ushort)(d.req.nr_rx_rings - 1);
	} else if (nr_flags ==  NR_REG_NIC_SW) {
		d.first_tx_ring = 0;
		d.first_rx_ring = 0;
		d.last_tx_ring = d.req.nr_tx_rings;
		d.last_rx_ring = d.req.nr_rx_rings;
		//todo } else if (nr_flags == NR_REG_ONE_NIC) {
		/* XXX check validity */
		//d.first_tx_ring = d.last_tx_ring =
		//	d.first_rx_ring = d.last_rx_ring = nr_ringid;
	} else { /* pipes */
		d.first_tx_ring = d.last_tx_ring = 0;
		d.first_rx_ring = d.last_rx_ring = 0;
	}
	d.cur_tx_ring = d.first_tx_ring;
	d.cur_rx_ring = d.first_rx_ring;
    +/

//------------------
int	process_rings(netmap_ring *rxring, netmap_ring *txring, uint limit, string msg)
{
	uint j, k, m;
	
	/* print a warning if any of the ring flags is set (e.g. NM_REINIT) */
	if (rxring.flags || txring.flags)
		writefln("%s rxflags %s txflags %s", msg, rxring.flags, txring.flags);
	j = rxring.cur; /* RX */
	k = txring.cur; /* TX */
	m = nm_ring_space(rxring);
	if (m < limit)
		limit = m;
	m = nm_ring_space(txring);
	if (m < limit)
		limit = m;
	m = limit;
	while (limit-- > 0) {
		netmap_slot *rs = rxring.slot.ptr+j;
		netmap_slot *ts = txring.slot.ptr+k;
		
		/* swap packets */
		if (ts.buf_idx < 2 || rs.buf_idx < 2) {
			writefln("wrong index rx[%s] = %s  . tx[%s] = %s", j, rs.buf_idx, k, ts.buf_idx);
			sleep(2);
		}
		/* copy the packet length. */
		if (rs.len > 2048) {
			writefln("wrong len %d rx[%s] . tx[%s]", rs.len, j, k);
			rs.len = 0;
		} else /*if (verbose > 1)*/ {
			writefln("%s send len %d rx[%s] . tx[%s]", msg, rs.len, j, k);
		}
		ts.len = rs.len;
		enum zerocopy = 1; /* enable zerocopy if possible */
		if (zerocopy) {
			uint32_t pkt = ts.buf_idx;
			ts.buf_idx = rs.buf_idx;
			rs.buf_idx = pkt;
			/* report the buffer change. */
			ts.flags |= NS_BUF_CHANGED;
			rs.flags |= NS_BUF_CHANGED;
		} else {
			byte *rxbuf = NETMAP_BUF(rxring, rs.buf_idx);
			byte *txbuf = NETMAP_BUF(txring, ts.buf_idx);
			nm_pkt_copy(rxbuf, txbuf, ts.len);
		}
		j = nm_ring_next(rxring, j);
		k = nm_ring_next(txring, k);
	}
	rxring.head = rxring.cur = j;
	txring.head = txring.cur = k;
	//if (verbose && m > 0)
	//	writefln("%s sent %d packets to %p", msg, m, txring);
	
	return (m);
}

int	move(nm_desc *src, nm_desc *dst, uint limit)
{
	netmap_ring* txring, rxring;
	uint m = 0, si = src.first_rx_ring, di = dst.first_tx_ring;
	string msg = (src.req.nr_ringid & nmreq.NETMAP_SW_RING) ? "host.net" : "net.host";
	
	while (si <= src.last_rx_ring && di <= dst.last_tx_ring) {
		rxring = NETMAP_RXRING(src.nifp, si);
		txring = NETMAP_TXRING(dst.nifp, di);
		writefln("%s txring %p rxring %p", msg, txring, rxring);
		if (nm_ring_empty(rxring)) {
			si++;
			continue;
		}
		if (nm_ring_empty(txring)) {
			di++;
			continue;
		}
		m += process_rings(rxring, txring, limit, msg);
	}
	
	return (m);
}

private import core.sys.posix.config;

version (Posix){
extern (C):
	extern uint netmap_buf_size;
//
// XOpen (XSI)
//
/*
struct pollfd
{
    int     fd;
    short   events;
    short   revents;
}

nfds_t

POLLIN
POLLRDNORM
POLLRDBAND
POLLPRI
POLLOUT
POLLWRNORM
POLLWRBAND
POLLERR
POLLHUP
POLLNVAL

int poll(pollfd[], nfds_t, int);
*/

version( linux )
{
	struct pollfd
	{
		int     fd;
		short   events;
		short   revents;
	}
	
	alias c_ulong nfds_t;
	
	enum
	{
		POLLIN      = 0x001,
		POLLRDNORM  = 0x040,
		POLLRDBAND  = 0x080,
		POLLPRI     = 0x002,
		POLLOUT     = 0x004,
		POLLWRNORM  = 0x100,
		POLLWRBAND  = 0x200,
		POLLERR     = 0x008,
		POLLHUP     = 0x010,
		POLLNVAL    = 0x020,
	}
	
	int poll(pollfd*, nfds_t, int);
}
else version( OSX )
{
	struct pollfd
	{
		int     fd;
		short   events;
		short   revents;
	};
	
	alias uint nfds_t;
	
	enum
	{
		POLLIN      = 0x0001,
		POLLPRI     = 0x0002,
		POLLOUT     = 0x0004,
		POLLRDNORM  = 0x0040,
		POLLWRNORM  = POLLOUT,
		POLLRDBAND  = 0x0080,
		POLLWRBAND  = 0x0100,
		POLLEXTEND  = 0x0200,
		POLLATTRIB  = 0x0400,
		POLLNLINK   = 0x0800,
		POLLWRITE   = 0x1000,
		POLLERR     = 0x0008,
		POLLHUP     = 0x0010,
		POLLNVAL    = 0x0020,
		
		POLLSTANDARD = (POLLIN|POLLPRI|POLLOUT|POLLRDNORM|POLLRDBAND|
		                POLLWRBAND|POLLERR|POLLHUP|POLLNVAL)
	}
	
	int poll(pollfd*, nfds_t, int);
}
else version( FreeBSD )
{
	alias uint nfds_t;
	
	struct pollfd
	{
		int     fd;
		short   events;
		short   revents;
	};
	
	enum
	{
		POLLIN      = 0x0001,
		POLLPRI     = 0x0002,
		POLLOUT     = 0x0004,
		POLLRDNORM  = 0x0040,
		POLLWRNORM  = POLLOUT,
		POLLRDBAND  = 0x0080,
		POLLWRBAND  = 0x0100,
		//POLLEXTEND  = 0x0200,
		//POLLATTRIB  = 0x0400,
		//POLLNLINK   = 0x0800,
		//POLLWRITE   = 0x1000,
		POLLERR     = 0x0008,
		POLLHUP     = 0x0010,
		POLLNVAL    = 0x0020,
		
		POLLSTANDARD = (POLLIN|POLLPRI|POLLOUT|POLLRDNORM|POLLRDBAND|
		                POLLWRBAND|POLLERR|POLLHUP|POLLNVAL)
	}
	
	int poll(pollfd*, nfds_t, int);
}
}

/*
 * The following flags control how the slot is used
 */

enum	NS_BUF_CHANGED =	0x0001;	/* buf_idx changed */
/*
	 * must be set whenever buf_idx is changed (as it might be
	 * necessary to recompute the physical address and mapping)
	 */

enum	NS_REPORT =	0x0002;	/* ask the hardware to report results */
/*
	 * Request notification when slot is used by the hardware.
	 * Normally transmit completions are handled lazily and
	 * may be unreported. This flag lets us know when a slot
	 * has been sent (e.g. to terminate the sender).
	 */

enum	NS_FORWARD =	0x0004;	/* pass packet 'forward' */
/*
	 * (Only for physical ports, rx rings with NR_FORWARD set).
	 * Slot released to the kernel (i.e. before ring->head) with
	 * this flag set are passed to the peer ring (host/NIC),
	 * thus restoring the host-NIC connection for these slots.
	 * This supports efficient traffic monitoring or firewalling.
	 */

enum	NS_NO_LEARN	= 0x0008;	/* disable bridge learning */
/*
	 * On a VALE switch, do not 'learn' the source port for
 	 * this buffer.
	 */

enum	NS_INDIRECT	= 0x0010;	/* userspace buffer */
/*
	 * (VALE tx rings only) data is in a userspace buffer,
	 * whose address is in the 'ptr' field in the slot.
	 */

enum	NS_MOREFRAG	= 0x0020;	/* packet has more fragments */

//------------------
static byte* nm_nextpkt(ref nm_desc d, ref int len)
{
	ushort ri = d.cur_rx_ring;
	
	do {
		/* compute current ring to use */
		netmap_ring* ring = NETMAP_RXRING(d.nifp, ri);
		if (!nm_ring_empty(ring)) {
			uint i = ring.cur;
			uint idx = (ring.slot.ptr+i).buf_idx;
			byte *buf = NETMAP_BUF(ring, idx);
			
			// __builtin_prefetch(buf);
			//hdr->ts = ring->ts;
			//hdr->len = hdr->caplen = ring->slot[i].len;
			len = (ring.slot.ptr+i).len;
			ring.cur = nm_ring_next(ring, i);
			/* we could postpone advancing head if we want
			 * to hold the buffer. This can be supported in
			 * the future.
			 */
			ring.head = ring.cur;
			d.cur_rx_ring = ri;
			return buf;
		}
		ri++;
		if (ri > d.last_rx_ring)
			ri = d.first_rx_ring;
	} while (ri != d.cur_rx_ring);
	return null; /* nothing found */
}

bool nm_ring_empty(netmap_ring *ring)
{
	return (ring.cur == ring.tail);
}
/* helper macro */
auto _NETMAP_OFFSET(type)(const netmap_if* 	ptr, size_t offset){
	return (cast(type)cast(void *)(cast(byte *)(ptr) + (offset)));
}

auto NETMAP_IF(const netmap_if*  _base, size_t _ofs){
	return _NETMAP_OFFSET!(netmap_if *)(_base, _ofs);
}

auto NETMAP_TXRING(const netmap_if* nifp, size_t index){
	return _NETMAP_OFFSET!(netmap_ring *)(nifp, *(nifp.ring_ofs.ptr + index ));
}
auto NETMAP_RXRING(const netmap_if *nifp, size_t index) {
	return _NETMAP_OFFSET!(netmap_ring *)(nifp, *(nifp.ring_ofs.ptr +index + nifp.ni_tx_rings + 1 ));
}

auto NETMAP_BUF(const netmap_ring *ring, size_t index){
	return (cast(byte *)ring + ring.buf_ofs + (index*ring.nr_buf_size));
}

auto NETMAP_BUF_IDX(const netmap_ring* ring, byte* buf){
	return ( (cast(char *)buf - (cast(char *)ring + ring.buf_ofs) ) /  ring.nr_buf_size );
}


uint32_t nm_ring_next( netmap_ring* r, uint32_t i)
{
	return ( (i + 1 == r.num_slots) ? 0 : i + 1);//unlikely
}


/*
 * Return 1 if we have pending transmissions in the tx ring.
 * When everything is complete ring->head = ring->tail + 1 (modulo ring size)
 */
int	nm_tx_pending(netmap_ring *r)
{
	return nm_ring_next(r, r.tail) != r.head;
}


uint32_t nm_ring_space(netmap_ring *ring)
{
	int ret = ring.tail - ring.cur;
	if (ret < 0)
		ret += ring.num_slots;
	return ret;
}


enum NETMAP_RING_MASK =	0x0fff;
enum NETMAP_API	= 11;
enum NIOCGINFO = _IOWR!nmreq(to!int('i'), 145); /* return IF info */
enum NIOCREGIF = _IOWR!nmreq(to!int('i'), 146); /* interface register */
enum NIOCTXSYNC	= _IO(to!int('i'), 148); /* sync tx queues */
enum NIOCRXSYNC	= _IO(to!int('i'), 149); /* sync rx queues */


alias wchar int8_t;
alias short int16_t;
alias int int32_t;
alias long int64_t;
alias ubyte uint8_t;
alias ushort uint16_t;
alias uint uint32_t;
alias ulong uint64_t;
alias wchar int_least8_t;
alias short int_least16_t;
alias int int_least32_t;
alias long int_least64_t;
alias ubyte uint_least8_t;
alias ushort uint_least16_t;
alias uint uint_least32_t;
alias ulong uint_least64_t;
alias wchar int_fast8_t;
alias int int_fast16_t;
alias int int_fast32_t;
alias long int_fast64_t;
alias ubyte uint_fast8_t;
alias uint uint_fast16_t;
alias uint uint_fast32_t;
alias ulong uint_fast64_t;
alias int intptr_t;
alias uint uintptr_t;
alias long intmax_t;
alias ulong uintmax_t;

/*
 * struct nmreq overlays a struct ifreq (just the name)
 *
 * On input, nr_ringid indicates which rings we are requesting,
 * with the low flags for the specific ring number.
 * selection			FLAGS	RING INDEX
 *
 *	all the NIC rings	0x0000	-
 *	only HOST ring		0x2000	-
 *	single NIC ring		0x4000	ring index
 *	all the NIC+HOST rings	0x6000	-
 *	one pipe ring, master	0x8000	ring index
 *	*** INVALID		0xA000
 *	one pipe ring, slave	0xC000	ring index
 *	*** INVALID		0xE000
 * 
 */
struct nmreq {
	char		nr_name[IF_NAMESIZE];
	uint32_t	nr_version;	/* API version */
	uint32_t	nr_offset;	/* nifp offset in the shared region */
	uint32_t	nr_memsize;	/* size of the shared region */
	uint32_t	nr_tx_slots;	/* slots in tx rings */
	uint32_t	nr_rx_slots;	/* slots in rx rings */
	uint16_t	nr_tx_rings;	/* number of tx rings */
	uint16_t	nr_rx_rings;	/* number of rx rings */
	
	uint16_t	nr_ringid;	/* ring(s) we care about */
	enum NETMAP_HW_RING	=	0x4000;	/* single NIC ring pair */
	enum NETMAP_SW_RING	=	0x2000;	/* only host ring pair */
	
	enum NETMAP_RING_MASK	=0x0fff;	/* the ring number */
	
	enum NETMAP_NO_TX_POLL	=0x1000;	/* no automatic txsync on poll */
	
	enum NETMAP_DO_RX_POLL	=0x8000;	/* DO automatic rxsync on poll */
	
	uint16_t	nr_cmd;
	enum NETMAP_BDG_ATTACH	=1;	/* attach the NIC */
	enum NETMAP_BDG_DETACH	=2;	/* detach the NIC */
	enum NETMAP_BDG_LOOKUP_REG	=3;	/* register lookup function */
	enum NETMAP_BDG_LIST		=4;	/* get bridge's info */
	enum NETMAP_BDG_VNET_HDR     =5;       /* set the port virtio-net-hdr length */
	enum NETMAP_BDG_OFFSET	=NETMAP_BDG_VNET_HDR;	/* deprecated alias */
	
	uint16_t	nr_arg1;	/* reserve extra rings in NIOCREGIF */
	enum NETMAP_BDG_HOST	=	1;	/* attach the host stack on ATTACH */
	
	uint16_t	nr_arg2;
	uint32_t	nr_arg3;	/* req. extra buffers in NIOCREGIF */
	uint32_t	nr_flags;
	/* various modes, extends nr_ringid */
	uint32_t	spare2[1];
};

enum NR_REG_MASK	=	0xf; /* values for nr_flags */
enum {	NR_REG_DEFAULT	= 0,	/* backward compat, should not be used. */
	NR_REG_ALL_NIC	= 1,
	NR_REG_SW	= 2,
	NR_REG_NIC_SW	= 3,
	NR_REG_ONE_NIC	= 4,
	NR_REG_PIPE_MASTER = 5,
	NR_REG_PIPE_SLAVE = 6,
};

/*
 * Netmap representation of an interface and its queue(s).
 * This is initialized by the kernel when binding a file
 * descriptor to a port, and should be considered as readonly
 * by user programs. The kernel never uses it.
 *
 * There is one netmap_if for each file descriptor on which we want
 * to select/poll.
 * select/poll operates on one or all pairs depending on the value of
 * nmr_queueid passed on the ioctl.
 */
struct netmap_if {
	char		ni_name[IF_NAMESIZE]; /* name of the interface. */
	const uint32_t	ni_version;	/* API version, currently unused */
	const uint32_t	ni_flags;	/* properties */
	enum NI_PRIV_MEM = 	0x1;		/* private memory region */
	
	/*
	 * The number of packet rings available in netmap mode.
	 * Physical NICs can have different numbers of tx and rx rings.
	 * Physical NICs also have a 'host' ring pair.
	 * Additionally, clients can request additional ring pairs to
	 * be used for internal communication.
	 */
	const uint32_t	ni_tx_rings;	/* number of HW tx rings */
	const uint32_t	ni_rx_rings;	/* number of HW rx rings */
	
	uint32_t	ni_bufs_head;	/* head index for extra bufs */
	uint32_t	ni_spare1[5];
	/*
	 * The following array contains the offset of each netmap ring
	 * from this structure, in the following order:
	 * NIC tx rings (ni_tx_rings); host tx ring (1); extra tx rings;
	 * NIC rx rings (ni_rx_rings); host tx ring (1); extra rx rings.
	 *
	 * The area is filled up by the kernel on NIOCREGIF,
	 * and then only read by userspace code.
	 */
	const ssize_t	ring_ofs[0];
};


struct nm_desc {
	nm_desc *self; /* point to self if netmap. */
	int fd;
	void *mem;
	int memsize;
	int done_mmap;	/* set if mem is the result of mmap */
	const netmap_if * nifp;
	uint16_t first_tx_ring, last_tx_ring, cur_tx_ring;
	uint16_t first_rx_ring, last_rx_ring, cur_rx_ring;
	nmreq req;	/* also contains the nr_name = ifname */
	nm_pkthdr hdr;
	
	/*
	 * The memory contains netmap_if, rings and then buffers.
	 * Given a pointer (e.g. to nm_inject) we can compare with
	 * mem/buf_start/buf_end to tell if it is a buffer or
	 * some other descriptor in our region.
	 * We also store a pointer to some ring as it helps in the
	 * translation from buffer indexes to addresses.
	 */
	const netmap_ring * some_ring;
	const void * buf_start;
	const void * buf_end;
	/* parameters from pcap_open_live */
	int snaplen;
	int promisc;
	int to_ms;
	char *errbuf;
	
	/* save flags so we can restore them on close */
	uint32_t if_flags;
	uint32_t if_reqcap;
	uint32_t if_curcap;
	
	nm_stat st;
	char msg[NM_ERRBUF_SIZE];
};

enum NM_ERRBUF_SIZE = 512;

struct nm_stat {	/* same as pcap_stat	*/
	uint32_t	ps_recv;
	uint32_t	ps_drop;
	uint32_t	ps_ifdrop;
};

struct nm_pkthdr {	/* same as pcap_pkthdr */
	timeval	ts;
	uint32_t	caplen;
	uint32_t	len;
};

struct timeval { 
	long    tv_sec;         /* seconds */
	long    tv_usec;        /* microseconds */
};

/*
 * struct netmap_ring
 *
 * Netmap representation of a TX or RX ring (also known as "queue").
 * This is a queue implemented as a fixed-size circular array.
 * At the software level the important fields are: head, cur, tail.
 *
 * In TX rings:
 *
 *	head	first slot available for transmission.
 *	cur	wakeup point. select() and poll() will unblock
 *		when 'tail' moves past 'cur'
 *	tail	(readonly) first slot reserved to the kernel
 *
 *	[head .. tail-1] can be used for new packets to send;
 *	'head' and 'cur' must be incremented as slots are filled
 *	    with new packets to be sent;
 *	'cur' can be moved further ahead if we need more space
 *	for new transmissions.
 *
 * In RX rings:
 *
 *	head	first valid received packet
 *	cur	wakeup point. select() and poll() will unblock
 *		when 'tail' moves past 'cur'
 *	tail	(readonly) first slot reserved to the kernel
 *
 *	[head .. tail-1] contain received packets;
 *	'head' and 'cur' must be incremented as slots are consumed
 *		and can be returned to the kernel;
 *	'cur' can be moved further ahead if we want to wait for
 *		new packets without returning the previous ones.
 *
 * DATA OWNERSHIP/LOCKING:
 *	The netmap_ring, and all slots and buffers in the range
 *	[head .. tail-1] are owned by the user program;
 *	the kernel only accesses them during a netmap system call
 *	and in the user thread context.
 *
 *	Other slots and buffers are reserved for use by the kernel
 */
struct netmap_ring {
	/*
	 * buf_ofs is meant to be used through macros.
	 * It contains the offset of the buffer region from this
	 * descriptor.
	 */
	const int64_t	buf_ofs;
	const uint32_t	num_slots;	/* number of slots in the ring. */
	const uint32_t	nr_buf_size;
	const uint16_t	ringid;
	const uint16_t	dir;		/* 0: tx, 1: rx */
	
	uint32_t        head;		/* (u) first user slot */
	uint32_t        cur;		/* (u) wakeup point */
	uint32_t	tail;		/* (k) first kernel slot */
	
	uint32_t	flags;
	
	timeval	ts;		/* (k) time of last *sync() */
	
	/* opaque room for a mutex or similar object */
	align (128)	uint8_t		sem[128]; //__attribute__((__aligned__(NM_CACHE_ALIGN)));
	
	/* the slots follow. This struct has variable size */
	netmap_slot[0] slot;	/* array of slots. */
};

/*
 * struct netmap_slot is a buffer descriptor
 */
struct netmap_slot {
	uint32_t buf_idx;	/* buffer index */
	uint16_t len;		/* length for this slot */
	uint16_t flags;		/* buf changed, etc. */
	uint64_t ptr;		/* pointer for indirect buffers */
};


/*
 * this is a slightly optimized copy routine which rounds
 * to multiple of 64 bytes and is often faster than dealing
 * with other odd sizes. We assume there is enough room
 * in the source and destination buffers.
 *
 * XXX only for multiples of 64 bytes, non overlapped.
 */
static void	nm_pkt_copy(const void* _src, void *_dst, ushort l)
{
	ulong *src = cast(ulong*)_src;
	ulong *dst = cast(ulong*)_dst;
	
	if ((l >= 1024)) {//unlikely
		memcpy(dst, src, l);
		return;
	}
	for (; (l > 0); l-=64) {//likely
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
	}
}





/+
import netmap_lib;

extern (C) void processPacket(const void* ptr, int len){
	writefln("got packet: %s", len);
}

int main(){
	writeln("Starting...");
	listen_netmap(toStringz("eth0"), &processPacket);
	return 0;
}+/
/+
int main()
{ 
	try{
		auto nmReq = nmreq();
		/*
		 * open("/dev/netmap", O_RDWR)             = 3
ioctl(3, 0xc03c6991, 0x7ffff34de950)    = 0
*/
		auto netmap = File("/dev/netmap", "r+");
		import std.range;
		string ifname = "eth0";
		char[IFNAMSIZ] name = ifname ~ array(take(repeat('\0'), IFNAMSIZ-ifname.length));
		nmReq.nr_name = name;
		nmReq.nr_version = NETMAP_API;

		writefln("-------------000 %s", errno);

		ioctl(netmap.fileno(), NIOCGINFO, &nmReq);
		writefln("-------------NIOCGINFO %s", errno);

		ioctl(netmap.fileno(), NIOCREGIF, &nmReq);
		writefln("-------------NIOCREGIF %s", errno);

		writefln("map size is %s Kb, offset: %s", nmReq.nr_memsize >> 10, nmReq.nr_offset);
		import linux.netmap;
		//void * ptr = cast(void*)
		writefln("------------- %s", errno);
	    void* ptr = mmap(null, nmReq.nr_memsize, PROT_WRITE | PROT_READ, MAP_SHARED, netmap.fileno(), 0);
		writefln("-------------mmap %s", errno);
		//netmap_if * mmap_addr = cast(netmap_if*)(cast(ubyte*)ptr + nmReq.nr_offset);
		writefln("ok: %s, %s", nmReq, ptr);

		netmap_if * nifp = cast(netmap_if *)(ptr+nmReq.nr_offset);
		writefln("%s", *nifp);

		while(true){
			pollfd x[1];
			writefln("before ring");
			netmap_ring *ring = NETMAP_RXRING(nifp, 0);
			writefln("Ring: %s", *ring);			
			x[0].fd = netmap.fileno();
			x[0].events = POLLIN;
			poll(x.ptr, 1, 1000);
			writefln("After poll");
			for ( ; (*ring).avail > 0 ; (*ring).avail--) {
				auto i = (*ring).cur;
				void* buf = NETMAP_BUF(ring, i);
				writefln("buf; %s, len: %s", buf, (*ring).slot[i].len);
				(*ring).cur = NETMAP_RING_NEXT(ring, i);
			}
		}

	}catch(ErrnoException e){
		writefln("%s", e);
	}
	return 0;
}

+/