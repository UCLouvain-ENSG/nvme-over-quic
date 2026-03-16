#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* QUIC packet format - we receive UDP payload directly */
#define QUIC_LONG_PACKET_BIT    0x80

/* Map to hold socket file descriptors - sized for up to 64 reactors */
#define MAX_REUSEPORT_SOCKETS 64
struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, MAX_REUSEPORT_SOCKETS);
    __type(key, __u32);
    __type(value, __u32);
} reuseport_array SEC(".maps");

/* Config map: key=0 holds num_sockets (populated by userspace after all sockets are ready) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

/* Debug/stats map:
 * 0..N-1  : per-reactor routing counters (N = num_sockets, up to 64)
 * 64      : total packets
 * 65      : parse errors
 * 66      : bpf_sk_select_reuseport errors
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u64);
} debug_stats SEC(".maps");

SEC("sk_reuseport")
int select_socket(struct sk_reuseport_md *reuse_md) {
    void *data_end = (void *)(long)reuse_md->data_end;
    void *data = (void *)(long)reuse_md->data;
    __u8 *quic_pkt;
    __u8 first_byte;
    __u8 dcid_len;
    __u8 *dcid;
    __u8 shard_id = 255;  /* Initialize to invalid value for debugging */
    __u32 index;
    __u32 stats_key;
    __u64 *counter;
    __u64 zero = 0;
    
    //bpf_printk("=== eBPF reuseport called! ===");
    
    /* Dump first 30 bytes of packet to find actual CID location */
    if (data + 30 <= data_end) {
        __u8 *bytes = (__u8 *)data;
        //bpf_printk("[0-2]: %02x %02x %02x", bytes[0], bytes[1], bytes[2]);
        //bpf_printk("[3-5]: %02x %02x %02x", bytes[3], bytes[4], bytes[5]);
        //bpf_printk("[6-8]: %02x %02x %02x", bytes[6], bytes[7], bytes[8]);
        //bpf_printk("[9-11]: %02x %02x %02x", bytes[9], bytes[10], bytes[11]);
        //bpf_printk("[12-14]: %02x %02x %02x", bytes[12], bytes[13], bytes[14]);
        //bpf_printk("[15-17]: %02x %02x %02x", bytes[15], bytes[16], bytes[17]);
        //bpf_printk("[18-20]: %02x %02x %02x", bytes[18], bytes[19], bytes[20]);
        //bpf_printk("[21-23]: %02x %02x %02x", bytes[21], bytes[22], bytes[23]);
        //bpf_printk("[24-26]: %02x %02x %02x", bytes[24], bytes[25], bytes[26]);
        //bpf_printk("[27-29]: %02x %02x %02x", bytes[27], bytes[28], bytes[29]);
    }
    
    /* Increment total packet counter (key=64) */
    stats_key = 64;
    counter = bpf_map_lookup_elem(&debug_stats, &stats_key);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
    
    /* SPDK sends UDP packets with an 8-byte header before QUIC data
     * Skip the first 8 bytes to get to the actual QUIC packet */
    if (data + 8 > data_end) {
        //bpf_printk("ERROR: packet too short for 8-byte header");
        return SK_PASS;
    }
    
    quic_pkt = (__u8 *)data + 8;  /* Skip 8-byte header */
    
    if (quic_pkt + 1 > (__u8 *)data_end) {
        //bpf_printk("ERROR: QUIC packet too short");
        /* Increment error counter (key=65) */
        stats_key = 65;
        counter = bpf_map_lookup_elem(&debug_stats, &stats_key);
        if (counter) {
            __sync_fetch_and_add(counter, 1);
        }
        return SK_PASS;
    }
    
    /* Read first byte of QUIC packet to determine packet type */
    first_byte = *quic_pkt;
    
    //bpf_printk("first_byte=0x%02x (after skipping 8-byte header)", first_byte);
    
    /* Check if it's a long header packet (Initial, 0-RTT, Handshake, Retry) */
    if (first_byte & QUIC_LONG_PACKET_BIT) {
        __u8 dcid_len;
        
        //bpf_printk("Long header packet detected");
        
        /* QUIC long header format:
         * Byte 0: Header form + Fixed bit + Packet Type + Type-Specific
         * Bytes 1-4: Version (4 bytes)
         * Byte 5: DCID Length (1 byte)
         * Bytes 6+: DCID (variable length, should be 16 bytes with shard_id in byte 0)
         */
        
        /* Read DCID length at byte 5 */
        if (quic_pkt + 6 > (__u8 *)data_end) {
            //bpf_printk("ERROR: Cannot read DCID length");
            return SK_PASS;
        }
        dcid_len = quic_pkt[5];
        //bpf_printk("DCID length = %u", dcid_len);
        
        /* DCID starts at byte 6 */
        dcid = quic_pkt + 6;
        
        /* Bounds check for DCID[0] */
        if (dcid + 1 > (__u8 *)data_end) {
            //bpf_printk("ERROR: DCID[0] position out of bounds");
            return SK_PASS;
        }
        
        /* Extract shard_id from DCID byte 0 */
        shard_id = *dcid;
        //bpf_printk("Long header: DCID[0]=%u (shard_id)", shard_id);
    }
    else {
        //bpf_printk("Short header packet (1-RTT)");
        /* Short header: DCID starts at byte 1, fixed 16 bytes */
        dcid = quic_pkt + 1;
        
        if (dcid + 1 > (__u8 *)data_end) {
            //bpf_printk("ERROR: Short header DCID out of bounds");
            return SK_PASS;
        }
        
        /* Extract shard_id from DCID byte 0 */
        shard_id = *dcid;
        //bpf_printk("Short header: shard_id=%u (from DCID[0])", shard_id);
    }
    
    /* Route to socket based on shard_id modulo number of sockets.
     * Read num_sockets from config_map so we don't hardcode 4. */
    __u32 cfg_key = 0;
    __u32 *num_sockets_ptr = bpf_map_lookup_elem(&config_map, &cfg_key);
    __u32 num_sockets = (num_sockets_ptr && *num_sockets_ptr > 0) ? *num_sockets_ptr : 4;
    index = shard_id % num_sockets;
    //bpf_printk("Routing to index=%u (shard_id=%u)", index, shard_id);
    
    /* Track per-index routing (keys 0..num_sockets-1) */
    stats_key = index;
    counter = bpf_map_lookup_elem(&debug_stats, &stats_key);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
    
    /* Select the socket - return value indicates success/failure but we can't log it
     * If this fails, kernel will use default reuseport distribution */
    int ret = bpf_sk_select_reuseport(reuse_md, &reuseport_array, &index, 0);
    
    //bpf_printk("bpf_sk_select_reuseport returned: %d", ret);
    
    /* Track bpf_sk_select_reuseport errors (key=66) */
    if (ret < 0) {
        stats_key = 66;
        counter = bpf_map_lookup_elem(&debug_stats, &stats_key);
        if (counter) {
            __sync_fetch_and_add(counter, 1);
        }
        //bpf_printk("ERROR: bpf_sk_select_reuseport failed!");
    }
    
    /* Always return SK_PASS to let packet through regardless of selection result */
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";