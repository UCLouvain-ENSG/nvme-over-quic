#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* QUIC packet format constants */
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
 * 65      : load_bytes errors (packet too short)
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
    __u32 num_sockets;
    __u32 index;
    __u32 stats_key;
    __u64 *counter;
    __u8 shard_id;
    __u8 buf[32];  /* Increased from 16 to 32 to read SCID when DCID is long */
    int ret;

    /* Read num_sockets from config map */
    {
        __u32 _cfg_key = 0;
        __u32 *_p = bpf_map_lookup_elem(&config_map, &_cfg_key);
        num_sockets = (_p && *_p > 0) ? *_p : 4;
    }

    /* Increment total packet counter (key=64) */
    stats_key = 64;
    counter = bpf_map_lookup_elem(&debug_stats, &stats_key);
    if (counter)
        __sync_fetch_and_add(counter, 1);

    /* Read first 32 bytes of QUIC packet via bpf_skb_load_bytes.
     * Offset 8 skips the 8-byte UDP header prefix.
     * 32 bytes is enough to read SCID even when DCID is 16 bytes:
     *   6 (header) + 16 (max DCID) + 1 (SCID len) + 8 (SCID) = 31 bytes
     * This works regardless of whether the payload is in the linear
     * region or in SKB frags (GRO / hardware coalescing). */
    if (bpf_skb_load_bytes(reuse_md, 8, buf, sizeof(buf)) != 0) {
        /* Packet too short to contain a QUIC header */
        stats_key = 65;
        counter = bpf_map_lookup_elem(&debug_stats, &stats_key);
        if (counter)
            __sync_fetch_and_add(counter, 1);
        index = reuse_md->hash % num_sockets;
        bpf_printk("ERROR: load_bytes failed, hash index=%u", index);
        goto do_select;
    }

    // /* buf[0] = first byte of QUIC packet
    //  * Long header: buf[6] = DCID[0]  (buf[5] = DCID length, buf[1-4] = version)
    //  * Short header: buf[1] = DCID[0] */
    // if (buf[0] & QUIC_LONG_PACKET_BIT)
    //     shard_id = buf[6];
    // else
    //     shard_id = buf[1];


    /* buf[0] = first byte of QUIC packet
    * Long header: Read SCID[0] instead of DCID[0] (SCID has thread_id)
    *   buf[5] = DCID length
    *   buf[6 + dcid_len] = SCID length
    *   buf[6 + dcid_len + 1] = SCID[0] ← Has thread_id
    * Short header: buf[1] = DCID[0] (server's CID with thread_id)
    */
    if (buf[0] & QUIC_LONG_PACKET_BIT) {
        __u8 dcid_len = buf[5];
        __u8 scid_offset = 6 + dcid_len + 1;  // Skip header + DCID + SCID length byte
        
        /* Bounds check: ensure SCID[0] is within our 16-byte buffer */
        if (scid_offset < sizeof(buf)) {
            shard_id = buf[scid_offset];  // SCID[0] has thread_id
           // bpf_printk("Long header: dcid_len=%u scid_offset=%u shard_id=%u", dcid_len, scid_offset, shard_id);
        } else {
            /* SCID is beyond our buffer, fallback to hash-based routing */
            shard_id = (reuse_md->hash & 0xFF) % num_sockets;
            //bpf_printk("Long header: SCID beyond buffer, dcid_len=%u scid_offset=%u", dcid_len, scid_offset);
        }
    } else {
        shard_id = buf[1];  // Short header: DCID[0]
    }


    index = shard_id % num_sockets;
    //bpf_printk("shard_id=%u num_sockets=%u index=%u", shard_id, num_sockets, index);

    /* Track per-reactor routing counter */
    stats_key = index;
    counter = bpf_map_lookup_elem(&debug_stats, &stats_key);
    if (counter)
        __sync_fetch_and_add(counter, 1);

do_select:
    ret = bpf_sk_select_reuseport(reuse_md, &reuseport_array, &index, 0);
    if (ret < 0) {
        stats_key = 66;
        counter = bpf_map_lookup_elem(&debug_stats, &stats_key);
        if (counter)
            __sync_fetch_and_add(counter, 1);
        //bpf_printk("ERROR: bpf_sk_select_reuseport failed (ret=%d index=%u)", ret, index);
    }

    return SK_PASS;
}

char _license[] SEC("license") = "GPL";