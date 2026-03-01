/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2018 Intel Corporation. All rights reserved.
 *   Copyright (c) 2020 Mellanox Technologies LTD. All rights reserved.
 *   Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

/*
 * NVMe/QUIC transport
 */


#include "nvme_internal.h"
#include "spdk/endian.h"
#include "spdk/likely.h"
#include "spdk/string.h"
#include "spdk/stdinc.h"
#include "spdk/crc32.h"
#include "spdk/assert.h"
#include "spdk/trace.h"
#include "spdk/util.h"
#include "spdk/nvmf.h"
#include "spdk/dma.h"

#include "spdk_internal/nvme_quic.h"
#include "spdk_internal/trace_defs.h"

#define NVME_QUIC_RW_BUFFER_SIZE 131072

#define NVME_QUIC_HPDA_DEFAULT			0
#define NVME_QUIC_MAX_R2T_DEFAULT		1
#define NVME_QUIC_PDU_H2C_MIN_DATA_SIZE		4096

#define NVME_QQPAIR_ERRLOG(qqpair, format, ...) NVME_QPAIR_ERRLOG((qqpair) ? &(qqpair)->qpair : NULL, "[%s,%s] " format, (qqpair) ? nvme_quic_qpair_state_string((qqpair)->state) : "", ##__VA_ARGS__)
#define NVME_QQPAIR_WARNLOG(qqpair, format, ...) NVME_QPAIR_WARNLOG((qqpair) ? &(qqpair)->qpair : NULL, format, ##__VA_ARGS__)
#define NVME_QQPAIR_NOTICELOG(qqpair, format, ...) NVME_QPAIR_NOTICELOG((qqpair) ? &(qqpair)->qpair : NULL, format, ##__VA_ARGS__)
#define NVME_QQPAIR_INFOLOG(qqpair, format, ...) NVME_QPAIR_INFOLOG((qqpair) ? &(qqpair)->qpair : NULL, format, ##__VA_ARGS__)
#define NVME_QQPAIR_DEBUGLOG(qqpair, format, ...) NVME_QPAIR_DEBUGLOG((qqpair) ? &(qqpair)->qpair : NULL, format, ##__VA_ARGS__)

#define nvme_quic_qpair_set_recv_state(_qqpair, _state) do { \
	NVME_QQPAIR_DEBUGLOG((_qqpair), "setting qpair state to %s\n", nvme_quic_qpair_state_string((_state))); \
	(_qqpair)->state = (_state); \
} while (0)



enum nvme_quic_qpair_state {
	NVME_QUIC_QPAIR_STATE_INVALID = 0,
	NVME_QUIC_QPAIR_STATE_SOCK_CONNECTING = 1,
	NVME_QUIC_QPAIR_STATE_INITIALIZING = 2,
	NVME_QUIC_QPAIR_STATE_FABRIC_CONNECT_SEND = 3,
	NVME_QUIC_QPAIR_STATE_FABRIC_CONNECT_POLL = 4,
	NVME_QUIC_QPAIR_STATE_AUTHENTICATING = 5,
	NVME_QUIC_QPAIR_STATE_RUNNING = 6,
	NVME_QUIC_QPAIR_STATE_EXITING = 7,
	NVME_QUIC_QPAIR_STATE_EXITED = 8,
};

static struct {
    ptls_iovec_t list[16];
    size_t count;
} negotiated_protocols;


/* NVMe QUIC transport extensions for spdk_nvme_ctrlr */
struct nvme_quic_ctrlr {
	struct spdk_nvme_ctrlr			ctrlr;

	/* Shared QUIC protocol configuration (across all qpairs) */
	quicly_context_t			quic_ctx;

	/* Shared TLS configuration (across all qpairs) */
	ptls_context_t				tls_ctx;
	ptls_key_exchange_algorithm_t		*key_exchanges[128];
	ptls_cipher_suite_t			*cipher_suites[128];

	/* TLS PSK credentials for QUIC */
	char					psk_identity[NVMF_PSK_IDENTITY_LEN];
	uint8_t					psk[SPDK_TLS_PSK_MAX_LEN];
	uint32_t				psk_size;
	const char				*tls_cipher_suite;
	ptls_hash_algorithm_t			*psk_hash_algo;

	/* Address token AEAD for Retry/Resumption tokens (shared, thread-safe) */
	struct {
		ptls_aead_context_t *enc, *dec;
	} address_token_aead;

	/* NVMe-QUIC specific transport parameters */
	uint8_t					nvme_quic_version;     /* NVMe-QUIC protocol version */
	uint32_t				max_in_capsule_data;   /* Max in-capsule data size */
};

struct nvme_quic_poll_group {
	struct spdk_nvme_transport_poll_group group;
	struct spdk_sock_group *sock_group;
	uint32_t completions_per_qpair;
	int64_t num_completions;

	TAILQ_HEAD(, nvme_quic_qpair) needs_poll;
	TAILQ_HEAD(, nvme_quic_qpair) timeout_enabled;

	/* QUIC stats tracking for debugging latency spikes */
	uint64_t stats_poll_counter;
	uint64_t stats_last_ptos;
	uint64_t stats_last_lost;
	uint64_t stats_last_resent;
	struct spdk_nvme_quic_stat stats;
};

/* NVMe QUIC qpair extensions for spdk_nvme_qpair */
struct nvme_quic_qpair {
	struct spdk_nvme_qpair			qpair;
	struct spdk_sock			*sock;

	/* QUIC connection (one per qpair) */
	quicly_conn_t				*conn;

	/* Local and remote addresses for QUIC packet processing */
	quicly_address_t			local_addr;
	quicly_address_t			remote_addr;

	/* Flags for qpair state */
	struct {
		uint8_t reserved : 8;
	} flags;

	/* Per-qpair CID generator (no synchronization needed) */
	quicly_cid_plaintext_t			next_cid;

	/* Per-qpair session resumption state */
	ptls_handshake_properties_t		hs_properties;
	quicly_transport_parameters_t		resumed_transport_params;
	ptls_iovec_t				resumption_token;

	TAILQ_HEAD(, nvme_quic_req)		free_reqs;
	TAILQ_HEAD(, nvme_quic_req)		outstanding_reqs;


	/* Free allocated streams with quic_reqs */
	struct nvme_quic_stream			*send_streams;
	struct nvme_quic_stream			*send_stream;
	struct nvme_quic_stream			*recv_stream;


	struct nvme_quic_req			*quic_reqs;
	struct spdk_nvme_quic_stat		*stats;

	uint16_t				num_entries;
	uint16_t				async_complete;
	uint16_t				async_stream_complete;

	enum nvme_quic_qpair_state		state;

	TAILQ_ENTRY(nvme_quic_qpair)		link_poll;

	TAILQ_ENTRY(nvme_quic_qpair)		link_timeout;

	bool					shared_stats;
};

enum nvme_quic_req_state {
    NVME_QUIC_REQ_FREE,
	NVME_QUIC_REQ_ACTIVE,
	NVME_QUIC_REQ_AWAIT_DATA,       // Waiting for READ data
	NVME_QUIC_REQ_AWAIT_R2T,      // Waiting for WRITE R2T
	NVME_QUIC_REQ_SENDING_DATA,     // Sending WRITE data
	NVME_QUIC_REQ_AWAIT_CQE,        // Waiting for completion
	NVME_QUIC_REQ_COMPLETE
};

struct nvme_quic_req {
	struct nvme_request			*req;
	enum nvme_quic_req_state		state;
	uint16_t				cid;
	uint32_t				datao;		/* Current data offset for WRITE */
	uint32_t				expected_datao;	/* Total data received for READ */
	uint32_t				r2t_len;	/* Granted data length for WRITE */
	bool					in_capsule_data;

	/* Embedded QUIC stream for this command */
	struct nvme_quic_stream			*stream;

	/* Application buffer info (for READ, WRITE data) */
	struct iovec				iov[NVME_QUIC_MAX_SGL_DESCRIPTORS];
	uint32_t				iovcnt; 

	/* Completion storage */
	struct spdk_nvme_cpl			cpl;

	/* Ordering bits for completion */
	union {
		uint8_t raw;
		struct {
			/* The last send operation completed - kernel released send buffer */
			uint8_t				send_ack : 1;
			/* Data transfer completed - target send resp or last data bit */
			uint8_t				data_recv : 1;
			/* CQE received from target */
			uint8_t				recv_cpl : 1;
			/* tcp_req is waiting for completion of the previous send operation (buffer reclaim notification
			 * from kernel) to send H2C */
			uint8_t				h2c_send_waiting_ack : 1;
			/* tcp_req received subsequent r2t while it is still waiting for send_ack.
			 * Rare case, actual when dealing with target that can send several R2T requests.
			 * SPDK TCP target sends 1 R2T for the whole data buffer */
			uint8_t				r2t_waiting_h2c_complete : 1;
			/* Accel operation is in progress */
			uint8_t				in_progress_accel : 1;
			uint8_t				domain_in_use: 1;
			uint8_t				reserved : 1;
		} bits;
	} ordering;

	struct nvme_quic_qpair			*qqpair;
	TAILQ_ENTRY(nvme_quic_req)		link;

	/* Padding to cache line size */
	uint8_t					reserved_pad[36];
};
SPDK_STATIC_ASSERT(sizeof(struct nvme_quic_req) % SPDK_CACHE_LINE_SIZE == 0, "unaligned size");

static struct spdk_nvme_quic_stat g_dummy_stats = {};

static void nvme_quic_write_data_send(struct nvme_quic_req *quic_req);
static int64_t nvme_quic_poll_group_process_completions(struct spdk_nvme_transport_poll_group
		*tgroup, uint32_t completions_per_qpair, spdk_nvme_disconnected_qpair_cb disconnected_qpair_cb);
static void nvme_quic_req_complete(struct nvme_quic_req *quic_req, struct nvme_quic_qpair *qqpair,
				  struct spdk_nvme_cpl *rsp, bool print_on_error);

static inline const char *
nvme_quic_qpair_state_string(enum nvme_quic_qpair_state state)
{
	switch (state) {
	case NVME_QUIC_QPAIR_STATE_INVALID:
		return "INVALID";
	case NVME_QUIC_QPAIR_STATE_SOCK_CONNECTING:
		return "SOCK_CONNECTING";
	case NVME_QUIC_QPAIR_STATE_INITIALIZING:
		return "INITIALIZING";
	case NVME_QUIC_QPAIR_STATE_FABRIC_CONNECT_SEND:
		return "FABRIC_CONNECT_SEND";
	case NVME_QUIC_QPAIR_STATE_FABRIC_CONNECT_POLL:
		return "FABRIC_CONNECT_POLL";
	case NVME_QUIC_QPAIR_STATE_AUTHENTICATING:
		return "AUTHENTICATING";
	case NVME_QUIC_QPAIR_STATE_RUNNING:
		return "RUNNING";
	case NVME_QUIC_QPAIR_STATE_EXITING:
		return "EXITING";
	case NVME_QUIC_QPAIR_STATE_EXITED:
		return "EXITED";
	default:
		return "UNKNOWN";
	}
}



static inline struct nvme_quic_qpair *
nvme_quic_qpair(struct spdk_nvme_qpair *qpair)
{
	assert(qpair->trtype == SPDK_NVME_TRANSPORT_QUIC);
	return SPDK_CONTAINEROF(qpair, struct nvme_quic_qpair, qpair);
}

static inline struct nvme_quic_poll_group *
nvme_quic_poll_group(struct spdk_nvme_transport_poll_group *group)
{
	return SPDK_CONTAINEROF(group, struct nvme_quic_poll_group, group);
}

static inline struct nvme_quic_ctrlr *
nvme_quic_ctrlr(struct spdk_nvme_ctrlr *ctrlr)
{
	assert(ctrlr->trid.trtype == SPDK_NVME_TRANSPORT_QUIC);
	return SPDK_CONTAINEROF(ctrlr, struct nvme_quic_ctrlr, ctrlr);
}

static struct nvme_quic_req *
nvme_quic_req_get(struct nvme_quic_qpair *qqpair)
{
    struct nvme_quic_req *quic_req;

    quic_req = TAILQ_FIRST(&qqpair->free_reqs);
    if (!quic_req) {
		NVME_QQPAIR_DEBUGLOG(qqpair, "[REQ_GET] No free requests available for qqpair %p\n", qqpair);
        return NULL;
    }

    assert(quic_req->state == NVME_QUIC_REQ_FREE);

    
    NVME_QQPAIR_DEBUGLOG(qqpair, "[REQ_GET] Reusing request, old cid=%u, stream=%p\n", quic_req->cid, quic_req->stream);
    if (quic_req->stream) {
        NVME_QQPAIR_DEBUGLOG(qqpair, "[REQ_GET]   stream sendbuf: vecs.size=%zu, capacity=%zu\n",
		    quic_req->stream->streambuf.egress.vecs.size,
		    quic_req->stream->streambuf.egress.vecs.capacity);
		
		/* Don't manually free vecs - QUIC manages this through shift callbacks */
		if (quic_req->stream->streambuf.egress.vecs.size > 0) {
			NVME_QQPAIR_DEBUGLOG(qqpair, "[REQ_GET]   **WARNING**: vecs.size=%zu > 0 on reuse (QUIC hasn't shifted yet)\n",
				    quic_req->stream->streambuf.egress.vecs.size);
		}
    }
    
    quic_req->state = NVME_QUIC_REQ_ACTIVE;
    TAILQ_REMOVE(&qqpair->free_reqs, quic_req, link);
    quic_req->datao = 0;
    quic_req->expected_datao = 0;
    quic_req->req = NULL;
    quic_req->in_capsule_data = false;
    quic_req->qqpair = qqpair;
    
    /* Clear ordering bits - important for send_ack and recv_cpl synchronization */
    quic_req->ordering.raw = 0;

    /* Do NOT reset stream - it's assigned during alloc_reqs and should persist */
    memset(&quic_req->cpl, 0, sizeof(struct spdk_nvme_cpl));

    return quic_req;
}

static void
nvme_quic_req_put(struct nvme_quic_qpair *qqpair, struct nvme_quic_req *quic_req)
{
	assert(quic_req->state != NVME_QUIC_REQ_FREE);
	
	NVME_QQPAIR_DEBUGLOG(qqpair, "[REQ_PUT] Freeing request cid=%u, state=%d, stream=%p\n",
		    quic_req->cid, quic_req->state, quic_req->stream);
	if (quic_req->stream) {
		NVME_QQPAIR_DEBUGLOG(qqpair, "[REQ_PUT]   stream sendbuf: vecs.entries=%p, size=%zu, capacity=%zu, off_in_first_vec=%zu\n",
			    quic_req->stream->streambuf.egress.vecs.entries,
			    quic_req->stream->streambuf.egress.vecs.size,
			    quic_req->stream->streambuf.egress.vecs.capacity,
			    quic_req->stream->streambuf.egress.off_in_first_vec);
		if (quic_req->stream->streambuf.egress.vecs.size > 0) {
			NVME_QQPAIR_DEBUGLOG(qqpair, "[REQ_PUT]   **CRITICAL BUG**: vecs.size=%zu > 0 when freeing!\n",
				    quic_req->stream->streambuf.egress.vecs.size);
			NVME_QQPAIR_DEBUGLOG(qqpair, "[REQ_PUT]   This means send ACK hasn't arrived yet OR vecs weren't shifted!\n");

			NVME_QQPAIR_DEBUGLOG(qqpair, "[REQ_PUT]   When send ACK arrives later, QUIC will try to shift INVALID vecs!\n");
			NVME_QQPAIR_DEBUGLOG(qqpair, "[REQ_PUT]   This will cause: Assertion `i < sb->vecs.size' failed\n");
		}
	}
	
	ptls_buffer_dispose(&quic_req->stream->streambuf.ingress);
	ptls_buffer_init(&quic_req->stream->streambuf.ingress, "", 0);

	quicly_sendbuf_dispose(&quic_req->stream->streambuf.egress);
	quicly_sendbuf_init(&quic_req->stream->streambuf.egress);


	quic_req->state = NVME_QUIC_REQ_FREE;
	// TAILQ_INSERT_HEAD(&qqpair->free_reqs, quic_req, link);

	qqpair->async_stream_complete++;

	TAILQ_INSERT_TAIL(&qqpair->free_reqs, quic_req, link);
}

static void
nvme_quic_free_reqs(struct nvme_quic_qpair *qqpair)
{
	free(qqpair->quic_reqs);
	qqpair->quic_reqs = NULL;

	spdk_free(qqpair->send_streams);
	qqpair->send_streams = NULL;
}

static int
nvme_quic_alloc_reqs(struct nvme_quic_qpair *qqpair)
{
	uint16_t i;
	struct nvme_quic_req *quic_req;
	uint16_t padded_qsize = qqpair->num_entries;  /* Convert back to actual qsize for allocation */
	// uint16_t padded_qsize = 1024;

	NVME_QQPAIR_DEBUGLOG(qqpair, "[ALLOC_REQS] Starting allocation: num_entries=%u, padded_qsize=%u (qsize)\n",
			    qqpair->num_entries, padded_qsize);

	qqpair->quic_reqs = aligned_alloc(SPDK_CACHE_LINE_SIZE,
					 padded_qsize * sizeof(*quic_req));
	if (qqpair->quic_reqs == NULL) {
		NVME_QQPAIR_ERRLOG(qqpair, "Failed to allocate quic_reqs\n");
		goto fail;
	}
	NVME_QQPAIR_DEBUGLOG(qqpair, "[ALLOC_REQS] Allocated quic_reqs array at %p (size=%zu bytes)\n",
			    qqpair->quic_reqs, padded_qsize * sizeof(*quic_req));

	/* Add additional 2 member for the send_stream, recv_stream owned by the qqpair */
	qqpair->send_streams = spdk_zmalloc((padded_qsize + 2) * sizeof(struct nvme_quic_stream),
					 0x1000, NULL,
					 SPDK_ENV_NUMA_ID_ANY, SPDK_MALLOC_DMA);

	if (qqpair->send_streams == NULL) {
		NVME_QQPAIR_ERRLOG(qqpair, "Failed to allocate send_streams\n");
		goto fail;
	}

	memset(qqpair->quic_reqs, 0, padded_qsize * sizeof(*quic_req));
	TAILQ_INIT(&qqpair->free_reqs);
	TAILQ_INIT(&qqpair->outstanding_reqs);
	qqpair->qpair.queue_depth = 0;
	for (i = 0; i < padded_qsize; i++) {
		quic_req = &qqpair->quic_reqs[i];
		quic_req->cid = i;
		quic_req->qqpair = qqpair;
		quic_req->stream = &qqpair->send_streams[i];

		quic_req->stream->quic_stream = NULL;

		quicly_sendbuf_init(&quic_req->stream->streambuf.egress);
		ptls_buffer_init(&quic_req->stream->streambuf.ingress, "", 0);

		if (i < 5 || i >= padded_qsize - 5) {
			/* Log first 5 and last 5 requests */
			NVME_QQPAIR_DEBUGLOG(qqpair, "[ALLOC_REQS]   req[%u]: cid=%u, quic_req=%p, stream=%p\n",
					    i, quic_req->cid, quic_req, quic_req->stream);
		}

		TAILQ_INSERT_TAIL(&qqpair->free_reqs, quic_req, link);
	}

	qqpair->send_stream = &qqpair->send_streams[i];
	qqpair->recv_stream = &qqpair->send_streams[i + 1];

	return 0;
fail:
	nvme_quic_free_reqs(qqpair);
	return -ENOMEM;
}

static void _quic_send_pending(struct nvme_quic_qpair *qqpair);
static void nvme_quic_qpair_abort_reqs(struct spdk_nvme_qpair *qpair, uint32_t dnr);
static int nvme_quic_ctrlr_connect_qpair_poll(struct spdk_nvme_ctrlr *ctrlr,
		struct spdk_nvme_qpair *qpair);



static void
nvme_quic_grace_disconnect_qpair(struct spdk_nvme_qpair *qpair)
{
	// Send CONNECTION CLOSE with NO_ERROR to allow graceful shutdown and avoid unnecessary retransmissions
	struct nvme_quic_qpair *qqpair = nvme_quic_qpair(qpair);
	if (qqpair->conn) {
		NVME_QQPAIR_DEBUGLOG(qqpair, "Initiating graceful QUIC disconnect for qpair %p\n", qqpair);
		quicly_close(qqpair->conn, 0, "");
	} else {
		NVME_QQPAIR_DEBUGLOG(qqpair, "No active QUIC connection for qpair %p, skipping graceful disconnect\n", qqpair);
	}

	_quic_send_pending(qqpair);
}


static void
nvme_quic_ctrlr_disconnect_qpair(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair)
{
	struct nvme_quic_qpair *qqpair = nvme_quic_qpair(qpair);
	int rc;
	struct nvme_quic_poll_group *group;

	if (TAILQ_ENTRY_ENQUEUED(qqpair, link_poll)) {
		group = nvme_quic_poll_group(qpair->poll_group);
		TAILQ_REMOVE_CLEAR(&group->needs_poll, qqpair, link_poll);
	}

	nvme_quic_grace_disconnect_qpair(qpair);

	if (qqpair->conn) {
		quicly_free(qqpair->conn);
		qqpair->conn = NULL;
	}

	rc = spdk_sock_close(&qqpair->sock);

	if (qqpair->sock != NULL) {
		NVME_QQPAIR_ERRLOG(qqpair, "errno=%d, rc=%d\n", errno, rc);
		/* Set it to NULL manually */
		qqpair->sock = NULL;
	}

	nvme_quic_qpair_abort_reqs(qpair, qpair->abort_dnr);

	SPDK_DEBUGLOG(nvme, "Disconnected QUIC qpair %p\n", qqpair);

	/* If the qpair is marked as asynchronous, let it go through the process_completions() to
	 * let any outstanding requests (e.g. those with outstanding accel operations) complete.
	 * Otherwise, there's no way of waiting for them, so qqpair->outstanding_reqs has to be
	 * empty.
	 */
	if (qpair->async) {
		nvme_quic_qpair_set_recv_state(qqpair, NVME_QUIC_RECV_STATE_QUIESCING);
		if(nvme_qpair_get_state(&qqpair->qpair) == NVME_QPAIR_DISCONNECTING) {
			SPDK_DEBUGLOG(nvme,"Continuing disconnect process for async qpair %p\n", qqpair);
			nvme_transport_ctrlr_disconnect_qpair_done(&qqpair->qpair);

			if (TAILQ_EMPTY(&qqpair->outstanding_reqs)) {
				if (nvme_qpair_get_state(&qqpair->qpair) == NVME_QPAIR_DISCONNECTING) {
					nvme_transport_ctrlr_disconnect_qpair_done(&qqpair->qpair);
				}
			}
		}
		

	} else {
		assert(TAILQ_EMPTY(&qqpair->outstanding_reqs));
		nvme_transport_ctrlr_disconnect_qpair_done(qpair);
	}
}

static int
nvme_quic_ctrlr_delete_io_qpair(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair)
{
	struct nvme_quic_qpair *qqpair = nvme_quic_qpair(qpair);

	assert(qpair != NULL);
	nvme_quic_qpair_abort_reqs(qpair, qpair->abort_dnr);
	assert(TAILQ_EMPTY(&qqpair->outstanding_reqs));

	nvme_qpair_deinit(qpair);
	nvme_quic_free_reqs(qqpair);
	if (!qqpair->shared_stats) {
		free(qqpair->stats);
	}
	free(qqpair);

	return 0;
}

static int
nvme_quic_ctrlr_enable(struct spdk_nvme_ctrlr *ctrlr)
{
	return 0;
}

static int
nvme_quic_ctrlr_destruct(struct spdk_nvme_ctrlr *ctrlr)
{
	struct nvme_quic_ctrlr *qctrlr = nvme_quic_ctrlr(ctrlr);

	if (ctrlr->adminq) {
		nvme_quic_ctrlr_delete_io_qpair(ctrlr, ctrlr->adminq);
	}

	nvme_ctrlr_destruct_finish(ctrlr);

	/* Free heap-allocated resources within QUIC/TLS contexts */
	if (qctrlr->address_token_aead.enc) {
		ptls_aead_free(qctrlr->address_token_aead.enc);
	}
	if (qctrlr->address_token_aead.dec) {
		ptls_aead_free(qctrlr->address_token_aead.dec);
	}

	/* Free plaintext CID encryptor */
	if (qctrlr->quic_ctx.cid_encryptor) {
		nvme_quic_free_plaintext_cid_encryptor(qctrlr->quic_ctx.cid_encryptor);
	}

	/* The quic_ctx and tls_ctx structures are embedded, not pointers,
	 * so they're freed automatically when qctrlr is freed */
	free(qctrlr);

	return 0;
}

static bool
nvme_quic_has_pending_data(struct nvme_quic_qpair *qqpair)
{
	int64_t now, first_timeout;

	if (!qqpair->conn) {
		return false;
	}

	now = spdk_get_ticks();
	first_timeout = quicly_get_first_timeout(qqpair->conn);
	/* If first_timeout is in the past or now, there's pending data (including ACKs, retransmissions, etc.) */
	return (first_timeout != INT64_MAX && first_timeout <= now);
}

static void

nvme_quic_cond_schedule_qpair_polling(struct nvme_quic_qpair *qqpair)
{
	struct nvme_quic_poll_group *pgroup;
	bool has_pending_data = false;

	if (TAILQ_ENTRY_ENQUEUED(qqpair, link_poll) || !qqpair->qpair.poll_group) {
		NVME_QQPAIR_DEBUGLOG(qqpair, "[NEEDS_POLL] Already enqueued or no poll_group\n");
		return;
	}

	/* Check if QUIC has pending data to send */
	has_pending_data = nvme_quic_has_pending_data(qqpair);
	if (has_pending_data) {
		NVME_QQPAIR_DEBUGLOG(qqpair, "[NEEDS_POLL] QUIC has pending data\n");
	}

	/* Skip only if: (1) no queued requests AND (2) no pending QUIC data AND (3) not in special states */
	if (STAILQ_EMPTY(&qqpair->qpair.queued_req) && !has_pending_data &&
	    spdk_likely(qqpair->state != NVME_QUIC_QPAIR_STATE_FABRIC_CONNECT_POLL &&
			qqpair->state != NVME_QUIC_QPAIR_STATE_INITIALIZING)) {
		NVME_QQPAIR_DEBUGLOG(qqpair, "[NEEDS_POLL] Skipped: queued_req empty, pending_data=%d, state=%d\n",
				      qqpair->state);
		return;
	}

	NVME_QQPAIR_DEBUGLOG(qqpair, "[NEEDS_POLL] Adding to needs_poll list (queued_req=%d, pending_data=%d)\n",
			     !STAILQ_EMPTY(&qqpair->qpair.queued_req));
	pgroup = nvme_quic_poll_group(qqpair->qpair.poll_group);
	TAILQ_INSERT_TAIL(&pgroup->needs_poll, qqpair, link_poll);
}

static void
stream_write_done(void *cb_arg, int err)
{
	struct nvme_quic_stream *stream = cb_arg;
	struct nvme_quic_qpair *qqpair = stream->qpair;

	nvme_quic_cond_schedule_qpair_polling(qqpair);
	if (err != 0) {
		nvme_transport_ctrlr_disconnect_qpair(qqpair->qpair.ctrlr, &qqpair->qpair);
		return;
	}

	assert(stream->cb_fn != NULL);
	stream->cb_fn(stream->cb_arg);
}

static void
stream_write_fail(struct nvme_quic_stream *stream, int status)
{
	/* This function is similar to pdu_write_done(), but it should be called before a PDU is
	 * sent over the socket */
	stream_write_done(stream, status);
}


static void
_quic_send_pending(struct nvme_quic_qpair *qqpair)
{
	quicly_address_t dest, src;
	size_t num_packets;
	struct iovec udp_datagrams[SPDK_NVME_ADMIN_QUEUE_QUIRK_ENTRIES_MULTIPLE];
	uint8_t buf[SPDK_NVME_ADMIN_QUEUE_QUIRK_ENTRIES_MULTIPLE * SPDK_NVME_QUIC_MAX_UDP_DATAGRAM_SIZE];
	quicly_error_t ret;
	int total_packets_sent = 0;

	/* Keep calling quicly_send() until all pending data is sent */
	do {
		num_packets = SPDK_NVME_ADMIN_QUEUE_QUIRK_ENTRIES_MULTIPLE;

		/* Ask quicly to generate UDP packets from queued stream data */
		ret = quicly_send(qqpair->conn, &dest, &src, udp_datagrams, &num_packets, buf, sizeof(buf));
		if (ret != 0) {
			SPDK_ERRLOG("quicly_send failed: %d\n", ret);
			return total_packets_sent;
		}

		if (num_packets == 0) {
			/* No more packets to send */
			// SPDK_DEBUGLOG(nvme, "Nothing to send PAKCET : quicly_send returned %zu packets\n", 
			// 			num_packets);
			break;
		}

		SPDK_DEBUGLOG(nvme, "Send PAKCET : quicly_send returned %zu packets\n", 
		            num_packets);

		/* Log destination address */
		{
			char dest_str[64] = "N/A";
			uint16_t dest_port = 0;
			if (dest.sa.sa_family == AF_INET) {
				struct sockaddr_in *d = (struct sockaddr_in *)&dest.sa;
				inet_ntop(AF_INET, &d->sin_addr, dest_str, sizeof(dest_str));
				dest_port = ntohs(d->sin_port);
			} else if (dest.sa.sa_family == AF_INET6) {
				struct sockaddr_in6 *d = (struct sockaddr_in6 *)&dest.sa;
				inet_ntop(AF_INET6, &d->sin6_addr, dest_str, sizeof(dest_str));
				dest_port = ntohs(d->sin6_port);
			} else {
				SPDK_ERRLOG("dest.sa.sa_family=%d (not AF_INET or AF_INET6!)\n", dest.sa.sa_family);
			}

		}
		
		/* Send all packets from this batch */
		for(int i = 0; i < num_packets; i++) {
			int rc = spdk_sock_writev_direct(qqpair->sock, &udp_datagrams[i], 1, &dest.sa, quicly_get_socklen(&dest.sa));
			if (rc < 0) {
				SPDK_DEBUGLOG(nvme, "spdk_sock_writev_direct failed: rc=%d, errno=%d (%s)\n", rc, errno, strerror(errno));
			}
		}
		total_packets_sent += num_packets;
	} while (num_packets > 0);

	if (total_packets_sent > 0) {
		SPDK_DEBUGLOG(nvme, "SERVER: _nvmf_quic_send_pending: sent total %d packets\n", 
		            total_packets_sent);
	}

	return total_packets_sent;
}



// static void
// nvme_quic_qpair_write_stream(struct nvme_quic_qpair *qqpair,
// 			 struct nvme_quic_stream *stream)
// {
// 	quicly_sendbuf_write_vec(stream->quic_stream, &stream->streambuf.egress, stream->send_buf);
// }

static int
nvme_quic_try_memory_translation(struct nvme_quic_req *quic_req, void **addr, uint32_t length)
{
	struct nvme_request *req = quic_req->req;
	struct spdk_memory_domain_translation_result translation = {
		.iov_count = 0,
		.size = sizeof(translation)
	};
	int rc;

	if (!req->payload.opts || !req->payload.opts->memory_domain) {
		return 0;
	}

	rc = spdk_memory_domain_translate_data(req->payload.opts->memory_domain,
					       req->payload.opts->memory_domain_ctx, spdk_memory_domain_get_system_domain(), NULL, *addr, length,
					       &translation);
	if (spdk_unlikely(rc || translation.iov_count != 1)) {
		NVME_QQPAIR_ERRLOG(quic_req->qqpair, "DMA memory translation failed, rc %d, iov_count %u\n", rc,
				   translation.iov_count);
		return -EFAULT;
	}

	assert(length == translation.iov.iov_len);
	*addr = translation.iov.iov_base;
	return 0;
}

/*
 * Build SGL describing contiguous payload buffer.
 */
static int
nvme_quic_build_contig_request(struct nvme_quic_qpair *qqpair, struct nvme_quic_req *quic_req)
{
	struct nvme_request *req = quic_req->req;

	/* ubsan complains about applying zero offset to null pointer if contig_or_cb_arg is NULL,
	 * so just double cast it to make it go away */
	void *addr = (void *)((uintptr_t)req->payload.contig_or_cb_arg + req->payload_offset);
	size_t length = req->payload_size;
	int rc;

	NVME_QQPAIR_DEBUGLOG(qqpair, "enter\n");

	assert(nvme_payload_type(&req->payload) == NVME_PAYLOAD_TYPE_CONTIG);
	rc = nvme_quic_try_memory_translation(quic_req, &addr, length);
	if (spdk_unlikely(rc)) {
		return rc;
	}

	quic_req->iov[0].iov_base = addr;
	quic_req->iov[0].iov_len = length;
	quic_req->iovcnt = 1;
	return 0;
}

/*
 * Build SGL describing scattered payload buffer.
 */
static int
nvme_quic_build_sgl_request(struct nvme_quic_qpair *qqpair, struct nvme_quic_req *quic_req)
{
	int rc;
	uint32_t length, remaining_size, iovcnt = 0, max_num_sgl;
	struct nvme_request *req = quic_req->req;
	NVME_QQPAIR_DEBUGLOG(qqpair, "enter\n");

	assert(req->payload_size != 0);
	assert(nvme_payload_type(&req->payload) == NVME_PAYLOAD_TYPE_SGL);
	assert(req->payload.reset_sgl_fn != NULL);
	assert(req->payload.next_sge_fn != NULL);
	req->payload.reset_sgl_fn(req->payload.contig_or_cb_arg, req->payload_offset);

	max_num_sgl = spdk_min(req->qpair->ctrlr->max_sges, NVME_QUIC_MAX_SGL_DESCRIPTORS);
	remaining_size = req->payload_size;

	do {
		void *addr;

		rc = req->payload.next_sge_fn(req->payload.contig_or_cb_arg, &addr, &length);
		if (rc) {
			return -1;
		}

		rc = nvme_quic_try_memory_translation(quic_req, &addr, length);
		if (spdk_unlikely(rc)) {
			return rc;
		}

		length = spdk_min(length, remaining_size);
		quic_req->iov[iovcnt].iov_base = addr;
		quic_req->iov[iovcnt].iov_len = length;
		remaining_size -= length;
		iovcnt++;
	} while (remaining_size > 0 && iovcnt < max_num_sgl);


	/* Should be impossible if we did our sgl checks properly up the stack, but do a sanity check here. */
	if (remaining_size > 0) {
		NVME_QQPAIR_ERRLOG(qqpair, "Failed to construct quic_req=%p, and the iovcnt=%u, remaining_size=%u\n",
				   quic_req, iovcnt, remaining_size);
		return -1;
	}

	quic_req->iovcnt = iovcnt;
	return 0;
}

static int
nvme_quic_req_init(struct nvme_quic_qpair *qqpair, struct nvme_request *req,
		  struct nvme_quic_req *quic_req)
{
	struct spdk_nvme_ctrlr *ctrlr = qqpair->qpair.ctrlr;
	int rc = 0;
	enum spdk_nvme_data_transfer xfer;
	uint32_t max_in_capsule_data_size;

	quic_req->req = req;

	req->cmd.cid = quic_req->cid;
	req->cmd.psdt = SPDK_NVME_PSDT_SGL_MPTR_CONTIG;
	req->cmd.dptr.sgl1.unkeyed.type = SPDK_NVME_SGL_TYPE_TRANSPORT_DATA_BLOCK;
	req->cmd.dptr.sgl1.unkeyed.subtype = SPDK_NVME_SGL_SUBTYPE_TRANSPORT;
	req->cmd.dptr.sgl1.unkeyed.length = req->payload_size;

	if (spdk_unlikely(req->cmd.opc == SPDK_NVME_OPC_FABRIC)) {
		struct spdk_nvmf_capsule_cmd *nvmf_cmd = (struct spdk_nvmf_capsule_cmd *)&req->cmd;

		xfer = spdk_nvme_opc_get_data_transfer(nvmf_cmd->fctype);
	} else {
		xfer = spdk_nvme_opc_get_data_transfer(req->cmd.opc);
	}

	/* Build iov array for both READ and WRITE commands */
	if (nvme_payload_type(&req->payload) == NVME_PAYLOAD_TYPE_CONTIG) {
		rc = nvme_quic_build_contig_request(qqpair, quic_req);
	} else if (nvme_payload_type(&req->payload) == NVME_PAYLOAD_TYPE_SGL) {
		rc = nvme_quic_build_sgl_request(qqpair, quic_req);
	} else if (req->payload_size > 0) {
		rc = -1;
	}

	if (rc) {
		return rc;
	}

	/* Set initial state based on transfer direction */
	if (xfer == SPDK_NVME_DATA_CONTROLLER_TO_HOST) {
		/* READ command - will receive data then CQE */
		quic_req->state = NVME_QUIC_REQ_AWAIT_DATA;
	} else if (xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER) {
		/* WRITE command - will need R2T or send in-capsule */
		quic_req->state = NVME_QUIC_REQ_AWAIT_R2T;
	} else {
		/* No data transfer - will receive CQE only */
		quic_req->state = NVME_QUIC_REQ_AWAIT_CQE;
		/* Mark data as "complete" since there's no data to transfer */
		quic_req->ordering.bits.data_recv = 1;
	}

	if (xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER) {
		/* Use negotiated max-in-capsule from QUIC handshake.
		 * If not negotiated yet (e.g., during initial connect), fall back to ioccsz_bytes
		 * which gets set from Fabric CONNECT response. */
		struct nvme_quic_ctrlr *qctrlr = nvme_quic_ctrlr(ctrlr);
		max_in_capsule_data_size = qctrlr->max_in_capsule_data;
		if (max_in_capsule_data_size == 0) {
			/* Fallback to controller identify data if handshake negotiation not complete */
			max_in_capsule_data_size = ctrlr->ioccsz_bytes;
		}
		if (spdk_unlikely((req->cmd.opc == SPDK_NVME_OPC_FABRIC) ||
				  nvme_qpair_is_admin_queue(&qqpair->qpair))) {
			max_in_capsule_data_size = SPDK_NVME_QUIC_IN_CAPSULE_DATA_MAX_SIZE;
		}

		if (req->payload_size <= max_in_capsule_data_size) {
			req->cmd.dptr.sgl1.unkeyed.type = SPDK_NVME_SGL_TYPE_DATA_BLOCK;
			req->cmd.dptr.sgl1.unkeyed.subtype = SPDK_NVME_SGL_SUBTYPE_OFFSET;
			req->cmd.dptr.sgl1.address = 0;
			quic_req->in_capsule_data = true;
			/* In-capsule data will be sent with command, transition to await CQE */
			quic_req->state = NVME_QUIC_REQ_AWAIT_CQE;
		}
	}

	return 0;
}

/* Forward declarations of QUIC stream callbacks - implementations defined later */
static void nvme_quic_stream_on_destroy(quicly_stream_t *stream, quicly_error_t err);
static void nvme_quic_stream_on_send_shift(quicly_stream_t *stream, size_t delta);
static void nvme_quic_stream_on_send_emit(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all);
static void nvme_quic_stream_on_send_stop(quicly_stream_t *stream, quicly_error_t err) {};
static void nvme_quic_stream_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
static void nvme_quic_stream_on_receive_reset(quicly_stream_t *stream, quicly_error_t err);

static inline bool
nvme_quic_req_complete_safe(struct nvme_quic_req *quic_req)
{
	/* All requests need CQE */
	if (!quic_req->ordering.bits.recv_cpl) {
		return false;
	}

	/* For commands with no data transfer, only need send_ack + CQE */
	if (quic_req->req->payload_size == 0) {
		if (!quic_req->ordering.bits.send_ack) {
			return false;
		}
	} else {
		/* For READ/WRITE, need send_ack, data, and CQE */
		if (!(quic_req->ordering.bits.send_ack && quic_req->ordering.bits.data_recv)) {
			return false;
		}
	}

	assert(quic_req->state == NVME_QUIC_REQ_ACTIVE);
	assert(quic_req->qqpair != NULL);
	assert(quic_req->req != NULL);

	nvme_quic_req_complete(quic_req, quic_req->qqpair, &quic_req->cpl, true);
	return true;
}

static void
nvme_quic_cmd_send_complete(quicly_sendbuf_vec_t *vec)
{
	struct nvme_quic_stream *stream = nvme_quic_stream_container_of(vec, struct nvme_quic_stream, cmd_buf);
	struct nvme_quic_req *quic_req = stream->req;	
	struct spdk_nvmf_quic_transport *qtransport;
	struct nvme_quic_qpair *qqpair;

	SPDK_ERRLOG("Check cmd_send_complete_pointe- stream: %p, quic_req: %p\n", stream, quic_req);
	SPDK_ERRLOG("cmd buf len: %zu\n", vec->len);

	if (quic_req == NULL) {
		/* Request already completed and freed */
		SPDK_ERRLOG("quic_req is NULL in cmd_send_complete\n");
		return;
	}

	qqpair = quic_req->qqpair;
	NVME_QQPAIR_DEBUGLOG(qqpair, "quic req %p, cid %u\n", quic_req, quic_req->cid);
	
	/* Command send acknowledged */
	quic_req->ordering.bits.send_ack = 1;
	
	/* For in-capsule WRITE, mark data as sent */
	if (quic_req->in_capsule_data && quic_req->req->payload_size > 0) {
		quic_req->ordering.bits.data_recv = 1;
		if (quic_req->ordering.bits.domain_in_use) {
			spdk_memory_domain_invalidate_data(quic_req->req->payload.opts->memory_domain,
							   quic_req->req->payload.opts->memory_domain_ctx, 
							   quic_req->iov, quic_req->iovcnt);
		}
	}
	
	/* Check if request can be completed now */
	// nvme_quic_req_complete(quic_req);
}

static quicly_error_t
nvme_quic_cmd_send_flatten(quicly_sendbuf_vec_t *vec, void *dst, size_t off, size_t len)
{
    /* cbdata points to element, need to get actual cmd buffer */
    struct spdk_nvmf_quic_sendbuf_element_t *element = vec->cbdata;
    struct nvme_quic_stream *stream = element->nvme_stream;
    struct nvme_quic_req *quic_req = stream ? stream->req : NULL;
    struct nvme_quic_qpair *qqpair = quic_req ? quic_req->qqpair : NULL;
    uint8_t *src = (uint8_t *)element->buf;
    
    NVME_QQPAIR_DEBUGLOG(qqpair, "cmd_send_flatten: vec=%p, element=%p, element->buf=%p, dst=%p, off=%zu, len=%zu\n",
                vec, element, element->buf, dst, off, len);
    NVME_QQPAIR_DEBUGLOG(qqpair, "  First 8 bytes of cmd: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7]);
    memcpy(dst, src + off, len);
    return 0;
}

static void
nvme_quic_cmd_send_completion(quicly_sendbuf_vec_t *vec)
{
	/* Called by QUIC after ACK is received for command transmission.
	 * Only free the request if the CQE has already been processed. */
	struct spdk_nvmf_quic_sendbuf_element_t *element = vec->cbdata;
	struct nvme_quic_stream *stream = element->nvme_stream;
	struct nvme_quic_req *quic_req = stream->req;
	struct nvme_quic_qpair *qqpair = quic_req ? quic_req->qqpair : NULL;
	
	NVME_QQPAIR_DEBUGLOG(qqpair, "[SEND_ACK_CB] vec=%p, vec->len=%zu, vec->cbdata=%p, stream=%p, quic_req=%p\n",
		    vec, vec->len, vec->cbdata, stream, quic_req);
	
	if (quic_req) {
		NVME_QQPAIR_DEBUGLOG(qqpair, "[SEND_ACK_CB] Command send ACKed for cid=%u, state=%d, recv_cpl=%d\n", 
			    quic_req->cid, quic_req->state, quic_req->ordering.bits.recv_cpl);
		NVME_QQPAIR_DEBUGLOG(qqpair, "[SEND_ACK_CB]   stream->cmd_buf: cb=%p, cbdata=%p, len=%zu\n",
			    stream->cmd_buf.cb, stream->cmd_buf.cbdata, stream->cmd_buf.len);
		NVME_QQPAIR_DEBUGLOG(qqpair, "[SEND_ACK_CB]   sendbuf vecs: entries=%p, size=%zu, capacity=%zu, off_in_first_vec=%zu\n",
			    stream->streambuf.egress.vecs.entries, stream->streambuf.egress.vecs.size,
			    stream->streambuf.egress.vecs.capacity, stream->streambuf.egress.off_in_first_vec);
		
		/* Only free if CQE was already received and processed.
		 * If CQE hasn't arrived yet, it will free the request after processing. */
		if (quic_req->ordering.bits.recv_cpl) {
			NVME_QQPAIR_DEBUGLOG(qqpair, "  CQE already processed - freeing request now\n");
			// nvme_quic_req_put(quic_req->qqpair, quic_req);
		} else {
			NVME_QQPAIR_DEBUGLOG(qqpair, "  CQE not received yet - marking send_ack and waiting\n");
			/* Mark that send ACK was received. When CQE arrives, it will free the request. */
			quic_req->ordering.bits.send_ack = 1;
		}
	} else {
		NVME_QQPAIR_DEBUGLOG(qqpair, "[SEND_ACK_CB] **CRITICAL WARNING**: stream->req is NULL!\n");
		NVME_QQPAIR_DEBUGLOG(qqpair, "[SEND_ACK_CB]   This means stream was reused or req freed BEFORE send ACK arrived!\n");
		NVME_QQPAIR_DEBUGLOG(qqpair, "[SEND_ACK_CB]   Stream may still have pending vecs that QUIC will try to shift!\n");
		NVME_QQPAIR_DEBUGLOG(qqpair, "[SEND_ACK_CB]   sendbuf vecs: entries=%p, size=%zu, capacity=%zu, off_in_first=%zu\n",
			    stream->streambuf.egress.vecs.entries, stream->streambuf.egress.vecs.size,
			    stream->streambuf.egress.vecs.capacity, stream->streambuf.egress.off_in_first_vec);
		if (stream->streambuf.egress.vecs.size > 0) {
			NVME_QQPAIR_DEBUGLOG(qqpair, "[SEND_ACK_CB]   **BUG**: vecs.size=%zu > 0, QUIC will try to shift invalid vecs!\n",
				    stream->streambuf.egress.vecs.size);
		}
	}
}

static const quicly_streambuf_sendvec_callbacks_t nvme_quic_cmd_callbacks = {
	.flatten_vec = nvme_quic_cmd_send_flatten,
	.discard_vec = nvme_quic_cmd_send_completion,
};

static quicly_error_t
nvme_quic_iovs_flatten(quicly_sendbuf_vec_t *vec, void *dst, size_t off, size_t len)
{
	/* cbdata points to element, need to get iov array from it */
	struct spdk_nvmf_quic_sendbuf_element_t *element = vec->cbdata;
	struct nvme_quic_stream *stream = element->nvme_stream;
	struct nvme_quic_req *quic_req = stream ? stream->req : NULL;
	struct nvme_quic_qpair *qqpair = quic_req ? quic_req->qqpair : NULL;
	struct iovec *iov = (struct iovec *)element->buf;
	size_t iov_offset = 0;
	size_t copied = 0;
	int i = 0;

	NVME_QQPAIR_DEBUGLOG(qqpair, "nvme_quic_iovs_flatten called: vec=%p, dst=%p, off=%zu, len=%zu, cbdata=%p\n",
		    vec, dst, off, len, vec->cbdata);
	
	if (iov && iov[0].iov_len > 0) {
		uint8_t *src = (uint8_t *)iov[0].iov_base;
		NVME_QQPAIR_DEBUGLOG(qqpair, "  iov[0]: base=%p, len=%zu\n", iov[0].iov_base, iov[0].iov_len);
		
		/* Offset 0-15: hostid (UUID) */
		NVME_QQPAIR_DEBUGLOG(qqpair, "  [0-15] hostid: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			    src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
			    src[8], src[9], src[10], src[11], src[12], src[13], src[14], src[15]);
		
		/* Offset 16-17: cntlid */
		NVME_QQPAIR_DEBUGLOG(qqpair, "  [16-17] cntlid: 0x%02x%02x\n", src[16], src[17]);
		
		/* Offset 256: subnqn (should start with 'nqn.') */
		if (iov[0].iov_len >= 272) {
			char subnqn_preview[65];
			memcpy(subnqn_preview, &src[256], 64);
			subnqn_preview[64] = '\0';
			NVME_QQPAIR_DEBUGLOG(qqpair, "  [256] subnqn: '%s...'\n", subnqn_preview);
		}
		
		/* Offset 512: hostnqn (should start with 'nqn.') */
		if (iov[0].iov_len >= 576) {
			char hostnqn_preview[65];
			memcpy(hostnqn_preview, &src[512], 64);
			hostnqn_preview[64] = '\0';
			NVME_QQPAIR_DEBUGLOG(qqpair, "  [512] hostnqn: '%s...'\n", hostnqn_preview);
		}
	}

	// /* Find which iov contains the starting offset */
	// while (iov[i].iov_len > 0 && iov_offset + iov[i].iov_len <= off) {
	// 	iov_offset += iov[i].iov_len;
	// 	i++;
	// }

	// /* Copy from iovs starting at offset */
	// while (copied < len && iov[i].iov_len > 0) {
	// 	size_t offset_in_iov = (copied == 0) ? (off - iov_offset) : 0;
	// 	size_t available = iov[i].iov_len - offset_in_iov;
	// 	size_t copy_len = spdk_min(len - copied, available);
		
	// 	memcpy((uint8_t *)dst + copied, (uint8_t *)iov[i].iov_base + offset_in_iov, copy_len);
	// 	copied += copy_len;
	// 	i++;
	// }
	
	memcpy(dst, (uint8_t *)iov[0].iov_base + off, len);
	copied = len;

	NVME_QQPAIR_DEBUGLOG(qqpair, "nvme_quic_iovs_flatten: copied %zu bytes (requested %zu)\n", copied, len);
	
	/* Print dst buffer at offset 0 (beginning) */
	if (len > 0) {
		uint8_t *dst_bytes = (uint8_t *)dst;
		NVME_QQPAIR_DEBUGLOG(qqpair, "  DST at offset 0 (first 16 bytes): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			    dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3],
			    dst_bytes[4], dst_bytes[5], dst_bytes[6], dst_bytes[7],
			    dst_bytes[8], dst_bytes[9], dst_bytes[10], dst_bytes[11],
			    dst_bytes[12], dst_bytes[13], dst_bytes[14], dst_bytes[15]);
	}
	
	/* Print dst buffer at offset 272 (after command header, should be in-capsule data) */
	if (len > 272) {
		uint8_t *dst_bytes = (uint8_t *)dst;
		NVME_QQPAIR_DEBUGLOG(qqpair, "  DST at offset 272 (next 16 bytes): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			    dst_bytes[272], dst_bytes[273], dst_bytes[274], dst_bytes[275],
			    dst_bytes[276], dst_bytes[277], dst_bytes[278], dst_bytes[279],
			    dst_bytes[280], dst_bytes[281], dst_bytes[282], dst_bytes[283],
			    dst_bytes[284], dst_bytes[285], dst_bytes[286], dst_bytes[287]);
	}

	return copied == len ? 0 : QUICLY_TRANSPORT_ERROR_INTERNAL;
}

static const quicly_streambuf_sendvec_callbacks_t nvme_quic_in_capsule_callbacks = {nvme_quic_iovs_flatten};



void 
nvme_quic_sendbuf_shift(quicly_stream_t *stream, size_t delta)
{
    size_t i;
	struct nvme_quic_stream *nvme_stream = stream ? (struct nvme_quic_stream *)stream->data : NULL;
	struct nvme_quic_req *quic_req = nvme_stream ? nvme_stream->req : NULL;
	struct nvme_quic_qpair *qqpair = quic_req ? quic_req->qqpair : NULL;
	quicly_sendbuf_t *sb = nvme_stream ? &nvme_stream->streambuf.egress : NULL;

	NVME_QQPAIR_DEBUGLOG(qqpair, "[SHIFT] stream=%p, delta=%zu (FIXED: getting sb from stream->data)\n", stream, delta);
	if (!nvme_stream || !sb) {
		NVME_QQPAIR_DEBUGLOG(qqpair, "[SHIFT] ERROR: nvme_stream=%p or sb=%p is NULL\n", nvme_stream, sb);
		return;
	}
	
	NVME_QQPAIR_DEBUGLOG(qqpair, "[SHIFT]   stream_id=%ld, nvme_stream=%p, sb=%p\n", 
		    stream->stream_id, nvme_stream, sb);
	NVME_QQPAIR_DEBUGLOG(qqpair, "[SHIFT]   sb->vecs: entries=%p, size=%zu, capacity=%zu, off_in_first=%zu\n",
		    sb->vecs.entries, sb->vecs.size, sb->vecs.capacity, sb->off_in_first_vec);
	if (quic_req) {
		NVME_QQPAIR_DEBUGLOG(qqpair, "[SHIFT]   req=%p, cid=%u, state=%d\n", quic_req, quic_req->cid, quic_req->state);
	}

    for (i = 0; delta != 0; ++i) {
		if(i >= sb->vecs.size) {
			NVME_QQPAIR_DEBUGLOG(qqpair, "[SHIFT] i=%zu >= vecs.size=%zu, cannot shift more (delta=%zu remaining)\n",
				    i, sb->vecs.size, delta);
			break;
		}

        quicly_sendbuf_vec_t *first_vec = sb->vecs.entries + i;
		NVME_QQPAIR_DEBUGLOG(qqpair, "[SHIFT] Processing vec[%zu]: cb=%p, cbdata=%p, len=%zu\n",
			    i, first_vec->cb, first_vec->cbdata, first_vec->len);
        size_t bytes_in_first_vec = first_vec->len - sb->off_in_first_vec;
        if (delta < bytes_in_first_vec) {
            sb->off_in_first_vec += delta;
			NVME_QQPAIR_DEBUGLOG(qqpair, "[SHIFT] Partial shift: off_in_first_vec now %zu\n", sb->off_in_first_vec);
            break;
        }
        delta -= bytes_in_first_vec;
		NVME_QQPAIR_DEBUGLOG(qqpair, "[SHIFT] Calling discard_vec for vec[%zu]\n", i);
        if (first_vec->cb->discard_vec != NULL)
            first_vec->cb->discard_vec(first_vec);
        sb->off_in_first_vec = 0;
    }
    if (i != 0) {
        if (sb->vecs.size != i) {
			NVME_QQPAIR_DEBUGLOG(qqpair, "[SHIFT] Partial shift: moving %zu vecs from [%zu] to [0]\n",
				    sb->vecs.size - i, i);
            memmove(sb->vecs.entries, sb->vecs.entries + i, (sb->vecs.size - i) * sizeof(*sb->vecs.entries));
            sb->vecs.size -= i;
			NVME_QQPAIR_DEBUGLOG(qqpair, "[SHIFT] After memmove: vecs.size=%zu\n", sb->vecs.size);
        } else {
			NVME_QQPAIR_DEBUGLOG(qqpair, "[SHIFT] **FREEING VECS.ENTRIES**: entries=%p, size=%zu, capacity=%zu\n",
				    sb->vecs.entries, sb->vecs.size, sb->vecs.capacity);
			if(sb->vecs.size == 0) {
				NVME_QQPAIR_DEBUGLOG(qqpair, "[SHIFT] vecs are already freed by the req_get() \n");
				quicly_stream_sync_sendbuf(stream, 0);
				return;
			}
            free(sb->vecs.entries);
            sb->vecs.entries = NULL;
            sb->vecs.size = 0;
            sb->vecs.capacity = 0;
			NVME_QQPAIR_DEBUGLOG(qqpair, "[SHIFT] **VECS FREED**: entries now NULL, size=0\n");
        }
    }
    quicly_stream_sync_sendbuf(stream, 0);
	NVME_QQPAIR_DEBUGLOG(qqpair, "[SHIFT] Done: final vecs.size=%zu\n", sb->vecs.size);
}


/* QUIC stream callbacks table */
static const quicly_stream_callbacks_t nvme_quic_stream_callbacks = {
	nvme_quic_stream_on_destroy,
	//quicly_streambuf_destroy,
	nvme_quic_sendbuf_shift,
	// quicly_streambuf_egress_shift,
	quicly_streambuf_egress_emit,
	nvme_quic_stream_on_send_stop,
	nvme_quic_stream_on_receive,
	nvme_quic_stream_on_receive_reset
};


static void
nvme_quic_qpair_capsule_cmd_send(struct nvme_quic_qpair *qqpair,
				struct nvme_quic_req *quic_req)
{
	struct nvme_quic_stream *nvme_stream;
	quicly_error_t ret;

	NVME_QQPAIR_DEBUGLOG(qqpair, "enter\n");

	nvme_stream = quic_req->stream;
	
	/* If stream already has an active QUIC stream, we need to handle it first */
	// if (nvme_stream->quic_stream != NULL) {
	// 	NVME_QQPAIR_DEBUGLOG(qqpair, "[CMD_SEND] **WARNING**: nvme_stream already has quic_stream=%p (stream_id=%ld)\n",
	// 		    nvme_stream->quic_stream, nvme_stream->quic_stream->stream_id);
	// 	NVME_QQPAIR_DEBUGLOG(qqpair, "[CMD_SEND]   sendbuf state: vecs.size=%zu, capacity=%zu\n",
	// 		    nvme_stream->streambuf.egress.vecs.size,
	// 		    nvme_stream->streambuf.egress.vecs.capacity);
	// 	/* This means the old stream hasn't been destroyed yet! 
	// 	 * We cannot safely reuse this nvme_stream structure. */
	// 	NVME_QQPAIR_ERRLOG(qqpair, "ERROR: Cannot open new stream - old stream still active!\n");
	// 	return;
	// }
	
	/* Sendbuf should be clean (vecs freed by last stream's shift callbacks) */
	NVME_QQPAIR_DEBUGLOG(qqpair, "[CMD_SEND] Opening new stream - sendbuf should be clean: vecs.size=%zu\n",
		    nvme_stream->streambuf.egress.vecs.size);

	/* Open QUIC stream (client-initiated bidirectional) */
	ret = quicly_open_stream(qqpair->conn, &nvme_stream->quic_stream, 0);
	if (ret != 0) {
		NVME_QQPAIR_ERRLOG(qqpair, "Failed to open QUIC stream: %d\n", ret);
		return;
	}
	
	NVME_QQPAIR_DEBUGLOG(qqpair, "Opened stream for req cid=%u (req index=%ld, stream=%p, quic_stream=%p)\n", 
			   quic_req->req->cmd.cid, quic_req - qqpair->quic_reqs, nvme_stream, nvme_stream->quic_stream);


	nvme_stream->quic_stream->data = nvme_stream;
	nvme_stream->qpair = qqpair;
	nvme_stream->req = quic_req;
	
	NVME_QQPAIR_DEBUGLOG(qqpair, "[CMD_SEND_SETUP] stream->data=%p, nvme_stream=%p, &streambuf=%p, &egress=%p\n",
		    nvme_stream->quic_stream->data, nvme_stream,
		    &nvme_stream->streambuf, &nvme_stream->streambuf.egress);
	NVME_QQPAIR_DEBUGLOG(qqpair, "[CMD_SEND_SETUP] Offset check: streambuf is at offset %zu in nvme_quic_stream\n",
		    offsetof(struct nvme_quic_stream, streambuf));


	/* Send NVMe-oF capsule command using write_vec with callback */
	/* Setup element structure for consistent callback access */

	NVME_QQPAIR_DEBUGLOG(qqpair, "About to set cmd_buf: cmd address=%p, quic_req=%p, quic_req->req=%p\n",
			   &quic_req->req->cmd, quic_req, quic_req->req);
	nvme_quic_stream_set_cmd_buf(nvme_stream, &quic_req->req->cmd, &nvme_quic_cmd_callbacks);
	NVME_QQPAIR_DEBUGLOG(qqpair, "After set_cmd_buf: cmd_element.buf=%p, cmd_buf.cbdata=%p\n",
			   nvme_stream->cmd_element.buf, nvme_stream->cmd_buf.cbdata);
	NVME_QQPAIR_DEBUGLOG(qqpair, "[CMD_SEND] Writing vec to stream, before: vecs.size=%zu\n",
		    nvme_stream->streambuf.egress.vecs.size);
	ret = quicly_streambuf_egress_write_vec(nvme_stream->quic_stream, &nvme_stream->cmd_buf);
	if (ret != 0) {
		NVME_QQPAIR_ERRLOG(qqpair, "Failed to write command to stream: %d\n", ret);
		return;
	}
	NVME_QQPAIR_DEBUGLOG(qqpair, "[CMD_SEND] After write_vec: vecs.size=%zu, off_in_first_vec=%zu\n",
		    nvme_stream->streambuf.egress.vecs.size, nvme_stream->streambuf.egress.off_in_first_vec);
	
	/* Check what quicly_get_first_timeout returns after writing */
	quicly_context_t *ctx = quicly_get_context(qqpair->conn);
	int64_t first_timeout = quicly_get_first_timeout(qqpair->conn);
	int64_t now = ctx->now->cb(ctx->now);
	NVME_QQPAIR_DEBUGLOG(qqpair, "[CMD_SEND] After write_vec: first_timeout=%ld, now=%ld, diff=%ld ms\n",
		    first_timeout, now, (first_timeout - now));
	
	/* Log detailed command information */
	NVME_QQPAIR_DEBUGLOG(qqpair, "CLIENT Sending Command:\n");
	NVME_QQPAIR_DEBUGLOG(qqpair, "  stream_id=%ld, opc=0x%02x, cid=%u, nsid=%u\n",
		       nvme_stream->quic_stream->stream_id, quic_req->req->cmd.opc, 
		       quic_req->req->cmd.cid, quic_req->req->cmd.nsid);
	NVME_QQPAIR_DEBUGLOG(qqpair, "  cdw10=0x%08x, cdw11=0x%08x, cdw12=0x%08x, cdw13=0x%08x\n",
		       quic_req->req->cmd.cdw10, quic_req->req->cmd.cdw11,
		       quic_req->req->cmd.cdw12, quic_req->req->cmd.cdw13);
	NVME_QQPAIR_DEBUGLOG(qqpair, "  payload_size=%u, in_capsule=%d\n",
		       quic_req->req->payload_size, quic_req->in_capsule_data);

	NVME_QQPAIR_DEBUGLOG(qqpair, "Checking payload: payload_size=%u, in_capsule_data=%d\n",
		       quic_req->req->payload_size, quic_req->in_capsule_data);
	
	if ((quic_req->req->payload_size == 0) || !quic_req->in_capsule_data) {
		NVME_QQPAIR_DEBUGLOG(qqpair, "No in-capsule data to send (payload_size=0 or in_capsule_data=false)\n");
		goto end;
	}

	NVME_QQPAIR_DEBUGLOG(qqpair, "Sending in-capsule data for cid=%u: iovcnt=%d\n", 
		       quic_req->req->cmd.cid, quic_req->iovcnt);
	
	/* Log the first iovec details */
	if (quic_req->iovcnt > 0) {
		NVME_QQPAIR_DEBUGLOG(qqpair, "  iov[0]: base=%p, len=%zu\n",
			       quic_req->iov[0].iov_base, quic_req->iov[0].iov_len);
		/* Log first few bytes of data */
		uint8_t *data = (uint8_t *)quic_req->iov[0].iov_base;
		NVME_QQPAIR_DEBUGLOG(qqpair, "  First 16 bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			       data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
			       data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);
		NVME_QQPAIR_DEBUGLOG(qqpair, "  First 50 bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			       data[50], data[51], data[52], data[53], data[54], data[55], data[56], data[57],
			       data[58], data[59], data[60], data[61], data[62], data[63], data[64], data[65]);
	}
	 
	/* Zero-copy send: store iovec pointers, quicly will read via flatten callback */
	quic_req->datao = 0;
	/* CRITICAL: Pass total byte length, not iovcnt! */
	uint32_t total_data_len = 0;
	for (int i = 0; i < quic_req->iovcnt; i++) {
		total_data_len += quic_req->iov[i].iov_len;
	}
	NVME_QQPAIR_DEBUGLOG(qqpair, "Setting up data_buf: total_len=%u bytes (from %d iovecs)\n",
		       total_data_len, quic_req->iovcnt);
	nvme_quic_stream_set_data_buf(nvme_stream, quic_req->iov, total_data_len, &nvme_quic_in_capsule_callbacks);
	quicly_streambuf_egress_write_vec(nvme_stream->quic_stream, &nvme_stream->data_buf);
	
	NVME_QQPAIR_DEBUGLOG(qqpair, "In-capsule data queued for sending\n");

end:
	/* State was already set correctly in nvme_quic_req_init() based on data transfer direction:
	 * - AWAIT_DATA for controller-to-host (READ/IDENTIFY)
	 * - AWAIT_R2T for host-to-controller (WRITE)
	 * - AWAIT_CQE for no data transfer
	 * Don't override it here! */
	
	
	/* BUG FIX: Check opcode (cmd.opc) not command ID (cmd.cid)! */
	if (quic_req->req->cmd.opc != SPDK_NVME_OPC_WRITE || quic_req->in_capsule_data) {
		quicly_streambuf_egress_shutdown(nvme_stream->quic_stream);
	}
	
	// test immediate send completion without waiting for poll
	nvme_quic_cond_schedule_qpair_polling(qqpair);
}



static int
nvme_quic_qpair_submit_request(struct spdk_nvme_qpair *qpair,
			      struct nvme_request *req)
{
	struct nvme_quic_qpair *qqpair;
	struct nvme_quic_req *quic_req;

	SPDK_DEBUGLOG(nvme, "[NEW_REQ_FROM_APP] enter: req opc=0x%02x\n",
			req->cmd.opc);

	qqpair = nvme_quic_qpair(qpair);
	assert(qqpair != NULL);
	assert(req != NULL);

	quic_req = nvme_quic_req_get(qqpair);
	if (!quic_req) {
		qqpair->stats->queued_requests++;
		/* Inform the upper layer to try again later. */
		return -EAGAIN;
	}

	if (spdk_unlikely(nvme_quic_req_init(qqpair, req, quic_req))) {
		NVME_QQPAIR_ERRLOG(qqpair, "nvme_quic_req_init() failed\n");
		nvme_quic_req_put(qqpair, quic_req);
		return -1;
	}

	qqpair->qpair.queue_depth++;
	spdk_trace_record(TRACE_NVME_QUIC_SUBMIT, qpair->id, 0, (uintptr_t)quic_req->stream, req->cb_arg,
			  (uint32_t)req->cmd.cid, (uint32_t)req->cmd.opc,
			  req->cmd.cdw10, req->cmd.cdw11, req->cmd.cdw12, qqpair->qpair.queue_depth);
	TAILQ_INSERT_TAIL(&qqpair->outstanding_reqs, quic_req, link);
	// if (TAILQ_ENTRY_NOT_ENQUEUED(qqpair, link_timeout) && qpair->poll_group != NULL &&
	//     qpair->ctrlr->timeout_enabled) {
	// 	struct nvme_quic_poll_group *qgroup;

	// 	qgroup = nvme_quic_poll_group(qpair->poll_group);
	// 	TAILQ_INSERT_TAIL(&qgroup->timeout_enabled, qqpair, link_timeout);
	// }

	nvme_quic_qpair_capsule_cmd_send(qqpair, quic_req);
	return 0;
}

static void
nvme_quic_h2c_data_send_complete(quicly_sendbuf_vec_t *vec)
{
	/* cbdata points to element structure */
	struct spdk_nvmf_quic_sendbuf_element_t *element = vec->cbdata;
	struct nvme_quic_stream *nvme_stream = element->nvme_stream;
	struct nvme_quic_req *quic_req = nvme_stream->req;
	struct nvme_quic_qpair *qqpair;

	if (!quic_req) {
		/* Request already completed and freed */
		SPDK_ERRLOG("quic_req is NULL in h2c_data_send_complete\n");
		return;
	}

	qqpair = quic_req->qqpair;
	NVME_QQPAIR_DEBUGLOG(qqpair, "quic req %p, cid %u\n", quic_req, quic_req->cid);
	quic_req->ordering.bits.h2c_send_waiting_ack = 0;
	quic_req->ordering.bits.send_ack = 1;

	/* Check if all data has been sent */
	if (quic_req->datao >= quic_req->req->payload_size) {
		/* All data sent, mark complete and wait for CQE */
		quic_req->ordering.bits.data_recv = 1;
		quic_req->state = NVME_QUIC_REQ_AWAIT_CQE;
		
		if (quic_req->ordering.bits.domain_in_use) {
			spdk_memory_domain_invalidate_data(quic_req->req->payload.opts->memory_domain,
							   quic_req->req->payload.opts->memory_domain_ctx, 
							   quic_req->iov, quic_req->iovcnt);
		}
	}

	// nvme_quic_req_complete_safe(quic_req);
}


static const quicly_streambuf_sendvec_callbacks_t nvme_quic_h2c_callbacks = {nvme_quic_iovs_flatten };

static void
nvme_quic_send_h2c_data(struct nvme_quic_req *quic_req)
{
    struct iovec send_iov[NVME_QUIC_MAX_SGL_DESCRIPTORS];
    uint32_t send_iovcnt = 0;
    uint32_t remain_len = quic_req->r2t_len;  // e.g., 120KB
    uint32_t offset = quic_req->datao;        // Starting offset in total data
    uint32_t idx = 0;

	struct nvme_quic_stream *nvme_stream = quic_req->stream;
	struct nvme_quic_qpair *qqpair = quic_req->qqpair;
    
    NVME_QQPAIR_DEBUGLOG(qqpair, "Sending H2C data: offset=%u, len=%u\n",
                 quic_req->datao, quic_req->r2t_len);
    
    /* Skip iovecs until we reach the starting offset */
    // while (offset >= quic_req->iov[idx].iov_len && idx < quic_req->iovcnt) {
    //     offset -= quic_req->iov[idx].iov_len;
    //     idx++;
    // }
    
    // /* Build send_iov array with exactly r2t_len bytes */
    // while (remain_len > 0 && idx < quic_req->iovcnt && send_iovcnt < NVME_QUIC_MAX_SGL_DESCRIPTORS) {
    //     uint32_t iov_remain = quic_req->iov[idx].iov_len - offset;
    //     uint32_t copy_len = spdk_min(iov_remain, remain_len);
        
    //     send_iov[send_iovcnt].iov_base = (uint8_t *)quic_req->iov[idx].iov_base + offset;
    //     send_iov[send_iovcnt].iov_len = copy_len;
    //     send_iovcnt++;
        
    //     remain_len -= copy_len;
    //     offset = 0;  // After first iovec, offset is always 0
    //     idx++;
    // }
    
    // assert(remain_len == 0);  // Must have sent exactly r2t_len
    
    /* Now pass the partial iovec array to QUIC */
    nvme_quic_stream_set_data_buf(nvme_stream,
                      quic_req->iov,
                      quic_req->r2t_len,
                      &nvme_quic_h2c_callbacks);
    
    quicly_streambuf_egress_write_vec(nvme_stream->quic_stream, 
                      &nvme_stream->data_buf);


	quic_req->datao += quic_req->r2t_len;  // Update offset for next send
	
	quic_req->ordering.bits.h2c_send_waiting_ack = 0;
	quic_req->ordering.bits.send_ack = 1;



	if (quic_req->datao >= quic_req->req->payload_size) {
		/* All data sent, mark complete and wait for CQE */
		quic_req->ordering.bits.data_recv = 1;
		quic_req->state = NVME_QUIC_REQ_AWAIT_CQE;

		quicly_streambuf_egress_shutdown(nvme_stream->quic_stream);
		
		if (quic_req->ordering.bits.domain_in_use) {
			spdk_memory_domain_invalidate_data(quic_req->req->payload.opts->memory_domain,
							   quic_req->req->payload.opts->memory_domain_ctx, 
							   quic_req->iov, quic_req->iovcnt);
		}
	}


	// nvme_quic_cond_schedule_qpair_polling(qqpair);
}



static void
nvme_quic_read_data_recv(struct nvme_quic_req *quic_req, ptls_iovec_t received_data)
{
	struct iovec iov[NVME_QUIC_MAX_SGL_DESCRIPTORS];
	int iovcnt;
	uint32_t payload_size;
	size_t remaining_data;
	size_t len;
	struct nvme_quic_qpair *qqpair = quic_req ? quic_req->qqpair : NULL;

	NVME_QQPAIR_DEBUGLOG(qqpair, "nvme_quic_read_data_recv ENTRY: quic_req=%p, quic_req->req=%p, received_data.len=%zu\n",
		    quic_req, quic_req->req, received_data.len);

	if (!quic_req->req) {
		SPDK_ERRLOG("ERROR: quic_req->req is NULL!\n");
		return;
	}

	payload_size = quic_req->req->payload_size;
	remaining_data = payload_size - quic_req->expected_datao;
	len = spdk_min(received_data.len, remaining_data);  /* Only consume what we need */

	NVME_QQPAIR_DEBUGLOG(qqpair, "nvme_quic_read_data_recv: cid=%u, received_data.len=%zu, payload_size=%u, expected_datao=%u, remaining=%zu, will_consume=%zu\n",
		    quic_req->cid, received_data.len, payload_size, quic_req->expected_datao, remaining_data, len);

	/* Validate data length doesn't exceed remaining payload */
	if (len > payload_size) {
		NVME_QQPAIR_ERRLOG(quic_req->qqpair,
				   "Invalid data length for quic_req(%p), len(%zu) exceeds payload_size(%u)\n",
				   quic_req, len, payload_size);
		return;
	}

	/* Validate data range (current offset + length) is within bounds */
	if ((quic_req->expected_datao + len) > payload_size) {
		NVME_QQPAIR_ERRLOG(quic_req->qqpair,
				   "Invalid data range for quic_req(%p), (datao(%u) + len(%zu)) > payload_size(%u)\n",
				   quic_req, quic_req->expected_datao, len, payload_size);
		return;
	}

	/* Build iov array starting at current offset */
	iovcnt = nvme_quic_build_payload_iovs(iov, NVME_QUIC_MAX_SGL_DESCRIPTORS,
					      quic_req->iov, quic_req->iovcnt,
					      quic_req->expected_datao, NULL);
	assert(iovcnt >= 0);

	/* Copy received QUIC data into user buffers */
	spdk_copy_buf_to_iovs(iov, iovcnt, received_data.base, len);

	/* Consume the data from stream buffer */
	quicly_streambuf_ingress_shift(quic_req->stream->quic_stream, len);

	/* Update received data offset (like TCP's tcp_req->datao) */
	quic_req->expected_datao += len;
	quic_req->ordering.bits.data_recv = 1;

	NVME_QQPAIR_DEBUGLOG(qqpair, "  After update: expected_datao=%u, payload_size=%u\n",
		    quic_req->expected_datao, payload_size);

	/* Check if all data received */
	if (quic_req->expected_datao == payload_size) {
		NVME_QQPAIR_DEBUGLOG(qqpair, "  ALL DATA RECEIVED! Transitioning to AWAIT_CQE (state %d -> %d)\n",
			    quic_req->state, NVME_QUIC_REQ_AWAIT_CQE);
		quic_req->state = NVME_QUIC_REQ_AWAIT_CQE;
	} else {
		NVME_QQPAIR_DEBUGLOG(qqpair, "  Still need %u more bytes, staying in AWAIT_DATA\n",
			    payload_size - quic_req->expected_datao);
	}
}


static int
nvme_quic_qpair_reset(struct spdk_nvme_qpair *qpair)
{
	return 0;
}

static void
nvme_quic_req_complete(struct nvme_quic_req *quic_req,
		      struct nvme_quic_qpair *qqpair,
		      struct spdk_nvme_cpl *rsp,
		      bool print_on_error)
{
	struct spdk_nvme_cpl	cpl;
	struct spdk_nvme_qpair	*qpair;
	struct nvme_request	*req;
	bool			print_error;

	assert(quic_req->req != NULL);
	req = quic_req->req;
	qpair = req->qpair;

	NVME_QQPAIR_DEBUGLOG(qqpair, "complete quic_req(%p)\n", quic_req);
	if (!qpair->in_completion_context) {
		qqpair->async_complete++;
	}

	/* Cache arguments to be passed to nvme_complete_request since quic_req can be zeroed when released */
	memcpy(&cpl, rsp, sizeof(cpl));

	if (spdk_unlikely(spdk_nvme_cpl_is_error(rsp))) {
		print_error = print_on_error && !qpair->ctrlr->opts.disable_error_logging;

		if (print_error) {
			spdk_nvme_qpair_print_command(qpair, &req->cmd);
		}

		if (print_error || SPDK_DEBUGLOG_FLAG_ENABLED("nvme")) {
			spdk_nvme_qpair_print_completion(qpair, rsp);
		}
	}

	qpair->queue_depth--;
	spdk_trace_record(TRACE_NVME_QUIC_COMPLETE, qpair->id, 0, (uintptr_t)quic_req->stream, req->cb_arg,
			  (uint32_t)req->cmd.cid, (uint32_t)cpl.status_raw, qpair->queue_depth);
	TAILQ_REMOVE(&qqpair->outstanding_reqs, quic_req, link);

	if (TAILQ_EMPTY(&qqpair->outstanding_reqs) && qpair->poll_group != NULL &&
	    TAILQ_ENTRY_ENQUEUED(qqpair, link_timeout)) {
		struct nvme_quic_poll_group *tgroup;

		assert(qpair->ctrlr->timeout_enabled);

		tgroup = nvme_quic_poll_group(qpair->poll_group);
		TAILQ_REMOVE_CLEAR(&tgroup->timeout_enabled, qqpair, link_timeout);
	}

	/* Don't free the request yet! The command send buffer still needs to be ACKed.
	 * nvme_quic_req_put() will be called in nvme_quic_cmd_send_completion() after ACK. */
	// nvme_quic_req_put(qqpair, quic_req);
	nvme_complete_request(req->cb_fn, req->cb_arg, req->qpair, req, &cpl);
}

static void
nvme_quic_qpair_abort_reqs(struct spdk_nvme_qpair *qpair, uint32_t dnr)
{
	struct nvme_quic_req *quic_req, *tmp;
	struct spdk_nvme_cpl cpl = {};
	struct nvme_quic_qpair *qqpair = nvme_quic_qpair(qpair);
	cpl.sqid = qpair->id;
	cpl.status.sc = SPDK_NVME_SC_ABORTED_SQ_DELETION;
	cpl.status.sct = SPDK_NVME_SCT_GENERIC;
	cpl.status.dnr = dnr;

	TAILQ_FOREACH_SAFE(quic_req, &qqpair->outstanding_reqs, link, tmp) {
		/* We cannot abort requests with accel operations in progress */
		if (quic_req->ordering.bits.in_progress_accel) {
			continue;
		}

		nvme_quic_req_complete(quic_req, qqpair, &cpl, true);
	}
}

static bool
nvme_quic_qpair_recv_state_valid(struct nvme_quic_qpair *qqpair)
{
	switch (qqpair->state) {
	case NVME_QUIC_QPAIR_STATE_FABRIC_CONNECT_SEND:
	case NVME_QUIC_QPAIR_STATE_FABRIC_CONNECT_POLL:
	case NVME_QUIC_QPAIR_STATE_AUTHENTICATING:
	case NVME_QUIC_QPAIR_STATE_RUNNING:
		return true;
	default:
		return false;
	}
}


static int
nvme_quic_read_datagram(struct nvme_quic_qpair *qqpair) {
	// feed data from socket to QUIC library
	struct spdk_sock *sock = qqpair->sock;
	
	/* Check if socket is valid (may be NULL after disconnect) */
	if (sock == NULL) {
		return -1;
	}
	
	struct spdk_udp_sock *udp_sock = (struct spdk_udp_sock *)sock;
	struct nvme_quic_ctrlr *qctrlr = nvme_quic_ctrlr(qqpair->qpair.ctrlr);
	struct nvme_quic_poll_group *qgroup = nvme_quic_poll_group(qqpair->qpair.poll_group);


	struct msghdr msg = {0};
	struct sockaddr_storage incoming_pkt_src;
	msg.msg_name = &incoming_pkt_src;
	msg.msg_namelen = sizeof(incoming_pkt_src);

	uint8_t recv_buf[quicly_get_context(qqpair->conn)->transport_params.max_udp_payload_size];
	int rc = 0;
	
	/* Read all incoming UDP packets for this loop */
	int read_count = 0;
	// SPDK_NOTICELOG("QUIC: read_datagram called for qid=%u, sock=%p\n", qqpair->qpair.id, sock);
	while(1) {
		errno = 0; /* Clear errno before recvmsg */
		rc = nvme_quic_read_data_with_msghdr(sock, sizeof(recv_buf), recv_buf, &msg);
		int saved_errno = errno;
		if(rc <= 0) {
			/* No more data to read */
			if (read_count == 0) {
				// SPDK_DEBUGLOG(nvme, "No data read on first attempt for qid=%u! rc=%d, errno=%d (%s)\n",
				// 	    qqpair->qpair.id, rc, saved_errno, strerror(saved_errno));
			} else {
				SPDK_DEBUGLOG(nvme, "Read %d datagrams for qid=%u, stopping (rc=%d, errno=%d)\n",
					      read_count, qqpair->qpair.id, rc, saved_errno);
			}
			break;
		}
		read_count++;
		
		/* Get local address ONCE per recvmsg (not per packet in the batch)
		 * This is a huge improvement over calling getsockname for every packet */
		struct sockaddr_storage local_sockaddr;
		socklen_t local_len = sizeof(local_sockaddr);
		struct sockaddr *src_addr = NULL;
		
		/* Use spdk_sock_getaddr to get local address - cache for this batch */
		char local_str[64];
		uint16_t local_port;
		if (spdk_sock_getaddr(sock, local_str, sizeof(local_str), &local_port, NULL, 0, NULL) == 0) {
			/* Convert back to sockaddr for quicly */
			if (strchr(local_str, ':')) {
				/* IPv6 */
				struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&local_sockaddr;
				s6->sin6_family = AF_INET6;
				s6->sin6_port = htons(local_port);
				inet_pton(AF_INET6, local_str, &s6->sin6_addr);
				local_len = sizeof(struct sockaddr_in6);
			} else {
				/* IPv4 */
				struct sockaddr_in *s4 = (struct sockaddr_in *)&local_sockaddr;
				s4->sin_family = AF_INET;
				s4->sin_port = htons(local_port);
				inet_pton(AF_INET, local_str, &s4->sin_addr);
				local_len = sizeof(struct sockaddr_in);
			}
			src_addr = (struct sockaddr *)&local_sockaddr;
		}
		
		size_t off = 0;
		while(off != rc) {
			quicly_decoded_packet_t decoded;
			
			if(quicly_decode_packet(&qctrlr->quic_ctx, &decoded, recv_buf, rc, &off) == SIZE_MAX) {
				// decode error, drop the rest data
				break;
			}
			
			/* Use incoming packet source address directly (already in msg.msg_name from recvmsg) */
			struct sockaddr *dest_addr = (struct sockaddr *)&incoming_pkt_src;
			
			/* Check if we have valid addresses */
			if (src_addr == NULL) {
				/* Shouldn't happen */
				break;
			}
			
			uint8_t first_byte = decoded.octets.base[0];
			const char *pkt_type = "UNKNOWN";
			if (QUICLY_PACKET_IS_LONG_HEADER(first_byte)) {
				if (QUICLY_PACKET_IS_INITIAL(first_byte)) pkt_type = "INITIAL";
				else if ((first_byte & 0x30) == 0x20) pkt_type = "HANDSHAKE";
				else if ((first_byte & 0x30) == 0x10) pkt_type = "0-RTT";
				else if ((first_byte & 0x30) == 0x00) pkt_type = "RETRY";
			} else {
				pkt_type = "1-RTT";
			}
			
			NVME_QQPAIR_DEBUGLOG(qqpair, "Processing packet: type=%s, len=%zu, first_byte=0x%02x\n", 
					   pkt_type, decoded.octets.len, first_byte);

			quicly_error_t quic_ret = quicly_receive(qqpair->conn, src_addr, dest_addr, &decoded);
			if (quic_ret != 0) {
				/* Check for specific PACKET_IGNORED error codes (0xff01-0xff17) */
				if ((quic_ret >= 0xff80 && quic_ret <= 0xff95) || quic_ret == QUICLY_ERROR_PACKET_IGNORED) {
					const char *ignore_reason = "UNKNOWN";
					switch (quic_ret) {
					case 0xff80: ignore_reason = "No suitable path index"; break;
					case 0xff81: ignore_reason = "aead_decrypt_fixed_key failed"; break;
					case 0xff82: ignore_reason = "aead_decrypt_1rtt failed"; break;
					case 0xff83: ignore_reason = "Encrypted length too short"; break;
					case 0xff84: ignore_reason = "accept() expects INITIAL"; break;
					case 0xff85: ignore_reason = "Unknown version in accept"; break;
					case 0xff86: ignore_reason = "Initial datagram too small in accept"; break;
					case 0xff87: ignore_reason = "Client src_addr mismatch"; break;
					case 0xff88: ignore_reason = "Server dest_addr mismatch"; break;
					case 0xff89: ignore_reason = "Server path validation failed"; break;
					case 0xff8a: ignore_reason = "Max path validation failures"; break;
					case 0xff8b: ignore_reason = "Version mismatch"; break;
					case 0xff8c: ignore_reason = "RETRY on non-client"; break;
					case 0xff8d: ignore_reason = "RETRY CID unchanged"; break;
					case 0xff8e: ignore_reason = "Second RETRY"; break;
					case 0xff8f: ignore_reason = "RETRY tag validation failed"; break;
					case 0xff90: ignore_reason = "RETRY token too large"; break;
					case 0xff91: ignore_reason = "INITIAL packet but no initial keys"; break;
					case 0xff92: ignore_reason = "Server INITIAL datagram too small"; break;
					case 0xff93: ignore_reason = "HANDSHAKE packet but no handshake keys"; break;
					case 0xff94: ignore_reason = "0RTT on client"; break;
					case 0xff95: ignore_reason = "Short header wrong epoch"; break;
					case QUICLY_ERROR_PACKET_IGNORED: ignore_reason = "Generic PACKET_IGNORED"; break;
					}
					NVME_QQPAIR_DEBUGLOG(qqpair, "*** PACKET IGNORED (0x%04lx): %s - type=%s ***\n", 
							   (unsigned long)quic_ret, ignore_reason, pkt_type);
				} else {
					NVME_QQPAIR_DEBUGLOG(qqpair, "quicly_receive FAILED: ret=%ld (0x%lx) - type=%s\n", 
							   (long)quic_ret, (unsigned long)quic_ret, pkt_type);
				}
			} else {
				NVME_QQPAIR_DEBUGLOG(qqpair, "quicly_receive: SUCCESS - type=%s\n", pkt_type);
			}
		}
	}


	/* Only send if QUIC has pending data (including ACKs) */
	if (nvme_quic_has_pending_data(qqpair)) {
		_quic_send_pending(qqpair);
	}

	return rc;
}

static void
nvme_quic_qpair_check_timeout(struct spdk_nvme_qpair *qpair)
{
	uint64_t t02;
	struct nvme_quic_req *quic_req, *tmp;
	struct nvme_quic_qpair *qqpair = nvme_quic_qpair(qpair);
	struct spdk_nvme_ctrlr *ctrlr = qpair->ctrlr;
	struct spdk_nvme_ctrlr_process *active_proc;

	/* Don't check timeouts during controller initialization. */
	if (spdk_unlikely(ctrlr->state != NVME_CTRLR_STATE_READY)) {
		return;
	}

	if (spdk_unlikely(nvme_qpair_is_admin_queue(qpair))) {
		active_proc = nvme_ctrlr_get_current_process(ctrlr);
	} else {
		active_proc = qpair->active_proc;
	}

	/* Only check timeouts if the current process has a timeout callback. */
	if (spdk_unlikely(active_proc == NULL || active_proc->timeout_cb_fn == NULL)) {
		return;
	}

	t02 = spdk_get_ticks();
	TAILQ_FOREACH_SAFE(quic_req, &qqpair->outstanding_reqs, link, tmp) {
		if (spdk_unlikely(ctrlr->is_failed)) {
			/* The controller state may be changed to failed in one of the nvme_request_check_timeout callbacks. */
			return;
		}
		assert(quic_req->req != NULL);

		if (spdk_likely(nvme_request_check_timeout(quic_req->req, quic_req->cid, active_proc, t02))) {
			/*
			 * The requests are in order, so as soon as one has not timed out,
			 * stop iterating.
			 */
			break;
		}
	}
}


static int
nvme_quic_qpair_process_completions(struct spdk_nvme_qpair *qpair, uint32_t max_completions)
{
	struct nvme_quic_qpair *qqpair = nvme_quic_qpair(qpair);
	quicly_context_t *ctx = quicly_get_context(qqpair->conn);

	uint16_t num_completions = qqpair->async_stream_complete;
	qqpair->async_stream_complete = 0;

	int rc;

	int64_t first_timeout = quicly_get_first_timeout(qqpair->conn);
	int64_t now = ctx->now->cb(ctx->now);
	
	/* Track PTO events for debugging latency spikes */
	if (first_timeout <= now) {
		quicly_stats_t stats_before;
		if (quicly_get_stats(qqpair->conn, &stats_before) == 0) {
			uint64_t ptos_before = stats_before.num_ptos;
			
			NVME_QQPAIR_DEBUGLOG(qqpair, "[PTO_CHECK] Timeout due: first_timeout=%ld, now=%ld, overdue=%ldms\n",
					     first_timeout, now, (now - first_timeout));
			NVME_QQPAIR_DEBUGLOG(qqpair, "[PTO_CHECK] Before send: PTOs=%lu, Lost=%lu, Sent=%lu, Acked=%lu, InFlight=%zu\n",
					     ptos_before, stats_before.num_packets.lost, 
					     stats_before.num_packets.sent, stats_before.num_packets.ack_received,
					     stats_before.num_packets.sent - stats_before.num_packets.ack_received - stats_before.num_packets.lost);
			
			_quic_send_pending(qqpair);
			
			/* Check if PTO actually fired */
			quicly_stats_t stats_after;
			if (quicly_get_stats(qqpair->conn, &stats_after) == 0 && stats_after.num_ptos > ptos_before) {
				SPDK_DEBUGLOG(nvme, "[PTO_FIRED] qpair %u: PTO #%lu fired! RTT=%ums/%ums/%ums, CWND=%u, Outstanding=%zu packets\n",
					     qpair->id, stats_after.num_ptos, 
					     stats_after.rtt.minimum, stats_after.rtt.smoothed, stats_after.rtt.variance,
					     stats_after.cc.cwnd,
					     stats_after.num_packets.sent - stats_after.num_packets.ack_received - stats_after.num_packets.lost);
			}
		} else {
			_quic_send_pending(qqpair);
		}
	}

	// SPDK_DEBUGLOG(nvme, "QUIC: qpair_process_completions calling read_datagram for qid=%u\n", qpair->id);
	/* Flush pending outgoing packets (analogous to spdk_sock_flush in TCP) */
	// if (qpair->poll_group == NULL) {
	// 	if (qpair->ctrlr->timeout_enabled) {
	// 		nvme_quic_qpair_check_timeout(qpair);
	// 	}

	// 	/* Send any pending QUIC packets generated from queued stream data */
	// 	// _quic_send_pending(qqpair);
	// }

	/* Receive any incoming UDP datagrams and feed them into QUIC connection */
	rc = nvme_quic_read_datagram(qqpair);

	if (rc < 0 && errno != EAGAIN) {
		SPDK_ERRLOG("Failed to read datagram: %d (%s)\n", errno, spdk_strerror(errno));
		if (nvme_qpair_get_state(qpair) == NVME_QPAIR_DISCONNECTING) {
			if (TAILQ_EMPTY(&qqpair->outstanding_reqs)) {
				nvme_transport_ctrlr_disconnect_qpair_done(qpair);
			}

			/* Don't return errors until the qpair gets disconnected */
			return 0;
		}
		goto fail;
	}

	/* Handle connection state machine during CONNECTING phase */
	if (spdk_unlikely(nvme_qpair_get_state(qpair) == NVME_QPAIR_CONNECTING)) {
		rc = nvme_quic_ctrlr_connect_qpair_poll(qpair->ctrlr, qpair);
		if (rc != 0 && rc != -EAGAIN) {
			NVME_QQPAIR_ERRLOG(qqpair, "Failed to connect\n");
			goto fail;
		} else if (rc == 0) {
			/* Once the connection is completed, we can submit queued requests */
			nvme_qpair_resubmit_requests(qpair, qqpair->num_entries);
		}
	}

	return num_completions + qqpair->async_stream_complete;

fail:
	qpair->transport_failure_reason = SPDK_NVME_QPAIR_FAILURE_UNKNOWN;
	nvme_ctrlr_disconnect_qpair(qpair);
	return -ENXIO;
}

static void
nvme_quic_qpair_sock_cb(void *ctx, struct spdk_sock_group *group, struct spdk_sock *sock)
{
	struct spdk_nvme_qpair *qpair = ctx;
	struct nvme_quic_poll_group *pgroup = nvme_quic_poll_group(qpair->poll_group);
	int32_t num_completions;
	struct nvme_quic_qpair *qqpair = nvme_quic_qpair(qpair);

	SPDK_NOTICELOG("QUIC: sock_cb invoked for qid=%u, callback_sock=%p, qqpair->sock=%p, match=%s\n",
		       qpair->id, sock, qqpair->sock, (sock == qqpair->sock) ? "YES" : "NO");

	if (TAILQ_ENTRY_ENQUEUED(qqpair, link_poll)) {
		TAILQ_REMOVE_CLEAR(&pgroup->needs_poll, qqpair, link_poll);
	}

	num_completions = spdk_nvme_qpair_process_completions(qpair, pgroup->completions_per_qpair);

	if (pgroup->num_completions >= 0 && num_completions >= 0) {
		pgroup->num_completions += num_completions;
		pgroup->stats.nvme_completions += num_completions;
	} else {
		pgroup->num_completions = -ENXIO;
	}
}


static void
nvme_quic_sock_connect_cb_fn(void *cb_arg, int status)
{
	struct nvme_quic_qpair *qqpair = cb_arg;

	if (status < 0) {
		NVME_QQPAIR_ERRLOG(qqpair, "sock connection error %d (%s)\n", status, spdk_strerror(abs(status)));
		return;
	}

	nvme_quic_qpair_set_recv_state(qqpair, NVME_QUIC_QPAIR_STATE_INITIALIZING);
}

static int
nvme_quic_qpair_connect_sock(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair)
{
	struct sockaddr_storage dst_addr;
	struct sockaddr_storage src_addr;
	int rc;
	struct nvme_quic_qpair *qqpair;
	int family;
	long int port, src_port = 0;
	struct spdk_sock_opts opts;
	struct nvme_quic_ctrlr *quic_ctrlr;

	qqpair = nvme_quic_qpair(qpair);
	
	NVME_QQPAIR_DEBUGLOG(qqpair, "nvme_quic_qpair_connect_sock: Creating connection for qid=%u\n",
			   qpair->id);

	switch (ctrlr->trid.adrfam) {
	case SPDK_NVMF_ADRFAM_IPV4:
		family = AF_INET;
		break;
	case SPDK_NVMF_ADRFAM_IPV6:
		family = AF_INET6;
		break;
	default:
		NVME_QQPAIR_ERRLOG(qqpair, "Unhandled ADRFAM %d\n", ctrlr->trid.adrfam);
		rc = -1;
		return rc;
	}

	NVME_QQPAIR_DEBUGLOG(qqpair, "adrfam %d ai_family %d\n", ctrlr->trid.adrfam, family);

	/* Parse destination address - always required */
	memset(&dst_addr, 0, sizeof(dst_addr));
	NVME_QQPAIR_DEBUGLOG(qqpair, "trsvcid is %s\n", ctrlr->trid.trsvcid);
	rc = nvme_parse_addr(&dst_addr, family, ctrlr->trid.traddr, ctrlr->trid.trsvcid, &port);
	if (rc != 0) {
		NVME_QQPAIR_ERRLOG(qqpair, "dst_addr nvme_parse_addr() failed\n");
		return rc;
	}

	/* Parse source address - optional (NULL means auto-select) */
	memset(&src_addr, 0, sizeof(src_addr));
	if (ctrlr->opts.src_addr[0] || ctrlr->opts.src_svcid[0]) {
		rc = nvme_parse_addr(&src_addr, family,
				     ctrlr->opts.src_addr[0] ? ctrlr->opts.src_addr : NULL,
				     ctrlr->opts.src_svcid[0] ? ctrlr->opts.src_svcid : NULL,
				     &src_port);
		if (rc != 0) {
			NVME_QQPAIR_ERRLOG(qqpair, "src_addr nvme_parse_addr() failed\n");
			return rc;
		}
	}

	quic_ctrlr = SPDK_CONTAINEROF(ctrlr, struct nvme_quic_ctrlr, ctrlr);

	/* QUIC doesn't use socket-level TLS like TCP does.
	 * TLS is integrated into QUIC protocol via picotls (ptls_context_t).
	 * The TLS context is already configured in quic_ctrlr->tls_ctx and
	 * linked to quic_ctrlr->quic_ctx->tls during controller construction. */

	opts.opts_size = sizeof(opts);
	spdk_sock_get_default_opts(&opts);
	opts.priority = ctrlr->trid.priority;
	opts.zcopy = !nvme_qpair_is_admin_queue(qpair);
	opts.src_addr = ctrlr->opts.src_addr[0] ? ctrlr->opts.src_addr : NULL;
	opts.src_port = src_port;
	if (ctrlr->opts.transport_ack_timeout) {
		opts.ack_timeout = 1ULL << ctrlr->opts.transport_ack_timeout;
	}

	opts.connect_timeout = g_spdk_nvme_transport_opts.tcp_connect_timeout_ms;

	
	/* QUIC has a udp socket per reactor */
	qqpair->sock = spdk_sock_connect_ext(ctrlr->trid.traddr, port, "udp", &opts);
	if (!qqpair->sock) {
		NVME_QQPAIR_ERRLOG(qqpair, "UDP socket connection error with addr=%s, port=%ld\n", 
				   ctrlr->trid.traddr, port);
		rc = -1;
		return rc;
	}

	/* Log the actual local address/port that the socket is bound to */
	{
		char local_addr[64], remote_addr[64];
		uint16_t local_port, remote_port;
		rc = spdk_sock_getaddr(qqpair->sock, local_addr, sizeof(local_addr), &local_port,
				       remote_addr, sizeof(remote_addr), &remote_port);
		if (rc == 0) {
			SPDK_NOTICELOG("CLIENT qid=%u: Socket created - local=%s:%u remote=%s:%u, sock=%p\n",
				       qpair->id, local_addr, local_port, remote_addr, remote_port, qqpair->sock);
		}
	}

	/* For QUIC, use plain UDP socket - TLS is handled by QUIC layer, not socket layer */
	nvme_quic_qpair_set_recv_state(qqpair, NVME_QUIC_QPAIR_STATE_SOCK_CONNECTING);

	/* Set up TLS handshake properties */
	qqpair->hs_properties.client.negotiated_protocols.list = NULL;
	qqpair->hs_properties.client.negotiated_protocols.count = 0;

	/* Create QUIC connection - this is NON-BLOCKING!
	 * quicly_connect() only initializes connection state and prepares Initial packets.
	 * The TLS handshake happens asynchronously through subsequent:
	 *   1. quicly_send() to send handshake packets
	 *   2. quicly_receive() to process handshake responses
	 *   3. quicly_connection_is_ready() to check completion
	 * This fits SPDK's async I/O model perfectly.
	 * 
	 * NVMe-QUIC parameters (version, max-in-capsule) should be negotiated via
	 * custom QUIC transport parameters, but quicly needs extension to support this.
	 */
	/* sockaddr_storage can be safely cast to sockaddr* - this is standard socket programming */
	
	/* Log addresses being passed to quicly_connect */
	{
		char dst_str[64] = "N/A", src_str[64] = "N/A";
		uint16_t dst_port = 0, src_port_val = 0;
		
		if (dst_addr.ss_family == AF_INET) {
			struct sockaddr_in *d = (struct sockaddr_in *)&dst_addr;
			inet_ntop(AF_INET, &d->sin_addr, dst_str, sizeof(dst_str));
			dst_port = ntohs(d->sin_port);
		} else if (dst_addr.ss_family == AF_INET6) {
			struct sockaddr_in6 *d = (struct sockaddr_in6 *)&dst_addr;
			inet_ntop(AF_INET6, &d->sin6_addr, dst_str, sizeof(dst_str));
			dst_port = ntohs(d->sin6_port);
		}
		
		if ((ctrlr->opts.src_addr[0] || ctrlr->opts.src_svcid[0]) && src_addr.ss_family != AF_UNSPEC) {
			if (src_addr.ss_family == AF_INET) {
				struct sockaddr_in *s = (struct sockaddr_in *)&src_addr;
				inet_ntop(AF_INET, &s->sin_addr, src_str, sizeof(src_str));
				src_port_val = ntohs(s->sin_port);
			} else if (src_addr.ss_family == AF_INET6) {
				struct sockaddr_in6 *s = (struct sockaddr_in6 *)&src_addr;
				inet_ntop(AF_INET6, &s->sin6_addr, src_str, sizeof(src_str));
				src_port_val = ntohs(s->sin6_port);
			}
		}
		
		NVME_QQPAIR_DEBUGLOG(qqpair, "Calling quicly_connect with dst=%s:%u, src=%s:%u\n",
				   dst_str, dst_port, src_str, src_port_val);
	}
	
	SPDK_NOTICELOG("CLIENT qid=%u: quicly_connect with thread_id=%u, cid_encryptor=%p (will pre-generate DCID with same shard_id)\n",
	               qpair->id, qqpair->next_cid.thread_id, quic_ctrlr->quic_ctx.cid_encryptor);
	
	rc = quicly_connect(&qqpair->conn, &quic_ctrlr->quic_ctx,
			    ctrlr->trid.traddr,  /* hostname for TLS SNI */
			    (struct sockaddr *)&dst_addr,  /* destination - always required */
			    (ctrlr->opts.src_addr[0] || ctrlr->opts.src_svcid[0]) ? 
				(struct sockaddr *)&src_addr : NULL,  /* source - optional, NULL = auto */
			    &qqpair->next_cid,
			    qqpair->resumption_token,
			    &qqpair->hs_properties,
			    NULL,  /* No session resumption on initial connection */
			    NULL);
	if (rc != 0) {
		NVME_QQPAIR_ERRLOG(qqpair, "quicly_connect failed: %d\n", rc);
		spdk_sock_close(&qqpair->sock);
		return rc;
	}

	/* Store qqpair pointer in connection data for stream callbacks to access */
	*quicly_get_data(qqpair->conn) = qqpair;

	/* Send Initial packet generated by quicly_connect */
	_quic_send_pending(qqpair);

	/* Increment CID for next connection (though each qpair only creates one) */
	++qqpair->next_cid.master_id;

	/* Transition to INITIALIZING state - handshake will complete asynchronously */
	// nvme_quic_qpair_set_recv_state(qqpair, NVME_QUIC_QPAIR_STATE_INITIALIZING);

	return 0;
}

static int
nvme_quic_ctrlr_connect_qpair_poll(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair)
{
	struct nvme_quic_qpair *qqpair;
	int rc;

	qqpair = nvme_quic_qpair(qpair);

	/* Prevent this function from being called recursively, as it could lead to issues with
	 * nvme_fabric_qpair_connect_poll() if the connect response is received in the recursive
	 * call.
	 */
	if (qpair->in_connect_poll) {
		return -EAGAIN;
	}

	qpair->in_connect_poll = true;

	switch (qqpair->state) {
	case NVME_QUIC_QPAIR_STATE_SOCK_CONNECTING:
		/* Socket connection established - proceed to QUIC handshake */
		if (quicly_connection_is_ready(qqpair->conn)) {
			NVME_QQPAIR_DEBUGLOG(qqpair, "QUIC handshake completed successfully\n");
			nvme_quic_qpair_set_recv_state(qqpair, NVME_QUIC_QPAIR_STATE_FABRIC_CONNECT_SEND);
			rc = -EAGAIN;  /* Return EAGAIN to be polled again for fabric connect */
		} else {
			/* Still handshaking - will be called again */
			// NVME_QQPAIR_ERRLOG(qqpair, "QUIC handshake in progress...\n");
			rc = -EAGAIN;
		}
		break;
	case NVME_QUIC_QPAIR_STATE_INITIALIZING:

		/* Send any pending handshake packets (responses, ACKs) */
		// _quic_send_pending(qqpair);
		
		/* Check if QUIC handshake is complete */
		// if (quicly_connection_is_ready(qqpair->conn)) {
		// 	SPDK_ERRLOG(qqpair, "QUIC handshake completed successfully\n");
		// 	nvme_quic_qpair_set_recv_state(qqpair, NVME_QUIC_QPAIR_STATE_FABRIC_CONNECT_SEND);
		// 	rc = -EAGAIN;
		// } else {
		// 	/* Still handshaking - will be called again */
		// 	rc = -EAGAIN;
		// }
		rc = -EAGAIN;
		break;
	case NVME_QUIC_QPAIR_STATE_FABRIC_CONNECT_SEND:
		/* Send NVMe-oF Fabric CONNECT command */
		NVME_QQPAIR_DEBUGLOG(qqpair, "Sending NVMe-oF Fabric CONNECT command over QUIC\n");
		rc = nvme_fabric_qpair_connect_async(&qqpair->qpair, qqpair->num_entries + 1);
		if (rc < 0) {
			NVME_QQPAIR_ERRLOG(qqpair, "Failed to send an NVMe-oF Fabric CONNECT command\n");
			break;
		}

		nvme_quic_qpair_set_recv_state(qqpair, NVME_QUIC_QPAIR_STATE_FABRIC_CONNECT_POLL);
		rc = -EAGAIN;
		break;
	case NVME_QUIC_QPAIR_STATE_FABRIC_CONNECT_POLL:
		// SPDK_ERRLOG("Polling NVMe-oF Fabric CONNECT command completion over QUIC\n");
		rc = nvme_fabric_qpair_connect_poll(&qqpair->qpair);
		if (rc == 0) {
			/* Fabric CONNECT completed successfully.
			 * Update the negotiated max-in-capsule size from controller identify data.
			 * In the future, this should come from QUIC transport parameters. */
			struct nvme_quic_ctrlr *qctrlr = nvme_quic_ctrlr(qpair->ctrlr);
			if (qctrlr->ctrlr.ioccsz_bytes > 0) {
				/* Use the value from Fabric CONNECT response as fallback */
				/* max size is received from CONNECT ??? */
				qctrlr->max_in_capsule_data = qctrlr->ctrlr.ioccsz_bytes;
				NVME_QQPAIR_DEBUGLOG(qqpair, "Updated max_in_capsule_data to %u bytes from CONNECT response\\n",
					      qctrlr->max_in_capsule_data);
			}

			if (nvme_fabric_qpair_auth_required(qpair)) {
				rc = nvme_fabric_qpair_authenticate_async(qpair);
				if (rc == 0) {
					nvme_quic_qpair_set_recv_state(qqpair, NVME_QUIC_QPAIR_STATE_AUTHENTICATING);
					rc = -EAGAIN;
				}
			} else {
				nvme_quic_qpair_set_recv_state(qqpair, NVME_QUIC_QPAIR_STATE_RUNNING);
				nvme_qpair_set_state(qpair, NVME_QPAIR_CONNECTED);
			}
		} else if (rc != -EAGAIN) {
			NVME_QQPAIR_ERRLOG(qqpair, "Failed to poll NVMe-oF Fabric CONNECT command\n");
		}
		break;
	case NVME_QUIC_QPAIR_STATE_AUTHENTICATING:
		rc = nvme_fabric_qpair_authenticate_poll(qpair);
		if (rc == 0) {
			nvme_quic_qpair_set_recv_state(qqpair, NVME_QUIC_QPAIR_STATE_RUNNING);
			nvme_qpair_set_state(qpair, NVME_QPAIR_CONNECTED);
		}
		break;
	case NVME_QUIC_QPAIR_STATE_RUNNING:
		rc = 0;
		break;
	default:
		assert(false);
		rc = -EINVAL;
		break;
	}

	qpair->in_connect_poll = false;
	return rc;
}

static int
nvme_quic_ctrlr_connect_qpair(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair)
{
	int rc = 0;
	struct nvme_quic_qpair *qqpair;
	struct nvme_quic_poll_group *qgroup;
	qqpair = nvme_quic_qpair(qpair);

	if (!qqpair->sock) {
		rc = nvme_quic_qpair_connect_sock(ctrlr, qpair);
		if (rc < 0) {
			return rc;
		}
	}

	if (qpair->poll_group) {
		rc = nvme_poll_group_connect_qpair(qpair);
		if (rc) {
			NVME_QQPAIR_ERRLOG(qqpair, "Unable to activate the quic qpair.\n");
			return rc;
		}
		qgroup = nvme_quic_poll_group(qpair->poll_group);
		qqpair->stats = &qgroup->stats;
		qqpair->shared_stats = true;
	} else {
		/* When resetting a controller, we disconnect adminq and then reconnect. The stats
		 * is not freed when disconnecting. So when reconnecting, don't allocate memory
		 * again.
		 */
		if (qqpair->stats == NULL) {
			qqpair->stats = calloc(1, sizeof(*qqpair->stats));
			if (!qqpair->stats) {
				NVME_QQPAIR_ERRLOG(qqpair, "quic stats memory allocation failed\n");
				return -ENOMEM;
			}
		}
	}

	// /* Explicitly set recv_state of qqpair */
	// if (qqpair->recv_state != NVME_QUIC_PDU_RECV_STATE_AWAIT_PDU_READY) {
	// 	nvme_quic_qpair_set_recv_state(qqpair, NVME_QUIC_PDU_RECV_STATE_AWAIT_PDU_READY);
	// }

	return rc;
}

static struct spdk_nvme_qpair *
nvme_quic_ctrlr_create_qpair(struct spdk_nvme_ctrlr *ctrlr,
			    uint16_t qid, uint32_t qsize,
			    enum spdk_nvme_qprio qprio,
			    uint32_t num_requests, bool async)
{
	struct nvme_quic_qpair *qqpair;
	struct spdk_nvme_qpair *qpair;
	int rc;

	if (qsize < SPDK_NVME_QUEUE_MIN_ENTRIES) {
		NVME_CTRLR_ERRLOG(ctrlr, "Failed to create qpair with size %u. Minimum queue size is %d.\n",
				  qsize, SPDK_NVME_QUEUE_MIN_ENTRIES);
		return NULL;
	}

	qqpair = calloc(1, sizeof(struct nvme_quic_qpair));
	if (!qqpair) {
		NVME_CTRLR_ERRLOG(ctrlr, "failed to get create qqpair\n");
		return NULL;
	}

	/* Set num_entries one less than queue size. According to NVMe
	 * and NVMe-oF specs we can not submit queue size requests,
	 * one slot shall always remain empty.
	 */
	qqpair->num_entries = qsize - 1;
	qpair = &qqpair->qpair;
	rc = nvme_qpair_init(qpair, qid, ctrlr, qprio, num_requests, async);
	if (rc != 0) {
		free(qqpair);
		return NULL;
	}

	/* Initialize per-qpair CID generator with unique thread_id (qid) */
	qqpair->next_cid.master_id = 0;
	qqpair->next_cid.thread_id = qid;  /* Unique across all qpairs */
	qqpair->next_cid.node_id = 0;

	qqpair->async_stream_complete = 0;
	
	SPDK_NOTICELOG("CLIENT qid=%u: Initialized next_cid with thread_id=%u for eBPF routing\n",
	               qid, qqpair->next_cid.thread_id);

	/* Initialize session resumption state */
	memset(&qqpair->hs_properties, 0, sizeof(qqpair->hs_properties));
	memset(&qqpair->resumed_transport_params, 0, sizeof(qqpair->resumed_transport_params));
	qqpair->resumption_token.base = NULL;
	qqpair->resumption_token.len = 0;

	rc = nvme_quic_alloc_reqs(qqpair);
	if (rc) {
		nvme_quic_ctrlr_delete_io_qpair(ctrlr, qpair);
		return NULL;
	}

	/* spdk_nvme_qpair_get_optimal_poll_group needs socket information.
	 * So create the socket first when creating a qpair. */
	rc = nvme_quic_qpair_connect_sock(ctrlr, qpair);
	if (rc) {
		nvme_quic_ctrlr_delete_io_qpair(ctrlr, qpair);
		return NULL;
	}

	return qpair;
}

static struct spdk_nvme_qpair *
nvme_quic_ctrlr_create_io_qpair(struct spdk_nvme_ctrlr *ctrlr, uint16_t qid,
			       const struct spdk_nvme_io_qpair_opts *opts)
{
	SPDK_DEBUGLOG(nvme, "IO Qpair Creation - nvme_quic_ctrlr_create_io_qpair called for qid %u\n", qid);
	return nvme_quic_ctrlr_create_qpair(ctrlr, qid, opts->io_queue_size, opts->qprio,
					   opts->io_queue_requests, opts->async_mode);
}


static int
nvme_quic_generate_tls_credentials(struct nvme_quic_ctrlr *qctrlr)
{
	struct spdk_nvme_ctrlr *ctrlr = &qctrlr->ctrlr;
	int rc;
	uint8_t psk_retained[SPDK_TLS_PSK_MAX_LEN] = {};
	uint8_t psk_configured[SPDK_TLS_PSK_MAX_LEN] = {};
	uint8_t pskbuf[SPDK_TLS_PSK_MAX_LEN + 1] = {};
	uint8_t tls_cipher_suite;
	uint8_t psk_retained_hash;
	uint64_t psk_configured_size;

	rc = spdk_key_get_key(ctrlr->opts.tls_psk, pskbuf, SPDK_TLS_PSK_MAX_LEN);
	if (rc < 0) {
		NVME_CTRLR_ERRLOG(ctrlr, "Failed to obtain key '%s': %s\n",
				  spdk_key_get_name(ctrlr->opts.tls_psk), spdk_strerror(-rc));
		goto finish;
	}

	rc = nvme_quic_parse_interchange_psk(pskbuf, psk_configured, sizeof(psk_configured),
					    &psk_configured_size, &psk_retained_hash);
	if (rc < 0) {
		NVME_CTRLR_ERRLOG(ctrlr, "Failed to parse PSK interchange!\n");
		goto finish;
	}

	/* The Base64 string encodes the configured PSK (32 or 48 bytes binary).
	 * This check also ensures that psk_configured_size is smaller than
	 * psk_retained buffer size. */
	if (psk_configured_size == SHA256_DIGEST_LENGTH) {
		tls_cipher_suite = NVME_QUIC_CIPHER_AES_128_GCM_SHA256;
		qctrlr->tls_cipher_suite = "TLS_AES_128_GCM_SHA256";
	} else if (psk_configured_size == SHA384_DIGEST_LENGTH) {
		tls_cipher_suite = NVME_QUIC_CIPHER_AES_256_GCM_SHA384;
		qctrlr->tls_cipher_suite = "TLS_AES_256_GCM_SHA384";
	} else {
		NVME_CTRLR_ERRLOG(ctrlr, "Unrecognized cipher suite!\n");
		rc = -ENOTSUP;
		goto finish;
	}

	rc = nvme_quic_generate_psk_identity(qctrlr->psk_identity, sizeof(qctrlr->psk_identity),
					    ctrlr->opts.hostnqn, ctrlr->trid.subnqn,
					    tls_cipher_suite);
	if (rc) {
		NVME_CTRLR_ERRLOG(ctrlr, "could not generate PSK identity\n");
		goto finish;
	}
	SPDK_NOTICELOG("Client generated PSK identity: '%s'\n", qctrlr->psk_identity);

	/* No hash indicates that Configured PSK must be used as Retained PSK. */
	if (psk_retained_hash == NVME_QUIC_HASH_ALGORITHM_NONE) {
		assert(psk_configured_size < sizeof(psk_retained));
		memcpy(psk_retained, psk_configured, psk_configured_size);
		rc = psk_configured_size;
	} else {
		/* Derive retained PSK. */
		rc = nvme_quic_derive_retained_psk(psk_configured, psk_configured_size, ctrlr->opts.hostnqn,
						  psk_retained, sizeof(psk_retained), psk_retained_hash);
		if (rc < 0) {
			NVME_CTRLR_ERRLOG(ctrlr, "Unable to derive retained PSK!\n");
			goto finish;
		}
	}

	rc = nvme_quic_derive_tls_psk(psk_retained, rc, qctrlr->psk_identity, qctrlr->psk,
				     sizeof(qctrlr->psk), tls_cipher_suite);
	if (rc < 0) {
		NVME_CTRLR_ERRLOG(ctrlr, "Could not generate TLS PSK!\n");
		goto finish;
	}

	qctrlr->psk_size = rc;
	rc = 0;
finish:
	spdk_memset_s(psk_configured, sizeof(psk_configured), 0, sizeof(psk_configured));
	spdk_memset_s(pskbuf, sizeof(pskbuf), 0, sizeof(pskbuf));

	return rc;
}



inline int
nvme_quic_derive_retained_psk(const uint8_t *psk_in, uint64_t psk_in_size, const char *hostnqn,
			     uint8_t *psk_out, uint64_t psk_out_len, enum nvme_quic_hash_algorithm psk_retained_hash)
{
	EVP_PKEY_CTX *ctx;
	uint64_t digest_len;
	uint8_t hkdf_info[NVME_QUIC_HKDF_INFO_MAX_LEN] = {};
	const char *label = "tls13 HostNQN";
	size_t pos, labellen, nqnlen;
	const EVP_MD *hash;
	int rc, hkdf_info_size;

	labellen = strlen(label);
	nqnlen = strlen(hostnqn);
	assert(nqnlen <= SPDK_NVMF_NQN_MAX_LEN);

	*(uint16_t *)&hkdf_info[0] = htons(psk_in_size);
	pos = sizeof(uint16_t);
	hkdf_info[pos] = (uint8_t)labellen;
	pos += sizeof(uint8_t);
	memcpy(&hkdf_info[pos], label, labellen);
	pos += labellen;
	hkdf_info[pos] = (uint8_t)nqnlen;
	pos += sizeof(uint8_t);
	memcpy(&hkdf_info[pos], hostnqn, nqnlen);
	pos += nqnlen;
	hkdf_info_size = pos;

	switch (psk_retained_hash) {
	case NVME_QUIC_HASH_ALGORITHM_SHA256:
		digest_len = SHA256_DIGEST_LENGTH;
		hash = EVP_sha256();
		break;
	case NVME_QUIC_HASH_ALGORITHM_SHA384:
		digest_len = SHA384_DIGEST_LENGTH;
		hash = EVP_sha384();
		break;
	default:
		SPDK_ERRLOG("Unknown PSK hash requested!\n");
		return -EOPNOTSUPP;
	}

	if (digest_len > psk_out_len) {
		SPDK_ERRLOG("Insufficient buffer size for out key!\n");
		return -EINVAL;
	}

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ctx) {
		SPDK_ERRLOG("Unable to initialize EVP_PKEY_CTX!\n");
		return -ENOMEM;
	}

	/* EVP_PKEY_* functions returns 1 as a success code and 0 or negative on failure. */
	if (EVP_PKEY_derive_init(ctx) != 1) {
		SPDK_ERRLOG("Unable to initialize key derivation ctx for HKDF!\n");
		rc = -ENOMEM;
		goto end;
	}
	if (EVP_PKEY_CTX_set_hkdf_md(ctx, hash) != 1) {
		SPDK_ERRLOG("Unable to set hash for HKDF!\n");
		rc = -EOPNOTSUPP;
		goto end;
	}
	if (EVP_PKEY_CTX_set1_hkdf_key(ctx, psk_in, psk_in_size) != 1) {
		SPDK_ERRLOG("Unable to set PSK key for HKDF!\n");
		rc = -ENOBUFS;
		goto end;
	}

	if (EVP_PKEY_CTX_add1_hkdf_info(ctx, hkdf_info, hkdf_info_size) != 1) {
		SPDK_ERRLOG("Unable to set info label for HKDF!\n");
		rc = -ENOBUFS;
		goto end;
	}
	if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, "", 0) != 1) {
		SPDK_ERRLOG("Unable to set salt for HKDF!\n");
		rc = -EINVAL;
		goto end;
	}
	if (EVP_PKEY_derive(ctx, psk_out, &digest_len) != 1) {
		SPDK_ERRLOG("Unable to derive the PSK key!\n");
		rc = -EINVAL;
		goto end;
	}

	rc = digest_len;

end:
	EVP_PKEY_CTX_free(ctx);
	return rc;
}


/* QUIC Context Callbacks */
static quicly_error_t
nvme_quic_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
	stream->callbacks = &nvme_quic_stream_callbacks;
	SPDK_DEBUGLOG(nvme, "New QUIC stream opened (id=%" PRIu64 ")\n", stream->stream_id);
	return 0;
}

static quicly_stream_open_t nvme_quic_stream_open = {&nvme_quic_on_stream_open};

static void
nvme_quic_on_closed_by_remote(quicly_closed_by_remote_t *self, quicly_conn_t *conn,
				     quicly_error_t err, uint64_t frame_type,
				     const char *reason, size_t reason_len)
{
	if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
		SPDK_DEBUGLOG(nvme, "QUIC transport close: code=0x%" PRIx64 "; frame=%" PRIu64 "; reason=%.*s\n",
			    QUICLY_ERROR_GET_ERROR_CODE(err), frame_type, (int)reason_len, reason);
	} else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
		SPDK_ERRLOG("QUIC application close: code=0x%" PRIx64 "; reason=%.*s\n",
			    QUICLY_ERROR_GET_ERROR_CODE(err), (int)reason_len, reason);
	} else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
		SPDK_ERRLOG("QUIC stateless reset\n");
	} else if (err == QUICLY_ERROR_NO_COMPATIBLE_VERSION) {
		SPDK_ERRLOG("QUIC no compatible version\n");
	} else {
		SPDK_ERRLOG("QUIC unexpected close: code=%" PRId64 "\n", err);
	}
}

static quicly_closed_by_remote_t nvme_quic_closed_by_remote = {&nvme_quic_on_closed_by_remote};

static quicly_error_t
nvme_quic_on_generate_resumption_token(quicly_generate_resumption_token_t *self,
					      quicly_conn_t *conn, ptls_buffer_t *buf,
					      quicly_address_token_plaintext_t *token)
{
	/* For NVMe-oF QUIC, we may not need resumption tokens in the same way as HTTP/3,
	 * but we provide a placeholder implementation for future use */
	return 0;
}

static quicly_generate_resumption_token_t nvme_quic_generate_resumption_token = {
	&nvme_quic_on_generate_resumption_token
};

static quicly_error_t
nvme_quic_on_save_resumption_token(quicly_save_resumption_token_t *self,
					  quicly_conn_t *conn, ptls_iovec_t token)
{
	/* Store resumption token if needed for session resumption */
	return 0;
}

static int 
on_client_hello_cb(ptls_on_client_hello_t *_self, ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    int ret;

    if (negotiated_protocols.count != 0) {
        size_t i, j;
        const ptls_iovec_t *x, *y;
        for (i = 0; i != negotiated_protocols.count; ++i) {
            x = negotiated_protocols.list + i;
            for (j = 0; j != params->negotiated_protocols.count; ++j) {
                y = params->negotiated_protocols.list + j;
                if (x->len == y->len && memcmp(x->base, y->base, x->len) == 0)
                    goto ALPN_Found;
            }
        }
        return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
    ALPN_Found:
        if ((ret = ptls_set_negotiated_protocol(tls, (const char *)x->base, x->len)) != 0)
            return ret;
    }

    return 0;
}

static ptls_on_client_hello_t on_client_hello = {on_client_hello_cb};

static quicly_save_resumption_token_t nvme_quic_save_resumption_token = {
	&nvme_quic_on_save_resumption_token
};


/* We have to use the typedef in the function declaration to appease astyle. */
typedef struct spdk_nvme_ctrlr spdk_nvme_ctrlr_t;

static spdk_nvme_ctrlr_t *
nvme_quic_ctrlr_construct(const struct spdk_nvme_transport_id *trid,
			 const struct spdk_nvme_ctrlr_opts *opts,
			 void *devhandle)
{
	struct nvme_quic_ctrlr *qctrlr;
	struct nvme_quic_qpair *qqpair;
	int rc;

	qctrlr = calloc(1, sizeof(*qctrlr));
	if (qctrlr == NULL) {
		SPDK_ERRLOG("could not allocate ctrlr\n");
		return NULL;
	}

	qctrlr->ctrlr.opts = *opts;
	qctrlr->ctrlr.trid = *trid;

	/* Initialize NVMe-QUIC specific parameters */
	qctrlr->nvme_quic_version = 0x01;  /* NVMe-QUIC version 1 */
	qctrlr->max_in_capsule_data = 4096; /* Default 4KB, will be negotiated */

	/* Initialize shared QUIC context from spec template */
	qctrlr->quic_ctx = quicly_spec_context;

	/* Tune QUIC for low-latency localhost/datacenter environments:
	 * 
	 * Current investigation: We see 1.7s max latency with 1 PTO firing but 0 packets lost!
	 * This indicates a spurious PTO where the packet wasn't actually lost, just ACK was delayed.
	 * 
	 * For diagnosis, using moderate settings to allow PTOs to fire while logging details:
	 *   - min_pto = 20ms: Allows PTOs to fire so we can capture what's happening
	 *   - initcwnd = 100: Prevent flow control blocking
	 *   - Added detailed logging when PTO fires to track packet counts and timing
	 */
	// qctrlr->quic_ctx.initcwnd_packets = 100;  /* 10 → 100 packets (~150KB) to support QD32 */
	// qctrlr->quic_ctx.loss.min_pto = 20;      /* 1ms → 20ms (diagnostic value to capture PTOs) */
	// qctrlr->quic_ctx.loss.default_initial_rtt = 10;  /* 66ms → 10ms for faster initial convergence */
	// qctrlr->quic_ctx.loss.num_speculative_ptos = 0;  /* Disable speculative PTOs for localhost */
	
	/* Also increase flow control limits to match larger CWND */
	qctrlr->quic_ctx.transport_params.max_stream_data.bidi_local = 64 * 1024 * 1024;   /* 1MB → 64MB */
	qctrlr->quic_ctx.transport_params.max_stream_data.bidi_remote = 64 * 1024 * 1024;  /* 11MB → 64MB */
	qctrlr->quic_ctx.transport_params.max_data = 256 * 1024 * 1024;  /* 16MB → 256MB */

	/* Use hybrid CID encryptor (plaintext byte 0 for eBPF routing) */
	qctrlr->quic_ctx.cid_encryptor = nvme_quic_new_plaintext_cid_encryptor();
	if (qctrlr->quic_ctx.cid_encryptor == NULL) {
		SPDK_ERRLOG("Failed to create hybrid CID encryptor\n");
		free(qctrlr);
		return NULL;
	}
	SPDK_DEBUGLOG(nvme, "Hybrid CID encryptor created: %p (16-byte CIDs with plaintext shard_id in byte 0)\n",
		      qctrlr->quic_ctx.cid_encryptor);

	/* Customize transport parameters with NVMe-QUIC extensions
	 * Note: quicly's encode/decode functions need to be extended to actually
	 * send these custom parameters. For now, we set defaults and rely on
	 * Fabric CONNECT command response for negotiation. */
	// qctrlr->quic_ctx.transport_params.max_stream_data.bidi_local = 1048576;  /* 1MB per stream */
	// qctrlr->quic_ctx.transport_params.max_stream_data.bidi_remote = 1048576;
	// qctrlr->quic_ctx.transport_params.max_stream_data.uni = 1048576;
	// qctrlr->quic_ctx.transport_params.max_data = 16777216;  /* 16MB connection-level */
	
	/* TODO: Extend quicly_encode_transport_parameter_list() to encode:
	 *   - Custom parameter 0xFF00 (nvme_quic_version): qctrlr->nvme_quic_version
	 *   - Custom parameter 0xFF01 (max_in_capsule_data): qctrlr->max_in_capsule_data
	 * This requires modifying quicly/lib/quicly.c encoding/decoding logic.
	 */

	/* Initialize shared TLS context */
	memset(&qctrlr->tls_ctx, 0, sizeof(qctrlr->tls_ctx));
	qctrlr->tls_ctx.random_bytes = ptls_openssl_random_bytes;
	qctrlr->tls_ctx.get_time = &ptls_get_time;
	qctrlr->tls_ctx.key_exchanges = qctrlr->key_exchanges;
	qctrlr->tls_ctx.cipher_suites = qctrlr->cipher_suites;
	qctrlr->tls_ctx.require_dhe_on_psk = 1;
	qctrlr->tls_ctx.on_client_hello = &on_client_hello;

	/* Set up cipher suites and key exchanges */
	qctrlr->cipher_suites[0] = &ptls_openssl_aes128gcmsha256;
	qctrlr->cipher_suites[1] = &ptls_openssl_aes256gcmsha384;
	qctrlr->cipher_suites[2] = NULL;
	qctrlr->key_exchanges[0] = &ptls_openssl_secp256r1;
	qctrlr->key_exchanges[1] = NULL;

	/* Link TLS context to QUIC context */
	qctrlr->quic_ctx.tls = &qctrlr->tls_ctx;

	/* Set QUIC context callbacks */
	qctrlr->quic_ctx.stream_open = &nvme_quic_stream_open;
	qctrlr->quic_ctx.closed_by_remote = &nvme_quic_closed_by_remote;
	qctrlr->quic_ctx.save_resumption_token = &nvme_quic_save_resumption_token;
	qctrlr->quic_ctx.generate_resumption_token = &nvme_quic_generate_resumption_token;

	/* Use default stream scheduler */
	qctrlr->quic_ctx.stream_scheduler = &quicly_default_stream_scheduler;

	/* Amend TLS context for QUIC compliance */
	quicly_amend_ptls_context(&qctrlr->tls_ctx);

	/* Initialize address token AEAD for session resumption */
	uint8_t secret[PTLS_MAX_DIGEST_SIZE];
	ptls_openssl_random_bytes(secret, ptls_openssl_sha256.digest_size);
	qctrlr->address_token_aead.enc = ptls_aead_new(&ptls_openssl_aes128gcm,
		&ptls_openssl_sha256, 1, secret, "");
	qctrlr->address_token_aead.dec = ptls_aead_new(&ptls_openssl_aes128gcm,
		&ptls_openssl_sha256, 0, secret, "");
	if (!qctrlr->address_token_aead.enc || !qctrlr->address_token_aead.dec) {
		SPDK_ERRLOG("Failed to create address token AEAD\n");
		free(qctrlr);
		return NULL;
	}

	/* Generate TLS credentials if PSK is provided */
	if (opts->tls_psk != NULL) {
		SPDK_NOTICELOG("QUIC client: Loading PSK from keyring\n");
		rc = nvme_quic_generate_tls_credentials(qctrlr);
		if (rc != 0) {
			SPDK_ERRLOG("QUIC client: PSK generation failed with rc=%d\n", rc);
			if (qctrlr->address_token_aead.enc) {
				ptls_aead_free(qctrlr->address_token_aead.enc);
			}
			if (qctrlr->address_token_aead.dec) {
				ptls_aead_free(qctrlr->address_token_aead.dec);
			}
			free(qctrlr);
			return NULL;
		}

		/* Configure PSK in TLS context for client authentication if PSK was successfully loaded */
		if (qctrlr->psk_size > 0 && qctrlr->psk_identity[0] != '\0') {
			NVME_QQPAIR_DEBUGLOG(qqpair, "QUIC client: Configuring TLS PSK - identity='%s', size=%u\n",
				    qctrlr->psk_identity, qctrlr->psk_size);
			NVME_QQPAIR_DEBUGLOG(qqpair, "QUIC client: PSK secret (full 32 bytes): "
				       "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
				       "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
				       qctrlr->psk[0], qctrlr->psk[1], qctrlr->psk[2], qctrlr->psk[3],
				       qctrlr->psk[4], qctrlr->psk[5], qctrlr->psk[6], qctrlr->psk[7],
				       qctrlr->psk[8], qctrlr->psk[9], qctrlr->psk[10], qctrlr->psk[11],
				       qctrlr->psk[12], qctrlr->psk[13], qctrlr->psk[14], qctrlr->psk[15],
				       qctrlr->psk[16], qctrlr->psk[17], qctrlr->psk[18], qctrlr->psk[19],
				       qctrlr->psk[20], qctrlr->psk[21], qctrlr->psk[22], qctrlr->psk[23],
				       qctrlr->psk[24], qctrlr->psk[25], qctrlr->psk[26], qctrlr->psk[27],
				       qctrlr->psk[28], qctrlr->psk[29], qctrlr->psk[30], qctrlr->psk[31]);
			qctrlr->tls_ctx.pre_shared_key.identity.base = (uint8_t *)qctrlr->psk_identity;
			qctrlr->tls_ctx.pre_shared_key.identity.len = strlen(qctrlr->psk_identity);
			qctrlr->tls_ctx.pre_shared_key.secret.base = qctrlr->psk;
			qctrlr->tls_ctx.pre_shared_key.secret.len = qctrlr->psk_size;
			/* Set hash algorithm based on PSK size */
			if (qctrlr->psk_size == 32) {
				qctrlr->tls_ctx.pre_shared_key.hash = &ptls_openssl_sha256;
			} else if (qctrlr->psk_size == 48) {
				qctrlr->tls_ctx.pre_shared_key.hash = &ptls_openssl_sha384;
			}
			NVME_QQPAIR_DEBUGLOG(qqpair, "------ Configured PSK for QUIC TLS (identity: %s, size: %u)\n",
				      qctrlr->psk_identity, qctrlr->psk_size);
			NVME_QQPAIR_DEBUGLOG(qqpair, "Client configured PSK: identity='%s', size=%u, hash=%s\n",
				      qctrlr->psk_identity, qctrlr->psk_size,
				      qctrlr->psk_size == 32 ? "SHA256" : "SHA384");
		}
	}
	
	rc = nvme_ctrlr_construct(&qctrlr->ctrlr);
	if (rc != 0) {
		free(qctrlr);
		return NULL;
	}

	/* Sequence might be used not only for data digest offload purposes but
	 * to handle a potential COPY operation appended as the result of translation. */
	qctrlr->ctrlr.flags |= SPDK_NVME_CTRLR_ACCEL_SEQUENCE_SUPPORTED;
	qctrlr->ctrlr.adminq = nvme_quic_ctrlr_create_qpair(&qctrlr->ctrlr, 0,
			       qctrlr->ctrlr.opts.admin_queue_size, 0,
			       qctrlr->ctrlr.opts.admin_queue_size, true);
	if (!qctrlr->ctrlr.adminq) {
		NVME_CTRLR_ERRLOG(&qctrlr->ctrlr, "failed to create admin qpair\n");
		nvme_quic_ctrlr_destruct(&qctrlr->ctrlr);
		return NULL;
	}

	qqpair = nvme_quic_qpair(qctrlr->ctrlr.adminq);
	qctrlr->ctrlr.numa.id_valid = 1;
	qctrlr->ctrlr.numa.id = spdk_sock_get_numa_id(qqpair->sock);

	if (nvme_ctrlr_add_process(&qctrlr->ctrlr, 0) != 0) {
		NVME_CTRLR_ERRLOG(&qctrlr->ctrlr, "nvme_ctrlr_add_process() failed\n");
		nvme_ctrlr_destruct(&qctrlr->ctrlr);
		return NULL;
	}

	return &qctrlr->ctrlr;
}

static uint32_t
nvme_quic_ctrlr_get_max_xfer_size(struct spdk_nvme_ctrlr *ctrlr)
{
	/* QUIC transport doesn't limit maximum IO transfer size. */
	return UINT32_MAX;
}

static uint16_t
nvme_quic_ctrlr_get_max_sges(struct spdk_nvme_ctrlr *ctrlr)
{
	return NVME_QUIC_MAX_SGL_DESCRIPTORS;
}

static int
nvme_quic_qpair_iterate_requests(struct spdk_nvme_qpair *qpair,
				int (*iter_fn)(struct nvme_request *req, void *arg),
				void *arg)
{
	struct nvme_quic_qpair *qqpair = nvme_quic_qpair(qpair);
	struct nvme_quic_req *quic_req, *tmp;
	int rc;

	assert(iter_fn != NULL);

	TAILQ_FOREACH_SAFE(quic_req, &qqpair->outstanding_reqs, link, tmp) {
		assert(quic_req->req != NULL);

		rc = iter_fn(quic_req->req, arg);
		if (rc != 0) {
			return rc;
		}
	}

	return 0;
}

static int
nvme_quic_qpair_authenticate(struct spdk_nvme_qpair *qpair)
{
	struct nvme_quic_qpair *qqpair = nvme_quic_qpair(qpair);
	int rc;

	/* If the qpair is still connecting, it'll be forced to authenticate later on */
	if (qqpair->state < NVME_QUIC_QPAIR_STATE_RUNNING) {
		return 0;
	} else if (qqpair->state != NVME_QUIC_QPAIR_STATE_RUNNING) {
		return -ENOTCONN;
	}

	rc = nvme_fabric_qpair_authenticate_async(qpair);
	if (rc == 0) {
		nvme_quic_qpair_set_recv_state(qqpair, NVME_QUIC_QPAIR_STATE_AUTHENTICATING);
		nvme_qpair_set_state(qpair, NVME_QPAIR_CONNECTING);
	}

	return rc;
}

static void
nvme_quic_admin_qpair_abort_aers(struct spdk_nvme_qpair *qpair)
{
	struct nvme_quic_req *quic_req, *tmp;
	struct spdk_nvme_cpl cpl = {};
	struct nvme_quic_qpair *qqpair = nvme_quic_qpair(qpair);
	cpl.sqid = qpair->id;
	cpl.status.sc = SPDK_NVME_SC_ABORTED_SQ_DELETION;
	cpl.status.sct = SPDK_NVME_SCT_GENERIC;

	TAILQ_FOREACH_SAFE(quic_req, &qqpair->outstanding_reqs, link, tmp) {
		assert(quic_req->req != NULL);
		if (quic_req->req->cmd.opc != SPDK_NVME_OPC_ASYNC_EVENT_REQUEST) {
			continue;
		}

		nvme_quic_req_complete(quic_req, qqpair, &cpl, false);
	}
}

static struct spdk_nvme_transport_poll_group *
nvme_quic_poll_group_create(void)
{
	struct nvme_quic_poll_group *group = calloc(1, sizeof(*group));
	struct spdk_sock *sock;

	if (group == NULL) {
		SPDK_ERRLOG("Unable to allocate poll group.\n");
		return NULL;
	}

	TAILQ_INIT(&group->needs_poll);
	TAILQ_INIT(&group->timeout_enabled);

	group->sock_group = spdk_sock_group_create(group);
	if (group->sock_group == NULL) {
		free(group);
		SPDK_ERRLOG("Unable to allocate sock group.\n");
		return NULL;
	}

	return &group->group;
}

static struct spdk_nvme_transport_poll_group *
nvme_quic_qpair_get_optimal_poll_group(struct spdk_nvme_qpair *qpair)
{
	struct nvme_quic_qpair *qqpair = nvme_quic_qpair(qpair);
	struct spdk_sock_group *group = NULL;
	int rc;

	rc = spdk_sock_get_optimal_sock_group(qqpair->sock, &group, NULL);
	if (!rc && group != NULL) {
		return spdk_sock_group_get_ctx(group);
	}

	return NULL;
}

static int
nvme_quic_poll_group_connect_qpair(struct spdk_nvme_qpair *qpair)
{
	struct nvme_quic_poll_group *group = nvme_quic_poll_group(qpair->poll_group);
	struct nvme_quic_qpair *qqpair = nvme_quic_qpair(qpair);

	if (spdk_sock_group_add_sock(group->sock_group, qqpair->sock, nvme_quic_qpair_sock_cb, qpair)) {
		return -EPROTO;
	}
	return 0;
}

static int
nvme_quic_poll_group_disconnect_qpair(struct spdk_nvme_qpair *qpair)
{
	struct nvme_quic_poll_group *group = nvme_quic_poll_group(qpair->poll_group);
	struct nvme_quic_qpair *qqpair = nvme_quic_qpair(qpair);

	if (TAILQ_ENTRY_ENQUEUED(qqpair, link_poll)) {
		TAILQ_REMOVE_CLEAR(&group->needs_poll, qqpair, link_poll);
	}

	if (qqpair->sock && group->sock_group) {
		if (spdk_sock_group_remove_sock(group->sock_group, qqpair->sock)) {
			return -EPROTO;
		}
	}
	return 0;
}

static int
nvme_quic_poll_group_add(struct spdk_nvme_transport_poll_group *qgroup,
			struct spdk_nvme_qpair *qpair)
{
	struct nvme_quic_qpair *qqpair = nvme_quic_qpair(qpair);
	struct nvme_quic_poll_group *group = nvme_quic_poll_group(qgroup);
	/* disconnected qpairs won't have a sock to add. */
	if (nvme_qpair_get_state(qpair) >= NVME_QPAIR_CONNECTED) {
		if (spdk_sock_group_add_sock(group->sock_group, qqpair->sock, nvme_quic_qpair_sock_cb, qpair)) {
			return -EPROTO;
		}
	}


	return 0;
}

static int
nvme_quic_poll_group_remove(struct spdk_nvme_transport_poll_group *tgroup,
			   struct spdk_nvme_qpair *qpair)
{
	struct nvme_quic_qpair *qqpair;
	struct nvme_quic_poll_group *group;
	assert(qpair->poll_group_tailq_head == &tgroup->disconnected_qpairs);

	qqpair = nvme_quic_qpair(qpair);
	group = nvme_quic_poll_group(tgroup);
	assert(qqpair->shared_stats == true);
	qqpair->stats = &g_dummy_stats;

	if (TAILQ_ENTRY_ENQUEUED(qqpair, link_poll)) {
		TAILQ_REMOVE_CLEAR(&group->needs_poll, qqpair, link_poll);
	}
	if (TAILQ_ENTRY_ENQUEUED(qqpair, link_timeout)) {
		TAILQ_REMOVE_CLEAR(&group->timeout_enabled, qqpair, link_timeout);
	}

	return 0;
}

static int64_t
nvme_quic_poll_group_process_completions(struct spdk_nvme_transport_poll_group *tgroup,
					uint32_t completions_per_qpair, spdk_nvme_disconnected_qpair_cb disconnected_qpair_cb)
{
	struct nvme_quic_poll_group *group = nvme_quic_poll_group(tgroup);
	struct spdk_nvme_qpair *qpair, *tmp_qpair;
	struct nvme_quic_qpair *qqpair, *tmp_tqpair;
	int num_events;

	group->completions_per_qpair = completions_per_qpair;
	group->num_completions = 0;
	group->stats.polls++;

	/* Periodically log QUIC stats to track packet loss and PTOs causing latency spikes */
	group->stats_poll_counter++;
	if (group->stats_poll_counter % 5000 == 0) {  /* Every 50K polls (~5-10 seconds) */
		STAILQ_FOREACH(qpair, &tgroup->connected_qpairs, poll_group_stailq) {
			qqpair = nvme_quic_qpair(qpair);
			if (qqpair->conn) {
				quicly_stats_t stats;
				if (quicly_get_stats(qqpair->conn, &stats) == 0) {
					uint64_t new_ptos = stats.num_ptos;
					uint64_t new_lost = stats.num_packets.lost;
					uint64_t new_resent = stats.num_bytes.stream_data_resent;
					
					/* Log detailed stats if any PTOs/loss occurred */
					if (new_ptos > group->stats_last_ptos || new_lost > group->stats_last_lost || 
					    new_resent > group->stats_last_resent) {
						uint64_t inflight = stats.num_packets.sent - stats.num_packets.ack_received - stats.num_packets.lost;
						SPDK_DEBUGLOG(nvme, "[QUIC_STATS] qpair %u: PTOs=%lu (+%lu), Lost=%lu (+%lu), Resent=%lu (+%lu)\n"
							     "  Packets: Sent=%lu Acked=%lu InFlight=%lu\n"
							     "  RTT: min=%ums smooth=%ums var=%ums, CWND=%u bytes\n",
							     qpair->id, new_ptos, new_ptos - group->stats_last_ptos,
							     new_lost, new_lost - group->stats_last_lost,
							     new_resent, new_resent - group->stats_last_resent,
							     stats.num_packets.sent, stats.num_packets.ack_received, inflight,
							     stats.rtt.minimum, stats.rtt.smoothed, stats.rtt.variance,
							     stats.cc.cwnd);
					}
					group->stats_last_ptos = new_ptos;
					group->stats_last_lost = new_lost;
					group->stats_last_resent = new_resent;
				}
			}
		}
	}

	//SPDK_DEBUGLOG(nvme, "[TIMING] BEFORE spdk_sock_group_poll()\n");
	num_events = spdk_sock_group_poll(group->sock_group);
	//SPDK_DEBUGLOG(nvme, "[TIMING] AFTER spdk_sock_group_poll() returned %d events\n", num_events);

	if(num_events > 0) {
		SPDK_DEBUGLOG(nvme, "spdk_sock_group_poll returned %d events\n", num_events);
	}

	/* PTO timer sweep: proactively drive QUIC retransmissions for all connected qpairs.
	 * Without this, an IO qpair with all in-flight responses lost will never retransmit
	 * because its sock_cb cannot fire (no incoming packets) and no new requests can be
	 * submitted (all CID slots occupied by stuck in-flight requests). The admin qpair
	 * "accidentally" works because periodic Keep Alive submissions force process_completions,
	 * but IO qpairs have no such trigger. We must sweep proactively here. */
	STAILQ_FOREACH(qpair, &tgroup->connected_qpairs, poll_group_stailq) {
		qqpair = nvme_quic_qpair(qpair);
		if (qqpair->conn) {
			quicly_context_t *ctx = quicly_get_context(qqpair->conn);
			int64_t now = ctx->now->cb(ctx->now);
			if (quicly_get_first_timeout(qqpair->conn) <= now) {
				SPDK_DEBUGLOG(nvme, "[PTO_SWEEP] qpair %u: timeout expired, flushing send queue\n",
					      qpair->id);
				_quic_send_pending(qqpair);
			}
		}
	}

	STAILQ_FOREACH_SAFE(qpair, &tgroup->disconnected_qpairs, poll_group_stailq, tmp_qpair) {
		qqpair = nvme_quic_qpair(qpair);
		if (nvme_qpair_get_state(qpair) == NVME_QPAIR_DISCONNECTING) {
			NVME_QQPAIR_DEBUGLOG(qqpair, "Let's Close QUIC qpair id=%u\n", qpair->id);
			if (TAILQ_EMPTY(&qqpair->outstanding_reqs)) {
				NVME_QQPAIR_DEBUGLOG(qqpair, "Bye QUIC qpair id=%u ! \n", qpair->id);

				nvme_transport_ctrlr_disconnect_qpair_done(qpair);
			}
		}
		/* Wait until the qpair transitions to the DISCONNECTED state, otherwise user might
		 * want to free it from disconnect_qpair_cb, while it's not fully disconnected (and
		 * might still have outstanding requests) */
		if (nvme_qpair_get_state(qpair) == NVME_QPAIR_DISCONNECTED) {
			disconnected_qpair_cb(qpair, tgroup->group->ctx);
		}
	}

	/* If any qpairs were marked as needing to be polled due to an asynchronous write completion
	 * and they weren't polled as a consequence of calling spdk_sock_group_poll above, poll them now. */
	int needs_poll_count = 0;
	TAILQ_FOREACH(qqpair, &group->needs_poll, link_poll) {
		needs_poll_count++;
	}
	if (needs_poll_count > 0) {
		SPDK_DEBUGLOG(nvme, "[NEEDS_POLL] Processing %d qpairs from needs_poll list\n", needs_poll_count);
	}
	TAILQ_FOREACH_SAFE(qqpair, &group->needs_poll, link_poll, tmp_tqpair) {
		// nvme_quic_qpair_sock_cb(&qqpair->qpair, group->sock_group, qqpair->sock);
		_quic_send_pending(qqpair);
		TAILQ_REMOVE_CLEAR(&group->needs_poll, qqpair, link_poll);
	}

	// TAILQ_FOREACH_SAFE(qqpair, &group->timeout_enabled, link_timeout, tmp_tqpair) {
	// 	qpair = &qqpair->qpair;
	// 	assert(qpair->ctrlr->timeout_enabled);
	// 	nvme_quic_qpair_check_timeout(qpair);
	// }

	if (spdk_unlikely(num_events < 0)) {
		return num_events;
	}

	group->stats.idle_polls += !num_events;
	group->stats.socket_completions += num_events;

	return group->num_completions;
}

/*
 * Handle disconnected qpairs when interrupt support gets added.
 */
static void
nvme_quic_poll_group_check_disconnected_qpairs(struct spdk_nvme_transport_poll_group *tgroup,
		spdk_nvme_disconnected_qpair_cb disconnected_qpair_cb)
{
}

static int
nvme_quic_poll_group_destroy(struct spdk_nvme_transport_poll_group *tgroup)
{
	int rc;
	struct nvme_quic_poll_group *group = nvme_quic_poll_group(tgroup);

	if (!STAILQ_EMPTY(&tgroup->connected_qpairs) || !STAILQ_EMPTY(&tgroup->disconnected_qpairs)) {
		return -EBUSY;
	}

	rc = spdk_sock_group_close(&group->sock_group);
	if (rc != 0) {
		SPDK_ERRLOG("Failed to close the sock group for a tcp poll group.\n");
		assert(false);
	}

	free(tgroup);

	return 0;
}

static int
nvme_quic_poll_group_get_stats(struct spdk_nvme_transport_poll_group *tgroup,
			      struct spdk_nvme_transport_poll_group_stat **_stats)
{
	struct nvme_quic_poll_group *group;
	struct spdk_nvme_transport_poll_group_stat *stats;

	if (tgroup == NULL || _stats == NULL) {
		SPDK_ERRLOG("Invalid stats or group pointer\n");
		return -EINVAL;
	}

	group = nvme_quic_poll_group(tgroup);

	stats = calloc(1, sizeof(*stats));
	if (!stats) {
		SPDK_ERRLOG("Can't allocate memory for QUIC stats\n");
		return -ENOMEM;
	}
	stats->trtype = SPDK_NVME_TRANSPORT_QUIC;
	memcpy(&stats->quic, &group->stats, sizeof(group->stats));

	*_stats = stats;

	return 0;
}

static void
nvme_quic_poll_group_free_stats(struct spdk_nvme_transport_poll_group *tgroup,
			       struct spdk_nvme_transport_poll_group_stat *stats)
{
	free(stats);
}

static int
nvme_quic_ctrlr_get_memory_domains(const struct spdk_nvme_ctrlr *ctrlr,
				  struct spdk_memory_domain **domains, int array_size)
{
	if (domains && array_size > 0) {
		domains[0] = spdk_memory_domain_get_system_domain();
	}

	return 1;
}

/* Stream callbacks for QUIC data transmission */
static void
nvme_quic_stream_on_destroy(quicly_stream_t *stream, quicly_error_t err)
{
	struct nvme_quic_stream *nvme_stream = stream->data;
	struct nvme_quic_req *quic_req = nvme_stream ? nvme_stream->req : NULL;

   if (!quic_req) {
		SPDK_ERRLOG("nvme_quic_stream_on_destroy: No associated request for stream_id=%" PRIu64 "\n",
			stream->stream_id);
        return;  // Nothing to complete
    }


	struct nvme_quic_qpair *qqpair = quic_req ? quic_req->qqpair : NULL;
		
	NVME_QQPAIR_DEBUGLOG(qqpair, "QUIC stream destroyed: stream_id=%" PRIu64 ", err=%d, nvme_stream=%p\n",
		stream->stream_id, err, nvme_stream);

	nvme_quic_req_put(qqpair, quic_req);
}

/* NVMe-over-QUIC stream receive callback
 * Handles out-of-order frame delivery using 'off' parameter.
 * 
 * Protocol flow (Host side):
 * 1. Send 64B SQE on stream open
 * 2. For READ: Receive data at offset 0+, then 16B CQE
 * 3. For WRITE: Receive 8B GRANTs, send data, then 16B CQE
 */
static void
nvme_quic_stream_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
	struct nvme_quic_stream *nvme_stream = stream->data;
	struct nvme_quic_req *quic_req;
	struct nvme_quic_qpair *qqpair;
	ptls_iovec_t stream_data;

	SPDK_DEBUGLOG(nvme, "CLIENT nvme_quic_stream_on_receive CALLED: stream_id=%" PRIu64 ", off=%zu, len=%zu, nvme_stream=%p\n",
		stream->stream_id, off, len, nvme_stream);

	/* Get the request from the nvme_stream */
	if (!nvme_stream || !nvme_stream->req) {
		SPDK_DEBUGLOG(nvme, "CLIENT: No nvme_stream or req for stream %" PRIu64 " - returning 0\n", stream->stream_id);
		return;
	}
	quic_req = nvme_stream->req;
	qqpair = quic_req->qqpair;

	if(quicly_streambuf_ingress_receive(stream, off, src, len) != 0) {
		return;
	}

	while(1) {
		stream_data = quicly_streambuf_ingress_get(stream);
		if (stream_data.len == 0) {
			/* No more data to process */
			break;
		}

		SPDK_DEBUGLOG(nvme, "Stream receive: stream_id=%" PRIu64 ", off=%zu, len=%zu, state=%d\n",
			stream->stream_id, off, len, quic_req->state);

		switch (quic_req->state) {
			case NVME_QUIC_REQ_AWAIT_DATA:
				SPDK_DEBUGLOG(nvme, "Awaiting DATA on stream_id=%" PRIu64 "\n", stream->stream_id);
				nvme_quic_read_data_recv(quic_req, stream_data);
				break;
			case NVME_QUIC_REQ_AWAIT_R2T:
				SPDK_DEBUGLOG(nvme, "Awaiting R2T on stream_id=%" PRIu64 "\n", stream->stream_id);
				/* Expecting R2T message (8 bytes: r2to + r2tl) for WRITE */
				if (stream_data.len < sizeof(struct spdk_nvme_quic_r2t)) {
					return;
				}

				struct spdk_nvme_quic_r2t *r2t = (struct spdk_nvme_quic_r2t *)stream_data.base;
				quic_req->datao = r2t->r2to;
				quic_req->r2t_len = r2t->r2tl;
				
				SPDK_DEBUGLOG(nvme, "R2T received: r2to=%u, r2tl=%u\n",
						    quic_req->datao, quic_req->r2t_len);

				/* Send WRITE data (H2C) for this R2T grant */
				nvme_quic_send_h2c_data(quic_req);
				
				/* If more data remains, wait for next R2T */
				if (quic_req->datao + quic_req->r2t_len < quic_req->req->payload_size) {
					quic_req->state = NVME_QUIC_REQ_AWAIT_R2T;
				} else {
					/* All data granted, transition to sending */
					quic_req->state = NVME_QUIC_REQ_AWAIT_CQE;
				}

				quicly_streambuf_ingress_shift(stream, sizeof(struct spdk_nvme_quic_r2t));
				break;

			case NVME_QUIC_REQ_AWAIT_CQE:
				NVME_QQPAIR_DEBUGLOG(qqpair, "Awaiting CQE on stream_id=%" PRIu64 ", expected CID=%u\n", 
					stream->stream_id, quic_req->cid);

				if (stream_data.len < sizeof(struct spdk_nvme_cpl)) {
					NVME_QQPAIR_DEBUGLOG(qqpair, "  Insufficient data: have %zu bytes, need %zu\n",
						stream_data.len, sizeof(struct spdk_nvme_cpl));
					return;
				}

				/* Log raw bytes BEFORE parsing */
				NVME_QQPAIR_DEBUGLOG(qqpair, "Raw stream buffer (%zu bytes): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
				stream_data.len,
				((uint8_t*)stream_data.base)[0], ((uint8_t*)stream_data.base)[1],
				((uint8_t*)stream_data.base)[2], ((uint8_t*)stream_data.base)[3],
				((uint8_t*)stream_data.base)[4], ((uint8_t*)stream_data.base)[5],
				((uint8_t*)stream_data.base)[6], ((uint8_t*)stream_data.base)[7],
				((uint8_t*)stream_data.base)[8], ((uint8_t*)stream_data.base)[9],
				((uint8_t*)stream_data.base)[10], ((uint8_t*)stream_data.base)[11],
				((uint8_t*)stream_data.base)[12], ((uint8_t*)stream_data.base)[13],
				((uint8_t*)stream_data.base)[14], ((uint8_t*)stream_data.base)[15]);

				/* Copy CQE to request */
				quic_req->cpl = *((struct spdk_nvme_cpl *)stream_data.base);
				
				/* Log the parsed CQE */
				NVME_QQPAIR_DEBUGLOG(qqpair, "Parsed CQE: cdw0=0x%x, sqhd=%u, sqid=%u, cid=%u (expected %u), status=0x%x\n",
						quic_req->cpl.cdw0, quic_req->cpl.sqhd, quic_req->cpl.sqid,
						quic_req->cpl.cid, quic_req->cid, quic_req->cpl.status_raw);
				
				/* Validate CID matches */
				if (quic_req->cpl.cid != quic_req->cid) {
					NVME_QQPAIR_DEBUGLOG(qqpair, "CID MISMATCH! Expected %u, got %u\n",
						quic_req->cid, quic_req->cpl.cid);
				}

				quicly_streambuf_ingress_shift(stream, sizeof(struct spdk_nvme_cpl));
			
				/* Fix sqid to match the actual qpair id (server might send sqid=0 for all queues) */
				// quic_req->cpl.sqid = quic_req->qqpair->qpair.id;
				
				/* Mark completion received */
				quic_req->ordering.bits.recv_cpl = 1;
				
				/* Complete the request - call user callback and remove from outstanding list.
				* Do NOT free yet - wait for send ACK. */
				NVME_QQPAIR_DEBUGLOG(qqpair, "CQE received for cid=%u, send_ack=%d\n", 
						quic_req->cid, quic_req->ordering.bits.send_ack);
				nvme_quic_req_complete(quic_req, quic_req->qqpair, &quic_req->cpl, false);
				break;
			default:
				return;
		};	
	}

	return;
}

static void
nvme_quic_stream_on_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
	/* RESET_STREAM received from peer - stream was terminated */
	struct nvme_quic_req *quic_req = stream->data;
	struct nvme_quic_qpair *qqpair = quic_req ? quic_req->qqpair : NULL;
	
	if (quic_req) {
		/* Handle stream reset - may need to fail the request */
		NVME_QQPAIR_DEBUGLOG(qqpair, "Stream reset with error: %ld\n", err);
	}
}

const struct spdk_nvme_transport_ops quic_ops = {
	.name = "QUIC",
	.type = SPDK_NVME_TRANSPORT_QUIC,
	.ctrlr_construct = nvme_quic_ctrlr_construct,
	.ctrlr_scan = nvme_fabric_ctrlr_scan,
	.ctrlr_destruct = nvme_quic_ctrlr_destruct,
	.ctrlr_enable = nvme_quic_ctrlr_enable,

	.ctrlr_set_reg_4 = nvme_fabric_ctrlr_set_reg_4,
	.ctrlr_set_reg_8 = nvme_fabric_ctrlr_set_reg_8,
	.ctrlr_get_reg_4 = nvme_fabric_ctrlr_get_reg_4,
	.ctrlr_get_reg_8 = nvme_fabric_ctrlr_get_reg_8,
	.ctrlr_set_reg_4_async = nvme_fabric_ctrlr_set_reg_4_async,
	.ctrlr_set_reg_8_async = nvme_fabric_ctrlr_set_reg_8_async,
	.ctrlr_get_reg_4_async = nvme_fabric_ctrlr_get_reg_4_async,
	.ctrlr_get_reg_8_async = nvme_fabric_ctrlr_get_reg_8_async,

	.ctrlr_get_max_xfer_size = nvme_quic_ctrlr_get_max_xfer_size,
	.ctrlr_get_max_sges = nvme_quic_ctrlr_get_max_sges,

	.ctrlr_create_io_qpair = nvme_quic_ctrlr_create_io_qpair,
	.ctrlr_delete_io_qpair = nvme_quic_ctrlr_delete_io_qpair,
	.ctrlr_connect_qpair = nvme_quic_ctrlr_connect_qpair,
	.ctrlr_disconnect_qpair = nvme_quic_ctrlr_disconnect_qpair,

	.ctrlr_get_memory_domains = nvme_quic_ctrlr_get_memory_domains,

	.qpair_abort_reqs = nvme_quic_qpair_abort_reqs,
	.qpair_reset = nvme_quic_qpair_reset,
	.qpair_process_completions = nvme_quic_qpair_process_completions,
	.qpair_submit_request = nvme_quic_qpair_submit_request,
	.qpair_iterate_requests = nvme_quic_qpair_iterate_requests,
	.qpair_authenticate = nvme_quic_qpair_authenticate,
	.admin_qpair_abort_aers = nvme_quic_admin_qpair_abort_aers,

	.poll_group_create = nvme_quic_poll_group_create,
	.qpair_get_optimal_poll_group = nvme_quic_qpair_get_optimal_poll_group,
	.poll_group_connect_qpair = nvme_quic_poll_group_connect_qpair,
	.poll_group_disconnect_qpair = nvme_quic_poll_group_disconnect_qpair,
	.poll_group_add = nvme_quic_poll_group_add,
	.poll_group_remove = nvme_quic_poll_group_remove,
	.poll_group_process_completions = nvme_quic_poll_group_process_completions,
	.poll_group_check_disconnected_qpairs = nvme_quic_poll_group_check_disconnected_qpairs,
	.poll_group_destroy = nvme_quic_poll_group_destroy,
	.poll_group_get_stats = nvme_quic_poll_group_get_stats,
	.poll_group_free_stats = nvme_quic_poll_group_free_stats,
};

SPDK_NVME_TRANSPORT_REGISTER(quic, &quic_ops);

static void
nvme_quic_trace(void)
{
	struct spdk_trace_tpoint_opts opts[] = {
		{
			"NVME_QUIC_SUBMIT", TRACE_NVME_QUIC_SUBMIT,
			OWNER_TYPE_NVME_QUIC_QP, OBJECT_NVME_QUIC_REQ, 1,
			{	{ "ctx", SPDK_TRACE_ARG_TYPE_PTR, 8 },
				{ "cid", SPDK_TRACE_ARG_TYPE_INT, 4 },
				{ "opc", SPDK_TRACE_ARG_TYPE_INT, 4 },
				{ "dw10", SPDK_TRACE_ARG_TYPE_PTR, 4 },
				{ "dw11", SPDK_TRACE_ARG_TYPE_PTR, 4 },
				{ "dw12", SPDK_TRACE_ARG_TYPE_PTR, 4 },
				{ "qd", SPDK_TRACE_ARG_TYPE_INT, 4 }
			}
		},
		{
			"NVME_QUIC_COMPLETE", TRACE_NVME_QUIC_COMPLETE,
			OWNER_TYPE_NVME_QUIC_QP, OBJECT_NVME_QUIC_REQ, 0,
			{	{ "ctx", SPDK_TRACE_ARG_TYPE_PTR, 8 },
				{ "cid", SPDK_TRACE_ARG_TYPE_INT, 4 },
				{ "cpl", SPDK_TRACE_ARG_TYPE_PTR, 4 },
				{ "qd", SPDK_TRACE_ARG_TYPE_INT, 4 }
			}
		},
	};

	spdk_trace_register_object(OBJECT_NVME_QUIC_REQ, 'p');
	spdk_trace_register_owner_type(OWNER_TYPE_NVME_QUIC_QP, 'q');
	spdk_trace_register_description_ext(opts, SPDK_COUNTOF(opts));

	spdk_trace_tpoint_register_relation(TRACE_SOCK_REQ_QUEUE, OBJECT_NVME_QUIC_REQ, 0);
	spdk_trace_tpoint_register_relation(TRACE_SOCK_REQ_PEND, OBJECT_NVME_QUIC_REQ, 0);
	spdk_trace_tpoint_register_relation(TRACE_SOCK_REQ_COMPLETE, OBJECT_NVME_QUIC_REQ, 0);
}
SPDK_TRACE_REGISTER_FN(nvme_quic_trace, "nvme_quic", TRACE_GROUP_NVME_QUIC)
