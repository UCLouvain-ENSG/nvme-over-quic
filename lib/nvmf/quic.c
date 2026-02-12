/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2025 Intel Corporation. All rights reserved.
 */

/*
 * NVMe over Fabrics QUIC transport
 */

#include "spdk/stdinc.h"
#include "spdk/assert.h"
#include "spdk/thread.h"
#include "spdk/nvmf_transport.h"
#include "spdk/string.h"
#include "spdk/trace.h"
#include "spdk/util.h"
#include "spdk/log.h"
#include "spdk/keyring.h"

#include "spdk_internal/assert.h"

#include "nvmf_internal.h"
#include "transport.h"

/* Include quicly library headers */
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include "picotls.h"
#include "picotls/openssl.h"
#include "spdk_internal/trace_defs.h"
#include "spdk_internal/nvme_quic.h"

#define MIN_SOCK_PIPE_SIZE 1024
#define NVMF_QUIC_MAX_ACCEPT_SOCK_ONE_TIME 16
#define SPDK_NVMF_QUIC_DEFAULT_MAX_SOCK_PRIORITY 16
#define SPDK_NVMF_QUIC_DEFAULT_SOCK_PRIORITY 0
#define SPDK_NVMF_QUIC_DEFAULT_CONTROL_MSG_NUM 32
#define SPDK_NVMF_QUIC_DEFAULT_SUCCESS_OPTIMIZATION true

#define SPDK_NVMF_QUIC_MIN_IO_QUEUE_DEPTH 2
#define SPDK_NVMF_QUIC_MAX_IO_QUEUE_DEPTH 65535
#define SPDK_NVMF_QUIC_MIN_ADMIN_QUEUE_DEPTH 2
#define SPDK_NVMF_QUIC_MAX_ADMIN_QUEUE_DEPTH 4096

#define SPDK_NVMF_QUIC_DEFAULT_MAX_IO_QUEUE_DEPTH 128
#define SPDK_NVMF_QUIC_DEFAULT_MAX_ADMIN_QUEUE_DEPTH 128
#define SPDK_NVMF_QUIC_DEFAULT_MAX_QPAIRS_PER_CTRLR 128
#define SPDK_NVMF_QUIC_DEFAULT_IN_CAPSULE_DATA_SIZE 4096
#define SPDK_NVMF_QUIC_DEFAULT_MAX_IO_SIZE 131072
#define SPDK_NVMF_QUIC_DEFAULT_IO_UNIT_SIZE 131072
#define SPDK_NVMF_QUIC_DEFAULT_NUM_SHARED_BUFFERS 511
#define SPDK_NVMF_QUIC_DEFAULT_BUFFER_CACHE_SIZE UINT32_MAX
#define SPDK_NVMF_QUIC_DEFAULT_DIF_INSERT_OR_STRIP false
#define SPDK_NVMF_QUIC_DEFAULT_ABORT_TIMEOUT_SEC 1

const struct spdk_nvmf_transport_ops spdk_nvmf_transport_quic;
static bool g_tls_log = false;


/* spdk nvmf related structure */
enum spdk_nvmf_quic_req_state {

	/* The request is not currently in use */
	QUIC_REQUEST_STATE_FREE = 0,

	/* Initial state when request first received */
	QUIC_REQUEST_STATE_NEW = 1,

	/* The request is queued until a data buffer is available. */
	QUIC_REQUEST_STATE_NEED_BUFFER = 2,

	/* The request has the data buffer available */
	QUIC_REQUEST_STATE_HAVE_BUFFER = 3,

	/* The request is waiting for zcopy_start to finish */
	QUIC_REQUEST_STATE_AWAITING_ZCOPY_START = 4,

	/* The request has received a zero-copy buffer */
	QUIC_REQUEST_STATE_ZCOPY_START_COMPLETED = 5,

	/* The request is currently transferring data from the host to the controller. */
	QUIC_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER = 6,

	/* The request is waiting for the R2T send acknowledgement. */
	QUIC_REQUEST_STATE_AWAITING_R2T_ACK = 7,

	/* The request is ready to execute at the block device */
	QUIC_REQUEST_STATE_READY_TO_EXECUTE = 8,

	/* The request is currently executing at the block device */
	QUIC_REQUEST_STATE_EXECUTING = 9,

	/* The request is waiting for zcopy buffers to be committed */
	QUIC_REQUEST_STATE_AWAITING_ZCOPY_COMMIT = 10,

	/* The request finished executing at the block device */
	QUIC_REQUEST_STATE_EXECUTED = 11,

	/* The request is ready to send a completion */
	QUIC_REQUEST_STATE_READY_TO_COMPLETE = 12,

	/* The request is currently transferring final pdus from the controller to the host. */
	QUIC_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST = 13,

	/* The request is waiting for zcopy buffers to be released (without committing) */
	QUIC_REQUEST_STATE_AWAITING_ZCOPY_RELEASE = 14,

	/* The request completed and can be marked free. */
	QUIC_REQUEST_STATE_COMPLETED = 15,

	/* Terminator */
	QUIC_REQUEST_NUM_STATES,
};

enum nvmf_quic_qpair_state {
	NVMF_QUIC_QPAIR_STATE_INVALID = 0,
	NVMF_QUIC_QPAIR_STATE_INITIALIZING = 1,
	NVMF_QUIC_QPAIR_STATE_RUNNING = 2,
	NVMF_QUIC_QPAIR_STATE_EXITING = 3,
	NVMF_QUIC_QPAIR_STATE_EXITED = 4,
};

enum spdk_nvme_quic_term_req_fes {
	SPDK_NVME_QUIC_TERM_REQ_FES_INVALID_HEADER_FIELD				= 0x01,
	SPDK_NVME_QUIC_TERM_REQ_FES_PDU_SEQUENCE_ERROR				= 0x02,
	SPDK_NVME_QUIC_TERM_REQ_FES_HDGST_ERROR					= 0x03,
	SPDK_NVME_QUIC_TERM_REQ_FES_DATA_TRANSFER_OUT_OF_RANGE			= 0x04,
	SPDK_NVME_QUIC_TERM_REQ_FES_DATA_TRANSFER_LIMIT_EXCEEDED			= 0x05,
	SPDK_NVME_QUIC_TERM_REQ_FES_R2T_LIMIT_EXCEEDED				= 0x05,
	SPDK_NVME_QUIC_TERM_REQ_FES_INVALID_DATA_UNSUPPORTED_PARAMETER		= 0x06,
};

static const char *spdk_nvmf_quic_term_req_fes_str[] = {
	"Data Transfer Out of Range",
	"R2T Limit Exceeded",
	"Unsupported parameter",
};


static void
nvmf_quic_trace(void)
{
	spdk_trace_register_owner_type(OWNER_TYPE_NVMF_QUIC, 't');
	spdk_trace_register_object(OBJECT_NVMF_QUIC_IO, 'r');
	spdk_trace_register_description("QUIC_REQ_NEW",
					TRACE_QUIC_REQUEST_STATE_NEW,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NVMF_QUIC_IO, 1,
					SPDK_TRACE_ARG_TYPE_INT, "qd");
	spdk_trace_register_description("QUIC_REQ_NEED_BUFFER",
					TRACE_QUIC_REQUEST_STATE_NEED_BUFFER,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NVMF_QUIC_IO, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("QUIC_REQ_HAVE_BUFFER",
					TRACE_QUIC_REQUEST_STATE_HAVE_BUFFER,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NVMF_QUIC_IO, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("Q_REQ_WAIT_ZCPY_START",
					TRACE_QUIC_REQUEST_STATE_AWAIT_ZCOPY_START,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NVMF_QUIC_IO, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("QUIC_REQ_ZCPY_START_CPL",
					TRACE_QUIC_REQUEST_STATE_ZCOPY_START_COMPLETED,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NVMF_QUIC_IO, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("QUIC_REQ_TX_H_TO_C",
					TRACE_QUIC_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NVMF_QUIC_IO, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("QUIC_REQ_RDY_TO_EXECUTE",
					TRACE_QUIC_REQUEST_STATE_READY_TO_EXECUTE,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NVMF_QUIC_IO, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("QUIC_REQ_EXECUTING",
					TRACE_QUIC_REQUEST_STATE_EXECUTING,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NVMF_QUIC_IO, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("QUIC_REQ_WAIT_ZCPY_CMT",
					TRACE_QUIC_REQUEST_STATE_AWAIT_ZCOPY_COMMIT,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NVMF_QUIC_IO, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("QUIC_REQ_EXECUTED",
					TRACE_QUIC_REQUEST_STATE_EXECUTED,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NVMF_QUIC_IO, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("Q_REQ_RDY_TO_COMPLETE",
					TRACE_QUIC_REQUEST_STATE_READY_TO_COMPLETE,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NVMF_QUIC_IO, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("QUIC_REQ_TRANSFER_C2H",
					TRACE_QUIC_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NVMF_QUIC_IO, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("QUIC_REQ_AWAIT_ZCPY_RLS",
					TRACE_QUIC_REQUEST_STATE_AWAIT_ZCOPY_RELEASE,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NVMF_QUIC_IO, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("QUIC_REQ_COMPLETED",
					TRACE_QUIC_REQUEST_STATE_COMPLETED,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NVMF_QUIC_IO, 0,
					SPDK_TRACE_ARG_TYPE_INT, "qd");
	spdk_trace_register_description("QUIC_READ_DONE",
					TRACE_QUIC_READ_FROM_SOCKET_DONE,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NONE, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("QUIC_REQ_AWAIT_R2T_ACK",
					TRACE_QUIC_REQUEST_STATE_AWAIT_R2T_ACK,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NVMF_QUIC_IO, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");

	spdk_trace_register_description("QUIC_QP_CREATE", TRACE_QUIC_QP_CREATE,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NONE, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("QUIC_QP_SOCK_INIT", TRACE_QUIC_QP_SOCK_INIT,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NONE, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("QUIC_QP_STATE_CHANGE", TRACE_QUIC_QP_STATE_CHANGE,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NONE, 0,
					SPDK_TRACE_ARG_TYPE_INT, "state");
	spdk_trace_register_description("QUIC_QP_DISCONNECT", TRACE_QUIC_QP_DISCONNECT,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NONE, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("QUIC_QP_DESTROY", TRACE_QUIC_QP_DESTROY,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NONE, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("QUIC_QP_ABORT_REQ", TRACE_QUIC_QP_ABORT_REQ,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NONE, 0,
					SPDK_TRACE_ARG_TYPE_INT, "");
	spdk_trace_register_description("Q_QP_RCV_STATE_CHANGE", TRACE_QUIC_QP_RCV_STATE_CHANGE,
					OWNER_TYPE_NVMF_QUIC, OBJECT_NONE, 0,
					SPDK_TRACE_ARG_TYPE_INT, "state");

	spdk_trace_tpoint_register_relation(TRACE_BDEV_IO_START, OBJECT_NVMF_QUIC_IO, 1);
	spdk_trace_tpoint_register_relation(TRACE_BDEV_IO_DONE, OBJECT_NVMF_QUIC_IO, 0);
	spdk_trace_tpoint_register_relation(TRACE_SOCK_REQ_QUEUE, OBJECT_NVMF_QUIC_IO, 0);
	spdk_trace_tpoint_register_relation(TRACE_SOCK_REQ_PEND, OBJECT_NVMF_QUIC_IO, 0);
	spdk_trace_tpoint_register_relation(TRACE_SOCK_REQ_COMPLETE, OBJECT_NVMF_QUIC_IO, 0);
}
SPDK_TRACE_REGISTER_FN(nvmf_quic_trace, "nvmf_quic", TRACE_GROUP_NVMF_QUIC)


struct spdk_nvmf_quic_req {
	struct spdk_nvmf_request		req;
	struct spdk_nvme_cpl			rsp;
	struct spdk_nvme_cmd			cmd;
	struct spdk_nvme_quic_r2t		r2t;


	/* A PDU that can be used for sending responses. This is
	 * not the incoming PDU! */
	struct nvme_quic_stream			*stream;

	/* In-capsule data buffer */
	void					*in_capsule_buf;

	struct spdk_nvmf_quic_req		*fused_pair;

	/*
	 * The PDU for a request may be used multiple times in serial over
	 * the request's lifetime. For example, first to send an R2T, then
	 * to send a completion. To catch mistakes where the PDU is used
	 * twice at the same time, add a debug flag here for init/fini.
	 */
	bool					stream_in_use;
	bool					has_in_capsule_data;
	bool					fused_failed;



	/* transfer_tag */
	uint16_t				ttag;

	enum spdk_nvmf_quic_req_state		state;

	/*
	 * h2c_offset is used when we receive the h2c_data PDU.
	 */
	uint32_t				h2c_offset;

	STAILQ_ENTRY(spdk_nvmf_quic_req)		link;
	TAILQ_ENTRY(spdk_nvmf_quic_req)		state_link;
	STAILQ_ENTRY(spdk_nvmf_quic_req)		control_msg_link;
};

struct spdk_nvmf_quic_qpair {
	struct spdk_nvmf_qpair			qpair;
	struct spdk_nvmf_quic_poll_group	*group;
	struct spdk_sock			*sock;

	enum nvme_quic_stream_recv_state	recv_state;
	enum nvmf_quic_qpair_state		state;

	/* quicly connection */
	quicly_conn_t				*conn;
	
	/* Connection ID for demultiplexing */
	uint64_t				cid_hash;  /* Hash of the CID for lookup */
	bool					in_hash_table;  /* Whether this qpair is in the hash table */
	
	/* Hash table link for CID-based lookup */
	TAILQ_ENTRY(spdk_nvmf_quic_qpair)	cid_hash_link;

	struct nvme_quic_stream			*stream_for_send;

	struct spdk_nvmf_quic_req		*fused_first;

	/* Queues to track the requests in all states */
	TAILQ_HEAD(, spdk_nvmf_quic_req)		quic_req_working_queue;
	TAILQ_HEAD(, spdk_nvmf_quic_req)		quic_req_free_queue;
	SLIST_HEAD(, nvme_quic_stream)		quic_stream_free_queue;
	/* Number of working streams */
	uint32_t				quic_stream_working_count;

	/* Number of requests in each state */
	uint32_t				state_cntr[QUIC_REQUEST_NUM_STATES];

	uint8_t					cpda;

	bool					host_hdgst_enable;
	bool					host_ddgst_enable;

	bool					await_req_msg_pending;

	/* This is a spare PDU used for sending special management
	 * operations. Primarily, this is used for the initial
	 * connection response and c2h termination request. */
	struct nvme_quic_stream			*mgmt_stream;

	/* Arrays of in-capsule buffers, requests, and pdus.
	 * Each array is 'resource_count' number of elements */
	void					*bufs;
	struct spdk_nvmf_quic_req		*reqs;
	struct nvme_quic_stream			*streams;
	uint32_t				resource_count;
	uint32_t				recv_buf_size;

	struct spdk_nvmf_tcp_port		*port;

	/* IP address */
	char					initiator_addr[SPDK_NVMF_TRADDR_MAX_LEN];
	char					target_addr[SPDK_NVMF_TRADDR_MAX_LEN];

	/* IP port */
	uint16_t				initiator_port;
	uint16_t				target_port;

	/* Wait until the host terminates the connection (e.g. after sending C2HTermReq) */
	bool					wait_terminate;

	spdk_nvmf_transport_qpair_fini_cb	fini_cb_fn;
	void					*fini_cb_arg;

	TAILQ_ENTRY(spdk_nvmf_quic_qpair)	link;

	/* QUIC/TLS contexts for this connection */
	quicly_context_t			*quic_ctx;
	ptls_context_t				*tls_ctx;
	quicly_stream_scheduler_t		stream_scheduler;
};

struct spdk_nvmf_quic_control_msg {
	STAILQ_ENTRY(spdk_nvmf_quic_control_msg) link;
};

struct spdk_nvmf_quic_control_msg_list {
	void *msg_buf;
	STAILQ_HEAD(, spdk_nvmf_quic_control_msg) free_msgs;
	STAILQ_HEAD(, spdk_nvmf_quic_req) waiting_for_msg_reqs;
};


/* Hash table size for CID -> qpair lookup. it would be same with tcp's established hash size */
#define QUIC_CID_HASH_SIZE 256

struct spdk_nvmf_quic_poll_group {
	struct spdk_nvmf_transport_poll_group	group;
	struct spdk_sock_group			*sock_group;

	TAILQ_HEAD(, spdk_nvmf_quic_qpair)	qpairs;
	
	/* Hash table for fast CID -> qpair lookup */
	struct {
		TAILQ_HEAD(, spdk_nvmf_quic_qpair) qpairs;
	} cid_hash[QUIC_CID_HASH_SIZE];

	struct spdk_io_channel			*accel_channel;
	struct spdk_nvmf_quic_control_msg_list	*control_msg_list;

	TAILQ_ENTRY(spdk_nvmf_quic_poll_group)	link;
};

struct spdk_nvmf_quic_port {
	const struct spdk_nvme_transport_id	*trid;
	struct spdk_sock 			*udp_sock;
	struct spdk_nvmf_transport		*transport;
	const char				*sock_impl_name;
	bool					secure_channel;
	TAILQ_ENTRY(spdk_nvmf_quic_port)	link;
};

struct nvmf_quic_port_create_ctx {
	struct spdk_nvmf_quic_port		*port;
	struct spdk_nvmf_quic_transport		*qtransport;
};

struct quic_transport_opts {
	bool		c2h_success;
	uint16_t	control_msg_num;
	uint32_t	sock_priority;
};

struct spdk_nvmf_quic_transport {
	struct spdk_nvmf_transport		transport;
	struct quic_transport_opts               quic_opts;
	uint32_t				ack_timeout;

	/* QUIC context */
	quicly_context_t		*quic_ctx;
	ptls_context_t			*tls_ctx;
	quicly_stream_scheduler_t	stream_scheduler;
	
	/* TLS cipher suites and key exchanges arrays */
	ptls_key_exchange_algorithm_t	*key_exchanges[128];
	ptls_cipher_suite_t		*cipher_suites[128];
	
	/* PSK selection callback structure */
	ptls_on_client_hello_t		on_client_hello_cb;

	/* for address token encryption and decryption of QUIC */
	struct {
		ptls_aead_context_t *enc, *dec;
	} address_token_aead;

	quicly_cid_plaintext_t next_cid;

	struct spdk_nvmf_quic_poll_group		*next_pg;

	struct spdk_poller			*accept_poller;
	struct spdk_sock_group			*listen_sock_group;

	struct spdk_sock		*listen_sock;

	TAILQ_HEAD(, spdk_nvmf_quic_port)	ports;
	TAILQ_HEAD(, spdk_nvmf_quic_poll_group)	poll_groups;

	TAILQ_HEAD(, quic_psk_entry)		psks;
};


struct quic_psk_entry {
	char				hostnqn[SPDK_NVMF_NQN_MAX_LEN + 1];
	char				subnqn[SPDK_NVMF_NQN_MAX_LEN + 1];
	char				pskid[NVMF_PSK_IDENTITY_LEN];
	uint8_t				psk[SPDK_TLS_PSK_MAX_LEN];
	struct spdk_key			*key;
	uint32_t			psk_size;
	enum nvme_quic_cipher_suite	tls_cipher_suite;
	TAILQ_ENTRY(quic_psk_entry)	link;
};

static const struct spdk_json_object_decoder quic_transport_opts_decoder[] = {
	{
		"c2h_success", offsetof(struct quic_transport_opts, c2h_success),
		spdk_json_decode_bool, true
	},
	{
		"control_msg_num", offsetof(struct quic_transport_opts, control_msg_num),
		spdk_json_decode_uint16, true
	},
	{
		"sock_priority", offsetof(struct quic_transport_opts, sock_priority),
		spdk_json_decode_uint32, true
	},
};

/* Forward declarations of QUIC stream callbacks - implementations defined later */
static void nvme_quic_stream_on_destroy(quicly_stream_t *stream, quicly_error_t err);
static void nvme_quic_stream_on_send_stop(quicly_stream_t *stream, quicly_error_t err);
static int nvme_quic_stream_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
static void nvme_quic_stream_on_receive_reset(quicly_stream_t *stream, quicly_error_t err);

static bool nvmf_quic_req_process(struct spdk_nvmf_quic_transport *ttransport,
				 struct spdk_nvmf_quic_req *quic_req);
static void nvmf_quic_poll_group_destroy(struct spdk_nvmf_transport_poll_group *group);

static void nvmf_quic_qpair_process(struct spdk_nvmf_quic_qpair *tqpair);
static void _nvmf_quic_send_pending(struct spdk_nvmf_quic_qpair *qqpair);
static void nvmf_quic_poll_group_flush(struct spdk_nvmf_quic_poll_group *qgroup);
static void nvmf_quic_poll_group_send_pending(struct spdk_nvmf_quic_poll_group *qgroup);

static inline uint64_t nvmf_quic_hash_cid(const void *cid_data, size_t cid_len);

static inline void
nvmf_quic_req_set_state(struct spdk_nvmf_quic_req *quic_req,
		       enum spdk_nvmf_quic_req_state state)
{
	struct spdk_nvmf_qpair *qpair;
	struct spdk_nvmf_quic_qpair *qqpair;

	qpair = quic_req->req.qpair;
	qqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_quic_qpair, qpair);

	assert(qqpair->state_cntr[quic_req->state] > 0);
	qqpair->state_cntr[quic_req->state]--;
	qqpair->state_cntr[state]++;

	quic_req->state = state;
}

static void
nvmf_quic_stream_set_state(struct nvme_quic_stream *stream,
			  enum nvme_quic_stream_recv_state state)
{
	stream->recv_state = state;
}



static inline struct nvme_quic_stream *
nvmf_quic_req_stream_init(struct spdk_nvmf_quic_req *quic_req)
{
	// assert(quic_req->stream_in_use == false);

	memset(quic_req->stream, 0, sizeof(*quic_req->stream));
	quic_req->stream->qpair = SPDK_CONTAINEROF(quic_req->req.qpair, struct spdk_nvmf_quic_qpair, qpair);

	return quic_req->stream;
}


static void
nvmf_quic_qpair_set_state(struct spdk_nvmf_quic_qpair *qqpair, enum nvmf_quic_qpair_state state)
{
	qqpair->state = state;
	spdk_trace_record(TRACE_QUIC_QP_STATE_CHANGE, qqpair->qpair.trace_id, 0, 0,
			  (uint64_t)qqpair->state);
}

static int
nvmf_quic_qpair_init(struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_quic_qpair *qqpair;

	qqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_quic_qpair, qpair);
	SPDK_DEBUGLOG(nvmf,"New QUIC Connection: %p\n", qpair);

	spdk_trace_record(TRACE_QUIC_QP_CREATE, qqpair->qpair.trace_id, 0, 0);

	/* Initialize request state queues of the qpair */
	TAILQ_INIT(&qqpair->quic_req_free_queue);
	TAILQ_INIT(&qqpair->quic_req_working_queue);
	SLIST_INIT(&qqpair->quic_stream_free_queue);
	qqpair->qpair.queue_depth = 0;

	qqpair->host_hdgst_enable = true;
	qqpair->host_ddgst_enable = true;
	return 0;
}

static int
nvmf_quic_qpair_sock_init(struct spdk_nvmf_quic_qpair *qqpair)
{
	char saddr[SPDK_NVMF_TRADDR_MAX_LEN], caddr[SPDK_NVMF_TRADDR_MAX_LEN];
	uint16_t sport, cport;
	/* 1 for colon, up to 5 for port number, 1 for null terminator */
	char owner[sizeof(caddr) + 1 + 5 + 1];
	int rc;

	/* For server-side accepted connections, sock is a listening UDP socket
	 * which doesn't have a connected peer address. Skip getaddr. */
	if (qqpair->group != NULL) {
		SPDK_DEBUGLOG(nvmf,"Qpair already has group assigned, skipping sock_init\n");
		return 0;
	}

	rc = spdk_sock_getaddr(qqpair->sock, saddr, sizeof(saddr), &sport,
			       caddr, sizeof(caddr), &cport);
	if (rc != 0) {
		SPDK_ERRLOG("spdk_sock_getaddr() failed\n");
		return rc;
	}
	/* update buffer size for owner when changing format or arguments here */
	snprintf(owner, sizeof(owner), "%s:%d", caddr, cport);
	qqpair->qpair.trace_id = spdk_trace_register_owner(OWNER_TYPE_NVMF_QUIC, owner);
	spdk_trace_record(TRACE_QUIC_QP_SOCK_INIT, qqpair->qpair.trace_id, 0, 0);
	/* set low water mark */
	rc = spdk_sock_set_recvlowat(qqpair->sock, 1);
	if (rc != 0) {
		SPDK_ERRLOG("spdk_sock_set_recvlowat() failed\n");
		return rc;
	}

	return 0;
}


static int
nvmf_quic_qpair_init_mem_resource(struct spdk_nvmf_quic_qpair *qqpair)
{
	uint32_t i;
	struct spdk_nvmf_transport_opts *opts;
	uint32_t in_capsule_data_size;

	opts = &qqpair->qpair.transport->opts;
	in_capsule_data_size = opts->in_capsule_data_size;
	if(opts->dif_insert_or_strip) {
		in_capsule_data_size = SPDK_BDEV_BUF_SIZE_WITH_MD(in_capsule_data_size);
	}

	qqpair->resource_count = opts->max_queue_depth;

	qqpair->reqs = calloc(qqpair->resource_count, sizeof(*qqpair->reqs));
	if(qqpair->reqs == NULL) {
		SPDK_ERRLOG("Failed to allocate memory for QUIC requests\n");
		return -1;
	}

	if(in_capsule_data_size) {
		qqpair->bufs = spdk_zmalloc(qqpair->resource_count * in_capsule_data_size, 0x1000, NULL, SPDK_ENV_LCORE_ID_ANY, SPDK_MALLOC_DMA);
		if(!qqpair->bufs) {
			SPDK_ERRLOG("Failed to allocate memory for QUIC in-capsule data buffers\n");
			return -1;
		}
	}

	qqpair->streams = spdk_dma_zmalloc((2*qqpair->resource_count + 1) * sizeof(*qqpair->streams), 0x1000, NULL);
	if (!qqpair->streams) {
		SPDK_ERRLOG("Failed to allocate memory for QUIC streams\n");
		return -1;
	}

	for(i=0; i<qqpair->resource_count; i++) {
		struct spdk_nvmf_quic_req *quic_req = &qqpair->reqs[i];

		quic_req->ttag = i + 1;
		quic_req->req.qpair = &qqpair->qpair;

		quic_req->stream = &qqpair->streams[i];
		quic_req->stream->qpair = qqpair;

		if(qqpair->bufs) {
			quic_req->in_capsule_buf = (uint8_t *)qqpair->bufs + (i * in_capsule_data_size);
		}

		quic_req->req.rsp = (union nvmf_c2h_msg *)&quic_req->rsp;
		quic_req->req.cmd = (union nvmf_h2c_msg *)&quic_req->cmd;

		quic_req->req.stripped_data = NULL;

		quic_req->state = QUIC_REQUEST_STATE_FREE;
		TAILQ_INSERT_TAIL(&qqpair->quic_req_free_queue, quic_req, state_link);
		qqpair->state_cntr[QUIC_REQUEST_STATE_FREE]++;
	}

	for(; i<2 *qqpair->resource_count; i++) {
		struct nvme_quic_stream *stream = &qqpair->streams[i];
		stream->qpair = qqpair;
		SLIST_INSERT_HEAD(&qqpair->quic_stream_free_queue, stream, slist);
	}

	qqpair->mgmt_stream = &qqpair->streams[2 * qqpair->resource_count];
	qqpair->mgmt_stream->qpair = qqpair;
	SLIST_REMOVE_HEAD(&qqpair->quic_stream_free_queue, slist);
	qqpair->quic_stream_working_count = 1;

	qqpair->recv_buf_size = (in_capsule_data_size + 64) * SPDK_NVMF_QUIC_RECV_BUF_SIZE_FACTOR;

	return 0;
}


/* Should check the state after implementation */
static void
nvmf_quic_qpair_set_recv_state(struct spdk_nvmf_quic_qpair *qqpair,
			      enum nvme_quic_stream_recv_state state)
{
	if (qqpair->recv_state == state) {
		SPDK_ERRLOG("The recv state of qqpair=%p is same with the state(%d) to be set\n",
			    qqpair, state);
		return;
	}


	SPDK_DEBUGLOG(nvmf,"qqpair(%p) recv state=%d\n", qqpair, state);
	qqpair->recv_state = state;
	spdk_trace_record(TRACE_QUIC_QP_RCV_STATE_CHANGE, qqpair->qpair.trace_id, 0, 0,
			  (uint64_t)qqpair->recv_state);
}


/* Add qpair to CID hash table */
static void
nvmf_quic_add_qpair_to_hash(struct spdk_nvmf_quic_poll_group *qgroup,
                             struct spdk_nvmf_quic_qpair *qqpair,
                             quicly_conn_t *conn)
{
	/* Get the encrypted local CID from the connection - this is what clients will use as DCID */
	struct _st_quicly_conn_public_t *c = (struct _st_quicly_conn_public_t *)conn;
	const quicly_cid_t *cid;

	if(c->local.long_header_src_cid.len > 0) {
		/* Use the original DCID if available (this is the CID the client used to connect) */
		cid = &c->local.long_header_src_cid;
	}


	/* Don't add twice */
	if (qqpair->in_hash_table) {
		return;
	}
	
	/* Hash the encrypted CID bytes directly - same as what lookup will do */
	uint64_t hash = nvmf_quic_hash_cid(cid->cid, cid->len);
	uint32_t bucket = hash % QUIC_CID_HASH_SIZE;
	
	qqpair->cid_hash = hash;
	qqpair->in_hash_table = true;
	TAILQ_INSERT_TAIL(&qgroup->cid_hash[bucket].qpairs, qqpair, cid_hash_link);
	
	SPDK_DEBUGLOG(nvmf,"Added qpair %p to hash bucket %u (hash=0x%lx, CID len=%u, bytes=%02x%02x%02x%02x%02x%02x%02x%02x)\n", 
		       qqpair, bucket, hash, cid->len,
		       cid->cid[0], cid->cid[1], cid->cid[2], cid->cid[3],
		       cid->cid[4], cid->cid[5], cid->cid[6], cid->cid[7]);
}

/* Remove qpair from CID hash table */
static void
nvmf_quic_remove_qpair_from_hash(struct spdk_nvmf_quic_poll_group *qgroup,
                                  struct spdk_nvmf_quic_qpair *qqpair)
{
	if (!qqpair->in_hash_table) {
		return;
	}
	
	uint32_t bucket = qqpair->cid_hash % QUIC_CID_HASH_SIZE;
	
	TAILQ_REMOVE(&qgroup->cid_hash[bucket].qpairs, qqpair, cid_hash_link);
	qqpair->in_hash_table = false;
}


/* This is called after qpair is created */
static int
nvmf_quic_poll_group_add(struct spdk_nvmf_transport_poll_group *group,
			 struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_quic_poll_group *qgroup;
	struct spdk_nvmf_quic_qpair *qqpair;
	int rc;


	qgroup = SPDK_CONTAINEROF(group, struct spdk_nvmf_quic_poll_group, group);
	qqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_quic_qpair, qpair);

	rc = nvmf_quic_qpair_sock_init(qqpair);
	if (rc != 0) {
		SPDK_ERRLOG("nvmf_quic_qpair_sock_init failed\n");
		return -1;
	}

	rc = nvmf_quic_qpair_init(&qqpair->qpair);
	if (rc != 0) {
		SPDK_ERRLOG("nvmf_quic_qpair_init failed\n");
		return -1;
	}

	rc = nvmf_quic_qpair_init_mem_resource(qqpair);
	if (rc != 0) {
		SPDK_ERRLOG("nvmf_quic_qpair_init_mem_resource failed\n");
		return -1;
	}

	/* For QUIC, only the udp socket is needed per core, not the connection level */
	// rc = spdk_sock_group_add_sock(qgroup->sock_group, qqpair->sock,
	// 			      nvmf_quic_sock_cb, qqpair);
	// if (rc != 0) {
	// 	SPDK_ERRLOG("spdk_sock_group_add_sock failed\n");
	// 	return -1;
	// }

	// SPDK_DEBUGLOG(nvmf,"POLL_GROUP_ADD ++++ Adding qpair %p to poll group %p\n", qqpair, qgroup);
	// qqpair->group = qgroup;
	// nvmf_quic_qpair_set_state(qqpair, NVMF_QUIC_QPAIR_STATE_RUNNING);
	// TAILQ_INSERT_TAIL(&qgroup->qpairs, qqpair, link);
	
	return 0;
}

static int
nvmf_quic_poll_group_poll(struct spdk_nvmf_transpot_poll_group *group)
{
	struct spdk_nvmf_quic_poll_group *qgroup;
	int num_events;

	qgroup = SPDK_CONTAINEROF(group, struct spdk_nvmf_quic_poll_group, group);

	num_events = spdk_sock_group_poll(qgroup->sock_group);
	if(spdk_unlikely(num_events < 0)) {
		SPDK_ERRLOG("Failed to poll sock_group=%p\n", qgroup->sock_group);
	}

	/* Send all pending responses */
	nvmf_quic_poll_group_send_pending(qgroup);

	return num_events;
}

static inline void
nvmf_quic_request_get_buffers_abort(struct spdk_nvmf_quic_req *quic_req)
{
	/* Request can wait either for the iobuf or control_msg */
	struct spdk_nvmf_qpair *qpair = quic_req->req.qpair;
	struct spdk_nvmf_quic_qpair *qqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_quic_qpair, qpair);
	struct spdk_nvmf_quic_poll_group *quic_group = qqpair->group;
	struct spdk_nvmf_quic_req *tmp_req, *abort_req;

	assert(quic_req->state == QUIC_REQUEST_STATE_NEED_BUFFER);

	if (quic_group->control_msg_list != NULL) {
		STAILQ_FOREACH_SAFE(abort_req, &quic_group->control_msg_list->waiting_for_msg_reqs,
				    control_msg_link, tmp_req) {
			if (abort_req == quic_req) {
				STAILQ_REMOVE(&quic_group->control_msg_list->waiting_for_msg_reqs,
					      abort_req, spdk_nvmf_quic_req, control_msg_link);
				return;
			}
		}
	}

	if (!nvmf_request_get_buffers_abort(&quic_req->req)) {
		SPDK_ERRLOG("Failed to abort quic_req=%p\n", quic_req);
		assert(0 && "Should never happen");
	}
}


static void
nvmf_quic_abort_await_buffer_reqs(struct spdk_nvmf_quic_qpair *qqpair)
{
	struct spdk_nvmf_quic_req *quic_req, *req_tmp;

	/* Remove requests waiting for buffer from the waiting list and mark as completed */
	TAILQ_FOREACH_SAFE(quic_req, &qqpair->quic_req_working_queue, state_link, req_tmp) {
		if (quic_req->state == QUIC_REQUEST_STATE_NEED_BUFFER) {
			nvmf_quic_request_get_buffers_abort(quic_req);
			nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_COMPLETED);
		}
	}
}


static int
nvmf_quic_poll_group_remove(struct spdk_nvmf_transport_poll_group *group,
				    struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_quic_poll_group *qgroup;
	struct spdk_nvmf_quic_qpair *qqpair;
	int rc;

	qgroup = SPDK_CONTAINEROF(group, struct spdk_nvmf_quic_poll_group, group);
	qqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_quic_qpair, qpair);

	assert(qqpair->group == qgroup);

	SPDK_DEBUGLOG(nvmf,"Removing qpair %p from poll group %p\n", qqpair, qgroup);
	if(qqpair->recv_state == NVME_QUIC_RECV_STATE_AWAIT_REQ) {
		/* Check if it's needed after implementation */
		nvmf_quic_qpair_set_recv_state(qqpair, NVME_QUIC_RECV_STATE_QUIESCING);
	}
	
	/* Remove from CID hash table */
	nvmf_quic_remove_qpair_from_hash(qgroup, qqpair);
	
	TAILQ_REMOVE(&qgroup->qpairs, qqpair, link);

	/* Remove socket from sock group before destroying qpair */
	rc = spdk_sock_group_remove_sock(qgroup->sock_group, qqpair->sock);
	if (rc != 0) {
		SPDK_ERRLOG("spdk_sock_group_remove_sock failed\n");
	}

	nvmf_quic_abort_await_buffer_reqs(qqpair);

	return 0;
}



/* This is also never called for quic because of the udp logic */
static int
nvmf_quic_sock_process(struct spdk_nvmf_quic_qpair *qqpair)
{
	int rc;
	struct nvme_quic_stream *stream;
	enum nvme_quic_stream_recv_state prev_state;
	struct spdk_nvmf_quic_transport *qtransport = SPDK_CONTAINEROF(qqpair->qpair.transport, struct spdk_nvmf_quic_transport, transport);
	quicly_context_t *ctx = qtransport->quic_ctx;

	quicly_address_t local, remote;
	uint8_t buf[ctx->transport_params.max_datagram_frame_size];
	ssize_t rret;

	// /* Read all incoming UDP datagrams for this loop */
	// while(1) {
	// 	rc = nvme_quic_read_data(qqpair->sock, sizeof(buf), buf);


	// }

	return 0;
}


static int
nvmf_quic_trsvcid_to_int(const char *trsvcid)
{
	unsigned long long ull;
	char *end = NULL;

	ull = strtoull(trsvcid, &end, 10);
	if (end == NULL || end == trsvcid || *end != '\0') {
		return -1;
	}

	/* Valid TCP/IP port numbers are in [1, 65535] */
	if (ull == 0 || ull > 65535) {
		return -1;
	}

	return (int)ull;
}


static int
quic_sock_get_key(uint8_t *out, int out_len, const char **cipher, const char *pskid, void *get_key_ctx) {
	struct quic_psk_entry *entry;
	struct spdk_nvmf_quic_transport *qtransport = get_key_ctx;
	size_t psk_len;
	int rc;

	TAILQ_FOREACH(entry, &qtransport->psks, link) {
		if (strcmp(pskid, entry->pskid) != 0) {
			continue;
		}

		psk_len = entry->psk_size;
		if((size_t)out_len < psk_len) {
			SPDK_ERRLOG("PSK buffer too small\n");
			return -ENOBUFS;
		}

		rc = nvme_quic_derive_tls_psk(entry->psk, psk_len, pskid, out, out_len, entry->tls_cipher_suite);
		if (rc < 0) {
			SPDK_ERRLOG("Failed to derive TLS PSK\n");
			return rc;
		}

		switch(entry->tls_cipher_suite) {
			case NVME_QUIC_CIPHER_AES_128_GCM_SHA256:
				*cipher = "TLS_AES_128_GCM_SHA256";
				break;
			case NVME_QUIC_CIPHER_AES_256_GCM_SHA384:
				*cipher = "TLS_AES_256_GCM_SHA384";
				break;
			default:
				*cipher = NULL;
				return -ENOTSUP;
		}

		return rc;
	}

	SPDK_ERRLOG("No matching PSK entry for pskid '%s'\n", pskid);
	return -EINVAL;
}

static int
nvmf_quic_accept(void *ctx)
{
	struct spdk_nvmf_transport *transport = ctx;
	struct spdk_nvmf_quic_transport *qtransport;
	int count;

	qtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_quic_transport, transport);

	count = spdk_sock_group_poll(qtransport->listen_sock_group);
	if (count > 0) {
		SPDK_DEBUGLOG(nvmf,"nvmf_quic_accept: GOT %d EVENTS from listen_sock_group=%p!\n", 
		              count, qtransport->listen_sock_group);
	}
	if (count < 0) {
		SPDK_ERRLOG("spdk_sock_group_poll failed\n");
	}

	return count != 0 ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}


static void
nvmf_quic_accept_cb(void *ctx, struct spdk_sock_group *group, struct spdk_sock *sock)
{
	struct spdk_nvmf_quic_port *port = ctx;

	// nvme_quic_port_accept(port);
}

/**
 * Canonicalize a listen address trid.
 */
static int
nvmf_quic_canon_listen_trid(struct spdk_nvme_transport_id *canon_trid,
			   const struct spdk_nvme_transport_id *trid)
{
	int trsvcid_int;

	trsvcid_int = nvmf_quic_trsvcid_to_int(trid->trsvcid);
	if (trsvcid_int < 0) {
		return -EINVAL;
	}

	memset(canon_trid, 0, sizeof(*canon_trid));
	spdk_nvme_trid_populate_transport(canon_trid, SPDK_NVME_TRANSPORT_QUIC);
	canon_trid->adrfam = trid->adrfam;
	snprintf(canon_trid->traddr, sizeof(canon_trid->traddr), "%s", trid->traddr);
	snprintf(canon_trid->trsvcid, sizeof(canon_trid->trsvcid), "%d", trsvcid_int);

	return 0;
}

/**
 * Find an existing listening port.
 */
static struct spdk_nvmf_quic_port *
nvmf_quic_find_port(struct spdk_nvmf_quic_transport *qtransport,
		   const struct spdk_nvme_transport_id *trid)
{
	struct spdk_nvme_transport_id canon_trid;
	struct spdk_nvmf_quic_port *port;

	if (nvmf_quic_canon_listen_trid(&canon_trid, trid) != 0) {
		return NULL;
	}

	TAILQ_FOREACH(port, &qtransport->ports, link) {
		if (spdk_nvme_transport_id_compare(&canon_trid, port->trid) == 0) {
			return port;
		}
	}

	return NULL;
}


static void
nvmf_quic_discover(struct spdk_nvmf_transport *transport,
		  struct spdk_nvme_transport_id *trid, struct spdk_nvmf_discovery_log_page_entry *entry) 
{
	struct spdk_nvmf_quic_port *port;
	struct spdk_nvmf_quic_transport *qtransport;

	entry->trtype = SPDK_NVMF_TRTYPE_QUIC;
	entry->adrfam = trid->adrfam;

	spdk_strcpy_pad(entry->trsvcid, trid->trsvcid, sizeof(entry->trsvcid), ' ');
	spdk_strcpy_pad(entry->traddr, trid->traddr, sizeof(entry->traddr), ' ');

	qtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_quic_transport, transport);
	port = nvmf_quic_find_port(qtransport, trid);

	assert(port != NULL);

	if(strcmp(spdk_sock_get_impl_name(port->udp_sock), "ssl") == 0) {
		entry->treq.secure_channel = SPDK_NVMF_TREQ_SECURE_CHANNEL_REQUIRED;
		entry->tsas.quic.sectype = 2; // TLS 1.3
	} else {
		SPDK_ERRLOG("QUIC transport only supports secure channel\n");
		return;
	}
}

/* Hash function for Connection ID */
static inline uint64_t
nvmf_quic_hash_cid(const void *cid_data, size_t cid_len)
{
	const uint8_t *data = cid_data;
	uint64_t hash = 0;
	
	/* Simple FNV-1a hash */
	for (size_t i = 0; i < cid_len; i++) {
		hash ^= data[i];
		hash *= 0x100000001b3ULL;
	}
	
	return hash;
}

/* Look up qpair by Connection ID from decoded QUIC packet */
static struct spdk_nvmf_quic_qpair *
nvmf_quic_find_qpair_by_decoded_cid(struct spdk_nvmf_quic_poll_group *qgroup,
                                     quicly_decoded_packet_t *packet)
{
	const uint8_t *cid_data;
	size_t cid_len;
	uint64_t hash;
	uint32_t bucket;
	struct spdk_nvmf_quic_qpair *qqpair;
	
	/* Extract CID from packet based on header type */
	if (QUICLY_PACKET_IS_LONG_HEADER(packet->octets.base[0])) {
		/* Long header: use DCID */
		cid_data = packet->cid.dest.encrypted.base;
		cid_len = packet->cid.dest.encrypted.len;
	} else {
		/* Short header: use the CID from packet */
		cid_data = packet->cid.dest.encrypted.base;
		cid_len = packet->cid.dest.encrypted.len;
	}
	
	if (cid_len == 0) {
		/* No CID - this shouldn't happen for server */
		SPDK_DEBUGLOG(nvmf,"Packet has no CID\n");
		return NULL;
	}
	
	hash = nvmf_quic_hash_cid(cid_data, cid_len);
	bucket = hash % QUIC_CID_HASH_SIZE;
	
	SPDK_DEBUGLOG(nvmf,"Looking up qpair: hash=0x%lx, bucket=%u, CID len=%zu, bytes=%02x%02x%02x%02x%02x%02x%02x%02x\n", 
		       hash, bucket, cid_len,
		       cid_data[0], cid_data[1], cid_data[2], cid_data[3],
		       cid_data[4], cid_data[5], cid_data[6], cid_data[7]);
	
	TAILQ_FOREACH(qqpair, &qgroup->cid_hash[bucket].qpairs, cid_hash_link) {
		if (qqpair->cid_hash == hash) {
			/* TODO: For collision safety, compare actual CID bytes
			 * Can get from qqpair->conn via quicly API */
			SPDK_DEBUGLOG(nvmf,"Found qpair %p with matching hash\n", qqpair);
			return qqpair;
		}
	}
	
	return NULL;
}

static int 
quicly_validate_token(quicly_context_t *ctx, struct sockaddr *remote, ptls_iovec_t client_cid, ptls_iovec_t server_cid,
                          quicly_address_token_plaintext_t *token, const char **err_desc)
{
    int64_t age;

    /* calculate and normalize age */
    if ((age = ctx->now->cb(ctx->now) - token->issued_at) < 0)
        age = 0;

    /* type-specific checks */
    switch (token->type) {
    case QUICLY_ADDRESS_TOKEN_TYPE_RETRY:
        if (age > 30000)
            goto Expired;
        if (!quicly_cid_is_equal(&token->retry.client_cid, client_cid))
            goto CIDMismatch;
        if (!quicly_cid_is_equal(&token->retry.server_cid, server_cid))
            goto CIDMismatch;
        break;
    case QUICLY_ADDRESS_TOKEN_TYPE_RESUMPTION:
        if (age > 10 * 60 * 1000)
            goto Expired;
        break;
    default:
        assert(!"unexpected token type");
        abort();
        break;
    }

    /* check address, deferring the use of port number match to type-specific checks */
    if (remote->sa_family != token->remote.sa.sa_family)
        goto AddressMismatch;
    switch (remote->sa_family) {
    case AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in *)remote;
        if (sin->sin_addr.s_addr != token->remote.sin.sin_addr.s_addr)
            goto AddressMismatch;
        if (token->type == QUICLY_ADDRESS_TOKEN_TYPE_RETRY && sin->sin_port != token->remote.sin.sin_port)
            goto AddressMismatch;
    } break;
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)remote;
        if (memcmp(&sin6->sin6_addr, &token->remote.sin6.sin6_addr, sizeof(sin6->sin6_addr)) != 0)
            goto AddressMismatch;
        if (token->type == QUICLY_ADDRESS_TOKEN_TYPE_RETRY && sin6->sin6_port != token->remote.sin6.sin6_port)
            goto AddressMismatch;
    } break;
    default:
        goto UnknownAddressType;
    }

    /* success */
    *err_desc = NULL;
    token->address_mismatch = 0;
    return 1;

AddressMismatch:
    token->address_mismatch = 1;
    *err_desc = NULL;
    return 1;

UnknownAddressType:
    *err_desc = "unknown address type";
    return 0;
Expired:
    *err_desc = "token expired";
    return 0;
CIDMismatch:
    *err_desc = "CID mismatch";
    return 0;
}

/* Forward declarations for callback functions */
static quicly_closed_by_remote_t closed_by_remote;
static quicly_generate_resumption_token_t generate_resumption_token;
static quicly_stream_open_t nvmf_quic_stream_open;
static quicly_error_t scheduler_do_send(quicly_stream_scheduler_t *sched, quicly_conn_t *conn, quicly_send_context_t *s);

static struct spdk_nvmf_quic_qpair *
nvmf_quic_qpair_create(struct spdk_nvmf_quic_poll_group *qgroup,
						quicly_conn_t *conn)
{
	struct spdk_nvmf_quic_qpair *qqpair;
	struct spdk_nvmf_quic_transport *qtransport;

	qqpair = calloc(1, sizeof(struct spdk_nvmf_quic_qpair));
	if(qqpair == NULL) {
		SPDK_ERRLOG("Failed to allocate memory for QUIC qpair\n");
		return NULL;
	}

	qqpair->conn = conn;
	qqpair->state_cntr[QUIC_REQUEST_STATE_FREE] = 0;
	qqpair->qpair.transport = qgroup->group.transport;
	qtransport = SPDK_CONTAINEROF(qgroup->group.transport, struct spdk_nvmf_quic_transport, transport);

	/* Context is now shared at qgroup level - no per-qpair TLS/QUIC setup needed */

	spdk_nvmf_tgt_new_qpair(qgroup->group.transport->tgt, &qqpair->qpair);
	return qqpair;
}


/* Stream callbacks for QUIC data transmission */
static void
nvme_quic_stream_on_destroy(quicly_stream_t *stream, quicly_error_t err)
{
	struct nvme_quic_stream *nvme_stream = stream->data;
	struct spdk_nvmf_quic_req *quic_req = nvme_stream->req;
	
	/* Clear stream pointer - request may still be completing */
	if (quic_req && quic_req->stream && quic_req->stream->quic_stream == stream) {
		quic_req->stream->quic_stream = NULL;
	}
}

static void
nvme_quic_stream_on_send_shift(quicly_stream_t *stream, size_t delta)
{
	/* Data acknowledged by peer - can free send buffers */
	/* For NVMe commands, we keep data until completion */

}

static void
nvme_quic_stream_on_send_emit(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all)
{
	struct nvme_quic_stream *nvme_stream = stream->data;

	if(nvme_stream->cb_fn) {
		nvme_stream->cb_fn(nvme_stream->cb_arg);
	}

	quicly_streambuf_t *streambuf = stream->data;
	quicly_sendbuf_emit(stream, &streambuf->egress, off, dst, len, wrote_all);
}

static void
nvme_quic_stream_on_send_stop(quicly_stream_t *stream, quicly_error_t err)
{
	/* STOP_SENDING received from peer */
}



static uint32_t
nvme_quic_get_in_capsule_data_length(struct spdk_nvmf_quic_req *quic_req)
{
	struct spdk_nvme_cmd			*cmd;
	struct spdk_nvme_sgl_descriptor		*sgl;
	uint32_t				length;

	cmd = &quic_req->req.cmd->nvme_cmd;
	sgl = &cmd->dptr.sgl1;

	assert(sgl->generic.type == SPDK_NVME_SGL_TYPE_DATA_BLOCK &&
	       sgl->unkeyed.subtype == SPDK_NVME_SGL_SUBTYPE_OFFSET);

	/* Capsule Cmd with In-capsule Data should get data length from pdu header */
	length = sgl->unkeyed.length;

	return length;
}

static inline void *
nvmf_quic_control_msg_get(struct spdk_nvmf_quic_control_msg_list *list,
			 struct spdk_nvmf_quic_req *quic_req)
{
	struct spdk_nvmf_quic_control_msg *msg;

	assert(list);

	msg = STAILQ_FIRST(&list->free_msgs);
	if (!msg) {
		SPDK_DEBUGLOG(nvmf,"Out of control messages\n");
		STAILQ_INSERT_TAIL(&list->waiting_for_msg_reqs, quic_req, control_msg_link);
		return NULL;
	}
	STAILQ_REMOVE_HEAD(&list->free_msgs, link);
	return msg;
}


static void
nvmf_quic_req_parse_sgl(struct spdk_nvmf_quic_req *quic_req,
		       struct spdk_nvmf_transport *transport,
		       struct spdk_nvmf_transport_poll_group *group)
{
	struct spdk_nvmf_request		*req = &quic_req->req;
	struct spdk_nvme_cmd			*cmd;
	struct spdk_nvme_sgl_descriptor		*sgl;
	struct spdk_nvmf_quic_poll_group		*qgroup;
	enum spdk_nvme_quic_term_req_fes		fes;
	struct spdk_nvmf_quic_qpair		*qqpair;
	uint32_t				length, error_offset = 0;

	cmd = &req->cmd->nvme_cmd;
	sgl = &cmd->dptr.sgl1;

	if (sgl->generic.type == SPDK_NVME_SGL_TYPE_TRANSPORT_DATA_BLOCK &&
	    sgl->unkeyed.subtype == SPDK_NVME_SGL_SUBTYPE_TRANSPORT) {
		/* get request length from sgl */
		length = sgl->unkeyed.length;
		if (spdk_unlikely(length > transport->opts.max_io_size)) {
			SPDK_ERRLOG("SGL length 0x%x exceeds max io size 0x%x\n",
				    length, transport->opts.max_io_size);
			fes = SPDK_NVME_QUIC_TERM_REQ_FES_DATA_TRANSFER_LIMIT_EXCEEDED;
			goto fatal_err;
		}

		/* fill request length and populate iovs */
		req->length = length;

		SPDK_DEBUGLOG(nvmf,"Data requested length= 0x%x\n", length);

		if (spdk_unlikely(req->dif_enabled)) {
			req->dif.orig_length = length;
			length = spdk_dif_get_length_with_md(length, &req->dif.dif_ctx);
			req->dif.elba_length = length;
		}

		if (nvmf_ctrlr_use_zcopy(req)) {
			SPDK_DEBUGLOG(nvmf,"Using zero-copy to execute request %p\n", quic_req);
			req->data_from_pool = false;
			nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_HAVE_BUFFER);
			return;
		}

		if (spdk_nvmf_request_get_buffers(req, group, transport, length)) {
			/* No available buffers. Queue this request up. */
			SPDK_DEBUGLOG(nvmf,"No available large data buffers. Queueing request %p\n",
				      quic_req);
			return;
		}

		nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_HAVE_BUFFER);
		SPDK_DEBUGLOG(nvmf,"Request %p took %d buffer/s from central pool, and data=%p\n",
			      quic_req, req->iovcnt, req->iov[0].iov_base);

		return;
	} else if (sgl->generic.type == SPDK_NVME_SGL_TYPE_DATA_BLOCK &&
		   sgl->unkeyed.subtype == SPDK_NVME_SGL_SUBTYPE_OFFSET) {
		uint64_t offset = sgl->address;
		uint32_t max_len = transport->opts.in_capsule_data_size;

		assert(quic_req->has_in_capsule_data);
		/* Capsule Cmd with In-capsule Data should get data length from pdu header */
		length = nvme_quic_get_in_capsule_data_length(quic_req);

		/* This error is not defined in NVMe/TCP spec, take this error as fatal error */
		if (spdk_unlikely(length != sgl->unkeyed.length)) {
			SPDK_ERRLOG("In-Capsule Data length 0x%x is not equal to SGL data length 0x%x\n",
				    length, sgl->unkeyed.length);
			fes = SPDK_NVME_QUIC_TERM_REQ_FES_INVALID_HEADER_FIELD;
			goto fatal_err;
		}

		SPDK_DEBUGLOG(nvmf,"In-capsule data: offset 0x%" PRIx64 ", length 0x%x\n",
			      offset, length);

		/* The NVMe/QUIC transport does not use ICDOFF to control the in-capsule data offset. ICDOFF should be '0' */
		if (spdk_unlikely(offset != 0)) {
			/* Not defined fatal error in NVMe/QUIC spec, handle this error as a fatal error */
			SPDK_ERRLOG("In-capsule offset 0x%" PRIx64 " should be ZERO in NVMe/QUIC\n", offset);
			fes = SPDK_NVME_QUIC_TERM_REQ_FES_INVALID_DATA_UNSUPPORTED_PARAMETER;
			error_offset = offsetof(struct spdk_nvme_quic_cmd, ccsqe.dptr.sgl1.address);
			goto fatal_err;
		}

		if (spdk_unlikely(length > max_len)) {
			/* According to the SPEC we should support ICD up to 8192 bytes for admin and fabric commands */
			if (length <= SPDK_NVME_QUIC_IN_CAPSULE_DATA_MAX_SIZE &&
			    (cmd->opc == SPDK_NVME_OPC_FABRIC || req->qpair->qid == 0)) {

				/* Get a buffer from dedicated list */
				SPDK_DEBUGLOG(nvmf,"Getting a buffer from control msg list\n");
				qgroup = SPDK_CONTAINEROF(group, struct spdk_nvmf_quic_poll_group, group);
				assert(qgroup->control_msg_list);
				req->iov[0].iov_base = nvmf_quic_control_msg_get(qgroup->control_msg_list, quic_req);
				if (!req->iov[0].iov_base) {
					/* No available buffers. Queue this request up. */
					SPDK_DEBUGLOG(nvmf,"No available ICD buffers. Queueing request %p\n", quic_req);
					nvmf_quic_stream_set_state(qqpair, NVME_QUIC_RECV_STATE_AWAIT_PDU_BUF);
					return;
				}
			} else {
				SPDK_ERRLOG("In-capsule data length 0x%x exceeds capsule length 0x%x\n",
					    length, max_len);
				fes = SPDK_NVME_QUIC_TERM_REQ_FES_DATA_TRANSFER_LIMIT_EXCEEDED;
				goto fatal_err;
			}
		} else {
			req->iov[0].iov_base = quic_req->in_capsule_buf;
		}

		req->length = length;
		req->data_from_pool = false;

		if (spdk_unlikely(req->dif_enabled)) {
			length = spdk_dif_get_length_with_md(length, &req->dif.dif_ctx);
			req->dif.elba_length = length;
		}

		req->iov[0].iov_len = length;
		req->iovcnt = 1;
		nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_HAVE_BUFFER);

		return;
	}
	/* If we want to handle the problem here, then we can't skip the following data segment.
	 * Because this function runs before reading data part, now handle all errors as fatal errors. */
	SPDK_ERRLOG("Invalid NVMf I/O Command SGL:  Type 0x%x, Subtype 0x%x\n",
		    sgl->generic.type, sgl->generic.subtype);
	fes = SPDK_NVME_QUIC_TERM_REQ_FES_INVALID_DATA_UNSUPPORTED_PARAMETER;
	error_offset = offsetof(struct spdk_nvme_quic_cmd, ccsqe.dptr.sgl1.generic);
fatal_err:
	/* Do the errer handling after checking the operation */
	//nvmf_quic_send_c2h_term_req(quic_req->pdu->qpair, quic_req->pdu, fes, error_offset);
}



static void
_nvmf_quic_send_pending(struct spdk_nvmf_quic_qpair *qqpair)
{
	quicly_address_t dest, src;
	size_t num_packets;
	struct iovec udp_datagrams[SPDK_NVME_ADMIN_QUEUE_QUIRK_ENTRIES_MULTIPLE];
	uint8_t buf[SPDK_NVME_ADMIN_QUEUE_QUIRK_ENTRIES_MULTIPLE * SPDK_NVME_QUIC_MAX_UDP_DATAGRAM_SIZE];
	quicly_error_t ret;
	num_packets = SPDK_NVME_ADMIN_QUEUE_QUIRK_ENTRIES_MULTIPLE;

	/* Ask quicly to generate UDP packets from queued stream data */
	ret = quicly_send(qqpair->conn, &dest, &src, udp_datagrams, &num_packets, buf, sizeof(buf));
	if (ret != 0) {
		SPDK_ERRLOG("quicly_send failed: %d\n", ret);
		return;
	}

	SPDK_DEBUGLOG(nvmf_quic, "SERVER: _nvmf_quic_send_pending: quicly_send returned %zu packets\n", 
	            num_packets);

	if (num_packets == 0) {
		/* Nothing to send */
		SPDK_DEBUGLOG(nvmf_quic, "SERVER: quicly_send returned ZERO packets - nothing to send\n");
		return;
	}

	/* Log the source address that quicly_send populated */
	{
		char src_str[64] = "N/A";
		uint16_t src_port = 0;
		if (src.sa.sa_family == AF_INET) {
			struct sockaddr_in *s = (struct sockaddr_in *)&src.sa;
			inet_ntop(AF_INET, &s->sin_addr, src_str, sizeof(src_str));
			src_port = ntohs(s->sin_port);
		} else if (src.sa.sa_family == AF_INET6) {
			struct sockaddr_in6 *s = (struct sockaddr_in6 *)&src.sa;
			inet_ntop(AF_INET6, &s->sin6_addr, src_str, sizeof(src_str));
			src_port = ntohs(s->sin6_port);
		}
		SPDK_DEBUGLOG(nvmf_quic, "SERVER _nvmf_quic_send_pending: quicly_send populated src=%s:%u, sock=%p, num_packets=%zu\n",
			    src_str, src_port, qqpair->sock, num_packets);
	}

	/* Send the generated UDP packets */
	SPDK_DEBUGLOG(nvmf_quic, "SERVER: Sending %zu UDP datagrams\n", num_packets);
	
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
		SPDK_DEBUGLOG(nvmf,"SERVER: Sending %zu packets to dest=%s:%u (qpair initiator=%s:%u), socklen=%d\n",
			       num_packets, dest_str, dest_port, qqpair->initiator_addr, qqpair->initiator_port,
			       quicly_get_socklen(&dest.sa));
	}
	
	for(int i=0; i<num_packets; i++) {
		SPDK_DEBUGLOG(nvmf_quic, "  Datagram %d: len=%zu\n", i, udp_datagrams[i].iov_len);
		int rc = spdk_sock_writev_direct(qqpair->sock, &udp_datagrams[i], 1, &dest.sa, quicly_get_socklen(&dest.sa));
		if (rc < 0) {
			SPDK_DEBUGLOG(nvmf_quic, "spdk_sock_writev_direct failed: rc=%d, errno=%d (%s)\n", rc, errno, strerror(errno));
		} else {
			SPDK_DEBUGLOG(nvmf_quic, "spdk_sock_writev_direct sent %d bytes\n", rc);
		}
	}

	return (int)num_packets;
}


/* Forward declaration */
static void nvmf_quic_send_capsule_resp(struct spdk_nvmf_quic_req *quic_req,
					 struct spdk_nvmf_quic_qpair *qqpair);

static quicly_error_t
nvme_quic_flatten(quicly_sendbuf_vec_t *vec, void *dst, size_t off, size_t len)
{
    /* cbdata points to spdk_nvmf_quic_sendbuf_element_t, need to get actual buffer */
    struct spdk_nvmf_quic_sendbuf_element_t *element = vec->cbdata;
    uint8_t *src = (uint8_t *)element->buf;
    
    SPDK_DEBUGLOG(nvmf,"nvme_quic_flatten: vec=%p, dst=%p, off=%zu, len=%zu\n", vec, dst, off, len);
    SPDK_DEBUGLOG(nvmf,"  vec->cbdata=%p (element), element->buf=%p (actual data)\n", vec->cbdata, element->buf);
    
    /* Log what we're copying - first 16 bytes (assumes it's a CQE or similar) */
    if (len >= 16 && off == 0) {
        SPDK_DEBUGLOG(nvmf,"  Source data (first 16 bytes): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                      src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
                      src[8], src[9], src[10], src[11], src[12], src[13], src[14], src[15]);
        
        /* Interpret as CQE */
        struct spdk_nvme_cpl *cpl = (struct spdk_nvme_cpl *)src;
        SPDK_DEBUGLOG(nvmf,"  As CQE: cdw0=0x%x, sqhd=%u, sqid=%u, cid=%u, status=0x%x\n",
                      cpl->cdw0, cpl->sqhd, cpl->sqid, cpl->cid, cpl->status_raw);
    }
    
    memcpy(dst, src + off, len);
    
    /* Log what we copied to dst */
    if (len >= 16 && off == 0) {
        uint8_t *d = (uint8_t *)dst;
        SPDK_DEBUGLOG(nvmf,"  Destination data (first 16 bytes): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                      d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
                      d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
    }
    
    return 0;
}

static void
nvme_quic_r2t_complete(quicly_sendbuf_vec_t *vec)
{
	/* cbdata now points to element structure */
	struct spdk_nvmf_quic_sendbuf_element_t *element = vec->cbdata;
	struct nvme_quic_stream *stream = element->nvme_stream;
	struct spdk_nvmf_quic_req *quic_req = stream->req;
	struct spdk_nvmf_quic_transport *qtransport;

	qtransport = SPDK_CONTAINEROF(quic_req->req.qpair->transport, struct spdk_nvmf_quic_transport, transport);

	/* R2T has been ACKed by the host - now wait for data to arrive.
	 * The stream receive callback will handle incoming data and
	 * transition to READY_TO_EXECUTE when all data is received. */
	nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER);
	
	/* Set stream to await data */
	nvmf_quic_stream_set_state(stream, NVME_QUIC_RECV_STATE_AWAIT_DATA);
}

static const quicly_streambuf_sendvec_callbacks_t nvme_quic_r2t_callbacks = {nvme_quic_flatten, nvme_quic_r2t_complete};

static void
nvmf_quic_send_r2t(struct spdk_nvmf_quic_qpair *qqpair,
		      struct spdk_nvmf_quic_req *quic_req)
{
	struct quicly_stream_t *send_stream = quic_req->stream->quic_stream;
	struct st_quicly_sendbuf_vec_t *sendbuf;

	assert(sendbuf != NULL);

	quic_req->r2t.r2tl = quic_req->req.length;
	quic_req->r2t.r2to = quic_req->h2c_offset;

	/* No need for AWAITING_R2T_ACK state - QUIC provides reliable delivery.
	 * The discard callback (nvme_quic_r2t_complete) will be called when R2T is ACKed,
	 * and will transition to TRANSFERRING_HOST_TO_CONTROLLER. */

	SPDK_DEBUGLOG(nvmf,"quic_req(%p) on qqpair(%p), r2t_info: cid=%u, r2to=%u, r2tl=%u\n",
		      quic_req, qqpair, quic_req->cmd.cid, quic_req->r2t.r2to, quic_req->r2t.r2tl);

	nvme_quic_stream_set_r2t_buf(quic_req->stream, &quic_req->r2t, &nvme_quic_r2t_callbacks);
	quicly_streambuf_egress_write_vec(send_stream, &quic_req->stream->r2t_buf);
}


/* It should have arg for quic_req and the shift design needed for safe re-transmission */
static quicly_error_t
nvme_quic_iovs_flatten(quicly_sendbuf_vec_t *vec, void *dst, size_t off, size_t len)
{
	/* cbdata points to element, need to get iov array from it */
	struct spdk_nvmf_quic_sendbuf_element_t *element = vec->cbdata;
	struct iovec *iov = (struct iovec *)element->buf;
	size_t iov_offset = 0;
	size_t copied = 0;
	int i = 0;

	/* Find which iov contains the starting offset */
	while (iov[i].iov_len > 0 && iov_offset + iov[i].iov_len <= off) {
		iov_offset += iov[i].iov_len;
		i++;
	}

	/* Copy from iovs starting at offset */
	while (copied < len && iov[i].iov_len > 0) {
		size_t offset_in_iov = (copied == 0) ? (off - iov_offset) : 0;
		size_t available = iov[i].iov_len - offset_in_iov;
		size_t copy_len = spdk_min(len - copied, available);
		
		memcpy((uint8_t *)dst + copied, (uint8_t *)iov[i].iov_base + offset_in_iov, copy_len);
		copied += copy_len;
		i++;
	}

	return copied == len ? 0 : QUICLY_TRANSPORT_ERROR_INTERNAL;
}

static void
nvme_quic_c2h_data_complete(quicly_sendbuf_vec_t *vec)
{
	/* Called when C2H data is fully ACKed - now send the CQE */
	/* Get the stream from the vec (which is the data_buf in the stream) */
	struct spdk_nvmf_quic_sendbuf_element_t* element = vec->cbdata;
	struct nvme_quic_stream* nvme_stream = element->nvme_stream;
	struct spdk_nvmf_quic_req *quic_req = nvme_stream->req;
	struct spdk_nvmf_quic_qpair *qqpair = nvme_stream->qpair;
	struct spdk_nvmf_quic_transport *qtransport;

	SPDK_DEBUGLOG(nvmf_quic, "nvme_quic_c2h_data_complete: C2H data fully ACKed for req=%p, stream=%p\n", quic_req, nvme_stream);
	
	//qqpair = SPDK_CONTAINEROF(quic_req->req.qpair, struct spdk_nvmf_quic_qpair, qpair);
	
	/* Data has been sent and ACKed, now send the completion */
	//nvmf_quic_send_capsule_resp(quic_req, qqpair);
}

static const quicly_streambuf_sendvec_callbacks_t nvme_quic_c2h_callbacks = {nvme_quic_iovs_flatten, nvme_quic_c2h_data_complete};

static void
nvmf_quic_send_c2h_data(struct spdk_nvmf_quic_qpair *qqpair, struct spdk_nvmf_quic_req *quic_req)
{
	struct quicly_stream_t *send_stream = quic_req->stream->quic_stream;
	quicly_sendbuf_vec_t *databuf = &quic_req->stream->data_buf;
	int ret;

	SPDK_DEBUGLOG(nvmf_quic, "enter: req=%p, stream=%p, data length=%u\n", quic_req, quic_req->stream, quic_req->req.length);

	nvme_quic_stream_set_data_buf(quic_req->stream, quic_req->req.iov, quic_req->req.length, &nvme_quic_c2h_callbacks);

	SPDK_DEBUGLOG(nvmf_quic, "  data_buf: cb=%p (flatten=%p, discard=%p), cbdata=%p, len=%zu\n",
		      databuf->cb, databuf->cb->flatten_vec, databuf->cb->discard_vec,
		      databuf->cbdata, databuf->len);

	ret = quicly_streambuf_egress_write_vec(send_stream, databuf);
	
	SPDK_DEBUGLOG(nvmf_quic, "  quicly_streambuf_egress_write_vec returned %d\n", ret);


	// Send the data first, and then send the completion in the discard callback (nvme_quic_c2h_data_complete) to ensure proper ordering and that we only send completion after data is ACKed. This also simplifies error handling - if data transmission fails, we won't have sent a completion that we then need to retract or ignore.
	nvmf_quic_send_capsule_resp(quic_req, qqpair);
}

static void
nvme_quic_response_complete(quicly_sendbuf_vec_t *vec)
{
	/* cbdata now points to the stream, not the CQE */
	struct spdk_nvmf_quic_sendbuf_element_t* element = vec->cbdata;
	struct nvme_quic_stream* nvme_stream = element->nvme_stream;
	struct spdk_nvmf_quic_req *quic_req = nvme_stream->req;
	struct spdk_nvmf_quic_transport *qtransport;

	/* Debug: Verify cbdata-based lookup is working correctly */
	SPDK_DEBUGLOG(nvmf_quic, "nvme_quic_response_complete: vec=%p, vec->cbdata=%p, stream=%p, quic_req=%p\n", 
		       vec, vec->cbdata, nvme_stream, quic_req);
	SPDK_DEBUGLOG(nvmf_quic, "  vec->len=%zu, vec->cb=%p\n", vec->len, vec->cb);

	/* This is called when the response completion vector is fully ACKed and discarded.
	 * For errors or non-READ commands, only completion is sent (no data).
	 * Transition to COMPLETED state to clean up resources. */
	
	qtransport = SPDK_CONTAINEROF(quic_req->req.qpair->transport, struct spdk_nvmf_quic_transport, transport);
	SPDK_DEBUGLOG(nvmf_quic, "  qtransport=%p\n", qtransport);
	
	/* Should be in TRANSFERRING_CONTROLLER_TO_HOST state */
	assert(quic_req->state == QUIC_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST);
	
	nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_COMPLETED);
	nvmf_quic_req_process(qtransport, quic_req);
}


static const quicly_streambuf_sendvec_callbacks_t nvme_quic_rsp_callbacks = {nvme_quic_flatten, nvme_quic_response_complete};

static void
nvmf_quic_send_capsule_resp(struct spdk_nvmf_quic_req *quic_req,
			       struct spdk_nvmf_quic_qpair *qqpair)
{
	struct quicly_stream_t *send_stream;
	int ret;
	
	if (!quic_req || !quic_req->stream || !quic_req->stream->quic_stream) {
		SPDK_ERRLOG("Invalid request or stream in send_capsule_resp\n");
		return;
	}
	
	send_stream = quic_req->stream->quic_stream;
	quic_req->rsp = quic_req->req.rsp->nvme_cpl;

	SPDK_DEBUGLOG(nvmf_quic, "nvmf_quic_send_capsule_resp: req=%p, stream=%p, cid=%u, status=%u/%u, sqhd=%u\n",
		       quic_req, send_stream, quic_req->rsp.cid, quic_req->rsp.status.sct,
		       quic_req->rsp.status.sc, quic_req->rsp.sqhd);
	SPDK_DEBUGLOG(nvmf_quic, "  quic_req->stream=%p, stream->req=%p (should be %p)\n",
		       quic_req->stream, quic_req->stream->req, quic_req);

	/* Log the CQE data we're about to send */
	uint8_t *cqe_bytes = (uint8_t *)&quic_req->rsp;
	SPDK_DEBUGLOG(nvmf_quic, "  CQE to send (16 bytes): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
		       cqe_bytes[0], cqe_bytes[1], cqe_bytes[2], cqe_bytes[3],
		       cqe_bytes[4], cqe_bytes[5], cqe_bytes[6], cqe_bytes[7],
		       cqe_bytes[8], cqe_bytes[9], cqe_bytes[10], cqe_bytes[11],
		       cqe_bytes[12], cqe_bytes[13], cqe_bytes[14], cqe_bytes[15]);
	SPDK_DEBUGLOG(nvmf_quic, "  Parsed: cdw0=0x%x, sqhd=%u, sqid=%u, cid=%u, status=0x%x\n",
		       quic_req->rsp.cdw0, quic_req->rsp.sqhd, quic_req->rsp.sqid,
		       quic_req->rsp.cid, quic_req->rsp.status_raw);

	SPDK_DEBUGLOG(nvmf_quic, "About to write %zu bytes to stream %p\n", sizeof(struct spdk_nvme_cpl), send_stream);

	/* Use vector API with discard callback to properly manage request lifecycle */
	nvme_quic_stream_set_rsp_buf(quic_req->stream, &quic_req->rsp, &nvme_quic_rsp_callbacks);

	SPDK_DEBUGLOG(nvmf_quic, "  After set_rsp_buf: rsp_buf addr=%p, rsp_buf.cb=%p, rsp_buf.cbdata=%p, rsp_buf.len=%zu\n",
		       &quic_req->stream->rsp_buf, quic_req->stream->rsp_buf.cb, 
		       quic_req->stream->rsp_buf.cbdata, quic_req->stream->rsp_buf.len);

	ret = quicly_streambuf_egress_write_vec(send_stream, &quic_req->stream->rsp_buf);
	if (ret != 0) {
		SPDK_ERRLOG("Failed to write response to stream %p: ret=%d\n", send_stream, ret);
		return;
	}
	quicly_streambuf_egress_shutdown(send_stream);
	
	SPDK_DEBUGLOG(nvmf_quic, "Response queued successfully on stream %p, ret=%d\n", send_stream, ret);
	
	/* Mark that this qpair has pending data to send */
	
	/* Don't flush here - we're inside QUIC receive callback (reentrancy issue)
	 * The poll group will flush all qpairs after datagram processing completes */
}


static int
request_transfer_out(struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_quic_req	*quic_req;
	struct spdk_nvmf_qpair		*qpair;
	struct spdk_nvmf_quic_qpair	*qqpair;
	struct spdk_nvme_cpl		*rsp;

	quic_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_quic_req, req);
	SPDK_DEBUGLOG(nvmf_quic, "request_transfer_out: req=%p, opc=0x%x\n", quic_req, quic_req->cmd.opc);

	qpair = req->qpair;
	rsp = &req->rsp->nvme_cpl;
	quic_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_quic_req, req);

	/* Advance our sq_head pointer */
	if (qpair->sq_head == qpair->sq_head_max) {
		qpair->sq_head = 0;
	} else {
		qpair->sq_head++;
	}
	rsp->sqhd = qpair->sq_head;

	qqpair = SPDK_CONTAINEROF(quic_req->req.qpair, struct spdk_nvmf_quic_qpair, qpair);
	nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST);
	if (spdk_nvme_cpl_is_success(rsp) && req->xfer == SPDK_NVME_DATA_CONTROLLER_TO_HOST) {
		nvmf_quic_send_c2h_data(qqpair, quic_req);
	} else {

		nvmf_quic_send_capsule_resp(quic_req, qqpair);
	}

	return 0;
}

static void
handle_await_req(void *arg)
{
	struct spdk_nvmf_quic_qpair *qqpair = arg;

	qqpair->await_req_msg_pending = false;
	if (qqpair->recv_state == NVME_QUIC_RECV_STATE_AWAIT_REQ) {
		nvmf_quic_qpair_process(qqpair);
	}
}

static inline void
nvmf_quic_req_put(struct spdk_nvmf_quic_qpair *qqpair, struct spdk_nvmf_quic_req *quic_req)
{
	TAILQ_REMOVE(&qqpair->quic_req_working_queue, quic_req, state_link);
	TAILQ_INSERT_TAIL(&qqpair->quic_req_free_queue, quic_req, state_link);
	qqpair->qpair.queue_depth--;
	nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_FREE);
	if (qqpair->recv_state == NVME_QUIC_RECV_STATE_AWAIT_REQ &&
	    !qqpair->await_req_msg_pending) {
		qqpair->await_req_msg_pending = true;
		spdk_thread_send_msg(spdk_get_thread(), handle_await_req, qqpair);
	}
}

static inline void
nvmf_quic_req_set_cpl(struct spdk_nvmf_quic_req *qreq, int sct, int sc)
{
	qreq->req.rsp->nvme_cpl.status.sct = sct;
	qreq->req.rsp->nvme_cpl.status.sc = sc;
	qreq->req.rsp->nvme_cpl.cid = qreq->req.cmd->nvme_cmd.cid;
}

static void
nvmf_quic_req_set_abort_status(struct spdk_nvmf_request *req, struct spdk_nvmf_quic_req *quic_req_to_abort)
{
	nvmf_quic_req_set_cpl(quic_req_to_abort, SPDK_NVME_SCT_GENERIC, SPDK_NVME_SC_ABORTED_BY_REQUEST);
	nvmf_quic_req_set_state(quic_req_to_abort, QUIC_REQUEST_STATE_READY_TO_COMPLETE);

	req->rsp->nvme_cpl.cdw0 &= ~1U; /* Command was successfully aborted */
}

static void
nvmf_quic_check_fused_ordering(struct spdk_nvmf_quic_transport *qtransport,
			      struct spdk_nvmf_quic_qpair *qqpair,
			      struct spdk_nvmf_quic_req *quic_req)
{
	enum spdk_nvme_cmd_fuse last, next;

	last = qqpair->fused_first ? qqpair->fused_first->cmd.fuse : SPDK_NVME_CMD_FUSE_NONE;
	next = quic_req->cmd.fuse;

	assert(last != SPDK_NVME_CMD_FUSE_SECOND);

	if (spdk_likely(last == SPDK_NVME_CMD_FUSE_NONE && next == SPDK_NVME_CMD_FUSE_NONE)) {
		return;
	}

	if (last == SPDK_NVME_CMD_FUSE_FIRST) {
		if (next == SPDK_NVME_CMD_FUSE_SECOND) {
			/* This is a valid pair of fused commands.  Point them at each other
			 * so they can be submitted consecutively once ready to be executed.
			 */
			qqpair->fused_first->fused_pair = quic_req;
			quic_req->fused_pair = qqpair->fused_first;
			qqpair->fused_first = NULL;
			return;
		} else {
			/* Mark the last req as failed since it wasn't followed by a SECOND. */
			qqpair->fused_first->fused_failed = true;

			/*
			 * If the last req is in READY_TO_EXECUTE state, then call
			 * nvmf_quic_req_process(), otherwise nothing else will kick it.
			 */
			if (qqpair->fused_first->state == QUIC_REQUEST_STATE_READY_TO_EXECUTE) {
				nvmf_quic_req_process(qtransport, qqpair->fused_first);
			}

			qqpair->fused_first = NULL;
		}
	}

	if (next == SPDK_NVME_CMD_FUSE_FIRST) {
		/* Set qqpair->fused_first here so that we know to check that the next request
		 * is a SECOND (and to fail this one if it isn't).
		 */
		qqpair->fused_first = quic_req;
	} else if (next == SPDK_NVME_CMD_FUSE_SECOND) {
		/* Mark this req failed since it is a SECOND and the last one was not a FIRST. */
		quic_req->fused_failed = true;
	}
}

static inline void
nvmf_quic_control_msg_put(struct spdk_nvmf_quic_control_msg_list *list, void *_msg)
{
	struct spdk_nvmf_quic_control_msg *msg = _msg;
	struct spdk_nvmf_quic_req *quic_req;
	struct spdk_nvmf_quic_transport *qtransport;
	assert(list);
	STAILQ_INSERT_HEAD(&list->free_msgs, msg, link);
	if (!STAILQ_EMPTY(&list->waiting_for_msg_reqs)) {
		quic_req = STAILQ_FIRST(&list->waiting_for_msg_reqs);
		STAILQ_REMOVE_HEAD(&list->waiting_for_msg_reqs, control_msg_link);
		qtransport = SPDK_CONTAINEROF(quic_req->req.qpair->transport,
					      struct spdk_nvmf_quic_transport, transport);
		nvmf_quic_req_process(qtransport, quic_req);
	}
}

static bool
nvmf_quic_req_process(struct spdk_nvmf_quic_transport *qtransport,
			  struct spdk_nvmf_quic_req *quic_req)
{
	struct spdk_nvmf_quic_qpair *qqpair;
	struct nvme_quic_stream *stream = quic_req->stream;
	enum spdk_nvmf_quic_req_state		prev_state;
	bool progress = false;
	struct spdk_nvmf_transport *transport = &qtransport->transport;
	struct spdk_nvmf_transport_poll_group *group;
	struct spdk_nvmf_quic_poll_group *qgroup;

	qqpair = SPDK_CONTAINEROF(quic_req->req.qpair, struct spdk_nvmf_quic_qpair, qpair);
	group = &qqpair->group->group;
	assert(quic_req->state != QUIC_REQUEST_STATE_FREE);

	if(!spdk_nvmf_qpair_is_active(&qqpair->qpair)) {
		if(quic_req->state != QUIC_REQUEST_STATE_NEED_BUFFER) {
			nvmf_quic_request_get_buffers_abort(quic_req);
		}
		nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_COMPLETED);
	}

	
	/* The loop here is to allow for several back-to-back state changes. */
	do {
		prev_state = quic_req->state;

		SPDK_DEBUGLOG(nvmf,"Request %p entering state %d on qqpair=%p\n", quic_req, prev_state,
			      qqpair);

		switch (quic_req->state) {
		case QUIC_REQUEST_STATE_FREE:
			/* Some external code must kick a request into QUIC_REQUEST_STATE_NEW
			 * to escape this state. */
			break;
		case QUIC_REQUEST_STATE_NEW:
			spdk_trace_record(TRACE_QUIC_REQUEST_STATE_NEW, qqpair->qpair.trace_id, 0, (uintptr_t)quic_req,
					  qqpair->qpair.queue_depth);


			/* Check for fused commands */
			nvmf_quic_check_fused_ordering(qtransport, qqpair, quic_req);

			/* The next state transition depends on the data transfer needs of this request. */
			quic_req->req.xfer = spdk_nvmf_req_get_xfer(&quic_req->req);
			if (spdk_unlikely(quic_req->req.xfer == SPDK_NVME_DATA_BIDIRECTIONAL)) {
				nvmf_quic_req_set_cpl(quic_req, SPDK_NVME_SCT_GENERIC, SPDK_NVME_SC_INVALID_OPCODE);
				nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_READY_TO_COMPLETE);
				SPDK_DEBUGLOG(nvmf,"Request %p: invalid xfer type (BIDIRECTIONAL)\n", quic_req);
				break;
			}

			/* If no data to transfer, ready to execute. */
			if (quic_req->req.xfer == SPDK_NVME_DATA_NONE) {
				/* Reset the qqpair receiving pdu state */
				nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_READY_TO_EXECUTE);
				break;
			}

			nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_NEED_BUFFER);
			break;
		case QUIC_REQUEST_STATE_NEED_BUFFER:
			spdk_trace_record(TRACE_QUIC_REQUEST_STATE_NEED_BUFFER, qqpair->qpair.trace_id, 0,
					  (uintptr_t)quic_req);
			assert(quic_req->req.xfer != SPDK_NVME_DATA_NONE);

			/* Try to get a data buffer */
			nvmf_quic_req_parse_sgl(quic_req, transport, group);
			break;
		case QUIC_REQUEST_STATE_HAVE_BUFFER:
			spdk_trace_record(TRACE_QUIC_REQUEST_STATE_HAVE_BUFFER, qqpair->qpair.trace_id, 0,
					  (uintptr_t)quic_req);
			/* Get a zcopy buffer if the request can be serviced through zcopy */
			if (spdk_nvmf_request_using_zcopy(&quic_req->req)) {
				if (spdk_unlikely(quic_req->req.dif_enabled)) {
					assert(quic_req->req.dif.elba_length >= quic_req->req.length);
					quic_req->req.length = quic_req->req.dif.elba_length;
				}

				nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_AWAITING_ZCOPY_START);
				spdk_nvmf_request_zcopy_start(&quic_req->req);
				break;
			}

			assert(quic_req->req.iovcnt > 0);

			/* If data is transferring from host to controller, we need to do a transfer from the host. */
			if (quic_req->req.xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER) {
				// This is a WRITE command - host wants to send data to controller
				if (quic_req->req.data_from_pool) {
					// R2T case
					SPDK_DEBUGLOG(nvmf,"Sending R2T for quic_req(%p) on qqpair=%p\n", quic_req, qqpair);
					nvmf_quic_send_r2t(qqpair, quic_req);
				} else {
					// In-capsule data case
					nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER);
					SPDK_DEBUGLOG(nvmf,"Not need to send r2t for quic_req(%p) on qqpair=%p, h2c_offset=%u, req.length=%u\n",
						       quic_req, qqpair, quic_req->h2c_offset, quic_req->req.length);
					/* No need to send r2t, contained in the capsuled data */
					nvmf_quic_stream_set_state(stream, NVME_QUIC_RECV_STATE_AWAIT_DATA);
					
					/* For in-capsule data, check if all data is already received */
					if (quic_req->h2c_offset >= quic_req->req.length) {
						SPDK_DEBUGLOG(nvmf,"In-capsule data complete, transitioning to READY_TO_EXECUTE\n");
						nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_READY_TO_EXECUTE);
					}
				}
				break;
			}

			nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_READY_TO_EXECUTE);
			break;
		case QUIC_REQUEST_STATE_AWAITING_ZCOPY_START:
			spdk_trace_record(TRACE_QUIC_REQUEST_STATE_AWAIT_ZCOPY_START, qqpair->qpair.trace_id, 0,
					  (uintptr_t)quic_req);
			/* Some external code must kick a request into  QUIC_REQUEST_STATE_ZCOPY_START_COMPLETED
			 * to escape this state. */
			break;
		case QUIC_REQUEST_STATE_ZCOPY_START_COMPLETED:
			spdk_trace_record(TRACE_QUIC_REQUEST_STATE_ZCOPY_START_COMPLETED, qqpair->qpair.trace_id, 0,
					  (uintptr_t)quic_req);
			if (spdk_unlikely(spdk_nvme_cpl_is_error(&quic_req->req.rsp->nvme_cpl))) {
				SPDK_DEBUGLOG(nvmf,"Zero-copy start failed for quic_req(%p) on qqpair=%p\n",
					      quic_req, qqpair);
				nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_READY_TO_COMPLETE);
				break;
			}
			if (quic_req->req.xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER) {
				SPDK_DEBUGLOG(nvmf,"Sending R2T for quic_req(%p) on qqpair=%p\n", quic_req, qqpair);
				nvmf_quic_send_r2t(qqpair, quic_req);
			} else {
				nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_EXECUTED);
			}
			break;
		case QUIC_REQUEST_STATE_AWAITING_R2T_ACK:
			/* NOT USED for QUIC - R2T discard callback directly transitions to
			 * TRANSFERRING_HOST_TO_CONTROLLER when R2T is ACKed.
			 * This state is kept for compatibility but should never be reached. */
			assert(false && "AWAITING_R2T_ACK should not be used with QUIC transport");
			break;
		case QUIC_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER:

			spdk_trace_record(TRACE_QUIC_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER, qqpair->qpair.trace_id,
					  0, (uintptr_t)quic_req);
			/* Some external code must kick a request into QUIC_REQUEST_STATE_READY_TO_EXECUTE
			 * to escape this state. */
			break;
		case QUIC_REQUEST_STATE_READY_TO_EXECUTE:
			SPDK_DEBUGLOG(nvmf_quic, "==> CASE READY_TO_EXECUTE: req=%p, opc=0x%x, fuse=%d\n",
				       quic_req, quic_req->cmd.opc, quic_req->cmd.fuse);
			spdk_trace_record(TRACE_QUIC_REQUEST_STATE_READY_TO_EXECUTE, qqpair->qpair.trace_id, 0,
					  (uintptr_t)quic_req);

			if (spdk_unlikely(quic_req->req.dif_enabled)) {
				assert(quic_req->req.dif.elba_length >= quic_req->req.length);
				quic_req->req.length = quic_req->req.dif.elba_length;
			}

			if (quic_req->cmd.fuse != SPDK_NVME_CMD_FUSE_NONE) {
				SPDK_DEBUGLOG(nvmf_quic, "This is a FUSED command, checking fused_pair\n");
				if (quic_req->fused_failed) {
					/* This request failed FUSED semantics.  Fail it immediately, without
					 * even sending it to the target layer.
					 */
					nvmf_quic_req_set_cpl(quic_req, SPDK_NVME_SCT_GENERIC, SPDK_NVME_SC_ABORTED_MISSING_FUSED);
					nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_READY_TO_COMPLETE);
					break;
				}

				if (quic_req->fused_pair == NULL ||
				    quic_req->fused_pair->state != QUIC_REQUEST_STATE_READY_TO_EXECUTE) {
					/* This request is ready to execute, but either we don't know yet if it's
					 * valid - i.e. this is a FIRST but we haven't received the next request yet),
					 * or the other request of this fused pair isn't ready to execute. So
					 * break here and this request will get processed later either when the
					 * other request is ready or we find that this request isn't valid.
					 */
					break;
				}
			}

			SPDK_DEBUGLOG(nvmf_quic, "Checking zcopy: using_zcopy=%d\n",
				       spdk_nvmf_request_using_zcopy(&quic_req->req));
			if (!spdk_nvmf_request_using_zcopy(&quic_req->req)) {
				nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_EXECUTING);
				SPDK_DEBUGLOG(nvmf_quic, "About to call spdk_nvmf_request_exec() for req=%p, opc=0x%x\n",
					       quic_req, quic_req->cmd.opc);
				/* If we get to this point, and this request is a fused command, we know that
				 * it is part of a valid sequence (FIRST followed by a SECOND) and that both
				 * requests are READY_TO_EXECUTE.  So call spdk_nvmf_request_exec() both on this
				 * request, and the other request of the fused pair, in the correct order.
				 * Also clear the ->fused_pair pointers on both requests, since after this point
				 * we no longer need to maintain the relationship between these two requests.
				 */
				if (quic_req->cmd.fuse == SPDK_NVME_CMD_FUSE_SECOND) {
					assert(quic_req->fused_pair != NULL);
					assert(quic_req->fused_pair->fused_pair == quic_req);
					nvmf_quic_req_set_state(quic_req->fused_pair, QUIC_REQUEST_STATE_EXECUTING);
					spdk_nvmf_request_exec(&quic_req->fused_pair->req);
					quic_req->fused_pair->fused_pair = NULL;
					quic_req->fused_pair = NULL;
				}
				spdk_nvmf_request_exec(&quic_req->req);
				SPDK_DEBUGLOG(nvmf_quic, "Returned from spdk_nvmf_request_exec() for req=%p\n", quic_req);
				if (quic_req->cmd.fuse == SPDK_NVME_CMD_FUSE_FIRST) {
					assert(quic_req->fused_pair != NULL);
					assert(quic_req->fused_pair->fused_pair == quic_req);
					nvmf_quic_req_set_state(quic_req->fused_pair, QUIC_REQUEST_STATE_EXECUTING);
					spdk_nvmf_request_exec(&quic_req->fused_pair->req);
					quic_req->fused_pair->fused_pair = NULL;
					quic_req->fused_pair = NULL;
				}
			} else {
				/* For zero-copy, only requests with data coming from host to the
				 * controller can end up here. */
				assert(quic_req->req.xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER);
				nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_AWAITING_ZCOPY_COMMIT);
				spdk_nvmf_request_zcopy_end(&quic_req->req, true);
			}

			break;
		case QUIC_REQUEST_STATE_EXECUTING:
			SPDK_DEBUGLOG(nvmf_quic, "State EXECUTING: req=%p, waiting for completion callback\n", quic_req);
			spdk_trace_record(TRACE_TCP_REQUEST_STATE_EXECUTING, qqpair->qpair.trace_id, 0, (uintptr_t)quic_req);
			/* Some external code must kick a request into TCP_REQUEST_STATE_EXECUTED
			 * to escape this state. */
			break;
		case QUIC_REQUEST_STATE_AWAITING_ZCOPY_COMMIT:
			spdk_trace_record(TRACE_TCP_REQUEST_STATE_AWAIT_ZCOPY_COMMIT, qqpair->qpair.trace_id, 0,
					  (uintptr_t)quic_req);
			/* Some external code must kick a request into TCP_REQUEST_STATE_EXECUTED
			 * to escape this state. */
			break;
		case QUIC_REQUEST_STATE_EXECUTED:
			spdk_trace_record(TRACE_TCP_REQUEST_STATE_EXECUTED, qqpair->qpair.trace_id, 0, (uintptr_t)quic_req);
			SPDK_DEBUGLOG(nvmf_quic, "State EXECUTED: req=%p, opc=0x%x\n", quic_req, quic_req->cmd.opc);
			if (spdk_unlikely(quic_req->req.dif_enabled)) {
				quic_req->req.length = quic_req->req.dif.orig_length;
			}

			nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_READY_TO_COMPLETE);
			break;
		case QUIC_REQUEST_STATE_READY_TO_COMPLETE:
			spdk_trace_record(TRACE_TCP_REQUEST_STATE_READY_TO_COMPLETE, qqpair->qpair.trace_id, 0,
					  (uintptr_t)quic_req);
			if (request_transfer_out(&quic_req->req) != 0) {
				assert(0); /* No good way to handle this currently */
			}
			break;
		case QUIC_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST:
			spdk_trace_record(TRACE_TCP_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST, qqpair->qpair.trace_id,
					  0, (uintptr_t)quic_req);
			/* Some external code must kick a request into TCP_REQUEST_STATE_COMPLETED
			 * to escape this state. */
			break;
		case QUIC_REQUEST_STATE_AWAITING_ZCOPY_RELEASE:
			spdk_trace_record(TRACE_TCP_REQUEST_STATE_AWAIT_ZCOPY_RELEASE, qqpair->qpair.trace_id, 0,
					  (uintptr_t)quic_req);
			/* Some external code must kick a request into TCP_REQUEST_STATE_COMPLETED
			 * to escape this state. */
			break;
		case QUIC_REQUEST_STATE_COMPLETED:
			spdk_trace_record(TRACE_TCP_REQUEST_STATE_COMPLETED, qqpair->qpair.trace_id, 0, (uintptr_t)quic_req,
					  qqpair->qpair.queue_depth);

			if (quic_req->req.data_from_pool) {
				spdk_nvmf_request_free_buffers(&quic_req->req, group, transport);
			} else if (spdk_unlikely(quic_req->has_in_capsule_data &&
						 (quic_req->cmd.opc == SPDK_NVME_OPC_FABRIC ||
						  qqpair->qpair.qid == 0) && quic_req->req.length > transport->opts.in_capsule_data_size)) {
				qgroup = SPDK_CONTAINEROF(group, struct spdk_nvmf_quic_poll_group, group);
				assert(qgroup->control_msg_list);
				SPDK_DEBUGLOG(nvmf_quic, "Put buf to control msg list\n");
				nvmf_quic_control_msg_put(qgroup->control_msg_list,
							 quic_req->req.iov[0].iov_base);
			} else if (quic_req->req.zcopy_bdev_io != NULL) {
				/* If the request has an unreleased zcopy bdev_io, it's either a
				 * read, a failed write, or the qpair is being disconnected */
				assert(spdk_nvmf_request_using_zcopy(&quic_req->req));
				assert(quic_req->req.xfer == SPDK_NVME_DATA_CONTROLLER_TO_HOST ||
				       spdk_nvme_cpl_is_error(&quic_req->req.rsp->nvme_cpl) ||
				       !spdk_nvmf_qpair_is_active(&qqpair->qpair));
				nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_AWAITING_ZCOPY_RELEASE);
				spdk_nvmf_request_zcopy_end(&quic_req->req, false);
				break;
			}
			quic_req->req.length = 0;
			quic_req->req.iovcnt = 0;
			quic_req->fused_failed = false;
			if (quic_req->fused_pair) {
				/* This req was part of a valid fused pair, but failed before it got to
				 * READ_TO_EXECUTE state.  This means we need to fail the other request
				 * in the pair, because it is no longer part of a valid pair.  If the pair
				 * already reached READY_TO_EXECUTE state, we need to kick it.
				 */
				quic_req->fused_pair->fused_failed = true;
				if (quic_req->fused_pair->state == QUIC_REQUEST_STATE_READY_TO_EXECUTE) {
					nvmf_quic_req_process(qtransport, quic_req->fused_pair);
				}
				quic_req->fused_pair = NULL;
			}

			nvmf_quic_req_put(qqpair, quic_req);
			break;
		case QUIC_REQUEST_NUM_STATES:
		default:
			assert(0);
			break;
		}

		if (quic_req->state != prev_state) {
			progress = true;
		}
	} while (quic_req->state != prev_state);
	return progress;
}


/* NVMe-over-QUIC stream receive callback
 * Handles out-of-order frame delivery using 'off' parameter.
 * 
 * Protocol flow (Controller side):
 * 1. 
 * 2. For READ: Receive data at offset 0+, then 16B CQE
 * 3. For WRITE: Receive 8B GRANTs, send data, then 16B CQE
 */
static int
nvme_quic_stream_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
	struct nvme_quic_stream *nvme_stream = stream->data;
	struct spdk_nvmf_quic_req *quic_req = nvme_stream->req;
	struct spdk_nvme_cpl *rsp;

	struct spdk_nvmf_quic_qpair *qqpair = *(struct spdk_nvmf_quic_qpair **)quicly_get_data(stream->conn);
	struct spdk_nvmf_quic_transport *qtransport = SPDK_CONTAINEROF(qqpair->qpair.transport, struct spdk_nvmf_quic_transport, transport);


	ptls_iovec_t stream_data;
	uint16_t offset = 0;

	int rc;

	if(quicly_streambuf_ingress_receive(stream, off, src, len) !=0) return 0;

	stream_data = quicly_streambuf_ingress_get(stream);

	if(stream_data.len == 0) {
		return 0;
	}

	/* Log raw stream buffer at key offsets BEFORE any processing */
	SPDK_DEBUGLOG(nvmf,"RAW STREAM BUFFER: len=%zu, base=%p\n", stream_data.len, stream_data.base);
	if (stream_data.len >= 64) {
		SPDK_DEBUGLOG(nvmf,"  [0-15] (cmd start): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			       ((uint8_t*)stream_data.base)[0], ((uint8_t*)stream_data.base)[1],
			       ((uint8_t*)stream_data.base)[2], ((uint8_t*)stream_data.base)[3],
			       ((uint8_t*)stream_data.base)[4], ((uint8_t*)stream_data.base)[5],
			       ((uint8_t*)stream_data.base)[6], ((uint8_t*)stream_data.base)[7],
			       ((uint8_t*)stream_data.base)[8], ((uint8_t*)stream_data.base)[9],
			       ((uint8_t*)stream_data.base)[10], ((uint8_t*)stream_data.base)[11],
			       ((uint8_t*)stream_data.base)[12], ((uint8_t*)stream_data.base)[13],
			       ((uint8_t*)stream_data.base)[14], ((uint8_t*)stream_data.base)[15]);
	}
	if (stream_data.len >= 80) {
		SPDK_DEBUGLOG(nvmf,"  [64-79] (data start): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			       ((uint8_t*)stream_data.base)[64], ((uint8_t*)stream_data.base)[65],
			       ((uint8_t*)stream_data.base)[66], ((uint8_t*)stream_data.base)[67],
			       ((uint8_t*)stream_data.base)[68], ((uint8_t*)stream_data.base)[69],
			       ((uint8_t*)stream_data.base)[70], ((uint8_t*)stream_data.base)[71],
			       ((uint8_t*)stream_data.base)[72], ((uint8_t*)stream_data.base)[73],
			       ((uint8_t*)stream_data.base)[74], ((uint8_t*)stream_data.base)[75],
			       ((uint8_t*)stream_data.base)[76], ((uint8_t*)stream_data.base)[77],
			       ((uint8_t*)stream_data.base)[78], ((uint8_t*)stream_data.base)[79]);
	}
	if (stream_data.len >= 320) {
		char subnqn_preview[65];
		memcpy(subnqn_preview, (uint8_t*)stream_data.base + 64 + 256, 64);
		subnqn_preview[64] = '\0';
		SPDK_DEBUGLOG(nvmf_quic, "  [64+256=320] subnqn: '%s'\n", subnqn_preview);
	}
	if (stream_data.len >= 576) {
		char hostnqn_preview[65];
		memcpy(hostnqn_preview, (uint8_t*)stream_data.base + 64 + 512, 64);
		hostnqn_preview[64] = '\0';
		SPDK_DEBUGLOG(nvmf_quic, "  [64+512=576] hostnqn: '%s'\n", hostnqn_preview);
	}

	while(offset < stream_data.len) {

		switch (nvme_stream->recv_state) {
			case NVME_QUIC_RECV_STATE_AWAIT_CMD:
				/* Check if we have a complete command (64 bytes) */
				if (stream_data.len - offset < sizeof(struct spdk_nvme_cmd)) {
					SPDK_DEBUGLOG(nvmf_quic, "Incomplete command in buffer: have %zu bytes, need %zu - waiting for more data\n",
						       stream_data.len - offset, sizeof(struct spdk_nvme_cmd));
					return 0; /* Wait for more data */
				}
				
				/* Read only the 64-byte command, don't read data yet */
				SPDK_DEBUGLOG(nvmf_quic, "Reading command from stream: stream_data.len=%zu, offset=%u, first 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
					       stream_data.len, offset,
					       ((uint8_t*)stream_data.base)[offset+0], ((uint8_t*)stream_data.base)[offset+1],
					       ((uint8_t*)stream_data.base)[offset+2], ((uint8_t*)stream_data.base)[offset+3],
					       ((uint8_t*)stream_data.base)[offset+4], ((uint8_t*)stream_data.base)[offset+5],
					       ((uint8_t*)stream_data.base)[offset+6], ((uint8_t*)stream_data.base)[offset+7]);
				quic_req->cmd = *((struct spdk_nvme_cmd *)(stream_data.base + offset));
				
				/* Verify command structure is correctly copied */
				SPDK_DEBUGLOG(nvmf_quic, "Command copied - verifying structure:\n");
				SPDK_DEBUGLOG(nvmf_quic, "  opc=0x%02x, fuse=0x%x, cid=0x%04x\n",
					       quic_req->cmd.opc, quic_req->cmd.fuse, quic_req->cmd.cid);
				SPDK_DEBUGLOG(nvmf_quic, "  nsid=0x%08x\n", quic_req->cmd.nsid);
				SPDK_DEBUGLOG(nvmf_quic, "  cdw10=0x%08x, cdw11=0x%08x, cdw12=0x%08x, cdw13=0x%08x\n",
					       quic_req->cmd.cdw10, quic_req->cmd.cdw11, 
					       quic_req->cmd.cdw12, quic_req->cmd.cdw13);
				SPDK_DEBUGLOG(nvmf_quic, "  SGL type=0x%02x, subtype=0x%02x, length=0x%08x\n",
					       quic_req->cmd.dptr.sgl1.generic.type,
					       quic_req->cmd.dptr.sgl1.generic.subtype,
					       quic_req->cmd.dptr.sgl1.unkeyed.length);

				quicly_streambuf_ingress_shift(stream, sizeof(struct spdk_nvme_cmd));
				offset += sizeof(struct spdk_nvme_cmd);

				/* Re-get stream buffer after shift - base pointer has changed! */
				stream_data = quicly_streambuf_ingress_get(stream);
				offset = 0; /* Reset offset since buffer was shifted */

				/* Detect in-capsule data: if there's data remaining after the command */
				if (stream_data.len > 0) {
					quic_req->has_in_capsule_data = true;
					SPDK_DEBUGLOG(nvmf_quic, "Detected in-capsule data: %zu bytes available\n", stream_data.len);
				}

				/* Process the command to parse SGL and transition to next state */
				nvmf_quic_req_process(qtransport, quic_req);
				
				/* Continue the loop to process any in-capsule data in AWAIT_DATA state */
				continue;
			case NVME_QUIC_RECV_STATE_AWAIT_DATA:
				/* Receive WRITE data */
				SPDK_DEBUGLOG(nvmf_quic, "AWAIT_DATA: stream_data.len=%zu, offset=%u, remaining=%zu, h2c_offset=%u, req.length=%u\n",
					       stream_data.len, offset, stream_data.len - offset, 
					       quic_req->h2c_offset, quic_req->req.length);
				SPDK_DEBUGLOG(nvmf_quic, "AWAIT_DATA: iov_base=%p, stream_data.base=%p, first 16 bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
					       quic_req->req.iov[0].iov_base, stream_data.base,
					       ((uint8_t*)stream_data.base)[offset+0], ((uint8_t*)stream_data.base)[offset+1],
					       ((uint8_t*)stream_data.base)[offset+2], ((uint8_t*)stream_data.base)[offset+3],
					       ((uint8_t*)stream_data.base)[offset+4], ((uint8_t*)stream_data.base)[offset+5],
					       ((uint8_t*)stream_data.base)[offset+6], ((uint8_t*)stream_data.base)[offset+7],
					       ((uint8_t*)stream_data.base)[offset+8], ((uint8_t*)stream_data.base)[offset+9],
					       ((uint8_t*)stream_data.base)[offset+10], ((uint8_t*)stream_data.base)[offset+11],
					       ((uint8_t*)stream_data.base)[offset+12], ((uint8_t*)stream_data.base)[offset+13],
					       ((uint8_t*)stream_data.base)[offset+14], ((uint8_t*)stream_data.base)[offset+15]);
				
				/* Print subnqn at offset 256 and hostnqn at offset 512 */
				if (stream_data.len - offset >= 512 + 64) {
					char subnqn_preview[65], hostnqn_preview[65];
					memcpy(subnqn_preview, (uint8_t*)stream_data.base + offset + 256, 64);
					subnqn_preview[64] = '\0';
					memcpy(hostnqn_preview, (uint8_t*)stream_data.base + offset + 512, 64);
					hostnqn_preview[64] = '\0';
					SPDK_DEBUGLOG(nvmf,"AWAIT_DATA: stream_data subnqn@256='%s', hostnqn@512='%s'\n",
						       subnqn_preview, hostnqn_preview);
				}
				
				/* Sadly, Incoming data should be copied from stream_data_buf to app_buf */
				rc = memcpy((uint8_t *)quic_req->req.iov[0].iov_base + quic_req->h2c_offset,
				       (uint8_t *)stream_data.base + offset,
				       stream_data.len - offset);

				if(rc < 0) {
					SPDK_ERRLOG("Failed to copy data from stream buffer to request buffer\n");
					return rc;
				}

				SPDK_DEBUGLOG(nvmf,"AWAIT_DATA: Copied %zu bytes, new h2c_offset will be %u\n",
					       stream_data.len - offset, quic_req->h2c_offset + (stream_data.len - offset));

				quic_req->h2c_offset += stream_data.len - offset;
				quicly_streambuf_ingress_shift(stream, stream_data.len - offset);
				offset += stream_data.len - offset;
			
				if(quic_req->h2c_offset == quic_req->req.length && quic_req->state == QUIC_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER) {
					/* All data received */
					rsp = &quic_req->req.rsp->nvme_cpl;

					if (spdk_unlikely(rsp->status.sc == SPDK_NVME_SC_COMMAND_TRANSIENT_TRANSPORT_ERROR)) {
						nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_READY_TO_COMPLETE);
					} else {
						nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_READY_TO_EXECUTE);
					}
					nvmf_quic_req_process(qtransport, quic_req);
				}
				break;
			default:
				/* For error handling case, it would be implemented after checking operation */
				break;
		}

	}

	return 0;
}

static void
nvme_quic_stream_on_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
	/* RESET_STREAM received from peer - stream was terminated */
	struct nvme_quic_stream *nvme_stream = stream->data;
	struct spdk_nvmf_quic_req *quic_req = nvme_stream->req;
	
	if (quic_req) {
		/* Handle stream reset - may need to fail the request */
		SPDK_DEBUGLOG(nvmf,"Stream reset with error: %ld\n", err);
	}
}

static struct spdk_nvmf_quic_req *
nvmf_quic_req_get(struct spdk_nvmf_quic_qpair *qqpair)
{
	struct spdk_nvmf_quic_req *quic_req;

	quic_req = TAILQ_FIRST(&qqpair->quic_req_free_queue);
	if (spdk_unlikely(!quic_req)) {
		return NULL;
	}

	memset(&quic_req->rsp, 0, sizeof(quic_req->rsp));
	quic_req->h2c_offset = 0;
	quic_req->has_in_capsule_data = false;
	quic_req->req.raw = 0; /* clear all flags */
	quic_req->req.zcopy_phase = NVMF_ZCOPY_PHASE_NONE;
	quic_req->req.cmd_cb_fn = NULL;

	TAILQ_REMOVE(&qqpair->quic_req_free_queue, quic_req, state_link);
	TAILQ_INSERT_TAIL(&qqpair->quic_req_working_queue, quic_req, state_link);
	qqpair->qpair.queue_depth++;
	nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_NEW);
	return quic_req;
}


/* QUIC stream callbacks table */
static const quicly_stream_callbacks_t nvme_quic_stream_callbacks = {
	nvme_quic_stream_on_destroy,
	quicly_streambuf_egress_shift,  /* Use streambuf functions since we created with quicly_streambuf_create() */
	quicly_streambuf_egress_emit,   /* This properly accesses stream->data->egress */
	nvme_quic_stream_on_send_stop,
	nvme_quic_stream_on_receive,
	nvme_quic_stream_on_receive_reset,
};


static quicly_error_t nvmf_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
	int ret;
	quicly_conn_t *conn;
	struct spdk_nvmf_quic_qpair *qqpair;
	struct spdk_nvmf_quic_req *quic_req;
	struct nvme_quic_stream *nvme_stream;

	/* Get the qqpair info from the new stream */
	conn = stream->conn;
	qqpair = *(struct spdk_nvmf_quic_qpair **)quicly_get_data(conn);

	/* Create new quic req */
	quic_req = nvmf_quic_req_get(qqpair);
	if (!quic_req) {
		return -1;
	}

	/* Create streambuf - this allocates stream->data with size of nvme_quic_stream */
	ret = quicly_streambuf_create(stream, sizeof(struct nvme_quic_stream));
	if (ret != 0) {
		return ret;
	}

	/* stream->data now points to the allocated nvme_quic_stream (with streambuf_t at offset 0) */
	nvme_stream = (struct nvme_quic_stream *)stream->data;
	
	/* Initialize the extended structure fields */
	nvme_stream->quic_stream = stream;
	nvme_stream->req = quic_req;
	nvme_stream->qpair = qqpair;
	nvme_stream->recv_state = NVME_QUIC_RECV_STATE_AWAIT_CMD;  /* Start waiting for command */

	/* Link the request to the stream */
	quic_req->stream = nvme_stream;

	/* Initialize stream callbacks */
	stream->callbacks = &nvme_quic_stream_callbacks;

	return 0;
}

/* Stream open callback structure for server side */
static quicly_stream_open_t nvmf_quic_stream_open = {&nvmf_on_stream_open};

static void
nvmf_quic_poll_group_flush(struct spdk_nvmf_quic_poll_group *qgroup)
{
	struct spdk_nvmf_quic_qpair *qqpair, *tmp;
	int count = 0;
	const int MAX_ITERATIONS = 128;  /* Safety limit */

	TAILQ_FOREACH_SAFE(qqpair, &qgroup->qpairs, link, tmp) {
		/* Unconditional flush - send for all qpairs */
		_nvmf_quic_send_pending(qqpair);
		
		count++;
		if (count >= MAX_ITERATIONS) {
			SPDK_ERRLOG("WARNING: Hit maximum iteration limit (%d), breaking to prevent infinite loop!\n", MAX_ITERATIONS);
			SPDK_ERRLOG("This indicates a corrupted qpair list - investigate!\n");
			break;
		}
	}
}

/* Send pending data only for qpairs that have queued responses OR need to send ACKs/retransmissions */
static void
nvmf_quic_poll_group_send_pending(struct spdk_nvmf_quic_poll_group *qgroup)
{
	struct spdk_nvmf_quic_qpair *qqpair, *tmp;
	int64_t timeout;
	struct spdk_nvmf_quic_transport *qtransport = SPDK_CONTAINEROF(qgroup->group.transport, struct spdk_nvmf_quic_transport, transport);
	quicly_context_t *ctx = qtransport->quic_ctx;

	// SPDK_ERRLOG("SERVER: poll_group_send_pending called #%lu at %lu ms\n", call_count, now_ms);

	TAILQ_FOREACH_SAFE(qqpair, &qgroup->qpairs, link, tmp) {
		//_nvmf_quic_send_pending(qqpair);

		if(quicly_get_first_timeout(qqpair->conn) <= ctx->now->cb(ctx->now)) {
			SPDK_DEBUGLOG(nvmf,"poll_group_send_pending: Sending pending data for qpair %p (conn=%p) due to timeout\n", qqpair, qqpair->conn);
			_nvmf_quic_send_pending(qqpair);
		}
	}
}


/* UDP datagram receive callback for QUIC connections */
static void
nvmf_quic_datagram_cb(void *arg, struct spdk_sock_group *group, struct spdk_sock *sock)
{
	struct spdk_nvmf_quic_poll_group *qgroup = arg;
	struct spdk_nvmf_quic_qpair *qqpair;
	struct spdk_nvmf_quic_transport *qtransport;
	int rc;
	struct sockaddr_storage local_addr, remote_addr;
	socklen_t local_len, remote_len;

	SPDK_DEBUGLOG(nvmf,"nvmf_quic_datagram_cb: CALLBACK INVOKED! sock=%p, group=%p, qgroup=%p\n",
	              sock, group, qgroup);

	enum nvme_quic_stream_recv_state prev_state;
	
	qtransport = SPDK_CONTAINEROF(qgroup->group.transport, struct spdk_nvmf_quic_transport, transport);
	/* Use shared context from transport */
	quicly_context_t *ctx = qtransport->quic_ctx;

	quicly_address_t local, remote;
	uint8_t buf[SPDK_NVME_QUIC_MAX_UDP_DATAGRAM_SIZE];
	ssize_t rret;
	struct msghdr msg;
	struct iovec iov;
	
	/* Initialize address structures */
	memset(&local, 0, sizeof(local));
	memset(&remote, 0, sizeof(remote));
	memset(&msg, 0, sizeof(msg));
	
	/* Setup for recvmsg to get source address */
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &remote.sa;
	msg.msg_namelen = sizeof(remote);
	
	/* Local address - server listening on 127.0.0.1:4420 */
	local.sa.sa_family = AF_INET;
	local.sin.sin_family = AF_INET;
	local.sin.sin_port = htons(4420);
	local.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	SPDK_DEBUGLOG(nvmf,"Received UDP datagram on QUIC poll group %p\n", qgroup);

	if(sock == NULL) {
		SPDK_ERRLOG("Invalid socket in QUIC datagram callback\n");
		return;
	}

	/* Read all incoming UDP datagrams for this loop */
	while(1) {
		/* Receive packet and extract source address */
		rc = nvme_quic_read_data_with_msghdr(sock, sizeof(buf), buf, &msg);
		SPDK_DEBUGLOG(nvmf_quic,"nvme_quic_read_data_with_msghdr returned rc=%d\n", rc);
		if (rc > 0) {
			/* Log the client address we received from */
			char remote_str[64];
			uint16_t remote_port = 0;
			if (remote.sa.sa_family == AF_INET) {
				inet_ntop(AF_INET, &remote.sin.sin_addr, remote_str, sizeof(remote_str));
				remote_port = ntohs(remote.sin.sin_port);
			}
			SPDK_DEBUGLOG(nvmf_quic,"Received %d bytes from client %s:%u\n", rc, remote_str, remote_port);
		}
		if (rc <= 0)
			break;
		
		size_t off = 0;
		quicly_conn_t *newly_created_conn = NULL; /* Track newly created connection for coalesced packets */
		
		while(off != rc) {
			quicly_decoded_packet_t packet;
			if(quicly_decode_packet(ctx, &packet, buf, rc, &off) == SIZE_MAX) {
				SPDK_ERRLOG("Failed to decode QUIC packet\n");
				break;
			}

			if(QUICLY_PACKET_IS_LONG_HEADER(packet.octets.base[0])) {
				const char *pkt_type_str = "UNKNOWN";
				uint8_t pkt_type = packet.octets.base[0] & QUICLY_PACKET_TYPE_BITMASK;
				if (QUICLY_PACKET_IS_INITIAL(packet.octets.base[0])) {
					pkt_type_str = "INITIAL";
				} else if (pkt_type == (QUICLY_PACKET_TYPE_HANDSHAKE & QUICLY_PACKET_TYPE_BITMASK)) {
					pkt_type_str = "HANDSHAKE";
				} else if (pkt_type == (QUICLY_PACKET_TYPE_0RTT & QUICLY_PACKET_TYPE_BITMASK)) {
					pkt_type_str = "0-RTT";
				} else if (pkt_type == (QUICLY_PACKET_TYPE_RETRY & QUICLY_PACKET_TYPE_BITMASK)) {
					pkt_type_str = "RETRY";
				}
				// Print first 8 bytes of DCID and SCID
				if (packet.cid.src.len > 0) {
					SPDK_DEBUGLOG(nvmf,"Long header packet: type=%s (0x%02x), version=0x%x, "
								"DCID=%02x%02x%02x%02x%02x%02x%02x%02x (len=%u), "
								"SCID=%02x%02x%02x%02x%02x%02x%02x%02x (len=%u), off=%zu\n",
								pkt_type_str, pkt_type, packet.version,
								packet.cid.dest.encrypted.base[0], packet.cid.dest.encrypted.base[1],
								packet.cid.dest.encrypted.base[2], packet.cid.dest.encrypted.base[3],
								packet.cid.dest.encrypted.base[4], packet.cid.dest.encrypted.base[5],
								packet.cid.dest.encrypted.base[6], packet.cid.dest.encrypted.base[7],
								packet.cid.dest.encrypted.len,
								packet.cid.src.base[0], packet.cid.src.base[1],
								packet.cid.src.base[2], packet.cid.src.base[3],
								packet.cid.src.base[4], packet.cid.src.base[5],
								packet.cid.src.base[6], packet.cid.src.base[7],
								packet.cid.src.len, off);
				} else {
					SPDK_DEBUGLOG(nvmf,"Long header packet: type=%s (0x%02x), version=0x%x, "
								"DCID=%02x%02x%02x%02x%02x%02x%02x%02x (len=%u), "
								"SCID_len=0, off=%zu\n",
								pkt_type_str, pkt_type, packet.version,
								packet.cid.dest.encrypted.base[0], packet.cid.dest.encrypted.base[1],
								packet.cid.dest.encrypted.base[2], packet.cid.dest.encrypted.base[3],
								packet.cid.dest.encrypted.base[4], packet.cid.dest.encrypted.base[5],
								packet.cid.dest.encrypted.base[6], packet.cid.dest.encrypted.base[7],
								packet.cid.dest.encrypted.len, off);
				}
				
				if(packet.version != 0 && !quicly_is_supported_version(packet.version)) {
					SPDK_DEBUGLOG(nvmf,"Received unsupported QUIC version: 0x%08x\n", packet.version);
					// just ignore unsupported version for now
					break;
				}

				if(packet.cid.dest.encrypted.len > QUICLY_MAX_CID_LEN_V1 || packet.cid.src.len > QUICLY_MAX_CID_LEN_V1) {
					SPDK_ERRLOG("Received QUIC packet with invalid CID length\n");
					break;
				}
			}

			/* For vailed packet's process */
			quicly_conn_t *conn = NULL;

			/* hash search like tcp's established hash table */
			qqpair = nvmf_quic_find_qpair_by_decoded_cid(qgroup, &packet);
			SPDK_DEBUGLOG(nvmf,"nvmf_quic_find_qpair_by_decoded_cid returned qqpair=%p\n", qqpair);
			if(qqpair) {
				conn = qqpair->conn;
				quicly_receive(conn, &local, &remote, &packet);
				newly_created_conn = conn; /* Update in case of multiple packets */
				continue;
			}
			
			if (QUICLY_PACKET_IS_LONG_HEADER(packet.octets.base[0]) && 
			    QUICLY_PACKET_IS_INITIAL(packet.octets.base[0]) &&
			    newly_created_conn == NULL) {
				/* New Connection request - INITIAL packet */
				/* Token validation if it exists */
				quicly_address_token_plaintext_t *token = NULL, token_buf;
				if(packet.token.len != 0) {
					const char *err_desc = NULL;
					quicly_error_t ret = quicly_decrypt_address_token(qtransport->address_token_aead.dec, 
										  &token_buf, packet.token.base,
										  packet.token.len, 0, &err_desc);
					/* Use quicly_spec_context for token validation (only needs timing info) */
					if(ret == 0 && quicly_validate_token(&quicly_spec_context, &remote.sa, packet.cid.dest.encrypted, packet.cid.src, &token_buf, &err_desc)) {
						token = &token_buf;
					} else {
						SPDK_DEBUGLOG(nvmf,"Invalid address token: %s\n", err_desc ? err_desc : "decryption failed");
					}
					
				}

				/* Debug: verify context state before quicly_accept */
				SPDK_DEBUGLOG(nvmf,"Before quicly_accept: quic_ctx=%p, tls=%p, cipher_suites=%p\n",
					       qtransport->quic_ctx, qtransport->quic_ctx ? qtransport->quic_ctx->tls : NULL,
					       qtransport->quic_ctx && qtransport->quic_ctx->tls ? qtransport->quic_ctx->tls->cipher_suites : NULL);
				if (qtransport->quic_ctx && qtransport->quic_ctx->tls && qtransport->quic_ctx->tls->cipher_suites) {
					SPDK_DEBUGLOG(nvmf,"  cipher_suites[0]=%p\n", qtransport->quic_ctx->tls->cipher_suites[0]);
				}
				if (qtransport->quic_ctx && qtransport->quic_ctx->tls) {
					SPDK_DEBUGLOG(nvmf,"  PSK identity=%.*s, secret_len=%zu\n",
						       (int)qtransport->quic_ctx->tls->pre_shared_key.identity.len,
						       qtransport->quic_ctx->tls->pre_shared_key.identity.base,
						       qtransport->quic_ctx->tls->pre_shared_key.secret.len);
				}

				/* accept new connection using qpair's context */
				SPDK_DEBUGLOG(nvmf,"About to call quicly_accept with next_cid: master_id=%lu, path_id=%lu, thread_id=%u\n",
					       qtransport->next_cid.master_id, qtransport->next_cid.path_id, qtransport->next_cid.thread_id);
				SPDK_DEBUGLOG(nvmf,"  cid_encryptor=%p\n", qtransport->quic_ctx->cid_encryptor);
				quicly_error_t ret = quicly_accept(&conn, qtransport->quic_ctx, &local.sa, &remote.sa,
								  &packet, token, &qtransport->next_cid, NULL, NULL);
				if(ret == 0) {
					SPDK_DEBUGLOG(nvmf,"Accepted new QUIC connection: conn=%p\n", conn);			
					
					/* Create new qpair first with its own contexts */
					qqpair = nvmf_quic_qpair_create(qgroup, conn);
					if(qqpair == NULL) {
						SPDK_ERRLOG("Failed to create QUIC qpair for new connection\n");
						continue;  /* Try next packet */
					}

					/* QUIC multiplexes connections over the same UDP socket */
					qqpair->sock = sock;
					
					/* Populate target (local) and initiator (remote) addresses from socket */
					if (local.sa.sa_family == AF_INET) {
						inet_ntop(AF_INET, &local.sin.sin_addr, qqpair->target_addr, sizeof(qqpair->target_addr));
						qqpair->target_port = ntohs(local.sin.sin_port);
					} else if (local.sa.sa_family == AF_INET6) {
						inet_ntop(AF_INET6, &local.sin6.sin6_addr, qqpair->target_addr, sizeof(qqpair->target_addr));
						qqpair->target_port = ntohs(local.sin6.sin6_port);
					}
					
					if (remote.sa.sa_family == AF_INET) {
						inet_ntop(AF_INET, &remote.sin.sin_addr, qqpair->initiator_addr, sizeof(qqpair->initiator_addr));
						qqpair->initiator_port = ntohs(remote.sin.sin_port);
					} else if (remote.sa.sa_family == AF_INET6) {
						inet_ntop(AF_INET6, &remote.sin6.sin6_addr, qqpair->initiator_addr, sizeof(qqpair->initiator_addr));
						qqpair->initiator_port = ntohs(remote.sin6.sin6_port);
					}
					
					/* Save this connection for processing coalesced packets in the same datagram */
					newly_created_conn = conn;

					*quicly_get_data(conn) = qqpair;
					
					/* Check CID immediately after accept - print all CIDs */
					struct _st_quicly_conn_public_t *conn_pub_dbg = (struct _st_quicly_conn_public_t *)conn;
					SPDK_DEBUGLOG(nvmf,"After quicly_accept - CID information:\n");
					SPDK_DEBUGLOG(nvmf,"  original_dcid.len=%u\n", conn_pub_dbg->original_dcid.len);
					if (conn_pub_dbg->original_dcid.len > 0) {
						SPDK_DEBUGLOG(nvmf,"  original_dcid.cid=%02x%02x%02x%02x%02x%02x%02x%02x\n",
							       conn_pub_dbg->original_dcid.cid[0], conn_pub_dbg->original_dcid.cid[1],
							       conn_pub_dbg->original_dcid.cid[2], conn_pub_dbg->original_dcid.cid[3],
							       conn_pub_dbg->original_dcid.cid[4], conn_pub_dbg->original_dcid.cid[5],
							       conn_pub_dbg->original_dcid.cid[6], conn_pub_dbg->original_dcid.cid[7]);
					}
					
					SPDK_DEBUGLOG(nvmf,"  local.cid_set._size=%zu\n", conn_pub_dbg->local.cid_set._size);
					if (conn_pub_dbg->local.cid_set._size > 0) {
						SPDK_DEBUGLOG(nvmf,"  local.cid_set.cids[0].cid.len=%u\n",
							       conn_pub_dbg->local.cid_set.cids[0].cid.len);
						if (conn_pub_dbg->local.cid_set.cids[0].cid.len > 0) {
							SPDK_DEBUGLOG(nvmf,"  local.cid_set.cids[0].cid=%02x%02x%02x%02x%02x%02x%02x%02x\n",
								       conn_pub_dbg->local.cid_set.cids[0].cid.cid[0],
								       conn_pub_dbg->local.cid_set.cids[0].cid.cid[1],
								       conn_pub_dbg->local.cid_set.cids[0].cid.cid[2],
								       conn_pub_dbg->local.cid_set.cids[0].cid.cid[3],
								       conn_pub_dbg->local.cid_set.cids[0].cid.cid[4],
								       conn_pub_dbg->local.cid_set.cids[0].cid.cid[5],
								       conn_pub_dbg->local.cid_set.cids[0].cid.cid[6],
								       conn_pub_dbg->local.cid_set.cids[0].cid.cid[7]);
						}
					}
					
					SPDK_DEBUGLOG(nvmf,"  local.long_header_src_cid.len=%u\n", conn_pub_dbg->local.long_header_src_cid.len);
					if (conn_pub_dbg->local.long_header_src_cid.len > 0) {
						SPDK_DEBUGLOG(nvmf,"  local.long_header_src_cid=%02x%02x%02x%02x%02x%02x%02x%02x\n",
							       conn_pub_dbg->local.long_header_src_cid.cid[0],
							       conn_pub_dbg->local.long_header_src_cid.cid[1],
							       conn_pub_dbg->local.long_header_src_cid.cid[2],
							       conn_pub_dbg->local.long_header_src_cid.cid[3],
							       conn_pub_dbg->local.long_header_src_cid.cid[4],
							       conn_pub_dbg->local.long_header_src_cid.cid[5],
							       conn_pub_dbg->local.long_header_src_cid.cid[6],
							       conn_pub_dbg->local.long_header_src_cid.cid[7]);
					}

					nvmf_quic_add_qpair_to_hash(qgroup, qqpair, conn);
					/* Don't add to hash yet - CID not set up until after first packet is processed */
					++qtransport->next_cid.master_id;
					
					/* Add qpair to poll group's list so it can be flushed */
					/* Check if already in a group to prevent double-insertion */
					if (qqpair->group != NULL) {
						SPDK_ERRLOG("WARNING: qpair %p already has group %p, not adding again!\n", 
						           qqpair, qqpair->group);
					} else {
						qqpair->group = qgroup;
						TAILQ_INSERT_TAIL(&qgroup->qpairs, qqpair, link);
						SPDK_DEBUGLOG(nvmf,"Added qpair %p to poll group qpairs list\n", qqpair);
						nvmf_quic_qpair_set_state(qqpair, NVMF_QUIC_QPAIR_STATE_RUNNING);
					}
				} else {
					SPDK_ERRLOG("quicly_accept failed: %d (0x%x)\n", ret, ret);
					/* Clean up qpair if accept failed - transport contexts are shared, don't free them */
					free(qqpair);
				}
			} else if (newly_created_conn != NULL) {
				/* Coalesced packet (0-RTT, HANDSHAKE, etc.) belonging to newly created connection */
				SPDK_DEBUGLOG(nvmf,"Processing coalesced packet with newly_created_conn=%p\n", newly_created_conn);
				quicly_error_t recv_ret = quicly_receive(newly_created_conn, &remote, &local, &packet);
				if (recv_ret != 0) {
					SPDK_ERRLOG("Failed to process coalesced packet: %d (0x%x)\n", recv_ret, recv_ret);
				}
			} else {
				/* Non-INITIAL packet without existing connection - this shouldn't happen */
				SPDK_ERRLOG("Received non-INITIAL packet without existing connection, ignoring\n");
			}
		}
		
		/* The CID is not populated yet at this point. It will be populated after
		 * quicly_send() is called during the flush operation. The qpair will be
		 * added to the hash table in _nvmf_quic_send_pending(). */
	}


	/* Flush every connection */
	SPDK_DEBUGLOG(nvmf,"Flushing QUIC poll group %p\n", qgroup);
	SPDK_DEBUGLOG(nvmf,"About to call nvmf_quic_poll_group_flush\n");
	nvmf_quic_poll_group_flush(qgroup);
	SPDK_DEBUGLOG(nvmf_quic, "Returned from nvmf_quic_poll_group_flush\n");

	SPDK_DEBUGLOG(nvmf_quic, "----------- CB Received UDP datagram on qgroup %p\n", qgroup);
}

static void
nvmf_quic_qpair_disconnect(struct spdk_nvmf_quic_qpair *qqpair)
{
	SPDK_DEBUGLOG(nvmf,"Disconnecting qpair %p\n", qqpair);

	spdk_trace_record(TRACE_QUIC_QP_DISCONNECT, qqpair->qpair.trace_id, 0, 0);
	if (qqpair->state <= NVMF_QUIC_QPAIR_STATE_RUNNING) {
		nvmf_quic_qpair_set_state(qqpair, NVMF_QUIC_QPAIR_STATE_EXITING);
		assert(qqpair->recv_state == NVME_QUIC_RECV_STATE_ERROR);

		/* This will end up calling nvmf_quic_close_qpair */
		spdk_nvmf_qpair_disconnect(&qqpair->qpair);
	}
}


static void
nvmf_quic_qpair_process(struct spdk_nvmf_quic_qpair *qqpair)
{
	int rc;
	struct spdk_nvmf_quic_poll_group *qgroup;
	qgroup = qqpair->group;

	assert(qqpair != NULL);

	nvmf_quic_datagram_cb(qgroup, qgroup->sock_group, qqpair->sock);
}

// static void
// nvmf_quic_sock_cb(void *arg, struct spdk_sock_group *group, struct spdk_sock *sock)
// {
// 	struct spdk_nvmf_quic_qpair *qqpair = arg;

// 	nvmf_quic_qpair_process(qqpair);
// }

static void
nvmf_quic_poll_group_add_port(void *ctx)
{
	struct nvmf_quic_port_create_ctx *create_ctx = ctx;
	struct spdk_nvmf_quic_port *port = create_ctx->port;
	struct spdk_nvmf_quic_transport *qtransport = create_ctx->qtransport;
	struct spdk_nvmf_quic_poll_group *qgroup;
	struct spdk_sock *udp_sock;
	struct spdk_sock_opts opts;
	struct spdk_sock_impl_opts impl_opts;
	size_t impl_opts_size = sizeof(impl_opts);
	int trsvcid_int;
	int rc;

	free(create_ctx);

	/* Get this thread's QUIC poll group by iterating the transport's poll groups
	 * and matching against the current thread */
	qgroup = NULL;
	TAILQ_FOREACH(qgroup, &qtransport->poll_groups, link) {
		if (qgroup->group.group->thread == spdk_get_thread()) {
			break;
		}
	}
	
	if (!qgroup) {
		SPDK_ERRLOG("Failed to find poll group for current thread\n");
		return;
	}

	trsvcid_int = nvmf_quic_trsvcid_to_int(port->trid->trsvcid);
	if (trsvcid_int < 0) {
		SPDK_ERRLOG("Invalid trsvcid '%s'\n", port->trid->trsvcid);
		return;
	}

	/* Setup socket options */
	opts.opts_size = sizeof(opts);
	spdk_sock_get_default_opts(&opts);
	opts.priority = qtransport->quic_opts.sock_priority;
	opts.ack_timeout = qtransport->transport.opts.ack_timeout;

	if (port->sock_impl_name) {
		spdk_sock_impl_get_opts(port->sock_impl_name, &impl_opts, &impl_opts_size);

		if (port->secure_channel && !strncmp("ssl", port->sock_impl_name, 3)) {
			impl_opts.tls_version = SPDK_TLS_VERSION_1_3;
			impl_opts.get_key = quic_sock_get_key;
			impl_opts.get_key_ctx = qtransport;
			impl_opts.tls_cipher_suites = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256";
		}

		opts.impl_opts = &impl_opts;
		opts.impl_opts_size = sizeof(impl_opts);
	}


	/* Create UDP socket with SO_REUSEPORT for this reactor */
	udp_sock = spdk_sock_listen_ext(port->trid->traddr, trsvcid_int, 
					port->sock_impl_name, &opts);
	if (udp_sock == NULL) {
		SPDK_ERRLOG("spdk_sock_listen_ext failed for addr='%s' port='%s' on reactor %u\n",
			    port->trid->traddr, port->trid->trsvcid, spdk_env_get_current_core());
		return;
	}

	/* Register socket to the transport's listen_sock_group (polled by nvmf_quic_accept) */
	SPDK_DEBUGLOG(nvmf,"Adding UDP socket %p to qtransport->listen_sock_group=%p on reactor %u\n",
	              udp_sock, qtransport->listen_sock_group, spdk_env_get_current_core());
	rc = spdk_sock_group_add_sock(qgroup->sock_group, udp_sock,
				      nvmf_quic_datagram_cb, qgroup);
	if (rc < 0) {
		SPDK_ERRLOG("spdk_sock_group_add_sock failed for addr='%s' port='%s' on reactor %u\n",
			    port->trid->traddr, port->trid->trsvcid, spdk_env_get_current_core());
		spdk_sock_close(&udp_sock);
		return;
	}

	SPDK_DEBUGLOG(nvmf,"Created UDP socket for %s:%s on reactor %u\n",
		      port->trid->traddr, port->trid->trsvcid, spdk_env_get_current_core());
}

static int
nvmf_quic_listen(struct spdk_nvmf_transport *transport, const struct spdk_nvme_transport_id *trid,
		 struct spdk_nvmf_listen_opts *listen_opts)
{
	struct spdk_nvmf_quic_transport *qtransport;
	struct spdk_nvmf_quic_port *port;
	struct spdk_nvmf_poll_group *pg;
	struct nvmf_quic_port_create_ctx *create_ctx;
	const char *sock_impl_name = NULL;
	int trsvcid_int;

	if (!strlen(trid->trsvcid)) {
		SPDK_ERRLOG("trsvcid is required for QUIC transport\n");
		return -EINVAL;
	}
	
	qtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_quic_transport, transport);

	/* Validate port number */
	trsvcid_int = nvmf_quic_trsvcid_to_int(trid->trsvcid);
	if (trsvcid_int < 0) {
		SPDK_ERRLOG("Invalid trsvcid '%s'\n", trid->trsvcid);
		return -EINVAL;
	}

	/* Allocate port structure to save configuration */
	port = calloc(1, sizeof(*port));
	if (!port) {
		SPDK_ERRLOG("Failed to allocate memory for QUIC port\n");
		return -ENOMEM;
	}

	port->trid = trid;
	port->transport = transport;
	port->secure_channel = listen_opts->secure_channel;

	/* Handle secure channel requirements */
	if (listen_opts->secure_channel) {
		if (listen_opts->sock_impl && strncmp("ssl", listen_opts->sock_impl, strlen(listen_opts->sock_impl))) {
			SPDK_ERRLOG("QUIC transport only supports ssl socket implementation when secure_channel is enabled\n");
			free(port);
			return -EINVAL;
		}
		sock_impl_name = "ssl";
		if (!g_tls_log) {
			SPDK_DEBUGLOG(nvmf,"Enabling TLS logging for QUIC transport\n");
			g_tls_log = true;
		}
	} else if (listen_opts->sock_impl) {
		sock_impl_name = listen_opts->sock_impl;
	}

	port->sock_impl_name = sock_impl_name;

	/* Add port to transport's port list */
	TAILQ_INSERT_TAIL(&qtransport->ports, port, link);

	SPDK_DEBUGLOG(nvmf,"QUIC Transport configured to listen on %s:%s\n", trid->traddr, trid->trsvcid);

	/* Send message to all existing poll groups to create UDP sockets */
	pthread_mutex_lock(&transport->tgt->mutex);
	TAILQ_FOREACH(pg, &transport->tgt->poll_groups, link) {
		create_ctx = calloc(1, sizeof(*create_ctx));
		if (!create_ctx) {
			SPDK_ERRLOG("Failed to allocate context for poll group message\n");
			pthread_mutex_unlock(&transport->tgt->mutex);
			/* Continue anyway - other reactors may succeed */
			continue;
		}

		create_ctx->port = port;
		create_ctx->qtransport = qtransport;

		spdk_thread_send_msg(pg->thread, nvmf_quic_poll_group_add_port, create_ctx);
	}
	pthread_mutex_unlock(&transport->tgt->mutex);

	return 0;
}

/* Message handler to remove UDP socket on a reactor thread */
static void
nvmf_quic_poll_group_remove_port(void *ctx)
{
	struct nvmf_quic_port_create_ctx *create_ctx = ctx;
	struct spdk_nvmf_quic_port *port = create_ctx->port;
	struct spdk_nvmf_quic_transport *qtransport = create_ctx->qtransport;
	struct spdk_nvmf_quic_poll_group *qgroup;

	free(create_ctx);

	/* Get this thread's QUIC poll group by iterating the transport's poll groups
	 * and matching against the current thread */
	qgroup = NULL;
	TAILQ_FOREACH(qgroup, &qtransport->poll_groups, link) {
		if (qgroup->group.group->thread == spdk_get_thread()) {
			break;
		}
	}
	
	if (!qgroup) {
		SPDK_ERRLOG("Failed to find poll group for current thread\n");
		return;
	}

	/* TODO: Find and remove the UDP socket for this port from qgroup->sock_group
	 * Currently we don't track individual sockets, so we can't remove them.
	 * Options:
	 * 1. Track sockets in poll group with a list (RECOMMENDED)
	 * 2. Iterate sock_group to find matching socket
	 * 3. Store socket reference in port (but that requires per-reactor storage)
	 */

	SPDK_DEBUGLOG(nvmf,"Removed UDP socket for %s:%s on reactor %u\n",
		      port->trid->traddr, port->trid->trsvcid, spdk_env_get_current_core());
}

static void
nvmf_quic_stop_listen(struct spdk_nvmf_transport *transport,
		     const struct spdk_nvme_transport_id *trid)
{
	struct spdk_nvmf_quic_transport *qtransport;
	struct spdk_nvmf_quic_port *port;
	struct spdk_nvmf_poll_group *pg;
	struct nvmf_quic_port_create_ctx *create_ctx;

	qtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_quic_transport, transport);

	SPDK_DEBUGLOG(nvmf,"Removing listen address %s port %s\n",
		      trid->traddr, trid->trsvcid);

	port = nvmf_quic_find_port(qtransport, trid);
	if (!port) {
		return;
	}

	/* Send message to all poll groups to remove their UDP sockets */
	pthread_mutex_lock(&transport->tgt->mutex);
	TAILQ_FOREACH(pg, &transport->tgt->poll_groups, link) {
		create_ctx = calloc(1, sizeof(*create_ctx));
		if (!create_ctx) {
			SPDK_ERRLOG("Failed to allocate context for poll group message\n");
			continue;
		}

		create_ctx->port = port;
		create_ctx->qtransport = qtransport;

		spdk_thread_send_msg(pg->thread, nvmf_quic_poll_group_remove_port, create_ctx);
	}
	pthread_mutex_unlock(&transport->tgt->mutex);

	/* Remove port from list */
	TAILQ_REMOVE(&qtransport->ports, port, link);
	/* Note: Can't free port immediately as reactor threads still reference it.
	 * Proper solution needs completion callback. For now, small memory leak on stop_listen. */
}
/* PSK selection callback for server TLS - called during client hello */
static int
nvmf_quic_on_client_hello_cb(ptls_on_client_hello_t *self, ptls_t *tls,
			     ptls_on_client_hello_parameters_t *params)
{
	struct spdk_nvmf_quic_transport *qtransport = SPDK_CONTAINEROF(self, struct spdk_nvmf_quic_transport, on_client_hello_cb);
	struct quic_psk_entry *entry;
	size_t i;
	
	/* If PSK identities are offered by client, find matching PSK in our list */
	if (params->psk_identities.count > 0) {
		SPDK_DEBUGLOG(nvmf,"Client offered %zu PSK identities\n", params->psk_identities.count);
		
		for (i = 0; i < params->psk_identities.count; i++) {
			ptls_iovec_t client_identity = params->psk_identities.list[i].identity;
			
			SPDK_DEBUGLOG(nvmf,"  PSK identity[%zu]: '%.*s'\n", i,
				       (int)client_identity.len, client_identity.base);
			
			TAILQ_FOREACH(entry, &qtransport->psks, link) {
				if (strlen(entry->pskid) == client_identity.len &&
				    memcmp(entry->pskid, client_identity.base, client_identity.len) == 0) {
					/* Found matching PSK - set it in TLS context for this connection */
					qtransport->tls_ctx->pre_shared_key.identity.base = (uint8_t *)entry->pskid;
					qtransport->tls_ctx->pre_shared_key.identity.len = strlen(entry->pskid);
					qtransport->tls_ctx->pre_shared_key.secret.base = entry->psk;
					qtransport->tls_ctx->pre_shared_key.secret.len = entry->psk_size;
					
					if (entry->psk_size == 32) {
						qtransport->tls_ctx->pre_shared_key.hash = &ptls_openssl_sha256;
					} else if (entry->psk_size == 48) {
						qtransport->tls_ctx->pre_shared_key.hash = &ptls_openssl_sha384;
					}
					
					SPDK_DEBUGLOG(nvmf,"Matched PSK for identity '%s', secret_len=%u\n", 
						       entry->pskid, entry->psk_size);
					return 0;
				}
			}
		}
		
		SPDK_ERRLOG("No matching PSK found for any of %zu client identities\n", 
			    params->psk_identities.count);
		return PTLS_ALERT_UNKNOWN_PSK_IDENTITY;
	}
	
	return 0;
}

static struct spdk_nvmf_transport *
nvmf_quic_create(struct spdk_nvmf_transport_opts *opts)
{
	struct spdk_nvmf_quic_transport *qtransport;
	uint32_t sge_count;
	uint32_t min_shared_buffers;
	int rc;
	uint64_t period;

	qtransport = calloc(1, sizeof(*qtransport));
	if(!qtransport) {
		return NULL;
	}

	TAILQ_INIT(&qtransport->ports);
	TAILQ_INIT(&qtransport->poll_groups);
	TAILQ_INIT(&qtransport->psks);

	qtransport->transport.ops = &spdk_nvmf_transport_quic;

	qtransport->quic_opts.c2h_success = true;
	qtransport->quic_opts.sock_priority = SPDK_NVMF_QUIC_DEFAULT_SOCK_PRIORITY;
	qtransport->quic_opts.control_msg_num = SPDK_NVMF_QUIC_DEFAULT_CONTROL_MSG_NUM;
	if(opts->transport_specific != NULL && spdk_json_decode_object_relaxed(opts->transport_specific,
							     quic_transport_opts_decoder,
							     SPDK_COUNTOF(quic_transport_opts_decoder), &qtransport->quic_opts)) {
		SPDK_ERRLOG("Failed to decode QUIC transport options\n");
		free(qtransport);
		return NULL;
	}

	SPDK_NOTICELOG("*** QUIC Transport Init ***\n");

	SPDK_INFOLOG(nvmf_quic, "*** QUIC Transport Init ***\n"
		     "  Transport opts:  max_ioq_depth=%d, max_io_size=%d,\n"
		     "  max_io_qpairs_per_ctrlr=%d, io_unit_size=%d,\n"
		     "  in_capsule_data_size=%d, max_aq_depth=%d\n"
		     "  num_shared_buffers=%d, c2h_success=%d,\n"
		     "  dif_insert_or_strip=%d, sock_priority=%d\n"
		     "  abort_timeout_sec=%d, control_msg_num=%hu\n"
		     "  ack_timeout=%d\n",
		     opts->max_queue_depth,
		     opts->max_io_size,
		     opts->max_qpairs_per_ctrlr - 1,
		     opts->io_unit_size,
		     opts->in_capsule_data_size,
		     opts->max_aq_depth,
		     opts->num_shared_buffers,
		     qtransport->quic_opts.c2h_success,
		     opts->dif_insert_or_strip,
		     qtransport->quic_opts.sock_priority,
		     opts->abort_timeout_sec,
		     qtransport->quic_opts.control_msg_num,
		     opts->ack_timeout);
	
	if(qtransport->quic_opts.sock_priority > SPDK_NVMF_QUIC_DEFAULT_SOCK_PRIORITY) {
		SPDK_ERRLOG("sock_priority %d is too high, max is %d\n",
			    qtransport->quic_opts.sock_priority,
			    SPDK_NVMF_QUIC_DEFAULT_SOCK_PRIORITY);
		free(qtransport);
		return NULL;
	}

	if(qtransport->quic_opts.control_msg_num == 0 && opts->in_capsule_data_size < SPDK_NVME_QUIC_IN_CAPSULE_DATA_MAX_SIZE) {
		SPDK_WARNLOG("control_msg_num is 0, but in_capsule_data_size %d is less than max %d. "
			     "Setting control_msg_num to default %d\n",
			     opts->in_capsule_data_size,
			     SPDK_NVME_QUIC_IN_CAPSULE_DATA_MAX_SIZE,
			     SPDK_NVMF_QUIC_DEFAULT_CONTROL_MSG_NUM);
		qtransport->quic_opts.control_msg_num = SPDK_NVMF_QUIC_DEFAULT_CONTROL_MSG_NUM;
	}

	/* I/O unit size cannot be larget than max I/O size */
	if(opts->io_unit_size > opts->max_io_size) {
		SPDK_WARNLOG("io_unit_size %d is greater than max_io_size %d. Setting io_unit_size to max_io_size\n",
			     opts->io_unit_size, opts->max_io_size);
		opts->io_unit_size = opts->max_io_size;
	}


	if(opts->in_capsule_data_size > opts->max_io_size) {
		SPDK_WARNLOG("in_capsule_data_size %d is greater than max_io_size %d. Setting in_capsule_data_size to max_io_size\n",
			     opts->in_capsule_data_size, opts->max_io_size);
		opts->in_capsule_data_size = opts->max_io_size;
	}

	/* max IO Queue depth 65535 */ 
	if(opts->max_queue_depth < SPDK_NVMF_QUIC_MIN_IO_QUEUE_DEPTH || opts->max_queue_depth > SPDK_NVMF_QUIC_MAX_IO_QUEUE_DEPTH) {
		SPDK_ERRLOG("max_queue_depth %d is out of range (%d - %d)\n",
			    opts->max_queue_depth,
			    SPDK_NVMF_QUIC_MIN_IO_QUEUE_DEPTH,
			    SPDK_NVMF_QUIC_MAX_IO_QUEUE_DEPTH);
		free(qtransport);
		return NULL;
	}

	/* max admin queue depth cannot be smaller than 2 or larget than 4096 */
	if(opts->max_aq_depth < SPDK_NVMF_QUIC_MIN_ADMIN_QUEUE_DEPTH || opts->max_aq_depth > SPDK_NVMF_QUIC_MAX_ADMIN_QUEUE_DEPTH) {
		SPDK_WARNLOG("max_aq_depth %d is out of range (%d - %d). Setting to default %d\n",
			     opts->max_aq_depth,
			     SPDK_NVMF_QUIC_MIN_ADMIN_QUEUE_DEPTH,
			     SPDK_NVMF_QUIC_MAX_ADMIN_QUEUE_DEPTH,
			     SPDK_NVMF_QUIC_DEFAULT_MAX_ADMIN_QUEUE_DEPTH);
		opts->max_aq_depth = SPDK_NVMF_QUIC_DEFAULT_MAX_ADMIN_QUEUE_DEPTH;
	}

	sge_count = opts->max_io_size / opts->io_unit_size;
	if(sge_count > SPDK_NVMF_MAX_SGL_ENTRIES) {
		SPDK_ERRLOG("max_io_size %d with io_unit_size %d requires %d SGE entries, which exceeds max %d\n",
			    opts->max_io_size,
			    opts->io_unit_size,
			    sge_count,
			    SPDK_NVMF_MAX_SGL_ENTRIES);
		free(qtransport);
		return NULL;
	}

	if(opts->buf_cache_size < UINT32_MAX) {
		min_shared_buffers = spdk_env_get_core_count() * opts->buf_cache_size;
		if(min_shared_buffers > opts->num_shared_buffers) {
			SPDK_ERRLOG("num_shared_buffers %d is too small for buf_cache_size %d\n",
				    opts->num_shared_buffers,
				    opts->buf_cache_size);
			free(qtransport);
			return NULL;
		}
	}


	period = spdk_interrupt_mode_is_enabled() ? 0 : opts->acceptor_poll_rate;
	SPDK_DEBUGLOG(nvmf,"Registering accept poller: period=%lu us, interrupt_mode=%d\n",
	              period, spdk_interrupt_mode_is_enabled());
	// qtransport->accept_poller = SPDK_POLLER_REGISTER(nvmf_quic_accept, &qtransport->transport, period);
	// if(!qtransport->accept_poller) {
	// 	SPDK_ERRLOG("Failed to create QUIC accept poller\n");
	// 	free(qtransport);
	// 	return NULL;
	// }
	// SPDK_DEBUGLOG(nvmf,"Accept poller registered successfully: poller=%p\n", qtransport->accept_poller);

	// spdk_poller_register_interrupt(qtransport->accept_poller, NULL, NULL);

	qtransport->listen_sock_group = spdk_sock_group_create(NULL);
	if(qtransport->listen_sock_group == NULL) {
		SPDK_ERRLOG("spdk_sock_group_create failed\n");
		spdk_poller_unregister(&qtransport->accept_poller);
		free(qtransport);
		return NULL;
	}

	if(spdk_interrupt_mode_is_enabled()) {
		rc = SPDK_SOCK_GROUP_REGISTER_INTERRUPT(qtransport->listen_sock_group, SPDK_INTERRUPT_EVENT_IN | SPDK_INTERRUPT_EVENT_OUT, nvmf_quic_accept, &qtransport->transport);

		if(rc != 0) {
			SPDK_ERRLOG("SPDK_SOCK_GROUP_REGISTER_INTERRUPT failed\n");
			spdk_sock_group_close(&qtransport->listen_sock_group);
			spdk_poller_unregister(&qtransport->accept_poller);
			free(qtransport);
			return NULL;
		}
	}

	/* Initialize shared TLS context for all connections */
	qtransport->tls_ctx = calloc(1, sizeof(ptls_context_t));
	if (!qtransport->tls_ctx) {
		SPDK_ERRLOG("Failed to allocate TLS context for transport\n");
		spdk_sock_group_close(&qtransport->listen_sock_group);
		// spdk_poller_unregister(&qtransport->accept_poller);
		free(qtransport);
		return NULL;
	}
	
	/* Set up basic TLS context fields */
	qtransport->tls_ctx->random_bytes = ptls_openssl_random_bytes;
	qtransport->tls_ctx->get_time = &ptls_get_time;
	
	/* Initialize cipher suites in qtransport array first */
	qtransport->cipher_suites[0] = &ptls_openssl_aes128gcmsha256;
	qtransport->cipher_suites[1] = &ptls_openssl_aes256gcmsha384;
	qtransport->cipher_suites[2] = NULL;
	
	/* Initialize key exchanges - use default secp256r1 */
	qtransport->key_exchanges[0] = &ptls_openssl_secp256r1;
	qtransport->key_exchanges[1] = NULL;
	
	/* Now assign the pointers to TLS context */
	qtransport->tls_ctx->key_exchanges = qtransport->key_exchanges;
	qtransport->tls_ctx->cipher_suites = qtransport->cipher_suites;
	qtransport->tls_ctx->require_dhe_on_psk = 0;  /* NVMe spec allows PSK without DHE */
	
	SPDK_DEBUGLOG(nvmf,"TLS context setup: tls_ctx=%p, cipher_suites=%p, cipher_suites[0]=%p\n",
		       qtransport->tls_ctx, qtransport->tls_ctx->cipher_suites, 
		       qtransport->tls_ctx->cipher_suites ? qtransport->tls_ctx->cipher_suites[0] : NULL);
	
	/* Initialize TLS context (must be called after setting cipher_suites and key_exchanges) */
	quicly_amend_ptls_context(qtransport->tls_ctx);

	/* Initialize shared QUIC context for all connections */
	qtransport->quic_ctx = calloc(1, sizeof(quicly_context_t));
	if (!qtransport->quic_ctx) {
		SPDK_ERRLOG("Failed to allocate QUIC context for transport\n");
		free(qtransport->tls_ctx);
		spdk_sock_group_close(&qtransport->listen_sock_group);
		// spdk_poller_unregister(&qtransport->accept_poller);
		free(qtransport);
		return NULL;
	}
	*qtransport->quic_ctx = quicly_spec_context;
	
	/* Link TLS context to QUIC context */
	qtransport->quic_ctx->tls = qtransport->tls_ctx;
	
	SPDK_DEBUGLOG(nvmf,"QUIC context setup: quic_ctx=%p, quic_ctx->tls=%p, quic_ctx->tls->cipher_suites=%p\n",
		       qtransport->quic_ctx, qtransport->quic_ctx->tls,
		       qtransport->quic_ctx->tls ? qtransport->quic_ctx->tls->cipher_suites : NULL);
	
	/* Setup callbacks */
	qtransport->quic_ctx->closed_by_remote = &closed_by_remote;
	qtransport->quic_ctx->generate_resumption_token = &generate_resumption_token;
	qtransport->quic_ctx->stream_open = &nvmf_quic_stream_open;
	
	/* Setup stream scheduler */
	qtransport->stream_scheduler = quicly_default_stream_scheduler;
	qtransport->stream_scheduler.do_send = scheduler_do_send;
	qtransport->quic_ctx->stream_scheduler = &qtransport->stream_scheduler;
	
	/* Setup CID encryptor with a random key */
	{
		static char cid_key[17];
		ptls_openssl_random_bytes(cid_key, sizeof(cid_key) - 1);
		size_t key_len = sizeof(cid_key) - 1;  /* Use actual buffer size, not strlen on random bytes! */
		SPDK_DEBUGLOG(nvmf,"CID key generated: actual_len=%zu, strlen=%zu, first_bytes=%02x%02x%02x%02x\n",
			       key_len, strlen(cid_key), (uint8_t)cid_key[0], (uint8_t)cid_key[1], 
			       (uint8_t)cid_key[2], (uint8_t)cid_key[3]);
		qtransport->quic_ctx->cid_encryptor = quicly_new_default_cid_encryptor(
			&ptls_openssl_quiclb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256,
			ptls_iovec_init(cid_key, key_len));
		SPDK_DEBUGLOG(nvmf,"CID encryptor created: %p\n", qtransport->quic_ctx->cid_encryptor);
	}

	/* Setup address token encryption for Retry/Resumption tokens (shared across all connections) */
	{
		uint8_t secret[PTLS_MAX_DIGEST_SIZE];
		ptls_openssl_random_bytes(secret, ptls_openssl_sha256.digest_size);
		qtransport->address_token_aead.enc = ptls_aead_new(&ptls_openssl_aes128gcm, &ptls_openssl_sha256, 1, secret, "");
		qtransport->address_token_aead.dec = ptls_aead_new(&ptls_openssl_aes128gcm, &ptls_openssl_sha256, 0, secret, "");
	}

	/* Initialize next CID */
	qtransport->next_cid.master_id = 0;
	qtransport->next_cid.path_id = 0;
	qtransport->next_cid.thread_id = 0;

	return &qtransport->transport;
}

static void
nvmf_quic_opts_init(struct spdk_nvmf_transport_opts *opts)
{
	opts->max_queue_depth =		SPDK_NVMF_QUIC_DEFAULT_MAX_IO_QUEUE_DEPTH;
	opts->max_qpairs_per_ctrlr =	SPDK_NVMF_QUIC_DEFAULT_MAX_QPAIRS_PER_CTRLR;
	opts->in_capsule_data_size =	SPDK_NVMF_QUIC_DEFAULT_IN_CAPSULE_DATA_SIZE;
	opts->max_io_size =		SPDK_NVMF_QUIC_DEFAULT_MAX_IO_SIZE;
	opts->io_unit_size =		SPDK_NVMF_QUIC_DEFAULT_IO_UNIT_SIZE;
	opts->max_aq_depth =		SPDK_NVMF_QUIC_DEFAULT_MAX_ADMIN_QUEUE_DEPTH;
	opts->num_shared_buffers =	SPDK_NVMF_QUIC_DEFAULT_NUM_SHARED_BUFFERS;
	opts->buf_cache_size =		SPDK_NVMF_QUIC_DEFAULT_BUFFER_CACHE_SIZE;
	opts->dif_insert_or_strip =	SPDK_NVMF_QUIC_DEFAULT_DIF_INSERT_OR_STRIP;
	opts->abort_timeout_sec =	SPDK_NVMF_QUIC_DEFAULT_ABORT_TIMEOUT_SEC;
	opts->transport_specific =      NULL;
}

static void
nvmf_quic_dump_opts(struct spdk_nvmf_transport *transport, struct spdk_json_write_ctx *w)
{
	struct spdk_nvmf_quic_transport	*qtransport;
	assert(w != NULL);

	qtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_quic_transport, transport);
	spdk_json_write_named_bool(w, "c2h_success", qtransport->quic_opts.c2h_success);
	spdk_json_write_named_uint32(w, "sock_priority", qtransport->quic_opts.sock_priority);
}

static void
nvmf_quic_free_psk_entry(struct quic_psk_entry *entry)
{
	if (entry == NULL) {
		return;
	}

	spdk_memset_s(entry->psk, sizeof(entry->psk), 0, sizeof(entry->psk));
	spdk_keyring_put_key(entry->key);
	free(entry);
}

static int
nvmf_quic_destroy(struct spdk_nvmf_transport *transport,
		 spdk_nvmf_transport_destroy_done_cb cb_fn, void *cb_arg)
{
	struct spdk_nvmf_quic_transport	*qtransport;
	struct quic_psk_entry *entry, *tmp;

	assert(transport != NULL);
	qtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_quic_transport, transport);

	TAILQ_FOREACH_SAFE(entry, &qtransport->psks, link, tmp) {
		TAILQ_REMOVE(&qtransport->psks, entry, link);
		nvmf_quic_free_psk_entry(entry);
	}

	spdk_poller_unregister(&qtransport->accept_poller);
	spdk_sock_group_unregister_interrupt(qtransport->listen_sock_group);
	spdk_sock_group_close(&qtransport->listen_sock_group);
	free(qtransport);

	if (cb_fn) {
		cb_fn(cb_arg);
	}
	return 0;
}

static struct spdk_nvmf_quic_control_msg_list *
nvmf_quic_control_msg_list_create(uint16_t num_messages)
{
	struct spdk_nvmf_quic_control_msg_list *list;
	struct spdk_nvmf_quic_control_msg *msg;
	uint16_t i;

	list = calloc(1, sizeof(*list));
	if(!list) {
		SPDK_ERRLOG("Failed to allocate memory for control message list\n");
		return NULL;
	}

	list->msg_buf = spdk_zmalloc(num_messages * SPDK_NVME_QUIC_IN_CAPSULE_DATA_MAX_SIZE, NVMF_DATA_BUFFER_ALIGNMENT, NULL, SPDK_ENV_NUMA_ID_ANY, SPDK_MALLOC_DMA);
	if(!list->msg_buf) {
		SPDK_ERRLOG("Failed to allocate memory for control message buffers\n");
		free(list);
		return NULL;
	}

	STAILQ_INIT(&list->free_msgs);
	STAILQ_INIT(&list->waiting_for_msg_reqs);

	for(i=0; i<num_messages; i++) {
		msg = (struct spdk_nvmf_quic_control_msg *)((char *)list->msg_buf + i * SPDK_NVME_QUIC_IN_CAPSULE_DATA_MAX_SIZE);
		STAILQ_INSERT_TAIL(&list->free_msgs, msg, link);
	}

	return list;
}

static void
nvmf_quic_control_msg_list_free(struct spdk_nvmf_quic_control_msg_list *list)
{
	if (!list) {
		return;
	}

	spdk_free(list->msg_buf);
	free(list);
}

static void
nvmf_quic_request_free(void *cb_arg)
{
	struct spdk_nvmf_quic_transport *qtransport;
	struct spdk_nvmf_quic_req *quic_req = cb_arg;

	assert(quic_req != NULL);

	SPDK_DEBUGLOG(nvmf,"Freeing QUIC request %p\n", quic_req);
	qtransport = SPDK_CONTAINEROF(quic_req->req.qpair->transport, struct spdk_nvmf_quic_transport, transport);
	nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_FREE);
	nvmf_quic_req_process(qtransport, quic_req);
}

static void
nvmf_quic_drain_state_queue(struct spdk_nvmf_quic_qpair *qqpair,
			   enum spdk_nvmf_quic_req_state state)
{
	struct spdk_nvmf_quic_req *quic_req, *req_tmp;

	assert(state != QUIC_REQUEST_STATE_FREE);
	TAILQ_FOREACH_SAFE(quic_req, &qqpair->quic_req_working_queue, state_link, req_tmp) {
		if (state == quic_req->state) {
			nvmf_quic_request_free(quic_req);
		}
	}
}

static void
nvmf_quic_cleanup_all_states(struct spdk_nvmf_quic_qpair *qqpair)
{
	nvmf_quic_drain_state_queue(qqpair, QUIC_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST);
	nvmf_quic_drain_state_queue(qqpair, QUIC_REQUEST_STATE_NEW);
	nvmf_quic_drain_state_queue(qqpair, QUIC_REQUEST_STATE_EXECUTING);
	nvmf_quic_drain_state_queue(qqpair, QUIC_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER);
	nvmf_quic_drain_state_queue(qqpair, QUIC_REQUEST_STATE_AWAITING_R2T_ACK);
	nvmf_quic_drain_state_queue(qqpair, QUIC_REQUEST_STATE_COMPLETED);
}

static void
nvmf_quic_dump_qpair_req_contents(struct spdk_nvmf_quic_qpair *qqpair)
{
	int i;
	struct spdk_nvmf_quic_req *quic_req;

	SPDK_ERRLOG("Dumping contents of queue pair (QID %d)\n", qqpair->qpair.qid);
	for (i = 1; i < QUIC_REQUEST_NUM_STATES; i++) {
		SPDK_ERRLOG("\tNum of requests in state[%d] = %u\n", i, qqpair->state_cntr[i]);
		TAILQ_FOREACH(quic_req, &qqpair->quic_req_working_queue, state_link) {
			if ((int)quic_req->state == i) {
				SPDK_ERRLOG("\t\tRequest Data From Pool: %d\n", quic_req->req.data_from_pool);
				SPDK_ERRLOG("\t\tRequest opcode: %d\n", quic_req->req.cmd->nvmf_cmd.opcode);
			}
		}
	}
}

static void
_nvmf_quic_qpair_destroy(void *_qqpair)
{
	struct spdk_nvmf_quic_qpair *qqpair = _qqpair;
	spdk_nvmf_transport_qpair_fini_cb cb_fn = qqpair->fini_cb_fn;
	void *cb_arg = qqpair->fini_cb_arg;
	int err = 0;

	spdk_trace_record(TRACE_QUIC_QP_DESTROY, qqpair->qpair.trace_id, 0, 0);

	SPDK_DEBUGLOG(nvmf,"enter\n");

	err = spdk_sock_close(&qqpair->sock);
	assert(err == 0);
	nvmf_quic_cleanup_all_states(qqpair);

	if (qqpair->state_cntr[QUIC_REQUEST_STATE_FREE] != qqpair->resource_count) {
		SPDK_ERRLOG("qqpair(%p) free quic request num is %u but should be %u\n", qqpair,
			    qqpair->state_cntr[QUIC_REQUEST_STATE_FREE],
			    qqpair->resource_count);
		err++;
	}

	if (err > 0) {
		nvmf_quic_dump_qpair_req_contents(qqpair);
	}

	/* Contexts are now shared at transport level - don't free them here */
	
	// spdk_dma_free(qqpair->);
	free(qqpair->reqs);
	spdk_free(qqpair->bufs);
	spdk_trace_unregister_owner(qqpair->qpair.trace_id);
	free(qqpair);

	if (cb_fn != NULL) {
		cb_fn(cb_arg);
	}

	SPDK_DEBUGLOG(nvmf,"Leave\n");
}

static void
nvmf_quic_qpair_destroy(struct spdk_nvmf_quic_qpair *qqpair)
{
	/* Delay the destruction to make sure it isn't performed from the context of a sock
	 * callback.  Otherwise, spdk_sock_close() might not abort pending requests, causing their
	 * completions to be executed after the qpair is freed.  (Note: this fixed issue #2471.)
	 */
	spdk_thread_send_msg(spdk_get_thread(), _nvmf_quic_qpair_destroy, qqpair);
}
static int
_nvmf_quic_qpair_abort_request(void *ctx)
{
	struct spdk_nvmf_request *req = ctx;
	struct spdk_nvmf_quic_req *quic_req_to_abort = SPDK_CONTAINEROF(req->req_to_abort,
			struct spdk_nvmf_quic_req, req);
	struct spdk_nvmf_quic_qpair *qqpair = SPDK_CONTAINEROF(req->req_to_abort->qpair,
					     struct spdk_nvmf_quic_qpair, qpair);
	struct spdk_nvmf_quic_transport *qtransport = SPDK_CONTAINEROF(qqpair->qpair.transport,
			struct spdk_nvmf_quic_transport, transport);
	int rc;

	spdk_poller_unregister(&req->poller);

	switch (quic_req_to_abort->state) {
	case QUIC_REQUEST_STATE_EXECUTING:
	case QUIC_REQUEST_STATE_AWAITING_ZCOPY_START:
	case QUIC_REQUEST_STATE_AWAITING_ZCOPY_COMMIT:
		rc = nvmf_ctrlr_abort_request(req);
		if (rc == SPDK_NVMF_REQUEST_EXEC_STATUS_ASYNCHRONOUS) {
			return SPDK_POLLER_BUSY;
		}
		break;

	case QUIC_REQUEST_STATE_NEED_BUFFER:
		nvmf_quic_request_get_buffers_abort(quic_req_to_abort);
		nvmf_quic_req_set_abort_status(req, quic_req_to_abort);
		nvmf_quic_req_process(qtransport, quic_req_to_abort);
		break;

	case QUIC_REQUEST_STATE_AWAITING_R2T_ACK:
	case QUIC_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER:
		if (spdk_get_ticks() < req->timeout_tsc) {
			req->poller = SPDK_POLLER_REGISTER(_nvmf_quic_qpair_abort_request, req, 0);
			return SPDK_POLLER_BUSY;
		}
		break;

	default:
		/* Requests in other states are either un-abortable (e.g.
		 * TRANSFERRING_CONTROLLER_TO_HOST) or should never end up here, as they're
		 * immediately transitioned to other states in nvmf_tcp_req_process() (e.g.
		 * READY_TO_EXECUTE).  But it is fine to end up here, as we'll simply complete the
		 * abort request with the bit0 of dword0 set (command not aborted).
		 */
		break;
	}

	spdk_nvmf_request_complete(req);
	return SPDK_POLLER_BUSY;
}

static void
nvmf_quic_qpair_abort_request(struct spdk_nvmf_qpair *qpair,
			     struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_quic_qpair *qqpair;
	struct spdk_nvmf_quic_transport *qtransport;
	struct spdk_nvmf_transport *transport;
	uint16_t cid;
	uint32_t i;
	struct spdk_nvmf_quic_req *quic_req_to_abort = NULL;
	qqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_quic_qpair, qpair);
	qtransport = SPDK_CONTAINEROF(qpair->transport, struct spdk_nvmf_quic_transport, transport);
	transport = &qtransport->transport;

	cid = req->cmd->nvme_cmd.cdw10_bits.abort.cid;

	for (i = 0; i < qqpair->resource_count; i++) {
		if (qqpair->reqs[i].state != QUIC_REQUEST_STATE_FREE &&
		    qqpair->reqs[i].req.cmd->nvme_cmd.cid == cid) {
			quic_req_to_abort = &qqpair->reqs[i];
			break;
		}
	}

	spdk_trace_record(TRACE_QUIC_QP_ABORT_REQ, qqpair->qpair.trace_id, 0, (uintptr_t)req);

	if (quic_req_to_abort == NULL) {
		spdk_nvmf_request_complete(req);
		return;
	}

	req->req_to_abort = &quic_req_to_abort->req;
	req->timeout_tsc = spdk_get_ticks() +
			   transport->opts.abort_timeout_sec * spdk_get_ticks_hz();
	req->poller = NULL;

	_nvmf_quic_qpair_abort_request(req);
}


static int
nvmf_quic_poll_group_intr(void *ctx)
{
	struct spdk_nvmf_transport_poll_group *group = ctx;
	int ret = 0;

	ret = nvmf_quic_poll_group_poll(group);

	return ret != 0 ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}


static void
nvmf_quic_poll_group_destroy(struct spdk_nvmf_transport_poll_group *group)
{
	struct spdk_nvmf_quic_poll_group *qgroup, *next_qgroup;
	struct spdk_nvmf_quic_transport *qtransport;

	qgroup = SPDK_CONTAINEROF(group, struct spdk_nvmf_quic_poll_group, group);
	spdk_sock_group_unregister_interrupt(qgroup->sock_group);
	spdk_sock_group_close(&qgroup->sock_group);
	if(qgroup->control_msg_list) {
		nvmf_quic_control_msg_list_free(qgroup->control_msg_list);
	}

	if(qgroup->accel_channel) {
		spdk_put_io_channel(qgroup->accel_channel);
	}

	if(qgroup->group.transport == NULL) {
		free(qgroup);
		return;
	}

	qtransport = SPDK_CONTAINEROF(group->transport, struct spdk_nvmf_quic_transport, transport);

	next_qgroup = TAILQ_NEXT(qgroup, link);
	TAILQ_REMOVE(&qtransport->poll_groups, qgroup, link);
	if(next_qgroup == NULL) {
		qtransport->next_pg = TAILQ_FIRST(&qtransport->poll_groups);
	} 
	if(qtransport->next_pg == qgroup) {
		qtransport->next_pg = next_qgroup;
	}

	free(qgroup);
}

static void on_closed_by_remote(quicly_closed_by_remote_t *self, quicly_conn_t *conn, quicly_error_t err, uint64_t frame_type,
                                const char *reason, size_t reason_len)
{
	SPDK_DEBUGLOG(nvmf,"Connection closed by remote: code=%" PRId64 "\n", err);
}

static quicly_closed_by_remote_t closed_by_remote = {&on_closed_by_remote};

static quicly_error_t on_generate_resumption_token(quicly_generate_resumption_token_t *self, quicly_conn_t *conn,
                                                   ptls_buffer_t *buf, quicly_address_token_plaintext_t *token)
{
	struct spdk_nvmf_quic_qpair *qqpair = *quicly_get_data(conn);
	struct spdk_nvmf_quic_transport *qtransport = SPDK_CONTAINEROF(qqpair->qpair.transport, struct spdk_nvmf_quic_transport, transport);
	return quicly_encrypt_address_token(qtransport->tls_ctx->random_bytes, 
					    qtransport->address_token_aead.enc, buf, buf->off, token);
}

static quicly_generate_resumption_token_t generate_resumption_token = {&on_generate_resumption_token};

static quicly_error_t scheduler_do_send(quicly_stream_scheduler_t *sched, quicly_conn_t *conn, quicly_send_context_t *s)
{
	/* Use default scheduler for server */
	return quicly_default_stream_scheduler.do_send(&quicly_default_stream_scheduler, conn, s);
}


static struct spdk_nvmf_transport_poll_group *
nvmf_quic_poll_group_create(struct spdk_nvmf_transport *transport, struct spdk_nvmf_poll_group *group)
{
	struct spdk_nvmf_quic_transport *qtransport;
	struct spdk_nvmf_quic_poll_group *qgroup;
	int rc;

	qgroup = calloc(1, sizeof(*qgroup));
	if(!qgroup) {
		return NULL;
	}

	qgroup->sock_group = spdk_sock_group_create(&qgroup->group);
	if(!qgroup->sock_group) {
		goto cleanup;
	}

	TAILQ_INIT(&qgroup->qpairs);
	
	/* Initialize CID hash table buckets */
	for (uint32_t i = 0; i < QUIC_CID_HASH_SIZE; i++) {
		TAILQ_INIT(&qgroup->cid_hash[i].qpairs);
	}

	qtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_quic_transport, transport);

	if(transport->opts.in_capsule_data_size < SPDK_NVME_QUIC_IN_CAPSULE_DATA_MAX_SIZE) {
		SPDK_DEBUGLOG(nvmf,"QUIC transport with in_capsule_data_size %d requires control messages\n",
			     transport->opts.in_capsule_data_size);
		qgroup->control_msg_list = nvmf_quic_control_msg_list_create(qtransport->quic_opts.control_msg_num);
		if(!qgroup->control_msg_list) {
			goto cleanup;
		}
	}

	qgroup->accel_channel = spdk_accel_get_io_channel();
	if(!qgroup->accel_channel) {
		SPDK_ERRLOG("spdk_accel_get_io_channel failed\n");
		goto cleanup;
	}

	TAILQ_INSERT_TAIL(&qtransport->poll_groups, qgroup, link);
	if(qtransport->next_pg == NULL) {
		qtransport->next_pg = qgroup;
	}

	if(spdk_interrupt_mode_is_enabled()) {
		rc = SPDK_SOCK_GROUP_REGISTER_INTERRUPT(qgroup->sock_group, SPDK_INTERRUPT_EVENT_IN | SPDK_INTERRUPT_EVENT_OUT, nvmf_quic_poll_group_intr, &qgroup->group);
		if(rc != 0) {
			SPDK_ERRLOG("SPDK_SOCK_GROUP_REGISTER_INTERRUPT failed\n");
			goto cleanup;
		}
	}

	return &qgroup->group;

cleanup:
	nvmf_quic_poll_group_destroy(&qgroup->group);
	return NULL;
}

static struct spdk_nvmf_transport_poll_group *
nvmf_quic_get_optimal_poll_group(struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_quic_transport *qtransport;
	struct spdk_nvmf_quic_poll_group **pg;
	struct spdk_nvmf_quic_qpair *qqpair;
	struct spdk_sock_group *group = NULL, *hint = NULL;
	int rc;

	qtransport = SPDK_CONTAINEROF(qpair->transport, struct spdk_nvmf_quic_transport, transport);

	if(TAILQ_EMPTY(&qtransport->poll_groups)) {
		SPDK_ERRLOG("No poll groups available for QUIC transport\n");
		return NULL;
	}

	pg = &qtransport->next_pg;
	assert(*pg != NULL);
	hint = (*pg)->sock_group;

	qqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_quic_qpair, qpair);
	/* TODO: spdk_sock_group_get_optimal_sock_group may not exist */
	group = NULL;
	rc = -1; /* spdk_sock_group_get_optimal_sock_group(qqpair->sock, &group, hint); */
	if(rc != 0) {
		return NULL;
	} else if (group != NULL) {
		/* Found optimal poll group */
		return spdk_sock_group_get_ctx(group);
	}

	/* The hint was used for optimal poll group, advance next_pg */
	*pg = TAILQ_NEXT(*pg, link);
	if(*pg == NULL) {
		*pg = TAILQ_FIRST(&qtransport->poll_groups);
	}

	return spdk_sock_group_get_ctx(hint);
}

static int
nvmf_quic_req_free(struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_quic_req *quic_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_quic_req, req);

	nvmf_quic_request_free(quic_req);
	return 0;
}


/* It also should be implemented in quic. it's for recv buffer to nvme device */
static int
nvmf_quic_req_complete(struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_quic_transport *qtransport;
	struct spdk_nvmf_quic_req *quic_req;

	qtransport = SPDK_CONTAINEROF(req->qpair->transport, struct spdk_nvmf_quic_transport, transport);
	quic_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_quic_req, req);

	SPDK_DEBUGLOG(nvmf,"nvmf_quic_req_complete: req=%p, state=%d, opc=0x%x\n",
		       quic_req, quic_req->state, quic_req->cmd.opc);

	switch(quic_req->state) {
		case QUIC_REQUEST_STATE_EXECUTING:
		case QUIC_REQUEST_STATE_AWAITING_ZCOPY_COMMIT:
			SPDK_DEBUGLOG(nvmf,"Completion: transitioning req=%p to EXECUTED state\n", quic_req);
			nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_EXECUTED);
			break;
		case QUIC_REQUEST_STATE_AWAITING_ZCOPY_START:
			nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_ZCOPY_START_COMPLETED);
			break;
		case QUIC_REQUEST_STATE_AWAITING_ZCOPY_RELEASE:
			nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_COMPLETED);
			break;
		default:
			SPDK_ERRLOG("Invalid QUIC request state %d on completion\n", quic_req->state);
			assert(0 && "Invalid QUIC request state on completion");
			break;
	}

	nvmf_quic_req_process(qtransport, quic_req);

	return 0;
}

static void
nvmf_quic_req_get_buffers_done(struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_quic_req *quic_req;
	struct spdk_nvmf_transport *transport;
	struct spdk_nvmf_quic_transport *qtransport;

	quic_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_quic_req, req);
	transport = req->qpair->transport;
	qtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_quic_transport, transport);

	nvmf_quic_req_set_state(quic_req, QUIC_REQUEST_STATE_HAVE_BUFFER);
	nvmf_quic_req_process(qtransport, quic_req);
}

static void
nvmf_quic_close_qpair(struct spdk_nvmf_qpair *qpair, spdk_nvmf_transport_qpair_fini_cb cb_fn, void *cb_arg)
{
	struct spdk_nvmf_quic_qpair *qqpair;

	SPDK_DEBUGLOG(nvmf,"Closing QUIC qpair %p\n", qpair);

	qqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_quic_qpair, qpair);

	assert(qqpair->fini_cb_fn == NULL);
	qqpair->fini_cb_fn = cb_fn;
	qqpair->fini_cb_arg = cb_arg;

	nvmf_quic_qpair_set_state(qqpair, NVMF_QUIC_QPAIR_STATE_EXITED);
	nvmf_quic_qpair_destroy(qqpair);
}

static void
nvmf_quic_qpair_get_trid(struct spdk_nvmf_qpair *qpair,
			  struct spdk_nvme_transport_id *trid, bool peer)
{
	struct spdk_nvmf_quic_qpair *qqpair;
	uint16_t port;

	qqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_quic_qpair, qpair);
	spdk_nvme_trid_populate_transport(trid, SPDK_NVME_TRANSPORT_QUIC);

	if(peer) {
		snprintf(trid->traddr, sizeof(trid->traddr), "%s", qqpair->initiator_addr);
		port = qqpair->initiator_port;
	} else {
		snprintf(trid->traddr, sizeof(trid->traddr), "%s", qqpair->target_addr);
		port = qqpair->target_port;
	}

	if(spdk_sock_is_ipv4(qqpair->sock)) {
		trid->adrfam = SPDK_NVMF_ADRFAM_IPV4;
	} else if(spdk_sock_is_ipv6(qqpair->sock)) {
		trid->adrfam = SPDK_NVMF_ADRFAM_IPV6;
	} else {
		SPDK_ERRLOG("Unbalanced address family for qpair %p\n", qpair);
		assert(false);
	}

	snprintf(trid->trsvcid, sizeof(trid->trsvcid), "%d", port);
}

static int
nvmf_quic_qpair_get_local_trid(struct spdk_nvmf_qpair *qpair,
			      struct spdk_nvme_transport_id *trid)
{
	nvmf_quic_qpair_get_trid(qpair, trid, 0);

	return 0;
}

static int
nvmf_quic_qpair_get_peer_trid(struct spdk_nvmf_qpair *qpair,
			     struct spdk_nvme_transport_id *trid)
{
	nvmf_quic_qpair_get_trid(qpair, trid, 1);
	return 0;
}

static int
nvmf_quic_qpair_get_listen_trid(struct spdk_nvmf_qpair *qpair,
			       struct spdk_nvme_transport_id *trid)
{
	nvmf_quic_qpair_get_trid(qpair, trid, 0);
	return 0;
}

struct quic_subsystem_add_host_opts {
	char *psk;
};

static const struct spdk_json_object_decoder quic_subsystem_add_host_opts_decoder[] = {
	{"psk", offsetof(struct quic_subsystem_add_host_opts, psk), spdk_json_decode_string, true},
};


/* PSK derivation function (duplicated from lib/nvme/nvme_quic.c for server use) */
static inline int
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

static int
nvmf_quic_subsystem_add_host(struct spdk_nvmf_transport *transport, const struct spdk_nvmf_subsystem *subsystem,
	const char *hostnqn, const struct spdk_json_val *transport_specific)
{
	struct quic_subsystem_add_host_opts opts;
	struct spdk_nvmf_quic_transport *qtransport;
	struct quic_psk_entry *tmp, *entry = NULL;
	uint8_t psk_configured[SPDK_TLS_PSK_MAX_LEN] = {};
	char psk_interchange[SPDK_TLS_PSK_MAX_LEN + 1] = {};
	uint8_t tls_cipher_suite;
	int rc = 0;
	uint8_t psk_retained_hash;
	uint64_t psk_configured_size;

	if(transport_specific == NULL) {
		return 0;
	}

	assert(transport != NULL);
	assert(subsystem != NULL);

	memset(&opts, 0, sizeof(opts));

	/* Decode PSK */
	if(spdk_json_decode_object_relaxed(transport_specific, quic_subsystem_add_host_opts_decoder,
					  SPDK_COUNTOF(quic_subsystem_add_host_opts_decoder), &opts)) {
		SPDK_ERRLOG("Failed to decode QUIC subsystem add host options\n");
		return -EINVAL;
	}

	if(opts.psk == NULL) {
		return 0;
	}

	entry = calloc(1, sizeof(struct quic_psk_entry));
	if(entry == NULL) {
		SPDK_ERRLOG("Failed to allocate memory for QUIC PSK entry\n");
		rc = -ENOMEM;
		goto end;
	}

	/* Get the key from keyring */
	entry->key = spdk_keyring_get_key(opts.psk);
	if (entry->key == NULL) {
		SPDK_ERRLOG("Key '%s' does not exist\n", opts.psk);
		rc = -EINVAL;
		goto end;
	}

	/* Retrieve the PSK interchange format from the key */
	rc = spdk_key_get_key(entry->key, psk_interchange, SPDK_TLS_PSK_MAX_LEN);
	if (rc < 0) {
		SPDK_ERRLOG("Failed to retrieve PSK '%s'\n", opts.psk);
		rc = -EINVAL;
		goto end;
	}

	/* Parse PSK interchange to determine cipher suite */
	rc = nvme_quic_parse_interchange_psk(psk_interchange, psk_configured, sizeof(psk_configured),
					     &psk_configured_size, &psk_retained_hash);
	if (rc < 0) {
		SPDK_ERRLOG("Failed to parse PSK interchange!\n");
		goto end;
	}

	/* Determine cipher suite based on PSK size */
	if (psk_configured_size == SHA256_DIGEST_LENGTH) {
		tls_cipher_suite = NVME_QUIC_CIPHER_AES_128_GCM_SHA256;
	} else if (psk_configured_size == SHA384_DIGEST_LENGTH) {
		tls_cipher_suite = NVME_QUIC_CIPHER_AES_256_GCM_SHA384;
	} else {
		SPDK_ERRLOG("Unrecognized cipher suite! PSK size: %lu\n", psk_configured_size);
		rc = -EINVAL;
		goto end;
	}

	qtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_quic_transport, transport);

	/* Generate PSK identity */
	rc = nvme_quic_generate_psk_identity(entry->pskid, sizeof(entry->pskid), hostnqn, subsystem->subnqn, tls_cipher_suite);
	if(rc) {
		rc = -EINVAL;
		goto end;
	}

	TAILQ_FOREACH(tmp, &qtransport->psks, link) {
		if (strncmp(tmp->pskid, entry->pskid, NVMF_PSK_IDENTITY_LEN) == 0) {
			SPDK_ERRLOG("PSK identity already exists for host NQN '%s' and subsystem NQN '%s'\n",
				    hostnqn, subsystem->subnqn);
			rc = -EEXIST;
			goto end;
		}
	}

	if (snprintf(entry->hostnqn, sizeof(entry->hostnqn), "%s", hostnqn) < 0) {
		SPDK_ERRLOG("Could not write hostnqn string!\n");
		rc = -EINVAL;
		goto end;
	}
	if (snprintf(entry->subnqn, sizeof(entry->subnqn), "%s", subsystem->subnqn) < 0) {
		SPDK_ERRLOG("Could not write subnqn string!\n");
		rc = -EINVAL;
		goto end;
	}

	entry->tls_cipher_suite = tls_cipher_suite;


	/* No hash indicates that Configured PSK must be used as Retained PSK. */
	if(psk_retained_hash == NVME_QUIC_HASH_ALGORITHM_NONE) {
		memcpy(entry->psk, psk_configured, psk_configured_size);
		entry->psk_size = psk_configured_size;
	} else {
		uint8_t psk_retained[SPDK_TLS_PSK_MAX_LEN];
		rc = nvme_quic_derive_retained_psk(psk_configured, psk_configured_size, hostnqn, psk_retained, SPDK_TLS_PSK_MAX_LEN, psk_retained_hash);
		if(rc < 0) {
			SPDK_ERRLOG("Failed to derive Retained PSK for host NQN '%s' and subsystem NQN '%s'\n",
				    hostnqn, subsystem->subnqn);
			goto end;
		}
		/* Now derive TLS PSK from retained PSK (same as client does) */
		rc = nvme_quic_derive_tls_psk(psk_retained, rc, entry->pskid, entry->psk,
					     sizeof(entry->psk), tls_cipher_suite);
		if (rc < 0) {
			SPDK_ERRLOG("Failed to derive TLS PSK for host NQN '%s' and subsystem NQN '%s'\n",
				    hostnqn, subsystem->subnqn);
			goto end;
		}
		entry->psk_size = rc;
	}

	TAILQ_INSERT_TAIL(&qtransport->psks, entry, link);
	// SPDK_ERRLOG("Added PSK to transport: identity='%s', size=%u, hostnqn=%s, subnqn=%s\n",
	// 	       entry->pskid, entry->psk_size, entry->hostnqn, entry->subnqn);
	// SPDK_ERRLOG("QUIC server: PSK secret (full 32 bytes): "
	// 	       "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
	// 	       "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	// 	       entry->psk[0], entry->psk[1], entry->psk[2], entry->psk[3],
	// 	       entry->psk[4], entry->psk[5], entry->psk[6], entry->psk[7],
	// 	       entry->psk[8], entry->psk[9], entry->psk[10], entry->psk[11],
	// 	       entry->psk[12], entry->psk[13], entry->psk[14], entry->psk[15],
	// 	       entry->psk[16], entry->psk[17], entry->psk[18], entry->psk[19],
	// 	       entry->psk[20], entry->psk[21], entry->psk[22], entry->psk[23],
	// 	       entry->psk[24], entry->psk[25], entry->psk[26], entry->psk[27],
	// 	       entry->psk[28], entry->psk[29], entry->psk[30], entry->psk[31]);
	
	/* For now, use the first PSK in the shared TLS context */
	/* TODO: Support multiple PSKs - would need per-connection TLS contexts */
	if (TAILQ_FIRST(&qtransport->psks) == entry && qtransport->tls_ctx) {
		qtransport->tls_ctx->pre_shared_key.identity.base = (uint8_t *)entry->pskid;
		qtransport->tls_ctx->pre_shared_key.identity.len = strlen(entry->pskid);
		qtransport->tls_ctx->pre_shared_key.secret.base = entry->psk;
		qtransport->tls_ctx->pre_shared_key.secret.len = entry->psk_size;
		if (entry->psk_size == 32) {
			qtransport->tls_ctx->pre_shared_key.hash = &ptls_openssl_sha256;
		} else if (entry->psk_size == 48) {
			qtransport->tls_ctx->pre_shared_key.hash = &ptls_openssl_sha384;
		}
		SPDK_DEBUGLOG(nvmf,"Configured PSK in TLS context for server authentication\n");
	}
	
	rc = 0;

end:
	spdk_memset_s(psk_configured, sizeof(psk_configured), 0, sizeof(psk_configured));
	spdk_memset_s(psk_interchange, sizeof(psk_interchange), 0, sizeof(psk_interchange));
	free(opts.psk);
	if(rc != 0) {
		nvmf_quic_free_psk_entry(entry);
	}

	return rc;
}

static void
nvmf_quic_subsystem_remove_host(struct spdk_nvmf_transport *transport,
				const struct spdk_nvmf_subsystem *subsystem,
				const char *hostnqn)
{
	struct spdk_nvmf_quic_transport *qtransport;
	struct quic_psk_entry *entry, *tmp;

	assert(transport != NULL);
	assert(subsystem != NULL);

	qtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_quic_transport, transport);

	TAILQ_FOREACH_SAFE(entry, &qtransport->psks, link, tmp) {
		if((strncmp(entry->hostnqn, hostnqn, SPDK_NVMF_NQN_MAX_LEN)) == 0 && (strncmp(entry->subnqn, subsystem->subnqn, SPDK_NVMF_NQN_MAX_LEN)) == 0) {
			TAILQ_REMOVE(&qtransport->psks, entry, link);
			nvmf_quic_free_psk_entry(entry);
			break;
		}
	}
}

static void
nvmf_quic_subsystem_dump_host(struct spdk_nvmf_transport *transport,
			     const struct spdk_nvmf_subsystem *subsystem,
			     const char *hostnqn,
			     struct spdk_json_write_ctx *w)
{
	struct spdk_nvmf_quic_transport *qtransport;
	struct quic_psk_entry *entry;

	assert(transport != NULL);
	assert(subsystem != NULL);

	qtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_quic_transport, transport);
	TAILQ_FOREACH(entry, &qtransport->psks, link) {
		if ((strncmp(entry->hostnqn, hostnqn, SPDK_NVMF_NQN_MAX_LEN)) == 0 &&
		    (strncmp(entry->subnqn, subsystem->subnqn, SPDK_NVMF_NQN_MAX_LEN)) == 0) {
			spdk_json_write_named_string(w, "psk",  spdk_key_get_name(entry->key));
			break;
		}
	}
}


// ptls_context_t *
// quic_create_tls_context_for_psk(struct quic_psk_entry *psk_entry)
// {
// 	ptls_context_t *tls_ctx = malloc(sizeof(*tls_ctx));
// 	memcpy(ctx, )
// }



const struct spdk_nvmf_transport_ops spdk_nvmf_transport_quic = {
	.name = "QUIC",
	.type = SPDK_NVME_TRANSPORT_QUIC,
	.opts_init = nvmf_quic_opts_init,
	.create = nvmf_quic_create,
	.dump_opts = nvmf_quic_dump_opts,
	.destroy = nvmf_quic_destroy,

	.listen = nvmf_quic_listen,
	.stop_listen = nvmf_quic_stop_listen,

	.listener_discover = nvmf_quic_discover,

	.poll_group_create = nvmf_quic_poll_group_create,
	.get_optimal_poll_group = nvmf_quic_get_optimal_poll_group,
	.poll_group_destroy = nvmf_quic_poll_group_destroy,
	.poll_group_add = nvmf_quic_poll_group_add,
	.poll_group_remove = nvmf_quic_poll_group_remove,
	.poll_group_poll = nvmf_quic_poll_group_poll,

	.req_free = nvmf_quic_req_free,
	.req_complete = nvmf_quic_req_complete,
	.req_get_buffers_done = nvmf_quic_req_get_buffers_done,

	.qpair_fini = nvmf_quic_close_qpair,
	.qpair_get_local_trid = nvmf_quic_qpair_get_local_trid,
	.qpair_get_peer_trid = nvmf_quic_qpair_get_peer_trid,
	.qpair_get_listen_trid = nvmf_quic_qpair_get_listen_trid,
	.qpair_abort_request = nvmf_quic_qpair_abort_request,
	.subsystem_add_host = nvmf_quic_subsystem_add_host,
	.subsystem_remove_host = nvmf_quic_subsystem_remove_host,
	.subsystem_dump_host = nvmf_quic_subsystem_dump_host,
};

SPDK_NVMF_TRANSPORT_REGISTER(quic, &spdk_nvmf_transport_quic);
SPDK_LOG_REGISTER_COMPONENT(nvmf_quic)
