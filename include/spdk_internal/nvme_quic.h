/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2018 Intel Corporation. All rights reserved.
 *   Copyright (c) 2020 Mellanox Technologies LTD. All rights reserved.
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef SPDK_INTERNAL_NVME_QUIC_H
#define SPDK_INTERNAL_NVME_QUIC_H

#include "spdk/likely.h"
#include "spdk/sock.h"
#include "spdk/dif.h"
#include "spdk/hexlify.h"
#include "spdk/nvmf_spec.h"
#include "spdk/util.h"
#include "spdk/base64.h"
#include "spdk/endian.h"
#include "spdk/crc32.h"

#include "sgl.h"

#include "openssl/evp.h"
#include "openssl/kdf.h"
#include "openssl/sha.h"


#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"


#define SPDK_NVMF_QUIC_RECV_BUF_SIZE_FACTOR	8
#define SPDK_NVME_QUIC_IN_CAPSULE_DATA_MAX_SIZE	4096u

// #define SPDK_NVME_QUIC_MAX_UDP_DATAGRAM_SIZE		1472u
// #define SPDK_NVME_QUIC_MAX_SEND_PACKETS		64u

// MTU 1500
#define SPDK_NVME_QUIC_MAX_UDP_DATAGRAM_SIZE		1472u

// MTU 9000
// #define SPDK_NVME_QUIC_MAX_UDP_DATAGRAM_SIZE		8972u
#define SPDK_NVME_QUIC_MAX_SEND_PACKETS		128u  /* 128 × 1472 = 184 KB/batch; reduces syscalls, fits L2 cache */

#define SPDK_NVME_QUIC_MAX_STREAM_BIDI		1024u


#define UDP_RECV_BATCH_SIZE     64  /* Match send batch size for balanced recv/send throughput */

/* Each recv slot must be large enough to hold a full UDP GRO super-segment.
 * The kernel coalesces up to 64KB, so allocate that much per slot. */
#define UDP_RECV_BATCH_BUF_SIZE 65536
/* Space for the UDP_GRO cmsg (gso_size) returned per slot */
#define UDP_RECV_CMSG_SIZE      CMSG_SPACE(sizeof(uint16_t))

/*
 * Maximum number of SGL elements.
 */
#define NVME_QUIC_MAX_SGL_DESCRIPTORS	(16)


#define nvme_quic_stream_container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))


#define NVMF_PSK_IDENTITY_LEN (SPDK_NVMF_NQN_MAX_LEN + SPDK_NVMF_NQN_MAX_LEN + 11)

#define NVME_QUIC_HKDF_INFO_MAX_LEN 514

#define PSK_ID_PREFIX "NVMe0R"

enum nvme_quic_cipher_suite {
	NVME_QUIC_CIPHER_AES_128_GCM_SHA256,
	NVME_QUIC_CIPHER_AES_256_GCM_SHA384,
};

enum nvme_quic_hash_algorithm {
	NVME_QUIC_HASH_ALGORITHM_NONE,
	NVME_QUIC_HASH_ALGORITHM_SHA256,
	NVME_QUIC_HASH_ALGORITHM_SHA384,
};


typedef void (*nvme_quic_qpair_xfer_complete_cb)(void *cb_arg);

enum nvme_quic_stream_recv_state {
	/* Ready to wait for PDU */
	NVME_QUIC_RECV_STATE_AWAIT_STREAM_READY,

	/* Active qqpair waiting for any PDU common header */
	NVME_QUIC_RECV_STATE_AWAIT_CMD,

	/* Active qqpair waiting for a quic request, only use in target side */
	NVME_QUIC_RECV_STATE_AWAIT_REQ,

	/* Active qqpair waiting for a free buffer to store PDU */
	NVME_QUIC_RECV_STATE_AWAIT_PDU_BUF,

	/* Active qqpair waiting for Read/Write Data */
	NVME_QUIC_RECV_STATE_AWAIT_DATA,

	/* Active qqpair waiting for all outstanding PDUs to complete */
	NVME_QUIC_RECV_STATE_QUIESCING,

	/* Active qqpair does not wait for payload */
	NVME_QUIC_RECV_STATE_ERROR,
};

/* Put this format for send buf for stream-based callback */
struct spdk_nvmf_quic_sendbuf_element_t {
	void		*buf;
	struct nvme_quic_stream		*nvme_stream;
};


struct spdk_udp_recv_batch {
	uint8_t                 bufs[UDP_RECV_BATCH_SIZE][UDP_RECV_BATCH_BUF_SIZE];
	struct iovec            iovecs[UDP_RECV_BATCH_SIZE];
	struct sockaddr_storage addrs[UDP_RECV_BATCH_SIZE];
	/* per-slot cmsg buffer to receive UDP_GRO gso_size annotation */
	uint8_t                 cmsgs[UDP_RECV_BATCH_SIZE][UDP_RECV_CMSG_SIZE];
	struct mmsghdr          msgs[UDP_RECV_BATCH_SIZE];
};

/* Initialise all iov/name pointers inside a batch so they're ready to pass to recvmmsg. */
static inline void
nvme_quic_recv_batch_init(struct spdk_udp_recv_batch *b)
{
	int i;
	for (i = 0; i < UDP_RECV_BATCH_SIZE; i++) {
			b->iovecs[i].iov_base            = b->bufs[i];
			b->iovecs[i].iov_len             = UDP_RECV_BATCH_BUF_SIZE;
			b->msgs[i].msg_hdr.msg_iov       = &b->iovecs[i];
			b->msgs[i].msg_hdr.msg_iovlen    = 1;
			b->msgs[i].msg_hdr.msg_name      = &b->addrs[i];
			b->msgs[i].msg_hdr.msg_namelen   = sizeof(b->addrs[i]);
			/* Provide cmsg buffer so kernel can write UDP_GRO gso_size */
			b->msgs[i].msg_hdr.msg_control   = b->cmsgs[i];
			b->msgs[i].msg_hdr.msg_controllen = UDP_RECV_CMSG_SIZE;
			b->msgs[i].msg_hdr.msg_flags     = 0;
	}
}

struct nvme_quic_stream {
	/* For containerof pattern of streambuf */
	quicly_streambuf_t			streambuf;

	/* QUIC stream pointer - stream->data points back to nvme_quic_stream */
	quicly_stream_t				*quic_stream;

	void	(*cb_fn)(void *cb_arg);
	void					*cb_arg;

	/*
	 * Two send vecs cover all cases on both sides:
	 *   client:  hdr_buf = NVMe command (64B), data_buf = in-capsule / H2C data
	 *   server:  hdr_buf = NVMe completion (16B) or R2T PDU (8B, never simultaneous),
	 *            data_buf = C2H data
	 * rsp_buf and r2t_buf were removed; they share hdr_buf since they are never
	 * simultaneously live in quicly's sendbuf queue.
	 */
	quicly_sendbuf_vec_t		hdr_buf;
	quicly_sendbuf_vec_t		data_buf;

	/* Callback elements — one per live send vec */
	struct spdk_nvmf_quic_sendbuf_element_t hdr_element;
	struct spdk_nvmf_quic_sendbuf_element_t data_element;

	uint32_t					rw_offset;

	/* Receive state */
	enum nvme_quic_stream_recv_state	recv_state;

	void						*req;   /* nvme_quic_req* or nvmf_quic_req* */
	void						*qpair; /* owning nvme_quic_qpair* (persists for stream lifetime) */

	bool					in_pending_queue;

	/* Free-list linkage — used by target-side (nvmf/quic.c) stream pool. */
	TAILQ_ENTRY(nvme_quic_stream)		stream_link;
};

/* Ensure data_buf array is properly aligned for efficient I/O operations */
SPDK_STATIC_ASSERT(offsetof(struct nvme_quic_stream, data_buf) % 8 == 0,
		   "data_buf is not 8-byte aligned");

/* For r2t grant type */
struct spdk_nvme_quic_r2t {
	uint32_t r2to;
	uint32_t r2tl;
};


enum nvme_quic_error_codes {
	NVME_QUIC_PDU_IN_PROGRESS        = 0,
	NVME_QUIC_CONNECTION_FATAL       = -1,
	NVME_QUIC_PDU_FATAL              = -2,
};

static inline void
_nvme_quic_sgl_get_buf(struct spdk_iov_sgl *s, void **_buf, uint32_t *_buf_len)
{
	if (_buf != NULL) {
		*_buf = (uint8_t *)s->iov->iov_base + s->iov_offset;
	}
	if (_buf_len != NULL) {
		*_buf_len = s->iov->iov_len - s->iov_offset;
	}
}

static inline bool
_nvme_quic_sgl_append_multi(struct spdk_iov_sgl *s, struct iovec *iov, int iovcnt)
{
	int i;

	for (i = 0; i < iovcnt; i++) {
		if (!spdk_iov_sgl_append(s, iov[i].iov_base, iov[i].iov_len)) {
			return false;
		}
	}

	return true;
}

static inline uint32_t
_get_iov_array_size(struct iovec *iov, int iovcnt)
{
	int i;
	uint32_t size = 0;

	for (i = 0; i < iovcnt; i++) {
		size += iov[i].iov_len;
	}

	return size;
}

static inline bool
_nvme_quic_sgl_append_multi_with_md(struct spdk_iov_sgl *s, struct iovec *iov, int iovcnt,
				   uint32_t data_len, const struct spdk_dif_ctx *dif_ctx)
{
	int rc;
	uint32_t mapped_len = 0;

	if (s->iov_offset >= data_len) {
		s->iov_offset -= _get_iov_array_size(iov, iovcnt);
	} else {
		rc = spdk_dif_set_md_interleave_iovs(s->iov, s->iovcnt, iov, iovcnt,
						     s->iov_offset, data_len - s->iov_offset,
						     &mapped_len, dif_ctx);
		if (rc < 0) {
			SPDK_ERRLOG("Failed to setup iovs for DIF insert/strip.\n");
			return false;
		}

		s->total_size += mapped_len;
		s->iov_offset = 0;
		assert(s->iovcnt >= rc);
		s->iovcnt -= rc;
		s->iov += rc;

		if (s->iovcnt == 0) {
			return false;
		}
	}

	return true;
}

static int
nvme_quic_build_payload_iovs(struct iovec *iov, int iovcnt, struct iovec *data_iov,
			    uint32_t data_iovcnt, uint32_t rw_offset, uint32_t *_mapped_length)
{
	struct spdk_iov_sgl sgl;

	if (iovcnt == 0) {
		return 0;
	}

	spdk_iov_sgl_init(&sgl, iov, iovcnt, rw_offset);

	/* Append the data buffers starting from rw_offset */
	if (!_nvme_quic_sgl_append_multi(&sgl, data_iov, data_iovcnt)) {
		goto end;
	}

end:
	if (_mapped_length != NULL) {
		*_mapped_length = sgl.total_size;
	}
	return iovcnt - sgl.iovcnt;
}

static int
nvme_quic_read_data(struct spdk_sock *sock, int bytes,
		   void *buf)
{
	return spdk_sock_recv(sock, buf, bytes);
}


static int
nvme_quic_read_data_with_msghdr(struct spdk_sock *sock, struct mmsghdr *msgs, int vlen)
{
    return spdk_sock_recv_with_msghdr(sock, msgs, vlen);
}


static int
nvme_quic_readv_data(struct spdk_sock *sock, struct iovec *iov, int iovcnt)
{
	int ret;

	assert(sock != NULL);
	if (iov == NULL || iovcnt == 0) {
		return 0;
	}

	if (iovcnt == 1) {
		return nvme_quic_read_data(sock, iov->iov_len, iov->iov_base);
	}

	ret = spdk_sock_readv(sock, iov, iovcnt);

	if (ret > 0) {
		return ret;
	}

	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}

		/* For connect reset issue, do not output error log */
		if (errno != ECONNRESET) {
			SPDK_ERRLOG("spdk_sock_readv() failed, errno %d: %s\n",
				    errno, spdk_strerror(errno));
		}
	}

	/* connection closed */
	return NVME_QUIC_CONNECTION_FATAL;
}


static void
nvme_quic_stream_set_data_buf(struct nvme_quic_stream *stream,
			  struct iovec *iov, uint32_t len, quicly_streambuf_sendvec_callbacks_t *cb)
{
	stream->data_buf.cb = cb;
	stream->data_buf.len = len;

	stream->data_element.buf = iov;
	stream->data_element.nvme_stream = stream;

	stream->data_buf.cbdata = &stream->data_element;
}

static void
nvme_quic_stream_set_cmd_buf(struct nvme_quic_stream *stream,
			 struct spdk_nvme_cmd *cmd,
			 quicly_streambuf_sendvec_callbacks_t *cb)
{
	stream->hdr_buf.cb = cb;
	stream->hdr_buf.len = 64; /* NVMe command size */

	stream->hdr_element.buf = cmd;
	stream->hdr_element.nvme_stream = stream;

	stream->hdr_buf.cbdata = &stream->hdr_element;
}

static void
nvme_quic_stream_set_rsp_buf(struct nvme_quic_stream *stream,
			 struct spdk_nvme_cpl *rsp,
			 quicly_streambuf_sendvec_callbacks_t *cb)
{
	stream->hdr_buf.cb = cb;
	stream->hdr_buf.len = 16; /* NVMe completion size */

	stream->hdr_element.buf = rsp;
	stream->hdr_element.nvme_stream = stream;

	stream->hdr_buf.cbdata = &stream->hdr_element;
}

static void
nvme_quic_stream_set_r2t_buf(struct nvme_quic_stream *stream,
			 struct spdk_nvme_quic_r2t *r2t,
			 quicly_streambuf_sendvec_callbacks_t *cb)
{
	/* R2T and RSP (rsp_buf) are never simultaneously live — both reuse hdr_buf */
	stream->hdr_buf.cb = cb;
	stream->hdr_buf.len = sizeof(struct spdk_nvme_quic_r2t);

	stream->hdr_element.buf = r2t;
	stream->hdr_element.nvme_stream = stream;

	stream->hdr_buf.cbdata = &stream->hdr_element;
}



static inline int
nvme_quic_generate_psk_identity(char *out_id, size_t out_id_len, const char *hostnqn,
			       const char *subnqn, enum nvme_quic_cipher_suite tls_cipher_suite)
{
	int rc;

	assert(out_id != NULL);

	if (out_id_len < strlen(PSK_ID_PREFIX) + strlen(hostnqn) + strlen(subnqn) + 5) {
		SPDK_ERRLOG("Out buffer too small!\n");
		return -1;
	}

	if (tls_cipher_suite == NVME_QUIC_CIPHER_AES_128_GCM_SHA256) {
		rc = snprintf(out_id, out_id_len, "%s%s %s %s", PSK_ID_PREFIX, "01",
			      hostnqn, subnqn);
	} else if (tls_cipher_suite == NVME_QUIC_CIPHER_AES_256_GCM_SHA384) {
		rc = snprintf(out_id, out_id_len, "%s%s %s %s", PSK_ID_PREFIX, "02",
			      hostnqn, subnqn);
	} else {
		SPDK_ERRLOG("Unknown cipher suite requested!\n");
		return -EOPNOTSUPP;
	}

	if (rc < 0) {
		SPDK_ERRLOG("Could not generate PSK identity\n");
		return -1;
	}

	return 0;
}


static inline int
nvme_quic_derive_tls_psk(const uint8_t *psk_in, uint64_t psk_in_size, const char *psk_identity, uint8_t *psk_out, uint64_t psk_out_size, enum nvme_quic_cipher_suite tls_cipher_suite) 
{
	EVP_PKEY_CTX *ctx;
	uint64_t digest_len = 0;
	char hkdf_info[NVME_QUIC_HKDF_INFO_MAX_LEN] = {};
	const char *label = "tls13 nvme-tls-psk";
	size_t pos, labellen, idlen;
	const EVP_MD *hash;
	int rc, hkdf_info_size;

	if(tls_cipher_suite == NVME_QUIC_CIPHER_AES_128_GCM_SHA256) {
		digest_len = SHA256_DIGEST_LENGTH;
		hash = EVP_sha256();
	} else if(tls_cipher_suite == NVME_QUIC_CIPHER_AES_256_GCM_SHA384) {
		digest_len = SHA384_DIGEST_LENGTH;
		hash = EVP_sha384();
	} else {
		SPDK_ERRLOG("Unkown cipher suite requested!\n");
		return -EOPNOTSUPP;
	}

	labellen = strlen(label);
	idlen = strlen(psk_identity);
	if(idlen > UINT8_MAX) {
		SPDK_ERRLOG("PSK identity length too long!\n");
		return -EINVAL;
	}

	*(uint16_t *)&hkdf_info[0] = htons(psk_in_size);
	pos = sizeof(uint16_t);
	hkdf_info[pos] = (uint8_t)labellen;
	pos += sizeof(uint8_t);
	memcpy(&hkdf_info[pos], label, labellen);
	pos += labellen;
	hkdf_info[pos] = (uint8_t)idlen;
	pos += sizeof(uint8_t);
	memcpy(&hkdf_info[pos], psk_identity, idlen);
	pos += idlen;
	hkdf_info_size = pos;

	if (digest_len > psk_out_size) {
		SPDK_ERRLOG("PSK output buffer too small!\n");
		return -EINVAL;
	}

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if(!ctx) {
		SPDK_ERRLOG("Unable to initialize EVP_PKEY_CTX!\n");
		return -1;
	}

	if(EVP_PKEY_derive_init(ctx) != 1) {
		SPDK_ERRLOG("Unable to initialize key derivation ctx for HKDF!\n");
		rc = -ENOMEM;
		goto end;
	}
	if (EVP_PKEY_CTX_set_hkdf_md(ctx, hash) != 1) {
		SPDK_ERRLOG("Unable to set hash method for HKDF!\n");
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

static inline int
nvme_quic_parse_interchange_psk(const char *psk_in, uint8_t *psk_out, size_t psk_out_size,
			       uint64_t *psk_out_decoded_size, uint8_t *hash)
{
	const char *delim = ":";
	char psk_cpy[SPDK_TLS_PSK_MAX_LEN] = {};
	char *sp = NULL;
	uint8_t psk_base64_decoded[SPDK_TLS_PSK_MAX_LEN] = {};
	uint64_t psk_configured_size = 0;
	uint32_t crc32_calc, crc32;
	char *psk_base64;
	uint64_t psk_base64_decoded_size = 0;
	int rc;

	/* Verify PSK format. */
	if (sscanf(psk_in, "NVMeTLSkey-1:%02hhx:", hash) != 1 || psk_in[strlen(psk_in) - 1] != delim[0]) {
		SPDK_ERRLOG("Invalid format of PSK interchange!\n");
		return -EINVAL;
	}

	if (strlen(psk_in) >= SPDK_TLS_PSK_MAX_LEN) {
		SPDK_ERRLOG("PSK interchange exceeds maximum %d characters!\n", SPDK_TLS_PSK_MAX_LEN);
		return -EINVAL;
	}
	if (*hash != NVME_QUIC_HASH_ALGORITHM_NONE && *hash != NVME_QUIC_HASH_ALGORITHM_SHA256 &&
	    *hash != NVME_QUIC_HASH_ALGORITHM_SHA384) {
		SPDK_ERRLOG("Invalid PSK length!\n");
		return -EINVAL;
	}

	/* Check provided hash function string. */
	memcpy(psk_cpy, psk_in, strlen(psk_in));
	strtok_r(psk_cpy, delim, &sp);
	strtok_r(NULL, delim, &sp);

	psk_base64 = strtok_r(NULL, delim, &sp);
	if (psk_base64 == NULL) {
		SPDK_ERRLOG("Could not get base64 string from PSK interchange!\n");
		return -EINVAL;
	}

	rc = spdk_base64_decode(psk_base64_decoded, &psk_base64_decoded_size, psk_base64);
	if (rc) {
		SPDK_ERRLOG("Could not decode base64 PSK!\n");
		return -EINVAL;
	}

	switch (*hash) {
	case NVME_QUIC_HASH_ALGORITHM_SHA256:
		psk_configured_size = SHA256_DIGEST_LENGTH;
		break;
	case NVME_QUIC_HASH_ALGORITHM_SHA384:
		psk_configured_size = SHA384_DIGEST_LENGTH;
		break;
	case NVME_QUIC_HASH_ALGORITHM_NONE:
		if (psk_base64_decoded_size == SHA256_DIGEST_LENGTH + SPDK_CRC32_SIZE_BYTES) {
			psk_configured_size = SHA256_DIGEST_LENGTH;
		} else if (psk_base64_decoded_size == SHA384_DIGEST_LENGTH + SPDK_CRC32_SIZE_BYTES) {
			psk_configured_size = SHA384_DIGEST_LENGTH;
		}
		break;
	default:
		SPDK_ERRLOG("Invalid key: unsupported key hash\n");
		assert(0);
		return -EINVAL;
	}
	if (psk_base64_decoded_size != psk_configured_size + SPDK_CRC32_SIZE_BYTES) {
		SPDK_ERRLOG("Invalid key: unsupported key length\n");
		return -EINVAL;
	}

	crc32 = from_le32(&psk_base64_decoded[psk_configured_size]);

	crc32_calc = spdk_crc32_ieee_update(psk_base64_decoded, psk_configured_size, ~0);
	crc32_calc = ~crc32_calc;

	if (crc32 != crc32_calc) {
		SPDK_ERRLOG("CRC-32 checksums do not match!\n");
		return -EINVAL;
	}

	if (psk_configured_size > psk_out_size) {
		SPDK_ERRLOG("Insufficient buffer size: %lu for configured PSK of size: %lu!\n",
			    psk_out_size, psk_configured_size);
		return -ENOBUFS;
	}
	memcpy(psk_out, psk_base64_decoded, psk_configured_size);
	*psk_out_decoded_size = psk_configured_size;

	return rc;
}

/**
 * Create a plaintext (unencrypted) CID encryptor for NVMe-oF QUIC.
 * 
 * This encryptor directly embeds the thread_id in the CID bytes without encryption,
 * allowing eBPF to extract it for SO_REUSEPORT load balancing.
 *
 * @return Pointer to CID encryptor, or NULL on allocation failure
 */
quicly_cid_encryptor_t *nvme_quic_new_plaintext_cid_encryptor(void);

/**
 * Free a plaintext CID encryptor created by nvme_quic_new_plaintext_cid_encryptor.
 *
 * @param encryptor Pointer to the encryptor to free
 */
void nvme_quic_free_plaintext_cid_encryptor(quicly_cid_encryptor_t *encryptor);


#endif /* SPDK_INTERNAL_NVME_QUIC_H */
