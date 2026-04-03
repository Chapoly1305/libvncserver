/*
 * ardhp_media.c
 * Helpers for extracting video bytestream payloads from ARD HP media packets.
 */

#include <rfb/rfbclient.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if defined(LIBVNCSERVER_HAVE_SRTP2)
#if defined(__has_include)
#if __has_include(<srtp3/srtp.h>)
#include <srtp3/srtp.h>
#elif __has_include(<srtp2/srtp.h>)
#include <srtp2/srtp.h>
#elif __has_include(<srtp/srtp.h>)
#include <srtp/srtp.h>
#endif
#else
#include <srtp3/srtp.h>
#endif
#endif

#include "ardhp_protocol.h"

struct rfbARDHPSRTPContext {
#if defined(LIBVNCSERVER_HAVE_SRTP2)
  srtp_t session;
  uint8_t key[ARD_HP_MEDIA_STREAM_OPTIONS_KEY_LEN];
  int short_auth_tag;
#else
  int unavailable;
#endif
};

#if defined(LIBVNCSERVER_HAVE_SRTP2)
static int g_ardhp_srtp_initialized = 0;
#endif

#if defined(LIBVNCSERVER_HAVE_SRTP2)
static rfbBool ardhp_srtp_init_once(void) {
  srtp_err_status_t st;
  if (g_ardhp_srtp_initialized) return TRUE;
  st = srtp_init();
  if (st != srtp_err_status_ok) {
    rfbClientErr("ard-hp: libsrtp init failed status=%d\n", (int)st);
    return FALSE;
  }
  g_ardhp_srtp_initialized = 1;
  return TRUE;
}
#endif

rfbARDHPSRTPContext *rfbClientARDHPSRTPCreateInboundSuite5(const uint8_t *key_material,
                                                           size_t key_len,
                                                           rfbBool short_auth_tag) {
#if defined(LIBVNCSERVER_HAVE_SRTP2)
  rfbARDHPSRTPContext *ctx = NULL;
  srtp_policy_t policy;
  srtp_err_status_t st;

  if (!key_material || key_len != ARD_HP_MEDIA_STREAM_OPTIONS_KEY_LEN) return NULL;
  if (!ardhp_srtp_init_once()) return NULL;

  ctx = (rfbARDHPSRTPContext *)calloc(1, sizeof(*ctx));
  if (!ctx) return NULL;
  memcpy(ctx->key, key_material, ARD_HP_MEDIA_STREAM_OPTIONS_KEY_LEN);
  ctx->short_auth_tag = short_auth_tag ? 1 : 0;

  memset(&policy, 0, sizeof(policy));
  if (ctx->short_auth_tag) {
    srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(&policy.rtp);
    srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(&policy.rtcp);
  } else {
    srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(&policy.rtp);
    srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(&policy.rtcp);
  }
  policy.ssrc.type = ssrc_any_inbound;
  policy.ssrc.value = 0;
  policy.key = ctx->key;
  policy.window_size = 128;
  policy.allow_repeat_tx = 1;
  policy.next = NULL;

  st = srtp_create(&ctx->session, &policy);
  if (st != srtp_err_status_ok) {
    rfbClientErr("ard-hp: libsrtp create failed status=%d (suite5 short_tag=%d)\n",
                 (int)st, ctx->short_auth_tag);
    free(ctx);
    return NULL;
  }
  return ctx;
#else
  (void)key_material;
  (void)key_len;
  (void)short_auth_tag;
  rfbClientErr("ard-hp: libsrtp2 support not built; rebuild with WITH_SRTP2=ON and libsrtp2 installed\n");
  return NULL;
#endif
}

void rfbClientARDHPSRTPDestroy(rfbARDHPSRTPContext *ctx) {
#if defined(LIBVNCSERVER_HAVE_SRTP2)
  if (!ctx) return;
  if (ctx->session) {
    srtp_dealloc(ctx->session);
    ctx->session = NULL;
  }
  memset(ctx->key, 0, sizeof(ctx->key));
  free(ctx);
#else
  (void)ctx;
#endif
}

rfbBool rfbClientARDHPSRTPUnprotectPacket(rfbARDHPSRTPContext *ctx,
                                          const uint8_t *packet,
                                          size_t packet_len,
                                          uint8_t **out_packet,
                                          size_t *out_len) {
#if defined(LIBVNCSERVER_HAVE_SRTP2)
  uint8_t *buf = NULL;
  int packet_len_i;
  size_t packet_len_z = 0;
  srtp_err_status_t st;

  if (out_packet) *out_packet = NULL;
  if (out_len) *out_len = 0;
  if (!ctx || !ctx->session || !packet || packet_len == 0 || !out_packet || !out_len) return FALSE;
  if (packet_len > (size_t)INT_MAX) return FALSE;

  buf = (uint8_t *)malloc(packet_len);
  if (!buf) return FALSE;
  packet_len_i = (int)packet_len;
#if defined(LIBVNCSERVER_HAVE_SRTP3_API)
  packet_len_z = packet_len;
  st = srtp_unprotect(ctx->session, packet, packet_len, buf, &packet_len_z);
  packet_len_i = (int)packet_len_z;
#else
  memcpy(buf, packet, packet_len);
  st = srtp_unprotect(ctx->session, buf, &packet_len_i);
#endif
  if (st != srtp_err_status_ok || packet_len_i <= 0) {
    free(buf);
    return FALSE;
  }
  *out_packet = buf;
  *out_len = (size_t)packet_len_i;
  return TRUE;
#else
  (void)ctx;
  (void)packet;
  (void)packet_len;
  (void)out_packet;
  (void)out_len;
  return FALSE;
#endif
}

static uint16_t read_be_u16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t read_be_u32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
         (uint32_t)p[3];
}

static int extract_rtp_payload_span(const uint8_t *packet, size_t packet_len,
                                    const uint8_t **out_payload, size_t *out_payload_len) {
  uint8_t b0;
  uint8_t csrc_count;
  size_t off;
  size_t end;

  if (!packet || packet_len < 12 || !out_payload || !out_payload_len) return 0;
  b0 = packet[0];
  if ((b0 >> 6) != 2) return 0;

  csrc_count = (uint8_t)(b0 & 0x0f);
  off = 12u + ((size_t)csrc_count * 4u);
  if (off > packet_len) return 0;

  if ((b0 & 0x10u) != 0) {
    uint16_t ext_words;
    if (off + 4u > packet_len) return 0;
    ext_words = read_be_u16(packet + off + 2u);
    off += 4u + ((size_t)ext_words * 4u);
    if (off > packet_len) return 0;
  }

  end = packet_len;
  if ((b0 & 0x20u) != 0) {
    uint8_t pad_len = packet[packet_len - 1u];
    if (pad_len == 0 || (size_t)pad_len > (packet_len - off)) return 0;
    end -= (size_t)pad_len;
  }
  if (end <= off) return 0;

  *out_payload = packet + off;
  *out_payload_len = end - off;
  return 1;
}

static int probe_annexb_video(const uint8_t *buf, size_t len) {
  size_t i;
  unsigned hits = 0;

  if (!buf || len < 5) return 0;
  for (i = 0; i + 4 < len; ++i) {
    size_t nal_off;
    uint8_t hdr;

    if (buf[i] == 0x00 && buf[i + 1] == 0x00 && buf[i + 2] == 0x01) {
      nal_off = i + 3;
    } else if (i + 5 < len && buf[i] == 0x00 && buf[i + 1] == 0x00 && buf[i + 2] == 0x00 &&
               buf[i + 3] == 0x01) {
      nal_off = i + 4;
    } else {
      continue;
    }
    if (nal_off >= len) continue;
    hdr = buf[nal_off];
    if (hdr & 0x80) continue;
    hits++;
  }

  return hits > 0;
}

static int convert_length_prefixed_to_annexb(const uint8_t *buf, size_t len, size_t nal_len_size,
                                             uint8_t **out_data, size_t *out_len) {
  size_t off = 0;
  size_t total = 0;
  unsigned nals = 0;
  uint8_t *out = NULL;
  size_t dst_off = 0;

  if (!buf || !out_data || !out_len || (nal_len_size != 2 && nal_len_size != 4)) return 0;

  while (off + nal_len_size <= len) {
    uint32_t nlen = 0;
    uint8_t hdr;

    if (nal_len_size == 4) {
      nlen = read_be_u32(buf + off);
    } else {
      nlen = read_be_u16(buf + off);
    }
    off += nal_len_size;
    if (nlen == 0 || off + nlen > len) return 0;
    hdr = buf[off];
    if (hdr & 0x80) return 0;

    total += 4 + (size_t)nlen;
    nals++;
    off += nlen;
  }

  if (off != len || nals == 0) return 0;

  out = (uint8_t *)malloc(total);
  if (!out) return 0;

  off = 0;
  while (off + nal_len_size <= len) {
    uint32_t nlen = 0;
    if (nal_len_size == 4) {
      nlen = read_be_u32(buf + off);
    } else {
      nlen = read_be_u16(buf + off);
    }
    off += nal_len_size;
    out[dst_off + 0] = 0x00;
    out[dst_off + 1] = 0x00;
    out[dst_off + 2] = 0x00;
    out[dst_off + 3] = 0x01;
    dst_off += 4;
    memcpy(out + dst_off, buf + off, nlen);
    dst_off += nlen;
    off += nlen;
  }

  *out_data = out;
  *out_len = total;
  return 1;
}

rfbBool rfbClientARDHPExtractVideoBytestream(uint32_t encoding, const uint8_t *packet, size_t packet_len,
                                             uint8_t **out_data, size_t *out_len,
                                             rfbBool *out_from_length_prefix) {
  const uint8_t *body = packet;
  const uint8_t *rtp_payload = NULL;
  size_t body_len = packet_len;
  size_t rtp_payload_len = 0;
  uint8_t *converted = NULL;
  size_t converted_len = 0;

  if (out_data) *out_data = NULL;
  if (out_len) *out_len = 0;
  if (out_from_length_prefix) *out_from_length_prefix = FALSE;
  if (!packet || !out_data || !out_len) return FALSE;

  if (encoding != 0x3ea && encoding != 0x3f3 && encoding != rfbEncodingH264) return FALSE;

  if (packet_len >= 2) {
    uint16_t declared = read_be_u16(packet);
    if ((size_t)declared + 2 <= packet_len) {
      body = packet + 2;
      body_len = (size_t)declared;
    }
  }
  if (!body || body_len < 5) return FALSE;
  if (extract_rtp_payload_span(body, body_len, &rtp_payload, &rtp_payload_len) && rtp_payload_len >= 5u) {
    body = rtp_payload;
    body_len = rtp_payload_len;
  }

  if (probe_annexb_video(body, body_len)) {
    uint8_t *copy = (uint8_t *)malloc(body_len);
    if (!copy) return FALSE;
    memcpy(copy, body, body_len);
    *out_data = copy;
    *out_len = body_len;
    return TRUE;
  }

  if (convert_length_prefixed_to_annexb(body, body_len, 4, &converted, &converted_len) ||
      convert_length_prefixed_to_annexb(body, body_len, 2, &converted, &converted_len)) {
    *out_data = converted;
    *out_len = converted_len;
    if (out_from_length_prefix) *out_from_length_prefix = TRUE;
    return TRUE;
  }

  return FALSE;
}
