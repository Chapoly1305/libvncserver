#include <rfb/rfbclient.h>

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include "applehp.h"
#include "applehp_protocol.h"

static const int32_t kAppleHPNativePostAuthEncodings[] = {
    0x6,
    0x10,
    (int32_t)0xffffff11u,
    APPLE_HP_ENCODING_CURSOR_IMAGE,
    APPLE_HP_ENCODING_POINTER_REBASE,
    (int32_t)0xffffff21u,
    APPLE_HP_ENCODING_DISPLAY_LAYOUT_SELECTOR,
    APPLE_HP_ENCODING_DISPLAY_LAYOUT,
    APPLE_HP_ENCODING_DISPLAY_MODE,
    APPLE_HP_ENCODING_KEYBOARD_LAYOUT,
    APPLE_HP_ENCODING_DISPLAY_INFO,
};
static const int32_t kAppleHPProModeEncoding = APPLE_HP_ENCODING_MEDIA_STREAM;

struct apple_hp_transport_state {
  int active;
  uint8_t wrap_key[16];
  uint8_t cbc_key[16];
  uint8_t send_iv[16];
  uint8_t recv_iv[16];
  uint32_t send_seq;
  uint32_t recv_seq;
  uint8_t *recv_buf;
  size_t recv_len;
  size_t recv_off;
  size_t recv_cap;
};

struct apple_hp_client_state {
  struct apple_hp_transport_state transport;
  uint32_t recv_records;
};

static char kAppleHPClientDataTag = 0;

static struct apple_hp_client_state *apple_hp_state(rfbClient *client) {
  struct apple_hp_client_state *state;

  if (!client) return NULL;
  state = (struct apple_hp_client_state *)rfbClientGetClientData(client, &kAppleHPClientDataTag);
  if (state) return state;
  state = (struct apple_hp_client_state *)calloc(1, sizeof(*state));
  if (!state) return NULL;
  rfbClientSetClientData(client, &kAppleHPClientDataTag, state);
  return state;
}

static const struct apple_hp_client_state *apple_hp_state_const(const rfbClient *client) {
  return client ? (const struct apple_hp_client_state *)rfbClientGetClientData((rfbClient *)client, &kAppleHPClientDataTag) : NULL;
}

static int apple_hp_env_flag_enabled(const char *name) {
  const char *s = getenv(name);
  if (!s || !*s) return 0;
  if (!strcmp(s, "0")) return 0;
  if (!strcmp(s, "false")) return 0;
  if (!strcmp(s, "FALSE")) return 0;
  if (!strcmp(s, "no")) return 0;
  if (!strcmp(s, "NO")) return 0;
  return 1;
}

static const char *apple_hp_encoding_name(int32_t encoding) {
  switch ((uint32_t)encoding) {
    case 0x00000006u: return "Zlib";
    case 0x00000010u: return "ZRLE";
    case 0xffffff11u: return "RichCursor";
    case 0xffffff21u: return "NewFBSize";
    case 0x0000044cu: return "ApplePointerRebase";
    case 0x0000044du: return "AppleDisplayLayoutSelector";
    case 0x00000450u: return "AppleCursorImage";
    case 0x00000451u: return "AppleDisplayLayout";
    case 0x00000453u: return "AppleVendorKeysym";
    case 0x00000455u: return "AppleKeyboardInputSource";
    case 0x00000456u: return "AppleDeviceInfo";
    case 0x000003f2u: return "RFBMediaStream";
    default: return "Unknown";
  }
}

static void apple_hp_log_post_auth_encodings(const int32_t *encodings, size_t count) {
  size_t i;

  rfbClientLog("apple-hp: post-auth encodings (%lu)\n", (unsigned long)count);
  for (i = 0; i < count; ++i) {
    rfbClientLog("apple-hp:   [%lu] %11d 0x%08x %s\n",
                 (unsigned long)i,
                 encodings[i],
                 (uint32_t)encodings[i],
                 apple_hp_encoding_name(encodings[i]));
  }
}

static int wait_for_socket_io(int fd, int want_write) {
  fd_set rfds;
  fd_set wfds;

  for (;;) {
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    if (want_write)
      FD_SET(fd, &wfds);
    else
      FD_SET(fd, &rfds);
    if (select(fd + 1, want_write ? NULL : &rfds, want_write ? &wfds : NULL, NULL, NULL) > 0)
      return 1;
    if (errno == EINTR) continue;
    return 0;
  }
}

static int raw_read_exact(rfbClient *client, void *out, size_t len) {
  uint8_t *p = (uint8_t *)out;

  if (!client) return 0;
  while (len > 0) {
    if (client->buffered > 0) {
      size_t take = client->buffered < len ? client->buffered : len;
      memcpy(p, client->bufoutptr, take);
      client->bufoutptr += take;
      client->buffered -= take;
      p += take;
      len -= take;
      continue;
    }
    {
      ssize_t n = read(client->sock, p, len);
      if (n < 0) {
        if (errno == EINTR) continue;
        if ((errno == EAGAIN || errno == EWOULDBLOCK) && wait_for_socket_io(client->sock, 0))
          continue;
        rfbClientErr("apple-hp transport: read failed (%d: %s)\n", errno, strerror(errno));
        return 0;
      }
      if (n == 0) {
        rfbClientLog("apple-hp transport: server closed connection\n");
        return 0;
      }
      p += (size_t)n;
      len -= (size_t)n;
    }
  }
  return 1;
}

static int raw_write_exact(rfbClient *client, const void *buf, size_t len) {
  const uint8_t *p = (const uint8_t *)buf;

  while (len > 0) {
    ssize_t n = write(client->sock, p, len);
    if (n < 0) {
      if (errno == EINTR) continue;
      if ((errno == EAGAIN || errno == EWOULDBLOCK) && wait_for_socket_io(client->sock, 1))
        continue;
      rfbClientErr("apple-hp transport: write failed (%d: %s)\n", errno, strerror(errno));
      return 0;
    }
    if (n == 0) {
      rfbClientErr("apple-hp transport: short write\n");
      return 0;
    }
    p += (size_t)n;
    len -= (size_t)n;
  }
  return 1;
}

static int aes_crypt(int op, int options, const uint8_t *key, const uint8_t *iv,
                     const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
  CCCryptorStatus st;
  size_t moved = 0;

  st = CCCrypt((CCOperation)op, kCCAlgorithmAES128, (CCOptions)options, key, 16, iv,
               in, in_len, out, in_len, &moved);
  if (st != kCCSuccess || moved != in_len) {
    rfbClientErr("apple-hp transport: CCCrypt failed status=%d moved=%zu expected=%zu\n",
                 (int)st, moved, in_len);
    return 0;
  }
  if (out_len) *out_len = moved;
  return 1;
}

static int aes_ecb_decrypt_block(const uint8_t *key, const uint8_t *in, uint8_t *out) {
  size_t out_len = 0;
  return aes_crypt(kCCDecrypt, kCCOptionECBMode, key, NULL, in, 16, out, &out_len);
}

static uint16_t apple_hp_read_be_u16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t apple_hp_read_be_u32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
         (uint32_t)p[3];
}

static int send_blob(rfbClient *client, const void *buf, size_t len, const char *label) {
  if (!client || !buf || !label || len == 0) return 0;
  rfbClientLog("%s: sending %zu bytes\n", label, len);
  return WriteToRFBServer(client, (const char *)buf, (unsigned int)len);
}

static void patch_display_configuration_dimensions(struct apple_hp_display_configuration_message *msg,
                                                   uint16_t logical_w,
                                                   uint16_t logical_h) {
  static const struct {
    uint32_t width;
    uint32_t height;
    uint32_t scaled_width;
    uint32_t scaled_height;
    double refresh_rate;
    uint32_t flags;
  } kBaseModes[APPLE_HP_DISPLAY_CONFIG_MODE_COUNT] = {
      {3840, 2160, 1920, 1080, 60.0, 0},
      {2880, 1800, 1440, 900, 60.0, 0},
      {3840, 2160, 1920, 1080, 60.0, 0},
      {2880, 1620, 1440, 810, 60.0, 0},
      {2624, 1696, 1312, 848, 60.0, 0},
  };
  size_t i;
  uint32_t max_w = 0;
  uint32_t max_h = 0;
  double sx;
  double sy;

  if (!msg || logical_w == 0 || logical_h == 0) return;

  sx = (double)logical_w / 1920.0;
  sy = (double)logical_h / 1080.0;
  apple_hp_store_be32(msg->display.display_flags_be,
                      APPLE_HP_DISPLAY_CONFIG_FLAG_DYNAMIC_RESOLUTION);
  apple_hp_store_be16(msg->display.current_mode_index_be, 0);
  apple_hp_store_be16(msg->display.preferred_mode_index_be, 0);
  for (i = 0; i < APPLE_HP_DISPLAY_CONFIG_MODE_COUNT; ++i) {
    uint32_t width = (uint32_t)((kBaseModes[i].width * sx) + 0.5);
    uint32_t height = (uint32_t)((kBaseModes[i].height * sy) + 0.5);
    uint32_t scaled_width = (uint32_t)((kBaseModes[i].scaled_width * sx) + 0.5);
    uint32_t scaled_height = (uint32_t)((kBaseModes[i].scaled_height * sy) + 0.5);
    if (width == 0) width = logical_w;
    if (height == 0) height = logical_h;
    if (scaled_width == 0) scaled_width = logical_w;
    if (scaled_height == 0) scaled_height = logical_h;
    if (width > max_w) max_w = width;
    if (height > max_h) max_h = height;
    apple_hp_store_be32(msg->display.modes[i].width_be, width);
    apple_hp_store_be32(msg->display.modes[i].height_be, height);
    apple_hp_store_be32(msg->display.modes[i].scaled_width_be, scaled_width);
    apple_hp_store_be32(msg->display.modes[i].scaled_height_be, scaled_height);
    apple_hp_store_be_double(msg->display.modes[i].refresh_rate_be, kBaseModes[i].refresh_rate);
    apple_hp_store_be32(msg->display.modes[i].flags_be, kBaseModes[i].flags);
  }
  if (max_w == 0) max_w = (uint32_t)logical_w * 2u;
  if (max_h == 0) max_h = (uint32_t)logical_h * 2u;
  apple_hp_store_be32(msg->display.max_width_be, max_w);
  apple_hp_store_be32(msg->display.max_height_be, max_h);
  apple_hp_store_be_float(msg->display.physical_width_be, (float)(max_w * (1.0 / 10.4)));
  apple_hp_store_be_float(msg->display.physical_height_be, (float)(max_h * (1.0 / 10.4)));
}

static int apple_hp_read_next_record(rfbClient *client, struct apple_hp_transport_state *st) {
  struct apple_hp_client_state *state = apple_hp_state(client);
  uint8_t hdr[2];
  uint8_t *cipher = NULL;
  uint8_t *plain = NULL;
  uint16_t cipher_len;
  uint16_t body_len;
  uint8_t seq_be[4];
  uint8_t digest[CC_SHA1_DIGEST_LENGTH];
  size_t moved = 0;
  size_t total_min;

  if (!raw_read_exact(client, hdr, sizeof(hdr))) return 0;
  cipher_len = apple_hp_read_be_u16(hdr);
  if (cipher_len == 0 || (cipher_len % 16) != 0) {
    rfbClientErr("apple-hp transport: invalid record length %u\n", (unsigned)cipher_len);
    return 0;
  }
  cipher = (uint8_t *)malloc(cipher_len);
  plain = (uint8_t *)malloc(cipher_len);
  if (!cipher || !plain) goto fail;
  if (!raw_read_exact(client, cipher, cipher_len)) goto fail;
  if (!aes_crypt(kCCDecrypt, 0, st->cbc_key, st->recv_iv, cipher, cipher_len, plain, &moved)) goto fail;
  if (moved != cipher_len || cipher_len < 22) goto fail;
  body_len = apple_hp_read_be_u16(plain);
  total_min = (size_t)body_len + 22u;
  if (total_min > cipher_len) {
    rfbClientErr("apple-hp transport: body len %u exceeds record size %u\n",
                 (unsigned)body_len, (unsigned)cipher_len);
    goto fail;
  }
  apple_hp_store_be32(seq_be, st->recv_seq);
  {
    CC_SHA1_CTX ctx;
    CC_SHA1_Init(&ctx);
    CC_SHA1_Update(&ctx, seq_be, sizeof(seq_be));
    CC_SHA1_Update(&ctx, plain, cipher_len - CC_SHA1_DIGEST_LENGTH);
    CC_SHA1_Final(digest, &ctx);
  }
  if (memcmp(digest, plain + cipher_len - CC_SHA1_DIGEST_LENGTH, CC_SHA1_DIGEST_LENGTH) != 0) {
    rfbClientErr("apple-hp transport: checksum mismatch seq=%u cipher_len=%u body_len=%u\n",
                 st->recv_seq, (unsigned)cipher_len, (unsigned)body_len);
    goto fail;
  }
  st->recv_seq++;
  if (state) state->recv_records++;
  if (body_len > st->recv_cap) {
    uint8_t *next = (uint8_t *)realloc(st->recv_buf, body_len);
    if (!next) goto fail;
    st->recv_buf = next;
    st->recv_cap = body_len;
  }
  memcpy(st->recv_buf, plain + 2, body_len);
  st->recv_len = body_len;
  st->recv_off = 0;
  memcpy(st->recv_iv, cipher + cipher_len - 16, 16);
  free(cipher);
  free(plain);
  return 1;

fail:
  free(cipher);
  free(plain);
  return 0;
}

static rfbBool apple_hp_transport_read(rfbClient *client, char *out, unsigned int n) {
  struct apple_hp_client_state *state = apple_hp_state(client);
  struct apple_hp_transport_state *st;
  size_t copied = 0;

  if (!state || !out) return FALSE;
  st = &state->transport;
  while (copied < n) {
    if (st->recv_off >= st->recv_len) {
      st->recv_off = 0;
      st->recv_len = 0;
      if (!apple_hp_read_next_record(client, st)) return FALSE;
    }
    {
      size_t avail = st->recv_len - st->recv_off;
      size_t take = avail;
      if (take > (size_t)(n - copied)) take = (size_t)(n - copied);
      memcpy(out + copied, st->recv_buf + st->recv_off, take);
      st->recv_off += take;
      copied += take;
    }
  }
  return TRUE;
}

static rfbBool apple_hp_transport_write(rfbClient *client, const char *buf, unsigned int n) {
  struct apple_hp_client_state *state = apple_hp_state(client);
  struct apple_hp_transport_state *st;
  size_t plain_len;
  size_t filler_len;
  uint8_t *plain = NULL;
  uint8_t *cipher = NULL;
  uint8_t hdr[2];
  uint8_t seq_be[4];
  size_t moved = 0;

  if (!state || !buf) return FALSE;
  st = &state->transport;
  plain_len = ((size_t)n + 22u + 15u) & ~((size_t)15u);
  plain = (uint8_t *)calloc(1, plain_len);
  cipher = (uint8_t *)malloc(plain_len);
  if (!plain || !cipher) goto fail;

  apple_hp_store_be16(plain, (uint16_t)n);
  memcpy(plain + 2, buf, n);
  filler_len = plain_len - ((size_t)n + 2u + CC_SHA1_DIGEST_LENGTH);
  (void)filler_len;
  apple_hp_store_be32(seq_be, st->send_seq);
  {
    CC_SHA1_CTX ctx;
    CC_SHA1_Init(&ctx);
    CC_SHA1_Update(&ctx, seq_be, sizeof(seq_be));
    CC_SHA1_Update(&ctx, plain, plain_len - CC_SHA1_DIGEST_LENGTH);
    CC_SHA1_Final(plain + plain_len - CC_SHA1_DIGEST_LENGTH, &ctx);
  }
  if (!aes_crypt(kCCEncrypt, 0, st->cbc_key, st->send_iv, plain, plain_len, cipher, &moved)) goto fail;
  apple_hp_store_be16(hdr, (uint16_t)moved);
  if (!raw_write_exact(client, hdr, sizeof(hdr))) goto fail;
  if (!raw_write_exact(client, cipher, moved)) goto fail;
  memcpy(st->send_iv, cipher + moved - 16, 16);
  st->send_seq++;
  free(plain);
  free(cipher);
  return TRUE;

fail:
  free(plain);
  free(cipher);
  return FALSE;
}

void rfbClientCleanupAppleHP(rfbClient *client) {
  struct apple_hp_client_state *state;

  if (!client) return;
  state = (struct apple_hp_client_state *)rfbClientGetClientData(client, &kAppleHPClientDataTag);
  if (!state) return;
  free(state->transport.recv_buf);
  free(state);
  rfbClientSetClientData(client, &kAppleHPClientDataTag, NULL);
}

rfbBool rfbClientConfigureAppleHP(rfbClient *client) {
  if (!client) return FALSE;
  rfbClientEnableARDHighPerf(client, TRUE);
  client->appData.deferInitialSetup = TRUE;
  client->appData.hasClientInitFlags = TRUE;
  client->appData.clientInitFlags = 0xC1;
  rfbClientLog("apple-hp: using ClientInit override 0xC1\n");
  return TRUE;
}

rfbBool rfbClientRunAppleHPPrelude(rfbClient *client) {
  struct apple_hp_viewer_info_message viewer_info;

  if (!client) return FALSE;
  rfbClientLog("apple-hp: sending cleartext pre-rekey setup\n");
  viewer_info = apple_hp_make_native_viewer_info();
  if (!send_blob(client, &viewer_info, sizeof(viewer_info), "apple-hp ViewerInfo")) return FALSE;
  {
    struct apple_hp_set_encryption_message msg = apple_hp_make_native_prelude_set_encryption();
    if (!send_blob(client, &msg, sizeof(msg), "apple-hp SetEncryptionMessage")) return FALSE;
  }
  {
    struct apple_hp_set_mode_message msg = apple_hp_make_native_prelude_set_mode();
    if (!send_blob(client, &msg, sizeof(msg), "apple-hp SetModeMessage")) return FALSE;
  }
  return TRUE;
}

rfbBool rfbClientAppleHPSendPostRekeySetEncryptionStage2(rfbClient *client) {
  struct apple_hp_set_encryption_stage2_message msg = apple_hp_make_post_rekey_set_encryption_stage2();
  return send_blob(client, &msg, sizeof(msg), "apple-hp post-0x44f SetEncryptionMessage");
}

rfbBool rfbClientAppleHPEnableTransport(rfbClient *client, const uint8_t *next_key, const uint8_t *next_iv,
                                        uint32_t counter) {
  struct apple_hp_client_state *state = apple_hp_state(client);
  struct apple_hp_transport_state *st;

  if (!state || !client || !next_key || !next_iv) return FALSE;
  st = &state->transport;
  memset(st, 0, sizeof(*st));
  memcpy(st->wrap_key, next_key, 16);
  memcpy(st->cbc_key, next_key, 16);
  memcpy(st->send_iv, next_iv, 16);
  memcpy(st->recv_iv, next_iv, 16);
  st->send_seq = counter ? (counter - 1) : 0;
  st->recv_seq = counter ? (counter - 1) : 0;
  st->active = 1;
  client->ReadFromTransport = apple_hp_transport_read;
  client->WriteToTransport = apple_hp_transport_write;
  rfbClientLog("apple-hp: enabled CBC transport counter=%u send_seq=%u recv_seq=%u\n",
               counter, st->send_seq, st->recv_seq);
  return TRUE;
}

rfbBool rfbClientAppleHPTransportActive(const rfbClient *client) {
  const struct apple_hp_client_state *state = apple_hp_state_const(client);
  return state && state->transport.active;
}

uint32_t rfbClientAppleHPReceivedRecordCount(const rfbClient *client) {
  const struct apple_hp_client_state *state = apple_hp_state_const(client);
  return state ? state->recv_records : 0;
}

rfbBool rfbClientAppleHPDecryptRekeyRecord(const rfbClient *client, const uint8_t *record, size_t len,
                                           uint32_t *counter, uint8_t next_key[16], uint8_t next_iv[16]) {
  const uint8_t *session_key = NULL;
  size_t session_key_len = 0;

  if (!client || !record || len < 36 || !counter || !next_key || !next_iv) return FALSE;
  if (!rfbClientGetARDSessionKey(client, &session_key, &session_key_len) || session_key_len < 16) {
    rfbClientErr("apple-hp: no ARD session key available; cannot decrypt 0x44f\n");
    return FALSE;
  }
  *counter = apple_hp_read_be_u32(record);
  if (!aes_ecb_decrypt_block(session_key, record + 4, next_key)) return FALSE;
  if (!aes_ecb_decrypt_block(session_key, record + 20, next_iv)) return FALSE;
  return TRUE;
}

rfbBool rfbClientAppleHPSendInitialDisplayConfiguration(rfbClient *client) {
  struct apple_hp_display_configuration_message msg;
  uint8_t *buf;
  size_t len;
  size_t display_offset = 12;
  uint16_t display_info_size;
  size_t effective_len;

  if (!client) return FALSE;
  msg = apple_hp_make_native_display_configuration();
  buf = (uint8_t *)&msg;
  len = sizeof(msg);
  if (len <= display_offset) {
    rfbClientErr("apple-hp SetDisplayConfiguration: payload too short (%zu)\n", len);
    return FALSE;
  }
  display_info_size = apple_hp_read_be_u16(buf + display_offset);
  if (display_offset + (size_t)display_info_size > len) {
    rfbClientErr("apple-hp SetDisplayConfiguration: unexpected displayInfoSize=%u len=%zu\n",
                 (unsigned)display_info_size, len);
    return FALSE;
  }
  effective_len = display_offset + (size_t)display_info_size;
  rfbClientLog("apple-hp SetDisplayConfiguration: sending %zu bytes display_count=1 flags=0x00000000\n",
               effective_len);
  return WriteToRFBServer(client, (const char *)buf, (unsigned int)effective_len);
}

rfbBool rfbClientAppleHPSendRuntimeDisplayConfiguration(rfbClient *client,
                                                        uint16_t logical_w,
                                                        uint16_t logical_h,
                                                        const char *reason) {
  struct apple_hp_display_configuration_message msg;

  if (!client || logical_w == 0 || logical_h == 0) return FALSE;
  msg = apple_hp_make_native_display_configuration();
  patch_display_configuration_dimensions(&msg, logical_w, logical_h);
  rfbClientLog("apple-hp: sending runtime SetDisplayConfiguration %ux%u reason=%s\n",
               (unsigned)logical_w, (unsigned)logical_h, reason ? reason : "unknown");
  return WriteToRFBServer(client, (const char *)&msg, (unsigned int)sizeof(msg));
}

void rfbClientAppleHPSetPostRekeyPixelFormat(rfbClient *client) {
  if (!client) return;
  client->format.bitsPerPixel = 32;
  client->format.depth = 32;
  client->format.bigEndian = 0;
  client->format.trueColour = 1;
  client->format.redMax = 255;
  client->format.greenMax = 255;
  client->format.blueMax = 255;
  client->format.redShift = 16;
  client->format.greenShift = 8;
  client->format.blueShift = 0;
}

rfbBool rfbClientAppleHPSendSetDisplayMessage(rfbClient *client) {
  struct apple_hp_set_display_message msg = apple_hp_make_set_display_message(1, 0);
  return send_blob(client, &msg, sizeof(msg), "apple-hp post-rekey hello");
}

rfbBool rfbClientAppleHPSendPostAuthEncodings(rfbClient *client) {
  int32_t encodings[(sizeof(kAppleHPNativePostAuthEncodings) / sizeof(kAppleHPNativePostAuthEncodings[0])) + 2];
  size_t count = 0;
  size_t i;
  int add_promode = apple_hp_env_flag_enabled("VNC_APPLE_HP_ADD_PROMODE_ENCODING");
  int prefer_promode = apple_hp_env_flag_enabled("VNC_APPLE_HP_PREFER_PROMODE_ENCODING");
  int omit_44c = apple_hp_env_flag_enabled("VNC_APPLE_HP_OMIT_44C");
  int omit_44d = apple_hp_env_flag_enabled("VNC_APPLE_HP_OMIT_44D");

  if (!client) return FALSE;
  if (add_promode && prefer_promode) {
    encodings[count++] = kAppleHPProModeEncoding;
    rfbClientLog("apple-hp: prepending ProMode SetEncodings capability 0x%03x\n",
                 kAppleHPProModeEncoding);
  }
  for (i = 0; i < sizeof(kAppleHPNativePostAuthEncodings) / sizeof(kAppleHPNativePostAuthEncodings[0]); ++i) {
    if (omit_44c && kAppleHPNativePostAuthEncodings[i] == APPLE_HP_ENCODING_POINTER_REBASE)
      continue;
    if (omit_44d && kAppleHPNativePostAuthEncodings[i] == APPLE_HP_ENCODING_DISPLAY_LAYOUT_SELECTOR)
      continue;
    if (add_promode && !prefer_promode &&
        kAppleHPNativePostAuthEncodings[i] == APPLE_HP_ENCODING_POINTER_REBASE)
      encodings[count++] = kAppleHPProModeEncoding;
    encodings[count++] = kAppleHPNativePostAuthEncodings[i];
  }
  if (add_promode && !prefer_promode) {
    rfbClientLog("apple-hp: adding ProMode SetEncodings capability 0x%03x\n",
                 kAppleHPProModeEncoding);
  }
  apple_hp_log_post_auth_encodings(encodings, count);
  return SendEncodingsOrdered(client, encodings, count);
}

rfbBool rfbClientAppleHPSendAutoPasteboardCommand(rfbClient *client, uint16_t selector) {
  struct apple_hp_auto_pasteboard_message msg =
      apple_hp_make_auto_pasteboard_message((uint8_t)(selector & 0xff));
  rfbClientLog("apple-hp: sending AutoPasteboard selector=%u\n", (unsigned)selector);
  return WriteToRFBServer(client, (const char *)&msg, sizeof(msg));
}

rfbBool rfbClientAppleHPSendScaleFactor(rfbClient *client, double scale) {
  struct apple_hp_scale_factor_message msg = apple_hp_make_scale_factor_message(scale);
  rfbClientLog("apple-hp: using scale factor %.6f\n", scale);
  return send_blob(client, &msg, sizeof(msg), "apple-hp scale factor");
}

rfbBool rfbClientAppleHPSendAutoFramebufferUpdate(rfbClient *client, uint16_t width, uint16_t height) {
  uint8_t buf[16];

  memset(buf, 0, sizeof(buf));
  buf[0] = APPLE_HP_MSG_AUTO_FRAMEBUFFER_UPDATE;
  buf[3] = 0x01;
  memset(buf + 4, 0xff, 4);
  buf[12] = (uint8_t)((width >> 8) & 0xff);
  buf[13] = (uint8_t)(width & 0xff);
  buf[14] = (uint8_t)((height >> 8) & 0xff);
  buf[15] = (uint8_t)(height & 0xff);
  rfbClientLog("apple-hp: sending AutoFrameBufferUpdate region=%ux%u\n",
               (unsigned)width, (unsigned)height);
  return WriteToRFBServer(client, (const char *)buf, sizeof(buf));
}

rfbBool rfbClientAppleHPResizeFramebufferIfNeeded(rfbClient *client,
                                                  uint16_t width,
                                                  uint16_t height,
                                                  uint16_t slack) {
  uint16_t alloc_w;
  uint16_t alloc_h;

  if (!client || width == 0 || height == 0) return TRUE;
  alloc_w = width + slack;
  alloc_h = height + slack;
  if (client->frameBuffer && client->width >= alloc_w && client->height >= alloc_h) return TRUE;
  client->width = alloc_w;
  client->height = alloc_h;
  client->screen.width = rfbClientSwap16IfLE(alloc_w);
  client->screen.height = rfbClientSwap16IfLE(alloc_h);
  if (client->isUpdateRectManagedByLib) {
    client->updateRect.x = 0;
    client->updateRect.y = 0;
    client->updateRect.w = alloc_w;
    client->updateRect.h = alloc_h;
  }
  rfbClientLog("apple-hp: resizing local framebuffer to %ux%u for backing %ux%u\n",
               (unsigned)alloc_w, (unsigned)alloc_h, (unsigned)width, (unsigned)height);
  return client->MallocFrameBuffer(client);
}
