#include <rfb/rfbclient.h>

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include "ardhp.h"
#include "ardhp_protocol.h"

static const int32_t kARDHPNativePostAuthEncodings[] = {
    0x10,
    0x6,
    (int32_t)0xffffff11u,
    ARD_HP_ENCODING_CURSOR_IMAGE,
    ARD_HP_ENCODING_POINTER_REBASE,
    (int32_t)0xffffff21u,
    ARD_HP_ENCODING_DISPLAY_LAYOUT_SELECTOR,
    ARD_HP_ENCODING_DISPLAY_LAYOUT,
    ARD_HP_ENCODING_DISPLAY_MODE,
    ARD_HP_ENCODING_KEYBOARD_LAYOUT,
    ARD_HP_ENCODING_DISPLAY_INFO,
};
static const int32_t kARDHPProModeEncoding = ARD_HP_ENCODING_MEDIA_STREAM;

struct ard_hp_transport_state {
  int active;
  uint8_t wrap_key[16];
  uint8_t cbc_key[16];
  uint8_t send_iv[16];
  uint8_t recv_iv[16];
  CCCryptorRef send_cryptor;
  CCCryptorRef recv_cryptor;
  uint32_t send_seq;
  uint32_t recv_seq;
  uint8_t *recv_buf;
  size_t recv_len;
  size_t recv_off;
  size_t recv_cap;
  uint8_t *wire_buf;
  size_t wire_cap;
  size_t wire_len;
  size_t wire_off;
  uint8_t *send_plain_buf;
  uint8_t *send_cipher_buf;
  size_t send_plain_cap;
  size_t send_cipher_cap;
};

struct ard_hp_client_state {
  struct ard_hp_transport_state transport;
  uint32_t recv_records;
};

static char kARDHPClientDataTag = 0;

static const char *ard_hp_getenv_compat(const char *name) {
  const char *value;
  const char *marker;
  char legacy_name[128];
  size_t prefix_len;
  size_t suffix_len;

  if (!name || !*name) return NULL;
  value = getenv(name);
  if (value && *value) return value;

  marker = strstr(name, "_ARD_");
  if (!marker) return NULL;

  prefix_len = (size_t)(marker - name);
  suffix_len = strlen(marker + 5);
  if (prefix_len + strlen("_APPLE_") + suffix_len + 1 > sizeof(legacy_name)) return NULL;

  memcpy(legacy_name, name, prefix_len);
  memcpy(legacy_name + prefix_len, "_APPLE_", strlen("_APPLE_"));
  memcpy(legacy_name + prefix_len + strlen("_APPLE_"), marker + 5, suffix_len + 1);
  value = getenv(legacy_name);
  return (value && *value) ? value : NULL;
}

static struct ard_hp_client_state *ard_hp_state(rfbClient *client) {
  struct ard_hp_client_state *state;

  if (!client) return NULL;
  state = (struct ard_hp_client_state *)rfbClientGetClientData(client, &kARDHPClientDataTag);
  if (state) return state;
  state = (struct ard_hp_client_state *)calloc(1, sizeof(*state));
  if (!state) return NULL;
  rfbClientSetClientData(client, &kARDHPClientDataTag, state);
  return state;
}

static const struct ard_hp_client_state *ard_hp_state_const(const rfbClient *client) {
  return client ? (const struct ard_hp_client_state *)rfbClientGetClientData((rfbClient *)client, &kARDHPClientDataTag) : NULL;
}

static int ard_hp_env_flag_enabled(const char *name) {
  const char *s = ard_hp_getenv_compat(name);
  if (!s || !*s) return 0;
  if (!strcmp(s, "0")) return 0;
  if (!strcmp(s, "false")) return 0;
  if (!strcmp(s, "FALSE")) return 0;
  if (!strcmp(s, "no")) return 0;
  if (!strcmp(s, "NO")) return 0;
  return 1;
}

static const char *ard_hp_encoding_name(int32_t encoding) {
  switch ((uint32_t)encoding) {
    case 0x00000006u: return "Zlib";
    case 0x00000010u: return "ZRLE";
    case 0xffffff11u: return "RichCursor";
    case 0xffffff21u: return "NewFBSize";
    case 0x0000044fu: return "ARDSetEncryptionMessage";
    case 0x0000044cu: return "ARDPointerRebase";
    case 0x0000044du: return "ARDDisplayLayoutSelector";
    case 0x00000450u: return "ARDCursorImage";
    case 0x00000451u: return "ARDDisplayLayout";
    case 0x00000453u: return "ARDVendorKeysym";
    case 0x00000455u: return "ARDKeyboardInputSource";
    case 0x00000456u: return "ARDDeviceInfo";
    case 0x000003f2u: return "ARDRFBMediaStreamMessage1";
    default: return "Unknown";
  }
}

static void ard_hp_log_post_auth_encodings(const int32_t *encodings, size_t count) {
  size_t i;

  rfbClientLog("ard-hp: post-auth encodings (%lu)\n", (unsigned long)count);
  for (i = 0; i < count; ++i) {
    rfbClientLog("ard-hp:   [%lu] %11d 0x%08x %s\n",
                 (unsigned long)i,
                 encodings[i],
                 (uint32_t)encodings[i],
                 ard_hp_encoding_name(encodings[i]));
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
        rfbClientErr("ard-hp transport: read failed (%d: %s)\n", errno, strerror(errno));
        return 0;
      }
      if (n == 0) {
        rfbClientLog("ard-hp transport: server closed connection\n");
        return 0;
      }
      p += (size_t)n;
      len -= (size_t)n;
    }
  }
  return 1;
}

static int raw_read_some(rfbClient *client, void *out, size_t len, size_t *read_len) {
  ssize_t n;

  if (read_len) *read_len = 0;
  if (!client || !out || len == 0) return 0;

  if (client->buffered > 0) {
    size_t take = client->buffered < len ? client->buffered : len;
    memcpy(out, client->bufoutptr, take);
    client->bufoutptr += take;
    client->buffered -= take;
    if (read_len) *read_len = take;
    return 1;
  }

  for (;;) {
    n = read(client->sock, out, len);
    if (n < 0) {
      if (errno == EINTR) continue;
      if ((errno == EAGAIN || errno == EWOULDBLOCK) && wait_for_socket_io(client->sock, 0))
        continue;
      rfbClientErr("ard-hp transport: read failed (%d: %s)\n", errno, strerror(errno));
      return 0;
    }
    if (n == 0) {
      rfbClientLog("ard-hp transport: server closed connection\n");
      return 0;
    }
    if (read_len) *read_len = (size_t)n;
    return 1;
  }
}

static int raw_write_exact(rfbClient *client, const void *buf, size_t len) {
  const uint8_t *p = (const uint8_t *)buf;

  while (len > 0) {
    ssize_t n = write(client->sock, p, len);
    if (n < 0) {
      if (errno == EINTR) continue;
      if ((errno == EAGAIN || errno == EWOULDBLOCK) && wait_for_socket_io(client->sock, 1))
        continue;
      rfbClientErr("ard-hp transport: write failed (%d: %s)\n", errno, strerror(errno));
      return 0;
    }
    if (n == 0) {
      rfbClientErr("ard-hp transport: short write\n");
      return 0;
    }
    p += (size_t)n;
    len -= (size_t)n;
  }
  return 1;
}

static void ard_hp_release_cryptor(CCCryptorRef *cryptor) {
  if (!cryptor || !*cryptor) return;
  CCCryptorRelease(*cryptor);
  *cryptor = NULL;
}

static int ard_hp_prepare_cbc_cryptor(CCCryptorRef *cryptor,
                                      CCOperation op,
                                      const uint8_t *key,
                                      const uint8_t *iv) {
  CCCryptorStatus st;

  if (!cryptor || !key || !iv) return 0;
  if (!*cryptor) {
    st = CCCryptorCreateWithMode(op,
                                 kCCModeCBC,
                                 kCCAlgorithmAES,
                                 ccNoPadding,
                                 iv,
                                 key,
                                 16,
                                 NULL,
                                 0,
                                 0,
                                 0,
                                 cryptor);
    if (st != kCCSuccess) {
      rfbClientErr("ard-hp transport: CCCryptorCreateWithMode failed status=%d\n",
                   (int)st);
      *cryptor = NULL;
      return 0;
    }
    return 1;
  }
  st = CCCryptorReset(*cryptor, iv);
  if (st != kCCSuccess) {
    rfbClientErr("ard-hp transport: CCCryptorReset failed status=%d\n", (int)st);
    return 0;
  }
  return 1;
}

static int ard_hp_cbc_crypt(CCCryptorRef *cryptor,
                            CCOperation op,
                            const uint8_t *key,
                            const uint8_t *iv,
                            const uint8_t *in,
                            size_t in_len,
                            uint8_t *out,
                            size_t *out_len) {
  CCCryptorStatus st;
  size_t moved = 0;

  if (!ard_hp_prepare_cbc_cryptor(cryptor, op, key, iv)) return 0;
  st = CCCryptorUpdate(*cryptor, in, in_len, out, in_len, &moved);
  if (st != kCCSuccess || moved != in_len) {
    rfbClientErr("ard-hp transport: CCCryptorUpdate failed status=%d moved=%zu expected=%zu\n",
                 (int)st, moved, in_len);
    return 0;
  }
  if (out_len) *out_len = moved;
  return 1;
}

static int aes_crypt(int op, int options, const uint8_t *key, const uint8_t *iv,
                     const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
  CCCryptorStatus st;
  size_t moved = 0;

  st = CCCrypt((CCOperation)op, kCCAlgorithmAES128, (CCOptions)options, key, 16, iv,
               in, in_len, out, in_len, &moved);
  if (st != kCCSuccess || moved != in_len) {
    rfbClientErr("ard-hp transport: CCCrypt failed status=%d moved=%zu expected=%zu\n",
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

static uint16_t ard_hp_read_be_u16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t ard_hp_read_be_u32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
         (uint32_t)p[3];
}

static int ard_hp_ensure_buf(uint8_t **buf, size_t *cap, size_t need) {
  uint8_t *next;

  if (!buf || !cap) return 0;
  if (*cap >= need) return 1;
  next = (uint8_t *)realloc(*buf, need);
  if (!next) return 0;
  *buf = next;
  *cap = need;
  return 1;
}

static int ard_hp_fill_wire(rfbClient *client, struct ard_hp_transport_state *st, size_t need) {
  size_t avail;

  if (!client || !st) return 0;

  avail = st->wire_len - st->wire_off;
  if (avail >= need) return 1;

  if (avail > 0 && st->wire_off > 0) {
    memmove(st->wire_buf, st->wire_buf + st->wire_off, avail);
    st->wire_len = avail;
    st->wire_off = 0;
  } else if (avail == 0) {
    st->wire_len = 0;
    st->wire_off = 0;
  }

  if (!ard_hp_ensure_buf(&st->wire_buf, &st->wire_cap, need > 65536 ? need : 65536)) {
    return 0;
  }

  while ((st->wire_len - st->wire_off) < need) {
    size_t got = 0;
    size_t free_space = st->wire_cap - st->wire_len;
    size_t want = need - (st->wire_len - st->wire_off);

    if (free_space < want) {
      size_t target = st->wire_cap ? st->wire_cap : 65536;
      while ((target - st->wire_len) < want) {
        size_t next = target * 2;
        if (next <= target) {
          target = st->wire_len + want;
          break;
        }
        target = next;
      }
      if (!ard_hp_ensure_buf(&st->wire_buf, &st->wire_cap, target)) {
        return 0;
      }
      free_space = st->wire_cap - st->wire_len;
    }

    if (!raw_read_some(client, st->wire_buf + st->wire_len, free_space, &got)) {
      return 0;
    }
    st->wire_len += got;
  }

  return 1;
}

static int send_blob(rfbClient *client, const void *buf, size_t len, const char *label) {
  if (!client || !buf || !label || len == 0) return 0;
  rfbClientLog("%s: sending %zu bytes\n", label, len);
  return WriteToRFBServer(client, (const char *)buf, (unsigned int)len);
}

static void patch_display_configuration_dimensions(struct ard_hp_display_configuration_message *msg,
                                                   uint16_t logical_w,
                                                   uint16_t logical_h) {
  static const struct {
    uint32_t width;
    uint32_t height;
    uint32_t scaled_width;
    uint32_t scaled_height;
    double refresh_rate;
    uint32_t flags;
  } kBaseModes[ARD_HP_DISPLAY_CONFIG_MODE_COUNT] = {
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
  ard_hp_store_be32(msg->display.display_flags_be,
                      ARD_HP_DISPLAY_CONFIG_FLAG_DYNAMIC_RESOLUTION);
  ard_hp_store_be16(msg->display.current_mode_index_be, 0);
  ard_hp_store_be16(msg->display.preferred_mode_index_be, 0);
  for (i = 0; i < ARD_HP_DISPLAY_CONFIG_MODE_COUNT; ++i) {
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
    ard_hp_store_be32(msg->display.modes[i].width_be, width);
    ard_hp_store_be32(msg->display.modes[i].height_be, height);
    ard_hp_store_be32(msg->display.modes[i].scaled_width_be, scaled_width);
    ard_hp_store_be32(msg->display.modes[i].scaled_height_be, scaled_height);
    ard_hp_store_be_double(msg->display.modes[i].refresh_rate_be, kBaseModes[i].refresh_rate);
    ard_hp_store_be32(msg->display.modes[i].flags_be, kBaseModes[i].flags);
  }
  if (max_w == 0) max_w = (uint32_t)logical_w * 2u;
  if (max_h == 0) max_h = (uint32_t)logical_h * 2u;
  ard_hp_store_be32(msg->display.max_width_be, max_w);
  ard_hp_store_be32(msg->display.max_height_be, max_h);
  ard_hp_store_be_float(msg->display.physical_width_be, (float)(max_w * (1.0 / 10.4)));
  ard_hp_store_be_float(msg->display.physical_height_be, (float)(max_h * (1.0 / 10.4)));
}

static int ard_hp_read_next_record(rfbClient *client, struct ard_hp_transport_state *st) {
  struct ard_hp_client_state *state = ard_hp_state(client);
  const uint8_t *cipher;
  uint16_t cipher_len;
  uint16_t body_len;
  uint8_t seq_be[4];
  uint8_t digest[CC_SHA1_DIGEST_LENGTH];
  size_t moved = 0;
  size_t total_min;

  if (!ard_hp_fill_wire(client, st, 2u)) return 0;
  cipher_len = ard_hp_read_be_u16(st->wire_buf + st->wire_off);
  if (cipher_len == 0 || (cipher_len % 16) != 0) {
    rfbClientErr("ard-hp transport: invalid record length %u\n", (unsigned)cipher_len);
    return 0;
  }
  if (!ard_hp_fill_wire(client, st, (size_t)cipher_len + 2u)) goto fail;
  if (!ard_hp_ensure_buf(&st->recv_buf, &st->recv_cap, cipher_len)) goto fail;
  cipher = st->wire_buf + st->wire_off + 2u;
  if (!ard_hp_cbc_crypt(&st->recv_cryptor,
                        kCCDecrypt,
                        st->cbc_key,
                        st->recv_iv,
                        cipher,
                        cipher_len,
                        st->recv_buf,
                        &moved)) goto fail;
  if (moved != cipher_len || cipher_len < 22) goto fail;
  body_len = ard_hp_read_be_u16(st->recv_buf);
  total_min = (size_t)body_len + 22u;
  if (total_min > cipher_len) {
    rfbClientErr("ard-hp transport: body len %u exceeds record size %u\n",
                 (unsigned)body_len, (unsigned)cipher_len);
    goto fail;
  }
  ard_hp_store_be32(seq_be, st->recv_seq);
  {
    CC_SHA1_CTX ctx;
    CC_SHA1_Init(&ctx);
    CC_SHA1_Update(&ctx, seq_be, sizeof(seq_be));
    CC_SHA1_Update(&ctx, st->recv_buf, cipher_len - CC_SHA1_DIGEST_LENGTH);
    CC_SHA1_Final(digest, &ctx);
  }
  if (memcmp(digest,
             st->recv_buf + cipher_len - CC_SHA1_DIGEST_LENGTH,
             CC_SHA1_DIGEST_LENGTH) != 0) {
    rfbClientErr("ard-hp transport: checksum mismatch seq=%u cipher_len=%u body_len=%u\n",
                 st->recv_seq, (unsigned)cipher_len, (unsigned)body_len);
    goto fail;
  }
  st->recv_seq++;
  if (state) state->recv_records++;
  st->recv_len = (size_t)body_len + 2u;
  st->recv_off = 2;
  memcpy(st->recv_iv, cipher + cipher_len - 16, 16);
  st->wire_off += (size_t)cipher_len + 2u;
  if (st->wire_off == st->wire_len) {
    st->wire_off = 0;
    st->wire_len = 0;
  }
  return 1;

fail:
  return 0;
}

static rfbBool ard_hp_transport_read(rfbClient *client, char *out, unsigned int n) {
  struct ard_hp_client_state *state = ard_hp_state(client);
  struct ard_hp_transport_state *st;
  size_t copied = 0;

  if (!state || !out) return FALSE;
  st = &state->transport;
  while (copied < n) {
    if (st->recv_off >= st->recv_len) {
      st->recv_off = 0;
      st->recv_len = 0;
      if (!ard_hp_read_next_record(client, st)) return FALSE;
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

static rfbBool ard_hp_transport_write(rfbClient *client, const char *buf, unsigned int n) {
  struct ard_hp_client_state *state = ard_hp_state(client);
  struct ard_hp_transport_state *st;
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
  if (!ard_hp_ensure_buf(&st->send_plain_buf, &st->send_plain_cap, plain_len)) goto fail;
  if (!ard_hp_ensure_buf(&st->send_cipher_buf, &st->send_cipher_cap, plain_len)) goto fail;
  plain = st->send_plain_buf;
  cipher = st->send_cipher_buf;
  memset(plain, 0, plain_len);

  ard_hp_store_be16(plain, (uint16_t)n);
  memcpy(plain + 2, buf, n);
  filler_len = plain_len - ((size_t)n + 2u + CC_SHA1_DIGEST_LENGTH);
  (void)filler_len;
  ard_hp_store_be32(seq_be, st->send_seq);
  {
    CC_SHA1_CTX ctx;
    CC_SHA1_Init(&ctx);
    CC_SHA1_Update(&ctx, seq_be, sizeof(seq_be));
    CC_SHA1_Update(&ctx, plain, plain_len - CC_SHA1_DIGEST_LENGTH);
    CC_SHA1_Final(plain + plain_len - CC_SHA1_DIGEST_LENGTH, &ctx);
  }
  if (!ard_hp_cbc_crypt(&st->send_cryptor,
                        kCCEncrypt,
                        st->cbc_key,
                        st->send_iv,
                        plain,
                        plain_len,
                        cipher,
                        &moved)) goto fail;
  ard_hp_store_be16(hdr, (uint16_t)moved);
  if (!raw_write_exact(client, hdr, sizeof(hdr))) goto fail;
  if (!raw_write_exact(client, cipher, moved)) goto fail;
  memcpy(st->send_iv, cipher + moved - 16, 16);
  st->send_seq++;
  return TRUE;

fail:
  return FALSE;
}

void rfbClientCleanupARDHP(rfbClient *client) {
  struct ard_hp_client_state *state;

  if (!client) return;
  state = (struct ard_hp_client_state *)rfbClientGetClientData(client, &kARDHPClientDataTag);
  if (!state) return;
  ard_hp_release_cryptor(&state->transport.send_cryptor);
  ard_hp_release_cryptor(&state->transport.recv_cryptor);
  free(state->transport.recv_buf);
  free(state->transport.wire_buf);
  free(state->transport.send_plain_buf);
  free(state->transport.send_cipher_buf);
  free(state);
  rfbClientSetClientData(client, &kARDHPClientDataTag, NULL);
}

rfbBool rfbClientConfigureARDHP(rfbClient *client) {
  if (!client) return FALSE;
  rfbClientEnableARDHighPerf(client, TRUE);
  client->appData.deferInitialSetup = TRUE;
  client->appData.hasClientInitFlags = TRUE;
  client->appData.clientInitFlags = 0xC1;
  rfbClientLog("ard-hp: using ClientInit override 0xC1\n");
  return TRUE;
}

rfbBool rfbClientRunARDHPPrelude(rfbClient *client) {
  struct ard_hp_viewer_info_message viewer_info;

  if (!client) return FALSE;
  rfbClientLog("ard-hp: sending cleartext pre-rekey setup\n");
  viewer_info = ard_hp_make_native_viewer_info();
  if (!send_blob(client, &viewer_info, sizeof(viewer_info), "ard-hp ViewerInfo")) return FALSE;
  {
    struct ard_hp_set_encryption_message msg = ard_hp_make_native_prelude_set_encryption();
    if (!send_blob(client, &msg, sizeof(msg), "ard-hp SetEncryptionMessage")) return FALSE;
  }
  {
    struct ard_hp_set_mode_message msg = ard_hp_make_native_prelude_set_mode();
    if (!send_blob(client, &msg, sizeof(msg), "ard-hp SetModeMessage")) return FALSE;
  }
  return TRUE;
}

rfbBool rfbClientARDHPSendPostRekeySetEncryptionStage2(rfbClient *client) {
  struct ard_hp_set_encryption_stage2_message msg = ard_hp_make_post_rekey_set_encryption_stage2();
  return send_blob(client, &msg, sizeof(msg), "ard-hp post-0x44f SetEncryptionMessage");
}

rfbBool rfbClientARDHPEnableTransport(rfbClient *client, const uint8_t *next_key, const uint8_t *next_iv,
                                        uint32_t counter) {
  struct ard_hp_client_state *state = ard_hp_state(client);
  struct ard_hp_transport_state *st;

  if (!state || !client || !next_key || !next_iv) return FALSE;
  st = &state->transport;
  ard_hp_release_cryptor(&st->send_cryptor);
  ard_hp_release_cryptor(&st->recv_cryptor);
  memset(st, 0, sizeof(*st));
  memcpy(st->wrap_key, next_key, 16);
  memcpy(st->cbc_key, next_key, 16);
  memcpy(st->send_iv, next_iv, 16);
  memcpy(st->recv_iv, next_iv, 16);
  st->send_seq = counter ? (counter - 1) : 0;
  st->recv_seq = counter ? (counter - 1) : 0;
  st->active = 1;
  client->ReadFromTransport = ard_hp_transport_read;
  client->WriteToTransport = ard_hp_transport_write;
  rfbClientLog("ard-hp: enabled CBC transport counter=%u send_seq=%u recv_seq=%u\n",
               counter, st->send_seq, st->recv_seq);
  return TRUE;
}

rfbBool rfbClientARDHPTransportActive(const rfbClient *client) {
  const struct ard_hp_client_state *state = ard_hp_state_const(client);
  return state && state->transport.active;
}

uint32_t rfbClientARDHPReceivedRecordCount(const rfbClient *client) {
  const struct ard_hp_client_state *state = ard_hp_state_const(client);
  return state ? state->recv_records : 0;
}

rfbBool rfbClientARDHPDecryptRekeyRecord(const rfbClient *client, const uint8_t *record, size_t len,
                                           uint32_t *counter, uint8_t next_key[16], uint8_t next_iv[16]) {
  const uint8_t *session_key = NULL;
  size_t session_key_len = 0;

  if (!client || !record || len < 36 || !counter || !next_key || !next_iv) return FALSE;
  if (!rfbClientGetARDSessionKey(client, &session_key, &session_key_len) || session_key_len < 16) {
    rfbClientErr("ard-hp: no ARD session key available; cannot decrypt 0x44f\n");
    return FALSE;
  }
  *counter = ard_hp_read_be_u32(record);
  if (!aes_ecb_decrypt_block(session_key, record + 4, next_key)) return FALSE;
  if (!aes_ecb_decrypt_block(session_key, record + 20, next_iv)) return FALSE;
  return TRUE;
}

rfbBool rfbClientARDHPSendInitialDisplayConfiguration(rfbClient *client) {
  struct ard_hp_display_configuration_message msg;
  uint8_t *buf;
  size_t len;
  size_t display_offset = 12;
  uint16_t display_info_size;
  size_t effective_len;

  if (!client) return FALSE;
  msg = ard_hp_make_native_display_configuration();
  buf = (uint8_t *)&msg;
  len = sizeof(msg);
  if (len <= display_offset) {
    rfbClientErr("ard-hp SetDisplayConfiguration: payload too short (%zu)\n", len);
    return FALSE;
  }
  display_info_size = ard_hp_read_be_u16(buf + display_offset);
  if (display_offset + (size_t)display_info_size > len) {
    rfbClientErr("ard-hp SetDisplayConfiguration: unexpected displayInfoSize=%u len=%zu\n",
                 (unsigned)display_info_size, len);
    return FALSE;
  }
  effective_len = display_offset + (size_t)display_info_size;
  rfbClientLog("ard-hp SetDisplayConfiguration: sending %zu bytes display_count=1 flags=0x00000000\n",
               effective_len);
  return WriteToRFBServer(client, (const char *)buf, (unsigned int)effective_len);
}

rfbBool rfbClientARDHPSendRuntimeDisplayConfiguration(rfbClient *client,
                                                        uint16_t logical_w,
                                                        uint16_t logical_h,
                                                        const char *reason) {
  struct ard_hp_display_configuration_message msg;

  if (!client || logical_w == 0 || logical_h == 0) return FALSE;
  msg = ard_hp_make_native_display_configuration();
  patch_display_configuration_dimensions(&msg, logical_w, logical_h);
  rfbClientLog("ard-hp: sending runtime SetDisplayConfiguration %ux%u reason=%s\n",
               (unsigned)logical_w, (unsigned)logical_h, reason ? reason : "unknown");
  return WriteToRFBServer(client, (const char *)&msg, (unsigned int)sizeof(msg));
}

void rfbClientARDHPSetPostRekeyPixelFormat(rfbClient *client) {
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

rfbBool rfbClientARDHPSendSetDisplayMessage(rfbClient *client) {
  struct ard_hp_set_display_message msg = ard_hp_make_set_display_message(1, 0);
  return send_blob(client, &msg, sizeof(msg), "ard-hp post-rekey hello");
}

rfbBool rfbClientARDHPSendPostAuthEncodings(rfbClient *client) {
  int32_t encodings[(sizeof(kARDHPNativePostAuthEncodings) / sizeof(kARDHPNativePostAuthEncodings[0])) + 2];
  size_t count = 0;
  size_t i;
  int add_promode = ard_hp_env_flag_enabled("VNC_ARD_HP_ADD_PROMODE_ENCODING");
  int prefer_promode = ard_hp_env_flag_enabled("VNC_ARD_HP_PREFER_PROMODE_ENCODING");
  int omit_44c = ard_hp_env_flag_enabled("VNC_ARD_HP_OMIT_44C");
  int omit_44d = ard_hp_env_flag_enabled("VNC_ARD_HP_OMIT_44D");

  if (!client) return FALSE;
  if (add_promode && prefer_promode) {
    encodings[count++] = kARDHPProModeEncoding;
    rfbClientLog("ard-hp: prepending ProMode SetEncodings capability 0x%03x\n",
                 kARDHPProModeEncoding);
  }
  for (i = 0; i < sizeof(kARDHPNativePostAuthEncodings) / sizeof(kARDHPNativePostAuthEncodings[0]); ++i) {
    if (ard_hp_env_flag_enabled("VNC_DISABLE_ZLIB") && kARDHPNativePostAuthEncodings[i] == 0x6)
      continue;
    if (omit_44c && kARDHPNativePostAuthEncodings[i] == ARD_HP_ENCODING_POINTER_REBASE)
      continue;
    if (omit_44d && kARDHPNativePostAuthEncodings[i] == ARD_HP_ENCODING_DISPLAY_LAYOUT_SELECTOR)
      continue;
    if (add_promode && !prefer_promode &&
        kARDHPNativePostAuthEncodings[i] == ARD_HP_ENCODING_POINTER_REBASE)
      encodings[count++] = kARDHPProModeEncoding;
    encodings[count++] = kARDHPNativePostAuthEncodings[i];
  }
  if (add_promode && !prefer_promode) {
    rfbClientLog("ard-hp: adding ProMode SetEncodings capability 0x%03x\n",
                 kARDHPProModeEncoding);
  }
  ard_hp_log_post_auth_encodings(encodings, count);
  return SendEncodingsOrdered(client, encodings, count);
}

rfbBool rfbClientARDHPSendAutoPasteboardCommand(rfbClient *client, uint16_t selector) {
  struct ard_hp_auto_pasteboard_message msg =
      ard_hp_make_auto_pasteboard_message((uint8_t)(selector & 0xff));
  rfbClientLog("ard-hp: sending AutoPasteboard selector=%u\n", (unsigned)selector);
  return WriteToRFBServer(client, (const char *)&msg, sizeof(msg));
}

rfbBool rfbClientARDHPSendScaleFactor(rfbClient *client, double scale) {
  struct ard_hp_scale_factor_message msg = ard_hp_make_scale_factor_message(scale);
  rfbClientLog("ard-hp: using scale factor %.6f\n", scale);
  return send_blob(client, &msg, sizeof(msg), "ard-hp scale factor");
}

rfbBool rfbClientARDHPSendAutoFramebufferUpdate(rfbClient *client, uint16_t width, uint16_t height) {
  uint8_t buf[16];

  memset(buf, 0, sizeof(buf));
  buf[0] = ARD_HP_MSG_AUTO_FRAMEBUFFER_UPDATE;
  buf[3] = 0x01;
  memset(buf + 4, 0xff, 4);
  buf[12] = (uint8_t)((width >> 8) & 0xff);
  buf[13] = (uint8_t)(width & 0xff);
  buf[14] = (uint8_t)((height >> 8) & 0xff);
  buf[15] = (uint8_t)(height & 0xff);
  rfbClientLog("ard-hp: sending AutoFrameBufferUpdate region=%ux%u\n",
               (unsigned)width, (unsigned)height);
  return WriteToRFBServer(client, (const char *)buf, sizeof(buf));
}

rfbBool rfbClientARDHPResizeFramebufferIfNeeded(rfbClient *client,
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
  rfbClientLog("ard-hp: resizing local framebuffer to %ux%u for backing %ux%u\n",
               (unsigned)alloc_w, (unsigned)alloc_h, (unsigned)width, (unsigned)height);
  return client->MallocFrameBuffer(client);
}
