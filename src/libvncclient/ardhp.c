#include <rfb/rfbclient.h>

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>

#include <errno.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <zlib.h>

#include "ardhp.h"
#include "ardhp_protocol.h"

static const int32_t kARDHPNativePostAuthEncodings[] = {
    0x6,
    0x10,
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
static const int32_t kARDHPAdaptiveEncodings[] = {
    ARD_HP_ENCODING_MEDIA_STREAM,
    ARD_HP_ENCODING_MEDIA_STREAM_MESSAGE2,
    ARD_HP_ENCODING_MEDIA_STREAM_MESSAGE3,
};
static const uint8_t kARDHPMediaOptionsPrefix1[] = {
    0x96, 0x38, 0xd2, 0xa0, 0xfa, 0x7e, 0x7f, 0x95, 0x04, 0x7e, 0x08, 0x58,
    0x67, 0xd8, 0xfe, 0x05, 0x8b, 0x57, 0x85, 0xf5, 0xb8, 0xa7, 0xce, 0x63,
    0xb8, 0x91, 0xc5, 0x02, 0x60, 0x03, 0xc8, 0xbc, 0xd6, 0x90, 0x53, 0x6a,
    0xb5, 0x3a, 0x76, 0x8f, 0x8c, 0x0c, 0xa7, 0xe7, 0x4d, 0x54, 0x61, 0x20,
    0x18, 0x30, 0xdf, 0x2c, 0x61, 0xd9, 0x56, 0x1b, 0xd7, 0xea, 0x6f, 0x67,
    0x48, 0xe3, 0x74, 0x48, 0x63, 0xf9, 0x7a, 0x99, 0x5b, 0x2f, 0xda, 0x74,
    0xa7, 0x6d, 0x98, 0xde, 0xb4, 0x45, 0x9f, 0xaf, 0x72, 0xd7, 0x81, 0xed,
    0x52, 0x02, 0xf5, 0x8b, 0xe6, 0x24, 0x21, 0x8c,
};
static const size_t kARDHPMediaOptionsPrefix1Len = sizeof(kARDHPMediaOptionsPrefix1);
static const uint8_t kARDHPMediaOptionsMid[] = {
    0x8e, 0x0a, 0x6c, 0x30, 0xb9, 0x8d, 0x12, 0xbf, 0x5c, 0x50, 0x79, 0x79,
    0x73, 0x66, 0xa5, 0x0d, 0xbd, 0xd9, 0x58, 0xcc, 0x92, 0x56, 0xef, 0x2c,
    0x7e, 0xdc, 0x59, 0xbd, 0x59, 0x69, 0x6a, 0x09, 0x6c, 0xa7, 0x91, 0x23,
    0xc7, 0xe8, 0x08, 0xe9, 0x42, 0x4b, 0xc1, 0xc8, 0x81, 0xf7, 0x17, 0xd5,
    0xa1, 0x56, 0x26, 0xe2, 0x25, 0x30, 0xf1, 0x42, 0xad, 0xde, 0x84, 0xa4,
    0xed, 0x36, 0x98, 0x59, 0x64, 0xeb, 0x08, 0x5c, 0xa0, 0x13, 0x49, 0xb3,
    0x68, 0x18, 0x5a, 0x84, 0xcf, 0xa6, 0x4f, 0x8b, 0xd0, 0xd3, 0xe8, 0xd4,
    0x02, 0xe9, 0xc7, 0x86, 0xb2, 0xcd, 0x0e, 0xe2,
};
static const size_t kARDHPMediaOptionsMidLen = sizeof(kARDHPMediaOptionsMid);
static const uint8_t kARDHPMediaBlobMode8Raw[] = {
    0x08, 0x01, 0x10, 0x01, 0x1a, 0x11, 0x08, 0xbb, 0xdf, 0x8e, 0xef, 0x05, 0x10, 0x00, 0x18, 0x00,
    0x20, 0xff, 0x3c, 0x28, 0x00, 0x30, 0x00, 0x32, 0x0d, 0x56, 0x69, 0x63, 0x65, 0x72, 0x6f, 0x79,
    0x20, 0x31, 0x2e, 0x37, 0x2e, 0x30, 0x40, 0x00, 0x4a, 0x09, 0x08, 0xea, 0x1f, 0x10, 0x00, 0x18,
    0x80, 0x80, 0x01, 0x4a, 0x0b, 0x08, 0x00, 0x10, 0x80, 0xda, 0xc4, 0x09, 0x18, 0x80, 0x80, 0x06,
    0x4a, 0x0a, 0x08, 0x00, 0x10, 0x80, 0xb4, 0x89, 0x13, 0x18, 0x80, 0x60, 0x4a, 0x05, 0x08, 0x01,
    0x10, 0xab, 0x02, 0x4a, 0x0b, 0x08, 0x00, 0x10, 0x80, 0x8e, 0xce, 0x1c, 0x18, 0x80, 0x80, 0x10,
    0x4a, 0x05, 0x08, 0x10, 0x10, 0x84, 0x20, 0x4a, 0x0b, 0x08, 0x00, 0x10, 0x80, 0x9b, 0xee, 0x02,
    0x18, 0x80, 0x80, 0x08, 0x4a, 0x05, 0x08, 0x04, 0x10, 0xe4, 0x32, 0x68, 0x80, 0x80, 0x89, 0xb2,
    0x80, 0xe5, 0xca, 0xb8, 0xed, 0x01, 0x70, 0x02, 0x80, 0x01, 0x00, 0x90, 0x01, 0x01,
};
static const size_t kARDHPMediaBlobMode8RawLen = sizeof(kARDHPMediaBlobMode8Raw);
static const uint8_t kARDHPMediaBlobMode7Raw[] = {
    0x08, 0x01, 0x10, 0x01, 0x2a, 0xee, 0x01, 0x08, 0xdf, 0xf6, 0xae, 0x75, 0x10, 0x00, 0x1a, 0x7d,
    0x08, 0x7b, 0x12, 0x0a, 0x08, 0x01, 0x10, 0x01, 0x18, 0xc3, 0x87, 0x03, 0x20, 0x00, 0x12, 0x0a,
    0x08, 0x01, 0x10, 0x02, 0x18, 0xc3, 0x87, 0x03, 0x20, 0x00, 0x12, 0x0a, 0x08, 0x01, 0x10, 0x01,
    0x18, 0xc3, 0x87, 0x03, 0x20, 0x00, 0x12, 0x0a, 0x08, 0x01, 0x10, 0x02, 0x18, 0xc3, 0x87, 0x03,
    0x20, 0x00, 0x1a, 0x47, 0x46, 0x4c, 0x53, 0x3b, 0x4d, 0x53, 0x3a, 0x2d, 0x31, 0x3b, 0x4c, 0x46,
    0x3a, 0x2d, 0x31, 0x3b, 0x4c, 0x54, 0x52, 0x3b, 0x43, 0x41, 0x42, 0x41, 0x43, 0x3b, 0x50, 0x4f,
    0x53, 0x3a, 0x30, 0x3b, 0x45, 0x4f, 0x44, 0x3a, 0x31, 0x3b, 0x48, 0x54, 0x53, 0x3a, 0x32, 0x3b,
    0x52, 0x52, 0x3a, 0x33, 0x3b, 0x41, 0x52, 0x3a, 0x38, 0x2f, 0x35, 0x2c, 0x35, 0x2f, 0x38, 0x3b,
    0x58, 0x52, 0x3a, 0x38, 0x2f, 0x35, 0x2c, 0x35, 0x2f, 0x38, 0x3b, 0x20, 0x01, 0x1a, 0x5c, 0x08,
    0x64, 0x12, 0x0a, 0x08, 0x01, 0x10, 0x01, 0x18, 0xc3, 0x87, 0x03, 0x20, 0x00, 0x12, 0x0a, 0x08,
    0x01, 0x10, 0x02, 0x18, 0xc3, 0x87, 0x03, 0x20, 0x00, 0x1a, 0x3e, 0x46, 0x4c, 0x53, 0x3b, 0x4c,
    0x46, 0x3a, 0x2d, 0x31, 0x3b, 0x50, 0x4f, 0x53, 0x3a, 0x35, 0x3b, 0x45, 0x4f, 0x44, 0x3a, 0x31,
    0x3b, 0x48, 0x54, 0x53, 0x3a, 0x32, 0x3b, 0x52, 0x52, 0x3a, 0x33, 0x3b, 0x50, 0x4f, 0x53, 0x45,
    0x3a, 0x34, 0x3b, 0x41, 0x52, 0x3a, 0x38, 0x2f, 0x35, 0x2c, 0x35, 0x2f, 0x38, 0x3b, 0x58, 0x52,
    0x3a, 0x38, 0x2f, 0x35, 0x2c, 0x35, 0x2f, 0x38, 0x3b, 0x20, 0x0e, 0x30, 0x04, 0x38, 0x01, 0x40,
    0x3f, 0x48, 0x01, 0x60, 0x01, 0x32, 0x0d, 0x56, 0x69, 0x63, 0x65, 0x72, 0x6f, 0x79, 0x20, 0x31,
    0x2e, 0x37, 0x2e, 0x30, 0x40, 0x00, 0x4a, 0x0a, 0x08, 0x00, 0x10, 0x80, 0xb4, 0x89, 0x13, 0x18,
    0x80, 0x60, 0x4a, 0x05, 0x08, 0x10, 0x10, 0x84, 0x20, 0x4a, 0x09, 0x08, 0xea, 0x1f, 0x10, 0x00,
    0x18, 0x80, 0x80, 0x01, 0x4a, 0x0b, 0x08, 0x00, 0x10, 0x80, 0x9b, 0xee, 0x02, 0x18, 0x80, 0x80,
    0x08, 0x4a, 0x0b, 0x08, 0x00, 0x10, 0x80, 0xda, 0xc4, 0x09, 0x18, 0x80, 0x80, 0x06, 0x4a, 0x05,
    0x08, 0x04, 0x10, 0xe4, 0x32, 0x4a, 0x05, 0x08, 0x01, 0x10, 0xab, 0x02, 0x4a, 0x0b, 0x08, 0x00,
    0x10, 0x80, 0x8e, 0xce, 0x1c, 0x18, 0x80, 0x80, 0x10, 0x68, 0x80, 0xc0, 0xe5, 0xb6, 0x80, 0xe5,
    0xca, 0xb8, 0xed, 0x01, 0x70, 0x02, 0x80, 0x01, 0x00, 0x90, 0x01, 0x01,
};
static const size_t kARDHPMediaBlobMode7RawLen = sizeof(kARDHPMediaBlobMode7Raw);
static const uint8_t kARDHPMediaBlobMode8ZlibGT[] = {
    0x78, 0xda, 0xe3, 0x60, 0x14, 0x60, 0x94, 0x12, 0xe0, 0x78, 0x3f, 0xab, 0xdf, 0x57, 0x80, 0x41,
    0x82, 0x41, 0xe1, 0xbf, 0x8d, 0x06, 0x83, 0x01, 0x83, 0x11, 0x6f, 0x58, 0x66, 0x72, 0x6a, 0x51,
    0x7e, 0xa5, 0x82, 0xa1, 0x9e, 0xb9, 0x9e, 0x81, 0x03, 0x83, 0x17, 0x27, 0xc7, 0x2b, 0x79, 0xa0,
    0x82, 0x86, 0x06, 0x46, 0x2f, 0x56, 0x0e, 0x16, 0x81, 0x27, 0x46, 0x5e, 0x5c, 0x1c, 0x0c, 0x02,
    0x0d, 0x5b, 0x3a, 0x85, 0x25, 0x1a, 0x12, 0x80, 0x42, 0x8c, 0x02, 0xab, 0x99, 0xbc, 0xb8, 0x41,
    0x42, 0x7d, 0xe7, 0x64, 0x80, 0xca, 0x04, 0x20, 0x9c, 0xd9, 0xef, 0x98, 0x80, 0x1c, 0x0e, 0x08,
    0xe7, 0xd6, 0x11, 0x4e, 0x20, 0x87, 0x0d, 0xa8, 0x5a, 0x40, 0xa0, 0x45, 0x21, 0xa3, 0x61, 0xc1,
    0xc7, 0xad, 0xb3, 0x9f, 0x9d, 0xda, 0xf1, 0x96, 0xb1, 0x80, 0xa9, 0x81, 0x91, 0x61, 0x02, 0x23,
    0x23, 0x00, 0x6a, 0x36, 0x25, 0xee,
};
static const size_t kARDHPMediaBlobMode8ZlibGTLen = sizeof(kARDHPMediaBlobMode8ZlibGT);
static const uint8_t kARDHPMediaBlobMode7ZlibGT[] = {
    0x78, 0xda, 0xe3, 0x60, 0x14, 0x60, 0xd4, 0x7a, 0xcf, 0xc8, 0x71, 0xfd, 0x7a, 0xcb, 0x1c, 0x46,
    0x01, 0x06, 0xa9, 0x5a, 0x8e, 0x6a, 0x21, 0x2e, 0x0e, 0xa0, 0xa0, 0xc4, 0xe1, 0x76, 0x66, 0x05,
    0x06, 0x30, 0x9b, 0x09, 0x89, 0x8d, 0x45, 0x5c, 0xca, 0xdd, 0xcd, 0x27, 0xd8, 0xda, 0x37, 0xd8,
    0x4a, 0xd7, 0xd0, 0xda, 0xc7, 0x0d, 0x4c, 0x86, 0x04, 0x59, 0x3b, 0x3b, 0x3a, 0x39, 0x3a, 0x5b,
    0x07, 0xf8, 0x07, 0x5b, 0x19, 0x58, 0xbb, 0xfa, 0xbb, 0x58, 0x19, 0x5a, 0x7b, 0x84, 0x04, 0x5b,
    0x19, 0x59, 0x07, 0x05, 0x59, 0x19, 0x5b, 0x3b, 0x06, 0x59, 0x59, 0xe8, 0x9b, 0xea, 0x98, 0xea,
    0x5b, 0x58, 0x47, 0x20, 0x98, 0x0a, 0x8c, 0x52, 0x31, 0x1c, 0x29, 0x38, 0xad, 0xb1, 0x03, 0x59,
    0x03, 0xb1, 0x00, 0x64, 0xac, 0x29, 0xa6, 0xb1, 0x40, 0x61, 0x57, 0x2b, 0x13, 0x5c, 0xa6, 0xf3,
    0x19, 0xb0, 0x58, 0x30, 0x3a, 0xd8, 0x7b, 0x30, 0x26, 0x30, 0x1a, 0xf1, 0x86, 0x65, 0x26, 0xa7,
    0x16, 0xe5, 0x57, 0x2a, 0x18, 0xea, 0x99, 0xeb, 0x19, 0x38, 0x30, 0x78, 0x71, 0x73, 0x30, 0x08,
    0x34, 0xdc, 0x3a, 0xc2, 0x29, 0xd1, 0xd0, 0xc0, 0xe6, 0xc5, 0x05, 0xe2, 0x6c, 0xe9, 0x14, 0x96,
    0x68, 0x48, 0xf0, 0xe2, 0xe4, 0x78, 0x25, 0x2f, 0xc0, 0x00, 0x14, 0x66, 0xf4, 0x62, 0x05, 0x3a,
    0x66, 0x35, 0x13, 0x44, 0xe9, 0xec, 0x77, 0x4c, 0x40, 0x31, 0x0e, 0x08, 0xa7, 0xef, 0x9c, 0x0c,
    0x90, 0x23, 0x00, 0x54, 0x20, 0x20, 0xd0, 0xa2, 0x00, 0xa4, 0x58, 0x04, 0x9e, 0x18, 0x65, 0x34,
    0x7c, 0x78, 0xb1, 0x7d, 0xf6, 0xb3, 0x53, 0x3b, 0xde, 0x32, 0x16, 0x30, 0x35, 0x30, 0x32, 0x4c,
    0x60, 0x64, 0x04, 0x00, 0x3e, 0x9b, 0x55, 0xa5,
};
static const size_t kARDHPMediaBlobMode7ZlibGTLen = sizeof(kARDHPMediaBlobMode7ZlibGT);
static const uint16_t kARDHPMediaOptionsVersion = 3;
enum {
  kARDHPMediaOptionsFlagStream1Supports60FPS = ARD_HP_MEDIA_STREAM_OPTIONS_FLAG_STREAM1_SUPPORTS_60FPS,
  kARDHPMediaOptionsFlagStream2Supports60FPS = ARD_HP_MEDIA_STREAM_OPTIONS_FLAG_STREAM2_SUPPORTS_60FPS,
  kARDHPMediaOptionsFlagDoNotSendCursor = ARD_HP_MEDIA_STREAM_OPTIONS_FLAG_DO_NOT_SEND_CURSOR,
  kARDHPMediaOptionsFlagAppleRemoteDesktopViewer = ARD_HP_MEDIA_STREAM_OPTIONS_FLAG_APPLE_REMOTE_DESKTOP_VIEWER,
};
static const uint32_t kARDHPMediaOptionsFlags =
    kARDHPMediaOptionsFlagStream1Supports60FPS |
    kARDHPMediaOptionsFlagDoNotSendCursor;
static const char kARDHPMediaAppVersion[] = "2125.2.1";

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

static int ard_hp_hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
  return -1;
}

static uint8_t *ard_hp_decode_hex_blob(const char *hex, size_t *out_len) {
  size_t digits = 0;
  size_t i;
  size_t out_off = 0;
  uint8_t *buf;
  int high = -1;

  if (out_len) *out_len = 0;
  if (!hex || !*hex) return NULL;
  for (i = 0; hex[i] != '\0'; ++i) {
    if (ard_hp_hex_nibble(hex[i]) >= 0) {
      digits++;
      continue;
    }
    if (hex[i] == ' ' || hex[i] == '\n' || hex[i] == '\r' || hex[i] == '\t' || hex[i] == ':' || hex[i] == ',')
      continue;
    return NULL;
  }
  if ((digits & 1u) != 0 || digits == 0) return NULL;
  buf = (uint8_t *)malloc(digits / 2u);
  if (!buf) return NULL;
  for (i = 0; hex[i] != '\0'; ++i) {
    int nibble = ard_hp_hex_nibble(hex[i]);
    if (nibble < 0) continue;
    if (high < 0) {
      high = nibble;
      continue;
    }
    buf[out_off++] = (uint8_t)((high << 4) | nibble);
    high = -1;
  }
  if (out_len) *out_len = out_off;
  return buf;
}

static void ard_hp_cf_release(CFTypeRef value) {
  if (value) CFRelease(value);
}

static void ard_hp_read_sysctl_string(const char *name,
                                      char *out,
                                      size_t out_len,
                                      const char *fallback) {
  size_t size = out_len;

  if (!out || out_len == 0) return;
  out[0] = '\0';
  if (name && sysctlbyname(name, out, &size, NULL, 0) == 0 && out[0] != '\0')
    return;
  if (fallback && *fallback) {
    snprintf(out, out_len, "%s", fallback);
  }
}

static int ard_hp_uuid_upper(char out[37]) {
  CFUUIDRef uuid = NULL;
  CFStringRef s = NULL;
  Boolean ok = false;

  if (!out) return 0;
  out[0] = '\0';
  uuid = CFUUIDCreate(kCFAllocatorDefault);
  if (!uuid) return 0;
  s = CFUUIDCreateString(kCFAllocatorDefault, uuid);
  if (s) {
    ok = CFStringGetCString(s, out, 37, kCFStringEncodingUTF8);
  }
  if (s) CFRelease(s);
  CFRelease(uuid);
  if (!ok) return 0;
  return 1;
}

static uint8_t *ard_hp_build_endpoint_info(size_t *out_len) {
  char model[128];
  char build[128];
  const char *version = kARDHPMediaAppVersion;
  size_t model_len;
  size_t version_len;
  size_t build_len;
  size_t total_len;
  uint8_t *buf;
  size_t off = 0;

  if (out_len) *out_len = 0;
  ard_hp_read_sysctl_string("hw.model", model, sizeof(model), "MacBookAir10,1");
  ard_hp_read_sysctl_string("kern.osversion", build, sizeof(build), "24G419");
  model_len = strlen(model);
  version_len = strlen(version);
  build_len = strlen(build);
  if (model_len > 127 || version_len > 127 || build_len > 127) return NULL;

  total_len = 2 + 2 + 2 + model_len + 2 + version_len + 2 + build_len;
  buf = (uint8_t *)malloc(total_len);
  if (!buf) return NULL;

  buf[off++] = 0x08;
  buf[off++] = 0x00;
  buf[off++] = 0x10;
  buf[off++] = 0x01;
  buf[off++] = 0x1a;
  buf[off++] = (uint8_t)model_len;
  memcpy(buf + off, model, model_len);
  off += model_len;
  buf[off++] = 0x22;
  buf[off++] = (uint8_t)version_len;
  memcpy(buf + off, version, version_len);
  off += version_len;
  buf[off++] = 0x2a;
  buf[off++] = (uint8_t)build_len;
  memcpy(buf + off, build, build_len);
  off += build_len;

  if (out_len) *out_len = off;
  return buf;
}

static int ard_hp_compress_blob(const uint8_t *src,
                                size_t src_len,
                                uint8_t **out,
                                size_t *out_len) {
  uLongf cap;
  uint8_t *buf;
  int zret;

  if (out) *out = NULL;
  if (out_len) *out_len = 0;
  if (!src || src_len == 0 || !out) return 0;

  cap = compressBound((uLong)src_len);
  buf = (uint8_t *)malloc((size_t)cap);
  if (!buf) return 0;
  zret = compress2(buf, &cap, src, (uLong)src_len, Z_BEST_COMPRESSION);
  if (zret != Z_OK) {
    free(buf);
    return 0;
  }
  *out = buf;
  if (out_len) *out_len = (size_t)cap;
  return 1;
}

static uint8_t *ard_hp_make_binary_plist(int negotiator_mode,
                                         const uint8_t *remote_info,
                                         size_t remote_info_len,
                                         const uint8_t *media_blob,
                                         size_t media_blob_len,
                                         const char *call_id,
                                         size_t *out_len) {
  CFMutableDictionaryRef dict = NULL;
  CFStringRef key_remote = NULL;
  CFStringRef key_mode = NULL;
  CFStringRef key_blob = NULL;
  CFStringRef key_call = NULL;
  CFDataRef remote = NULL;
  CFDataRef blob = NULL;
  CFNumberRef mode = NULL;
  CFStringRef call = NULL;
  CFErrorRef error = NULL;
  CFDataRef plist = NULL;
  uint8_t *out = NULL;
  CFIndex plist_len = 0;

  if (out_len) *out_len = 0;
  if (!remote_info || !media_blob || !call_id) return NULL;

  dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 4,
                                   &kCFTypeDictionaryKeyCallBacks,
                                   &kCFTypeDictionaryValueCallBacks);
  key_remote = CFStringCreateWithCString(kCFAllocatorDefault,
                                         "avcMediaStreamOptionRemoteEndpointInfo",
                                         kCFStringEncodingUTF8);
  key_mode = CFStringCreateWithCString(kCFAllocatorDefault,
                                       "avcMediaStreamNegotiatorMode",
                                       kCFStringEncodingUTF8);
  key_blob = CFStringCreateWithCString(kCFAllocatorDefault,
                                       "avcMediaStreamNegotiatorMediaBlob",
                                       kCFStringEncodingUTF8);
  key_call = CFStringCreateWithCString(kCFAllocatorDefault,
                                       "avcMediaStreamOptionCallID",
                                       kCFStringEncodingUTF8);
  remote = CFDataCreate(kCFAllocatorDefault, remote_info, (CFIndex)remote_info_len);
  blob = CFDataCreate(kCFAllocatorDefault, media_blob, (CFIndex)media_blob_len);
  mode = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &negotiator_mode);
  call = CFStringCreateWithCString(kCFAllocatorDefault, call_id, kCFStringEncodingUTF8);
  if (!dict || !key_remote || !key_mode || !key_blob || !key_call || !remote || !blob || !mode || !call)
    goto cleanup;

  CFDictionarySetValue(dict, key_remote, remote);
  CFDictionarySetValue(dict, key_mode, mode);
  CFDictionarySetValue(dict, key_blob, blob);
  CFDictionarySetValue(dict, key_call, call);

  plist = CFPropertyListCreateData(kCFAllocatorDefault,
                                   dict,
                                   kCFPropertyListBinaryFormat_v1_0,
                                   0,
                                   &error);
  if (!plist) goto cleanup;
  plist_len = CFDataGetLength(plist);
  if (plist_len <= 0) goto cleanup;
  out = (uint8_t *)malloc((size_t)plist_len);
  if (!out) goto cleanup;
  memcpy(out, CFDataGetBytePtr(plist), (size_t)plist_len);
  if (out_len) *out_len = (size_t)plist_len;

cleanup:
  if (!out && error) {
    CFStringRef desc = CFErrorCopyDescription(error);
    char text[256];
    text[0] = '\0';
    if (desc) {
      CFStringGetCString(desc, text, sizeof(text), kCFStringEncodingUTF8);
      CFRelease(desc);
    }
    rfbClientErr("ard-hp: failed to build MediaStreamOptions plist%s%s\n",
                 text[0] ? ": " : "",
                 text[0] ? text : "");
  }
  ard_hp_cf_release(plist);
  ard_hp_cf_release(error);
  ard_hp_cf_release(call);
  ard_hp_cf_release(mode);
  ard_hp_cf_release(blob);
  ard_hp_cf_release(remote);
  ard_hp_cf_release(key_call);
  ard_hp_cf_release(key_blob);
  ard_hp_cf_release(key_mode);
  ard_hp_cf_release(key_remote);
  ard_hp_cf_release(dict);
  return out;
}

static uint8_t *ard_hp_build_adaptive_media_stream_options(size_t *out_len) {
  uint8_t *endpoint_info = NULL;
  uint8_t *blob_mode8_owned = NULL;
  uint8_t *blob_mode7_owned = NULL;
  const uint8_t *blob_mode8 = NULL;
  const uint8_t *blob_mode7 = NULL;
  uint8_t *plist_mode8 = NULL;
  uint8_t *plist_mode7 = NULL;
  uint8_t *msg = NULL;
  size_t endpoint_info_len = 0;
  size_t blob_mode8_len = 0;
  size_t blob_mode7_len = 0;
  size_t plist_mode8_len = 0;
  size_t plist_mode7_len = 0;
  size_t total_len;
  size_t off = 0;
  char call_id_mode8[37];
  char call_id_mode7[37];
  uint16_t audio_offer_len = 0;
  uint16_t video1_offer_len = 0;
  uint16_t video2_offer_len = 0;
  int runtime_blob_compress = 0;
  uint8_t prefix1_dynamic[sizeof(kARDHPMediaOptionsPrefix1)];
  uint8_t mid_dynamic[sizeof(kARDHPMediaOptionsMid)];
  const uint8_t *prefix1_data = kARDHPMediaOptionsPrefix1;
  const uint8_t *mid_data = kARDHPMediaOptionsMid;

  if (out_len) *out_len = 0;
  endpoint_info = ard_hp_build_endpoint_info(&endpoint_info_len);
  if (!endpoint_info) goto cleanup;
  if (!ard_hp_uuid_upper(call_id_mode8) || !ard_hp_uuid_upper(call_id_mode7)) goto cleanup;
  runtime_blob_compress = ard_hp_env_flag_enabled("VNC_ARD_HP_MEDIA_USE_RUNTIME_ZLIB");
  if (runtime_blob_compress) {
    if (!ard_hp_compress_blob(kARDHPMediaBlobMode8Raw, kARDHPMediaBlobMode8RawLen,
                              &blob_mode8_owned, &blob_mode8_len))
      goto cleanup;
    if (!ard_hp_compress_blob(kARDHPMediaBlobMode7Raw, kARDHPMediaBlobMode7RawLen,
                              &blob_mode7_owned, &blob_mode7_len))
      goto cleanup;
    blob_mode8 = blob_mode8_owned;
    blob_mode7 = blob_mode7_owned;
  } else {
    blob_mode8 = kARDHPMediaBlobMode8ZlibGT;
    blob_mode8_len = kARDHPMediaBlobMode8ZlibGTLen;
    blob_mode7 = kARDHPMediaBlobMode7ZlibGT;
    blob_mode7_len = kARDHPMediaBlobMode7ZlibGTLen;
  }
  if (!ard_hp_env_flag_enabled("VNC_ARD_HP_MEDIA_USE_STATIC_PREFIX_MID")) {
    /* Native ScreenSharing generates these 46-byte control chunks per stream. */
    arc4random_buf(prefix1_dynamic, sizeof(prefix1_dynamic));
    arc4random_buf(mid_dynamic, sizeof(mid_dynamic));
    prefix1_data = prefix1_dynamic;
    mid_data = mid_dynamic;
  }
  plist_mode8 = ard_hp_make_binary_plist(8, endpoint_info, endpoint_info_len,
                                         blob_mode8, blob_mode8_len,
                                         call_id_mode8, &plist_mode8_len);
  plist_mode7 = ard_hp_make_binary_plist(7, endpoint_info, endpoint_info_len,
                                         blob_mode7, blob_mode7_len,
                                         call_id_mode7, &plist_mode7_len);
  if (!plist_mode8 || !plist_mode7) goto cleanup;

  if (plist_mode8_len > 0xffffu || plist_mode7_len > 0xffffu) goto cleanup;
  total_len = ARD_HP_MEDIA_STREAM_OPTIONS_HEADER_LEN + kARDHPMediaOptionsPrefix1Len + plist_mode8_len +
              kARDHPMediaOptionsMidLen + plist_mode7_len;
  msg = (uint8_t *)calloc(1, total_len);
  if (!msg) goto cleanup;

  msg[0] = ARD_HP_MSG_MEDIA_STREAM_OPTIONS;
  ard_hp_store_be16(msg + 2, (uint16_t)(total_len - 4));
  ard_hp_store_be16(msg + 4, kARDHPMediaOptionsVersion);
  ard_hp_store_be32(msg + 6, kARDHPMediaOptionsFlags);
  if (ard_hp_env_flag_enabled("VNC_ARD_HP_MEDIA_SESSION_ID_ZERO")) {
    memset(msg + 20, 0, ARD_HP_MEDIA_STREAM_OPTIONS_SESSION_ID_LEN);
  } else {
    arc4random_buf(msg + 20, ARD_HP_MEDIA_STREAM_OPTIONS_SESSION_ID_LEN);
  }
  audio_offer_len = (uint16_t)plist_mode8_len;
  video1_offer_len = (uint16_t)plist_mode7_len;
  video2_offer_len = 0;
  ard_hp_store_be16(msg + 10, audio_offer_len);
  ard_hp_store_be16(msg + 12, video1_offer_len);
  ard_hp_store_be16(msg + 14, video2_offer_len);
  off = ARD_HP_MEDIA_STREAM_OPTIONS_HEADER_LEN;
  memcpy(msg + off, prefix1_data, kARDHPMediaOptionsPrefix1Len);
  off += kARDHPMediaOptionsPrefix1Len;
  memcpy(msg + off, plist_mode8, plist_mode8_len);
  off += plist_mode8_len;
  memcpy(msg + off, mid_data, kARDHPMediaOptionsMidLen);
  off += kARDHPMediaOptionsMidLen;
  memcpy(msg + off, plist_mode7, plist_mode7_len);
  off += plist_mode7_len;
  if (out_len) *out_len = off;

cleanup:
  free(plist_mode7);
  free(plist_mode8);
  free(blob_mode7_owned);
  free(blob_mode8_owned);
  free(endpoint_info);
  return msg;
}

static uint32_t ard_hp_auto_fbu_interval_ms(void) {
  const char *s = ard_hp_getenv_compat("VNC_ARD_HP_AUTO_FBU_INTERVAL_MS");
  char *end = NULL;
  long parsed;

  if (!s || !*s)
    return ARD_HP_AUTO_FRAMEBUFFER_UPDATE_INTERVAL_DEFAULT;

  parsed = strtol(s, &end, 10);
  if (!end || *end != '\0') {
    rfbClientLog("ard-hp: ignoring invalid VNC_ARD_HP_AUTO_FBU_INTERVAL_MS='%s'\n", s);
    return ARD_HP_AUTO_FRAMEBUFFER_UPDATE_INTERVAL_DEFAULT;
  }
  if (parsed < 0)
    return ARD_HP_AUTO_FRAMEBUFFER_UPDATE_INTERVAL_DEFAULT;
  if (parsed > INT_MAX)
    parsed = INT_MAX;
  return (uint32_t)parsed;
}

static void ard_hp_hex_encode(const uint8_t *src, size_t len, char *dst, size_t dst_len) {
  static const char hex[] = "0123456789abcdef";
  size_t i;

  if (!dst || dst_len == 0) return;
  if (!src || dst_len < (len * 2 + 1)) {
    dst[0] = '\0';
    return;
  }
  for (i = 0; i < len; ++i) {
    dst[i * 2] = hex[(src[i] >> 4) & 0xf];
    dst[i * 2 + 1] = hex[src[i] & 0xf];
  }
  dst[len * 2] = '\0';
}

static void ard_hp_socket_endpoint_json(int sock, int peer, char *ip_out, size_t ip_out_len, uint16_t *port_out) {
  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  int ok;

  if (ip_out && ip_out_len > 0) ip_out[0] = '\0';
  if (port_out) *port_out = 0;

  ok = peer ? getpeername(sock, (struct sockaddr *)&addr, &addr_len) : getsockname(sock, (struct sockaddr *)&addr, &addr_len);
  if (ok != 0) return;

  if (addr.ss_family == AF_INET) {
    const struct sockaddr_in *sin = (const struct sockaddr_in *)&addr;
    if (ip_out) inet_ntop(AF_INET, &sin->sin_addr, ip_out, (socklen_t)ip_out_len);
    if (port_out) *port_out = ntohs(sin->sin_port);
  } else if (addr.ss_family == AF_INET6) {
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)&addr;
    if (ip_out) inet_ntop(AF_INET6, &sin6->sin6_addr, ip_out, (socklen_t)ip_out_len);
    if (port_out) *port_out = ntohs(sin6->sin6_port);
  }
}

static void ard_hp_write_trace_sidecar(const rfbClient *client,
                                       const uint8_t *initial_key,
                                       size_t initial_key_len,
                                       uint32_t counter,
                                       const uint8_t next_key[16],
                                       const uint8_t next_iv[16]) {
  const char *path = ard_hp_getenv_compat("VNC_ARD_HP_TRACE_SIDECAR");
  FILE *fp;
  char initial_key_hex[33];
  char next_key_hex[33];
  char next_iv_hex[33];
  char local_ip[INET6_ADDRSTRLEN];
  char peer_ip[INET6_ADDRSTRLEN];
  uint16_t local_port = 0;
  uint16_t peer_port = 0;

  if (!path || !*path || !client || !initial_key || initial_key_len < 16 || !next_key || !next_iv)
    return;

  ard_hp_hex_encode(initial_key, 16, initial_key_hex, sizeof(initial_key_hex));
  ard_hp_hex_encode(next_key, 16, next_key_hex, sizeof(next_key_hex));
  ard_hp_hex_encode(next_iv, 16, next_iv_hex, sizeof(next_iv_hex));
  ard_hp_socket_endpoint_json(client->sock, 0, local_ip, sizeof(local_ip), &local_port);
  ard_hp_socket_endpoint_json(client->sock, 1, peer_ip, sizeof(peer_ip), &peer_port);

  fp = fopen(path, "w");
  if (!fp) {
    rfbClientErr("ard-hp: failed to write trace sidecar '%s' (%d: %s)\n", path, errno, strerror(errno));
    return;
  }

  fprintf(fp,
          "{\n"
          "  \"schema\": \"ardhp-trace-sidecar-v1\",\n"
          "  \"local_ip\": \"%s\",\n"
          "  \"local_port\": %u,\n"
          "  \"peer_ip\": \"%s\",\n"
          "  \"peer_port\": %u,\n"
          "  \"initial_session_key_hex\": \"%s\",\n"
          "  \"rekey_counter\": %u,\n"
          "  \"rekey_key_hex\": \"%s\",\n"
          "  \"rekey_iv_hex\": \"%s\"\n"
          "}\n",
          local_ip,
          (unsigned)local_port,
          peer_ip,
          (unsigned)peer_port,
          initial_key_hex,
          (unsigned)counter,
          next_key_hex,
          next_iv_hex);
  fclose(fp);
  rfbClientLog("ard-hp: wrote trace sidecar %s\n", path);
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
    case 0x000003eau: return "ARDRFBMediaStreamMessage3";
    case 0x000003f2u: return "ARDRFBMediaStreamMessage1";
    case 0x000003f3u: return "ARDRFBMediaStreamMessage2";
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

static void ard_hp_media_stream_flags_to_text(uint32_t flags, char *out, size_t out_len) {
  size_t off = 0;
#define APPEND_FLAG(name)                                                                \
  do {                                                                                   \
    int wrote;                                                                           \
    if (!out || out_len == 0) break;                                                     \
    wrote = snprintf(out + off, out_len - off, "%s%s", off ? "|" : "", (name));         \
    if (wrote < 0) return;                                                               \
    if ((size_t)wrote >= out_len - off) {                                                \
      off = out_len - 1;                                                                 \
      out[off] = '\0';                                                                   \
      return;                                                                            \
    }                                                                                    \
    off += (size_t)wrote;                                                                \
  } while (0)

  if (!out || out_len == 0) return;
  out[0] = '\0';
  if (flags & ARD_HP_MEDIA_STREAM_OPTIONS_FLAG_STREAM1_SUPPORTS_60FPS)
    APPEND_FLAG("stream1_supports_60fps");
  if (flags & ARD_HP_MEDIA_STREAM_OPTIONS_FLAG_STREAM2_SUPPORTS_60FPS)
    APPEND_FLAG("stream2_supports_60fps");
  if (flags & ARD_HP_MEDIA_STREAM_OPTIONS_FLAG_DO_NOT_SEND_CURSOR)
    APPEND_FLAG("do_not_send_cursor");
  if (flags & ARD_HP_MEDIA_STREAM_OPTIONS_FLAG_APPLE_REMOTE_DESKTOP_VIEWER)
    APPEND_FLAG("apple_remote_desktop_viewer");
  if (off == 0 && out_len > 1) snprintf(out, out_len, "none");
#undef APPEND_FLAG
}

static int ard_hp_parse_media_stream_options_header(const uint8_t *buf, size_t len,
                                                    uint16_t *declared_size,
                                                    uint16_t *version,
                                                    uint32_t *flags,
                                                    uint16_t *audio_offer_len,
                                                    uint16_t *video1_offer_len,
                                                    uint16_t *video2_offer_len,
                                                    int *declared_size_matches) {
  if (!buf || len < ARD_HP_MEDIA_STREAM_OPTIONS_HEADER_LEN) return 0;
  if (buf[0] != ARD_HP_MSG_MEDIA_STREAM_OPTIONS) return 0;
  if (declared_size) *declared_size = ard_hp_read_be_u16(buf + 2);
  if (version) *version = ard_hp_read_be_u16(buf + 4);
  if (flags) *flags = ard_hp_read_be_u32(buf + 6);
  if (audio_offer_len) *audio_offer_len = ard_hp_read_be_u16(buf + 10);
  if (video1_offer_len) *video1_offer_len = ard_hp_read_be_u16(buf + 12);
  if (video2_offer_len) *video2_offer_len = ard_hp_read_be_u16(buf + 14);
  if (declared_size_matches) {
    uint16_t msg_size = ard_hp_read_be_u16(buf + 2);
    *declared_size_matches = ((size_t)msg_size == (len - 4));
  }
  return 1;
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
  if (n > 0 && ard_hp_env_flag_enabled("VNC_ARD_HP_TRACE_CLIENT_MSGS")) {
    rfbClientLog("ard-hp: transport send msg=0x%02x len=%u\n", (unsigned)((const uint8_t *)buf)[0], n);
  }
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
  int adaptive_mode;

  if (!client) return FALSE;
  adaptive_mode = ard_hp_env_flag_enabled("VNC_ARD_HP_ADAPTIVE_MODE");
  rfbClientLog("ard-hp: sending cleartext pre-rekey setup\n");
  viewer_info = ard_hp_make_native_viewer_info();
  if (!send_blob(client, &viewer_info, sizeof(viewer_info), "ard-hp ViewerInfo")) return FALSE;
  {
    struct ard_hp_set_encryption_message msg = ard_hp_make_native_prelude_set_encryption();
    if (!send_blob(client, &msg, sizeof(msg), "ard-hp SetEncryptionMessage")) return FALSE;
  }
  if (adaptive_mode) {
    struct ard_hp_set_mode_message msg = ard_hp_make_set_mode_message(0);
    if (!send_blob(client, &msg, sizeof(msg), "ard-hp SetModeMessage")) return FALSE;
    rfbClientLog("ard-hp: adaptive mode uses SetModeMessage mode=0\n");
  } else {
    struct ard_hp_set_mode_message msg = ard_hp_make_native_prelude_set_mode();
    if (!send_blob(client, &msg, sizeof(msg), "ard-hp SetModeMessage")) return FALSE;
  }
  if (!rfbClientARDHPSendInitialDisplayConfiguration(client)) return FALSE;
  if (adaptive_mode) {
    rfbClientLog("ard-hp: adaptive mode defers pre-rekey SetEncodings until post-rekey transport\n");
  } else {
    if (!rfbClientARDHPSendPostAuthEncodings(client)) return FALSE;
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
  ard_hp_write_trace_sidecar(client, session_key, session_key_len, *counter, next_key, next_iv);
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
  int32_t encodings[(sizeof(kARDHPNativePostAuthEncodings) / sizeof(kARDHPNativePostAuthEncodings[0])) + 4];
  size_t count = 0;
  size_t i;
  int add_promode = ard_hp_env_flag_enabled("VNC_ARD_HP_ADD_PROMODE_ENCODING");
  int prefer_promode = ard_hp_env_flag_enabled("VNC_ARD_HP_PREFER_PROMODE_ENCODING");
  int adaptive_mode = ard_hp_env_flag_enabled("VNC_ARD_HP_ADAPTIVE_MODE");
  int adaptive_advertise_media_encodings =
      !ard_hp_env_flag_enabled("VNC_ARD_HP_ADAPTIVE_DISABLE_MEDIA_ENCODINGS");
  int omit_44c = ard_hp_env_flag_enabled("VNC_ARD_HP_OMIT_44C");
  int omit_44d = ard_hp_env_flag_enabled("VNC_ARD_HP_OMIT_44D");
  int disable_zlib = ard_hp_env_flag_enabled("VNC_DISABLE_ZLIB");
  int disable_zrle = ard_hp_env_flag_enabled("VNC_DISABLE_ZRLE");

  if (!client) return FALSE;
  if (adaptive_mode) {
    if (adaptive_advertise_media_encodings) {
      add_promode = 1;
      prefer_promode = 1;
      rfbClientLog("ard-hp: adaptive/media branch also uses client message 0x1c MediaStreamOptions; "
                   "advertising the native 0x3f2/0x3f3/0x3ea media family\n");
    } else {
      rfbClientLog("ard-hp: adaptive/media branch uses client message 0x1c MediaStreamOptions; "
                   "keeping SetEncodings on native non-media family (set "
                   "VNC_ARD_HP_ADAPTIVE_DISABLE_MEDIA_ENCODINGS=1 to disable 0x3f2/0x3f3/0x3ea)\n");
    }
  }
  if (add_promode && prefer_promode) {
    if (adaptive_mode) {
      for (i = 0; i < sizeof(kARDHPAdaptiveEncodings) / sizeof(kARDHPAdaptiveEncodings[0]); ++i) {
        encodings[count++] = kARDHPAdaptiveEncodings[i];
        rfbClientLog("ard-hp: prepending adaptive SetEncodings capability 0x%03x\n",
                     (unsigned)kARDHPAdaptiveEncodings[i]);
      }
    } else {
      encodings[count++] = kARDHPProModeEncoding;
      rfbClientLog("ard-hp: prepending %s SetEncodings capability 0x%03x\n",
                   adaptive_mode ? "adaptive" : "ProMode",
                   kARDHPProModeEncoding);
    }
  }
  for (i = 0; i < sizeof(kARDHPNativePostAuthEncodings) / sizeof(kARDHPNativePostAuthEncodings[0]); ++i) {
    if (disable_zlib && kARDHPNativePostAuthEncodings[i] == 0x6)
      continue;
    if (disable_zrle && kARDHPNativePostAuthEncodings[i] == 0x10)
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
    rfbClientLog("ard-hp: adding %s SetEncodings capability 0x%03x\n",
                 adaptive_mode ? "adaptive" : "ProMode",
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

rfbBool rfbClientARDHPSendMediaStreamOptionsHex(rfbClient *client, const char *hex) {
  uint8_t *buf;
  size_t len = 0;
  rfbBool ok;
  uint16_t declared_size = 0;
  uint16_t version = 0;
  uint16_t audio_offer_len = 0;
  uint16_t video1_offer_len = 0;
  uint16_t video2_offer_len = 0;
  uint32_t flags = 0;
  int declared_size_matches = 0;
  char flag_text[128];

  if (!client || !hex || !*hex) return TRUE;
  buf = ard_hp_decode_hex_blob(hex, &len);
  if (!buf || len == 0) {
    free(buf);
    rfbClientErr("ard-hp: invalid VNC_ARD_HP_MEDIA_STREAM_OPTIONS_HEX payload\n");
    return FALSE;
  }
  if (buf[0] != ARD_HP_MSG_MEDIA_STREAM_OPTIONS) {
    rfbClientErr("ard-hp: media-stream options blob must start with 0x%02x, got 0x%02x\n",
                 ARD_HP_MSG_MEDIA_STREAM_OPTIONS, buf[0]);
    free(buf);
    return FALSE;
  }
  if (ard_hp_parse_media_stream_options_header(
          buf, len, &declared_size, &version, &flags, &audio_offer_len,
          &video1_offer_len, &video2_offer_len, &declared_size_matches)) {
    ard_hp_media_stream_flags_to_text(flags, flag_text, sizeof(flag_text));
    rfbClientLog("ard-hp: sending MediaStreamOptions 0x1c (%lu bytes ver=%u declared=%u match=%d flags=0x%08x[%s] audio_offer=%u video1_offer=%u video2_offer=%u)\n",
                 (unsigned long)len,
                 (unsigned)version,
                 (unsigned)declared_size,
                 declared_size_matches,
                 (unsigned)flags,
                 flag_text,
                 (unsigned)audio_offer_len,
                 (unsigned)video1_offer_len,
                 (unsigned)video2_offer_len);
  } else {
    rfbClientLog("ard-hp: sending MediaStreamOptions 0x1c (%lu bytes)\n", (unsigned long)len);
  }
  ok = WriteToRFBServer(client, (const char *)buf, (unsigned int)len);
  free(buf);
  return ok;
}

rfbBool rfbClientARDHPSendAdaptiveMediaStreamOptions(rfbClient *client) {
  uint8_t *buf;
  size_t len = 0;
  rfbBool ok;
  uint16_t audio_offer_len;
  uint16_t video1_offer_len;
  uint16_t video2_offer_len;
  uint16_t declared_size = 0;
  uint16_t version = 0;
  uint32_t flags;
  int declared_size_matches = 0;
  char flag_text[128];

  if (!client) return FALSE;
  buf = ard_hp_build_adaptive_media_stream_options(&len);
  if (!buf || len == 0) {
    free(buf);
    rfbClientErr("ard-hp: failed to build adaptive MediaStreamOptions 0x1c payload\n");
    return FALSE;
  }
  audio_offer_len = 0;
  video1_offer_len = 0;
  video2_offer_len = 0;
  flags = 0;
  if (!ard_hp_parse_media_stream_options_header(
          buf, len, &declared_size, &version, &flags, &audio_offer_len,
          &video1_offer_len, &video2_offer_len, &declared_size_matches)) {
    declared_size = 0;
    version = 0;
    declared_size_matches = 0;
  }
  ard_hp_media_stream_flags_to_text(flags, flag_text, sizeof(flag_text));
  rfbClientLog("ard-hp: sending adaptive MediaStreamOptions 0x1c (%lu bytes version=%u declared=%u match=%d flags=0x%08x[%s] audio_offer=%u video1_offer=%u video2_offer=%u)\n",
               (unsigned long)len,
               (unsigned)version,
               (unsigned)declared_size,
               declared_size_matches,
               (unsigned)flags,
               flag_text,
               (unsigned)audio_offer_len,
               (unsigned)video1_offer_len,
               (unsigned)video2_offer_len);
  ok = WriteToRFBServer(client, (const char *)buf, (unsigned int)len);
  free(buf);
  return ok;
}

rfbBool rfbClientARDHPBuildAdaptiveMediaStreamOptionsHex(char **out_hex) {
  uint8_t *buf = NULL;
  size_t len = 0;
  char *hex = NULL;

  if (out_hex) *out_hex = NULL;
  if (!out_hex) return FALSE;

  buf = ard_hp_build_adaptive_media_stream_options(&len);
  if (!buf || len == 0) {
    free(buf);
    return FALSE;
  }

  if (len > ((SIZE_MAX - 1u) / 2u)) {
    free(buf);
    return FALSE;
  }
  hex = (char *)malloc((len * 2u) + 1u);
  if (!hex) {
    free(buf);
    return FALSE;
  }
  ard_hp_hex_encode(buf, len, hex, (len * 2u) + 1u);
  free(buf);
  *out_hex = hex;
  return TRUE;
}

rfbBool rfbClientARDHPSendScaleFactor(rfbClient *client, double scale) {
  struct ard_hp_scale_factor_message msg = ard_hp_make_scale_factor_message(scale);
  rfbClientLog("ard-hp: using scale factor %.6f\n", scale);
  return send_blob(client, &msg, sizeof(msg), "ard-hp scale factor");
}

rfbBool rfbClientARDHPSendAutoFramebufferUpdate(rfbClient *client, uint16_t width, uint16_t height) {
  uint32_t interval_ms = ard_hp_auto_fbu_interval_ms();
  struct ard_hp_auto_framebuffer_update_message msg =
      ard_hp_make_auto_framebuffer_update_message(
          ARD_HP_AUTO_FRAMEBUFFER_UPDATE_ENABLE,
          interval_ms,
          0, 0, width, height);

  rfbClientLog("ard-hp: sending AutoFrameBufferUpdate interval=%u region=%ux%u\n",
               (unsigned)interval_ms,
               (unsigned)width, (unsigned)height);
  return WriteToRFBServer(client, (const char *)&msg, sizeof(msg));
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
  if (client->frameBuffer && client->width == alloc_w && client->height == alloc_h) return TRUE;
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
