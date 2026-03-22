#ifndef LIBVNCSERVER_EXAMPLES_CLIENT_APPLEHP_PROTOCOL_H
#define LIBVNCSERVER_EXAMPLES_CLIENT_APPLEHP_PROTOCOL_H

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

enum apple_hp_client_message_type {
  APPLE_HP_MSG_SET_ENCODINGS = 0x02,
  APPLE_HP_MSG_FRAMEBUFFER_UPDATE_REQUEST = 0x03,
  APPLE_HP_MSG_SCALE_FACTOR = 0x08,
  APPLE_HP_MSG_AUTO_FRAMEBUFFER_UPDATE = 0x09,
  APPLE_HP_MSG_SET_MODE = 0x0a,
  APPLE_HP_MSG_SET_DISPLAY = 0x0d,
  APPLE_HP_MSG_EXTENSION_0x12 = 0x12,
  APPLE_HP_MSG_AUTO_PASTEBOARD = 0x15,
  APPLE_HP_MSG_DISPLAY_CONFIGURATION = 0x1d,
  APPLE_HP_MSG_VIEWER_INFO = 0x21,
};

enum apple_hp_encoding_type {
  /* Apple-private FramebufferUpdate rectangle encodings observed on the wire. */
  APPLE_HP_ENCODING_CURSOR_IMAGE = 0x450,
  APPLE_HP_ENCODING_DISPLAY_LAYOUT = 0x451,
  APPLE_HP_ENCODING_DISPLAY_MODE = 0x453,
  APPLE_HP_ENCODING_KEYBOARD_LAYOUT = 0x455,
  APPLE_HP_ENCODING_DISPLAY_INFO = 0x456,
  APPLE_HP_ENCODING_MEDIA_STREAM = 0x3f2,
};

enum apple_hp_auth33_constants {
  APPLE_HP_AUTH33_KEY_REQUEST_PACKET_LEN = 14,
  APPLE_HP_AUTH33_INIT_PACKET_LEN = 654,
  APPLE_HP_AUTH33_KEY_MATERIAL_LEN = 256,
  APPLE_HP_AUTH33_INIT_PLAINTEXT_FIXED_FIELDS_LEN = 11,
  APPLE_HP_VIEWER_INFO_FEATURE_BITMAP_LEN = 32,
  APPLE_HP_DISPLAY_CONFIG_INFO_REGION_LEN = 0x78,
  APPLE_HP_DISPLAY_CONFIG_MODE_COUNT = 5,
};

enum apple_hp_display_config_flags {
  APPLE_HP_DISPLAY_CONFIG_FLAG_DYNAMIC_RESOLUTION = 0x00000001u,
};

struct apple_hp_auth33_rsa1_init_prefix {
  uint8_t packet_len_be[4];
  uint8_t packet_version_be[2];
  char envelope[4];
  uint8_t auth_type_be[2];
  uint8_t aux_type_be[2];
  uint8_t key_material[APPLE_HP_AUTH33_KEY_MATERIAL_LEN];
};

struct apple_hp_auth33_rsa1_key_request {
  uint8_t packet_len_be[4];
  uint8_t packet_version_be[2];
  char envelope[4];
  uint8_t auth_type_be[2];
  uint8_t aux_type_be[2];
};

struct apple_hp_auth33_step1_prefix {
  uint8_t payload_len_be[4];
  uint8_t empty_string0_len_be[2];
  uint8_t username_len_be[2];
};

enum { APPLE_HP_SET_MODE_CONTROL = 1 };

enum {
  APPLE_HP_ENCRYPTION_COMMAND_ENABLE = 1,
  /* Native 8-byte follow-up sent during the 0x455 keyboard-input-source path. */
  APPLE_HP_ENCRYPTION_COMMAND_STAGE2 = 2,
  APPLE_HP_ENCRYPTION_METHOD_AES128 = 1,
};

enum {
  /*
   * Viewer-command support bitmap bits from the native ViewerInfo payload.
   * These are capability ids, not rect encodings. Keep the numeric names for
   * ids whose semantics are not proven yet.
   */
  APPLE_HP_VIEWER_CMD_FRAMEBUFFER_UPDATE = 0,
  APPLE_HP_VIEWER_CMD_BELL = 2,
  APPLE_HP_VIEWER_CMD_SERVER_CUT_TEXT = 3,
  APPLE_HP_VIEWER_CMD_MISC_STATE_CHANGE = 20,
  APPLE_HP_VIEWER_CMD_0x1e = 30,
  APPLE_HP_VIEWER_CMD_0x1f = 31,
  APPLE_HP_VIEWER_CMD_0x20 = 32,
  APPLE_HP_VIEWER_CMD_0x23 = 35,
  APPLE_HP_VIEWER_CMD_0x51 = 81,
};

struct apple_hp_set_mode_message {
  uint8_t type;
  uint8_t reserved;
  uint8_t mode_be[2];
};

struct apple_hp_set_encryption_message {
  uint8_t type;
  uint8_t reserved;
  uint8_t message_version_be[2];
  uint8_t encryption_command_be[2];
  uint8_t encryption_method_count_be[2];
  uint8_t encryption_method_be[4];
};

struct apple_hp_set_encryption_stage2_message {
  uint8_t type;
  uint8_t reserved;
  uint8_t encryption_command_be[2];
  uint8_t value_be[2];
  uint8_t trailing_zero_be[2];
};

struct apple_hp_set_display_message {
  uint8_t type;
  uint8_t combine_all_displays;
  uint8_t reserved[2];
  uint8_t display_id_be[4];
};

struct apple_hp_scale_factor_message {
  uint8_t type;
  uint8_t flags;
  uint8_t scale_be[8];
};

struct apple_hp_auto_pasteboard_message {
  uint8_t type;
  uint8_t reserved[2];
  uint8_t selector;
  uint8_t reserved_tail[4];
};

struct apple_hp_display_configuration_header {
  uint8_t type;
  uint8_t reserved;
  uint8_t message_size_be[2];
  uint8_t version_be[2];
  uint8_t display_count_be[2];
  uint8_t flags_be[4];
};

struct apple_hp_viewer_info_message {
  uint8_t type;
  uint8_t reserved;
  uint8_t body_len_be[2];
  uint8_t viewer_info_version_be[2];
  uint8_t viewer_app_be[4];
  uint8_t viewer_app_major_be[4];
  uint8_t viewer_app_minor_be[4];
  uint8_t viewer_app_bugfix_be[4];
  uint8_t system_major_be[4];
  uint8_t system_minor_be[4];
  uint8_t system_bugfix_be[4];
  uint8_t viewer_command_bitmap[APPLE_HP_VIEWER_INFO_FEATURE_BITMAP_LEN];
};

struct apple_hp_display_mode_entry {
  uint8_t width_be[4];
  uint8_t height_be[4];
  uint8_t scaled_width_be[4];
  uint8_t scaled_height_be[4];
  uint8_t refresh_rate_be[8];
  uint8_t flags_be[4];
};

struct apple_hp_display_info_entry {
  uint8_t display_info_size_be[2];
  char display_info_region[APPLE_HP_DISPLAY_CONFIG_INFO_REGION_LEN];
  uint8_t display_flags_be[4];
  uint8_t display_type_be[4];
  uint8_t physical_width_be[4];
  uint8_t physical_height_be[4];
  uint8_t max_width_be[4];
  uint8_t max_height_be[4];
  uint8_t current_mode_index_be[2];
  uint8_t preferred_mode_index_be[2];
  /* Constant native field in SetDisplayConfiguration; exact meaning still open. */
  uint8_t unknown_config_u32_be[4];
  uint8_t mode_count_be[2];
  struct apple_hp_display_mode_entry modes[APPLE_HP_DISPLAY_CONFIG_MODE_COUNT];
};

struct apple_hp_display_configuration_message {
  struct apple_hp_display_configuration_header header;
  struct apple_hp_display_info_entry display;
};

static inline void apple_hp_store_be16(uint8_t out[2], uint16_t value) {
  out[0] = (uint8_t)((value >> 8) & 0xff);
  out[1] = (uint8_t)(value & 0xff);
}

static inline void apple_hp_store_be32(uint8_t out[4], uint32_t value) {
  out[0] = (uint8_t)((value >> 24) & 0xff);
  out[1] = (uint8_t)((value >> 16) & 0xff);
  out[2] = (uint8_t)((value >> 8) & 0xff);
  out[3] = (uint8_t)(value & 0xff);
}

static inline void apple_hp_store_be_float(uint8_t out[4], float value) {
  union {
    float f;
    uint32_t u;
  } v;

  v.f = value;
  apple_hp_store_be32(out, v.u);
}

static inline void apple_hp_store_be_double(uint8_t out[8], double value) {
  union {
    double d;
    uint64_t u;
  } v;

  v.d = value;
  out[0] = (uint8_t)((v.u >> 56) & 0xff);
  out[1] = (uint8_t)((v.u >> 48) & 0xff);
  out[2] = (uint8_t)((v.u >> 40) & 0xff);
  out[3] = (uint8_t)((v.u >> 32) & 0xff);
  out[4] = (uint8_t)((v.u >> 24) & 0xff);
  out[5] = (uint8_t)((v.u >> 16) & 0xff);
  out[6] = (uint8_t)((v.u >> 8) & 0xff);
  out[7] = (uint8_t)(v.u & 0xff);
}

static inline void apple_hp_set_bitmap_bit(uint8_t *bitmap, uint8_t bit_index) {
  bitmap[bit_index >> 3] |= (uint8_t)(1u << (7u - (bit_index & 7u)));
}

static inline int apple_hp_build_auth33_rsa1_init_packet(
    uint8_t *out, size_t out_len, uint16_t packet_version, uint16_t auth_type,
    uint16_t aux_type, const uint8_t *key_material, size_t key_material_len) {
  struct apple_hp_auth33_rsa1_init_prefix *prefix;

  if (!out || out_len < APPLE_HP_AUTH33_INIT_PACKET_LEN) return 0;
  if (!key_material || key_material_len != APPLE_HP_AUTH33_KEY_MATERIAL_LEN) return 0;
  memset(out, 0, APPLE_HP_AUTH33_INIT_PACKET_LEN);
  prefix = (struct apple_hp_auth33_rsa1_init_prefix *)out;
  apple_hp_store_be32(prefix->packet_len_be, APPLE_HP_AUTH33_INIT_PACKET_LEN - 4);
  apple_hp_store_be16(prefix->packet_version_be, packet_version);
  memcpy(prefix->envelope, "RSA1", 4);
  apple_hp_store_be16(prefix->auth_type_be, auth_type);
  apple_hp_store_be16(prefix->aux_type_be, aux_type);
  memcpy(prefix->key_material, key_material, APPLE_HP_AUTH33_KEY_MATERIAL_LEN);
  return 1;
}

static inline int apple_hp_build_auth33_rsa1_key_request_packet(
    uint8_t *out, size_t out_len, uint16_t packet_version) {
  struct apple_hp_auth33_rsa1_key_request *req;

  if (!out || out_len < APPLE_HP_AUTH33_KEY_REQUEST_PACKET_LEN) return 0;
  memset(out, 0, APPLE_HP_AUTH33_KEY_REQUEST_PACKET_LEN);
  req = (struct apple_hp_auth33_rsa1_key_request *)out;
  apple_hp_store_be32(req->packet_len_be, APPLE_HP_AUTH33_KEY_REQUEST_PACKET_LEN - 4);
  apple_hp_store_be16(req->packet_version_be, packet_version);
  memcpy(req->envelope, "RSA1", 4);
  apple_hp_store_be16(req->auth_type_be, 0);
  apple_hp_store_be16(req->aux_type_be, 0);
  return 1;
}

static inline int apple_hp_build_auth33_init_plaintext(
    const char *username, uint8_t *out, size_t out_len, size_t *plaintext_len) {
  size_t user_len;
  size_t total_plain_len;
  struct apple_hp_auth33_step1_prefix *prefix;
  uint8_t *p;

  if (!username || !out || !plaintext_len) return 0;
  user_len = strlen(username);
  if (user_len > 0xffffu) return 0;
  total_plain_len = APPLE_HP_AUTH33_INIT_PLAINTEXT_FIXED_FIELDS_LEN + user_len;
  if (out_len < total_plain_len) return 0;
  memset(out, 0, out_len);
  prefix = (struct apple_hp_auth33_step1_prefix *)out;
  apple_hp_store_be32(prefix->payload_len_be,
                      (uint32_t)(total_plain_len - sizeof(prefix->payload_len_be)));
  apple_hp_store_be16(prefix->empty_string0_len_be, 0);
  apple_hp_store_be16(prefix->username_len_be, (uint16_t)user_len);
  memcpy(out + sizeof(*prefix), username, user_len);
  p = out + sizeof(*prefix) + user_len;
  apple_hp_store_be16(p, 0); /* %s: empty string from data_1c21e3bbc */
  p += 2;
  *p++ = 0; /* %o: empty octet string */
  *plaintext_len = total_plain_len;
  return 1;
}

static inline struct apple_hp_set_encryption_message
apple_hp_make_set_encryption_message(uint16_t command, uint16_t method_count,
                                     uint32_t method) {
  struct apple_hp_set_encryption_message msg;

  memset(&msg, 0, sizeof(msg));
  msg.type = APPLE_HP_MSG_EXTENSION_0x12;
  apple_hp_store_be16(msg.message_version_be, 1);
  apple_hp_store_be16(msg.encryption_command_be, command);
  apple_hp_store_be16(msg.encryption_method_count_be, method_count);
  apple_hp_store_be32(msg.encryption_method_be, method);
  return msg;
}

static inline struct apple_hp_set_encryption_message
apple_hp_make_native_prelude_set_encryption(void) {
  return apple_hp_make_set_encryption_message(
      APPLE_HP_ENCRYPTION_COMMAND_ENABLE, 1, APPLE_HP_ENCRYPTION_METHOD_AES128);
}

static inline struct apple_hp_set_encryption_stage2_message
apple_hp_make_post_rekey_set_encryption_stage2(void) {
  struct apple_hp_set_encryption_stage2_message msg;

  memset(&msg, 0, sizeof(msg));
  msg.type = APPLE_HP_MSG_EXTENSION_0x12;
  apple_hp_store_be16(msg.encryption_command_be, APPLE_HP_ENCRYPTION_COMMAND_STAGE2);
  apple_hp_store_be16(msg.value_be, 1);
  return msg;
}

static inline struct apple_hp_set_mode_message
apple_hp_make_set_mode_message(uint16_t mode) {
  struct apple_hp_set_mode_message msg;

  memset(&msg, 0, sizeof(msg));
  msg.type = APPLE_HP_MSG_SET_MODE;
  apple_hp_store_be16(msg.mode_be, mode);
  return msg;
}

static inline struct apple_hp_set_mode_message
apple_hp_make_native_prelude_set_mode(void) {
  return apple_hp_make_set_mode_message(APPLE_HP_SET_MODE_CONTROL);
}

static inline struct apple_hp_set_display_message
apple_hp_make_set_display_message(uint8_t combine_all_displays, uint32_t display_id) {
  struct apple_hp_set_display_message msg;

  memset(&msg, 0, sizeof(msg));
  msg.type = APPLE_HP_MSG_SET_DISPLAY;
  msg.combine_all_displays = combine_all_displays;
  apple_hp_store_be32(msg.display_id_be, display_id);
  return msg;
}

static inline struct apple_hp_scale_factor_message
apple_hp_make_scale_factor_message(double scale) {
  struct apple_hp_scale_factor_message msg;

  memset(&msg, 0, sizeof(msg));
  msg.type = APPLE_HP_MSG_SCALE_FACTOR;
  apple_hp_store_be_double(msg.scale_be, scale);
  return msg;
}

static inline struct apple_hp_auto_pasteboard_message
apple_hp_make_auto_pasteboard_message(uint8_t selector) {
  struct apple_hp_auto_pasteboard_message msg;

  memset(&msg, 0, sizeof(msg));
  msg.type = APPLE_HP_MSG_AUTO_PASTEBOARD;
  msg.selector = selector;
  return msg;
}

static inline struct apple_hp_viewer_info_message apple_hp_make_native_viewer_info(void) {
  struct apple_hp_viewer_info_message msg;

  memset(&msg, 0, sizeof(msg));
  msg.type = APPLE_HP_MSG_VIEWER_INFO;
  apple_hp_store_be16(msg.body_len_be, sizeof(msg) - 4);
  apple_hp_store_be16(msg.viewer_info_version_be, 1);
  apple_hp_store_be32(msg.viewer_app_be, 2);
  apple_hp_store_be32(msg.viewer_app_major_be, 5);
  apple_hp_store_be32(msg.viewer_app_minor_be, 3);
  apple_hp_store_be32(msg.viewer_app_bugfix_be, 0);
  apple_hp_store_be32(msg.system_major_be, 15);
  apple_hp_store_be32(msg.system_minor_be, 7);
  apple_hp_store_be32(msg.system_bugfix_be, 0);
  apple_hp_set_bitmap_bit(msg.viewer_command_bitmap, APPLE_HP_VIEWER_CMD_FRAMEBUFFER_UPDATE);
  apple_hp_set_bitmap_bit(msg.viewer_command_bitmap, APPLE_HP_VIEWER_CMD_BELL);
  apple_hp_set_bitmap_bit(msg.viewer_command_bitmap, APPLE_HP_VIEWER_CMD_SERVER_CUT_TEXT);
  apple_hp_set_bitmap_bit(msg.viewer_command_bitmap, APPLE_HP_VIEWER_CMD_MISC_STATE_CHANGE);
  apple_hp_set_bitmap_bit(msg.viewer_command_bitmap, APPLE_HP_VIEWER_CMD_0x1e);
  apple_hp_set_bitmap_bit(msg.viewer_command_bitmap, APPLE_HP_VIEWER_CMD_0x1f);
  apple_hp_set_bitmap_bit(msg.viewer_command_bitmap, APPLE_HP_VIEWER_CMD_0x20);
  apple_hp_set_bitmap_bit(msg.viewer_command_bitmap, APPLE_HP_VIEWER_CMD_0x23);
  apple_hp_set_bitmap_bit(msg.viewer_command_bitmap, APPLE_HP_VIEWER_CMD_0x51);
  return msg;
}

static inline struct apple_hp_display_configuration_message
apple_hp_make_native_display_configuration(void) {
  struct apple_hp_display_configuration_message msg;
  const char *simple_1080p = getenv("VNC_APPLE_HP_SIMPLE_1080P");
  int force_simple_1080p = simple_1080p && *simple_1080p &&
                           strcmp(simple_1080p, "0") != 0 &&
                           strcmp(simple_1080p, "false") != 0 &&
                           strcmp(simple_1080p, "FALSE") != 0 &&
                           strcmp(simple_1080p, "no") != 0 &&
                           strcmp(simple_1080p, "NO") != 0;
  static const struct {
    uint32_t width;
    uint32_t height;
    uint32_t scaled_width;
    uint32_t scaled_height;
    double refresh_rate;
    uint32_t flags;
  } kModes[APPLE_HP_DISPLAY_CONFIG_MODE_COUNT] = {
      {3840, 2160, 1920, 1080, 60.0, 0},
      {2880, 1800, 1440, 900, 60.0, 0},
      {3840, 2160, 1920, 1080, 60.0, 0},
      {2880, 1620, 1440, 810, 60.0, 0},
      {2624, 1696, 1312, 848, 60.0, 0},
  };
  size_t i;

  memset(&msg, 0, sizeof(msg));
  msg.header.type = APPLE_HP_MSG_DISPLAY_CONFIGURATION;
  apple_hp_store_be16(msg.header.message_size_be, sizeof(msg) - 4);
  apple_hp_store_be16(msg.header.version_be, 1);
  apple_hp_store_be16(msg.header.display_count_be, 1);
  apple_hp_store_be16(msg.display.display_info_size_be, sizeof(msg.display));
  memcpy(msg.display.display_info_region, "Screen Sharing Virtual Display",
         sizeof("Screen Sharing Virtual Display"));
  apple_hp_store_be_float(msg.display.physical_width_be, 369.4545593261719f);
  apple_hp_store_be_float(msg.display.physical_height_be, 207.81817626953125f);
  apple_hp_store_be32(msg.display.max_width_be, force_simple_1080p ? 1920 : 3840);
  apple_hp_store_be32(msg.display.max_height_be, force_simple_1080p ? 1080 : 2160);
  apple_hp_store_be16(msg.display.current_mode_index_be, 0);
  apple_hp_store_be16(msg.display.preferred_mode_index_be, 0);
  apple_hp_store_be32(msg.display.unknown_config_u32_be, 7);
  apple_hp_store_be16(msg.display.mode_count_be, APPLE_HP_DISPLAY_CONFIG_MODE_COUNT);
  for (i = 0; i < APPLE_HP_DISPLAY_CONFIG_MODE_COUNT; ++i) {
    apple_hp_store_be32(msg.display.modes[i].width_be, force_simple_1080p ? 1920 : kModes[i].width);
    apple_hp_store_be32(msg.display.modes[i].height_be, force_simple_1080p ? 1080 : kModes[i].height);
    apple_hp_store_be32(msg.display.modes[i].scaled_width_be, 1920);
    apple_hp_store_be32(msg.display.modes[i].scaled_height_be, 1080);
    apple_hp_store_be_double(msg.display.modes[i].refresh_rate_be, kModes[i].refresh_rate);
    apple_hp_store_be32(msg.display.modes[i].flags_be, kModes[i].flags);
  }
  return msg;
}

#endif
