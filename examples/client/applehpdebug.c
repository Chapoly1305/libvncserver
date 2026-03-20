/**
 * applehpdebug.c
 * Debug-focused libvncclient example for macOS Screen Sharing / ARD targets.
 *
 * Usage:
 *   applehpdebug <host> [port] [seconds]
 *
 * Environment:
 *   VNC_USER=<username>
 *   VNC_PASS=<password>
 *   VNC_ENCODINGS="<encodings string>"
 */

#include <rfb/rfbclient.h>

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "applehp_protocol.h"

#if defined(__has_include)
#if __has_include(<SDL.h>)
#include <SDL.h>
#include <zlib.h>
#define APPLEHPDEBUG_HAS_SDL 1
#endif
#endif

#if !defined(NDEBUG)
#define APPLEHPDEBUG_DEBUG_BUILD 1
#else
#define APPLEHPDEBUG_DEBUG_BUILD 0
#endif

#define APPLEHP_INFO_LOG(...) rfbClientLog(__VA_ARGS__)
#define APPLEHP_ERROR_LOG(...) rfbClientErr(__VA_ARGS__)

static volatile sig_atomic_t g_stop = 0;
struct apple_hp_frame_stats {
  unsigned long long rects;
  unsigned long long frames;
  unsigned long long pixels;
  unsigned long long frame_pixels;
  unsigned long long bytes_est;
  long long first_frame_ms;
  long long last_frame_ms;
};

struct apple_hp_runtime_options {
  int live_view;
  int live_view_vsync;
  int low_latency_input;
  int log_input;
  int apple_hp_mode;
};

struct apple_hp_known_krb_realm {
  const char *host;
  const char *realm;
};

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

struct apple_hp_session_state {
  int rekey_seen;
  int post_rekey_ready;
  int post_rekey_sent;
  int post_rekey_server_records;
  int post_rekey_phase;
  int initial_full_refresh_done;
  int initial_full_refresh_retries;
  int displayinfo2_seen;
  int auto_fbu_active;
  int visible_content_valid;
  int visible_content_x;
  int visible_content_y;
  int visible_content_w;
  int visible_content_h;
  uint16_t display_scaled_w;
  uint16_t display_scaled_h;
  uint16_t display_ui_w;
  uint16_t display_ui_h;
  uint16_t layout_scaled_w;
  uint16_t layout_scaled_h;
  uint16_t pending_refresh_w;
  uint16_t pending_refresh_h;
  uint16_t pending_dynamic_target_w;
  uint16_t pending_dynamic_target_h;
  uint16_t last_dynamic_request_w;
  uint16_t last_dynamic_request_h;
  long long dynamic_request_started_ms;
  int dynamic_request_in_flight;
  int dynamic_refresh_queued_for_request;
  struct apple_hp_transport_state transport;
};

static struct apple_hp_frame_stats g_frame = {0};
static struct apple_hp_runtime_options g_runtime = {0};
static struct apple_hp_session_state g_hp = {0};

/* Confirmed from native Screen Sharing.app on 24G231:
 * the first post-rekey client body is 0x0d01000000000000, i.e. a SetDisplayMessage
 * with combine-all-displays enabled and no explicit display id. */
static const int32_t kNativePostAuthEncodings[] = {
    0x6,
    0x10,
    (int32_t)0xffffff11u,
    APPLE_HP_ENCODING_CURSOR_IMAGE,
    0x44c,
    (int32_t)0xffffff21u,
    0x44d,
    APPLE_HP_ENCODING_DISPLAY_LAYOUT,
    APPLE_HP_ENCODING_DISPLAY_MODE,
    APPLE_HP_ENCODING_KEYBOARD_LAYOUT,
    APPLE_HP_ENCODING_DISPLAY_INFO,
};
static const int32_t kAppleHPProModeEncoding = APPLE_HP_ENCODING_MEDIA_STREAM;
static const uint16_t kAppleHPFramebufferSlack = 2;

#if defined(APPLEHPDEBUG_HAS_SDL)
#define APPLEHPDEBUG_CURSOR_CACHE_MAX 16
struct apple_hp_cursor_cache_entry {
  uint32_t cache_id;
  int hot_x;
  int hot_y;
  int width;
  int height;
  uint8_t *pixels;
  SDL_Texture *texture;
};

struct apple_hp_live_view_state {
  SDL_Texture *texture;
  SDL_Renderer *renderer;
  SDL_Window *window;
  int synthetic_resize_events;
  int window_user_sized;
  int pending_dynamic_resize;
  int runtime_size_valid;
  uint16_t cached_runtime_w;
  uint16_t cached_runtime_h;
  uint16_t last_runtime_w;
  uint16_t last_runtime_h;
  int has_pending_present;
  int pending_x;
  int pending_y;
  int pending_w;
  int pending_h;
  int needs_clear;
  int present_per_rect;
  long long last_present_us;
  long long last_input_us;
  struct apple_hp_cursor_cache_entry cursor_cache[APPLEHPDEBUG_CURSOR_CACHE_MAX];
  uint32_t cursor_current_cache_id;
  int cursor_visible;
  int button_mask;
  int pointer_x;
  int pointer_y;
  int pointer_draw_x;
  int pointer_draw_y;
  int right_alt_key_down;
  int left_alt_key_down;
  int crop_x;
  int crop_y;
  int crop_w;
  int crop_h;
  int skip_next_fb_update;
};

static struct apple_hp_live_view_state g_live = {.needs_clear = 1};

struct apple_hp_live_view_geometry {
  SDL_Rect src;
  SDL_Rect dst;
  int output_w;
  int output_h;
  int window_w;
  int window_h;
  int valid;
};

static void present_live_view(rfbClient *client, int x, int y, int w, int h);
static void invalidate_live_view_runtime_size(void);
static int maybe_present_live_view_if_due(rfbClient *client, int force);
static void note_live_view_input(void);
static long long monotonic_us(void);
static uint16_t read_be_u16(const uint8_t *p);
static uint16_t apple_hp_request_width(rfbClient *client);
static uint16_t apple_hp_request_height(rfbClient *client);
static int apple_hp_request_full_refresh_now(rfbClient *client, uint16_t w, uint16_t h,
                                             const char *reason);
static int maybe_send_dynamic_resolution_update(rfbClient *client, const char *reason, int force);
#endif

static int apple_hp_should_suppress_incremental(void) {
#if defined(APPLEHPDEBUG_HAS_SDL)
  if (g_runtime.live_view) return 0;
#endif
  return g_runtime.apple_hp_mode && g_hp.auto_fbu_active;
}

#if defined(APPLEHPDEBUG_HAS_SDL)
static void reset_live_view_pending_present(void) {
  g_live.has_pending_present = 0;
  g_live.pending_x = 0;
  g_live.pending_y = 0;
  g_live.pending_w = 0;
  g_live.pending_h = 0;
}

static void queue_live_view_present(int x, int y, int w, int h) {
  int x2;
  int y2;

  if (w <= 0 || h <= 0) return;
  if (!g_live.has_pending_present) {
    g_live.has_pending_present = 1;
    g_live.pending_x = x;
    g_live.pending_y = y;
    g_live.pending_w = w;
    g_live.pending_h = h;
    return;
  }

  x2 = x + w;
  y2 = y + h;
  if (x < g_live.pending_x) {
    g_live.pending_w += g_live.pending_x - x;
    g_live.pending_x = x;
  }
  if (y < g_live.pending_y) {
    g_live.pending_h += g_live.pending_y - y;
    g_live.pending_y = y;
  }
  if (x2 > g_live.pending_x + g_live.pending_w) {
    g_live.pending_w = x2 - g_live.pending_x;
  }
  if (y2 > g_live.pending_y + g_live.pending_h) {
    g_live.pending_h = y2 - g_live.pending_y;
  }
}

static int live_view_recent_input_active(long long now_us) {
  long long elapsed_us = 0;

  if (!g_runtime.low_latency_input || g_live.last_input_us <= 0 || now_us <= 0) return 0;
  if (now_us <= g_live.last_input_us) return 1;
  elapsed_us = now_us - g_live.last_input_us;
  return elapsed_us >= 0 && elapsed_us < 100000;
}

static long long live_view_present_interval_us(long long now_us) {
  if (live_view_recent_input_active(now_us)) return 16666;
  return 33333;
}

static int maybe_present_live_view_if_due(rfbClient *client, int force) {
  long long now_us = 0;
  long long elapsed_us = 0;
  long long min_interval_us = 33333;

  if (!g_runtime.live_view || !client || !g_live.has_pending_present) return 1;
  if (g_live.present_per_rect) return 1;
  if (!force && client->buffered > 0) return 1;
  if (!force) {
    now_us = monotonic_us();
    if (now_us > 0) {
      min_interval_us = live_view_present_interval_us(now_us);
      if (live_view_recent_input_active(now_us) &&
          g_live.last_present_us > 0 &&
          g_live.last_present_us < g_live.last_input_us) {
        min_interval_us = 0;
      }
    }
    if (g_live.last_present_us > 0 && now_us > 0) {
      elapsed_us = now_us - g_live.last_present_us;
      if (elapsed_us >= 0 && elapsed_us < min_interval_us) return 1;
    }
  }
  present_live_view(client,
                    g_live.pending_x,
                    g_live.pending_y,
                    g_live.pending_w,
                    g_live.pending_h);
  return 1;
}

static void note_live_view_input(void) {
  g_live.last_input_us = monotonic_us();
}

#endif

static long long monotonic_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
  return (long long)ts.tv_sec * 1000LL + (long long)(ts.tv_nsec / 1000000LL);
}

static long long monotonic_us(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
  return (long long)ts.tv_sec * 1000000LL + (long long)(ts.tv_nsec / 1000LL);
}

static long long elapsed_us_since(long long started_us) {
  long long now_us = 0;
  if (started_us <= 0) return 0;
  now_us = monotonic_us();
  if (now_us <= started_us) return 0;
  return now_us - started_us;
}

static unsigned int main_loop_wait_usecs(void) {
#if defined(APPLEHPDEBUG_HAS_SDL)
  long long now_us = 0;
  long long elapsed_us = 0;
  long long due_in_us = 0;

  if (g_runtime.live_view) {
    if (g_runtime.low_latency_input && g_live.last_input_us > 0) {
      now_us = monotonic_us();
      if (now_us > g_live.last_input_us) {
        elapsed_us = now_us - g_live.last_input_us;
        if (elapsed_us >= 0 && elapsed_us < 50000) return 1000;
      }
    }
    /* Keep live-view input/window handling responsive without spinning at a
     * sub-millisecond socket poll interval. */
    if (!g_live.present_per_rect && g_live.has_pending_present) {
      now_us = monotonic_us();
      if (g_live.last_present_us <= 0 || now_us <= 0) return 0;
      elapsed_us = now_us - g_live.last_present_us;
      if (elapsed_us < 0) elapsed_us = 0;
      due_in_us = live_view_present_interval_us(now_us) - elapsed_us;
      if (due_in_us <= 0) return 0;
      if (due_in_us < 16000) return (unsigned int)due_in_us;
    }
    return 16000;
  }
#endif
  return 500000;
}

static int env_flag_enabled(const char *name) {
  const char *s = getenv(name);
  if (!s || !*s) return 0;
  if (!strcmp(s, "0")) return 0;
  if (!strcmp(s, "false")) return 0;
  if (!strcmp(s, "FALSE")) return 0;
  if (!strcmp(s, "no")) return 0;
  if (!strcmp(s, "NO")) return 0;
  return 1;
}

static int env_flag_default_true(const char *name) {
  const char *s = getenv(name);
  if (!s || !*s) return 1;
  return env_flag_enabled(name);
}

static const char *apple_hp_getenv_first(const char *a, const char *b) {
  const char *s = NULL;
  if (a) {
    s = getenv(a);
    if (s && *s) return s;
  }
  if (b) {
    s = getenv(b);
    if (s && *s) return s;
  }
  return NULL;
}

static void apple_hp_normalize_host(const char *host, char *out, size_t out_cap) {
  size_t n = 0;
  const char *start = host;
  const char *end = NULL;

  if (!out || out_cap == 0) return;
  out[0] = '\0';
  if (!host || !*host) return;

  if (*start == '[') {
    start++;
    end = strchr(start, ']');
    if (!end) end = start + strlen(start);
  } else {
    end = start + strlen(start);
    if (strchr(start, ':') && !strchr(start, '.')) {
      /* likely raw IPv6 literal without brackets */
      end = start + strlen(start);
    } else {
      const char *colon = strrchr(start, ':');
      if (colon) end = colon;
    }
  }

  while (end > start && (end[-1] == '.' || end[-1] == ' ' || end[-1] == '\t')) end--;
  while (start < end && (*start == ' ' || *start == '\t')) start++;
  for (; start < end && n + 1 < out_cap; ++start) {
    unsigned char ch = (unsigned char)*start;
    if (ch >= 'A' && ch <= 'Z') ch = (unsigned char)(ch - 'A' + 'a');
    out[n++] = (char)ch;
  }
  out[n] = '\0';
}

static void apple_hp_seed_known_auth35_realm(const char *host) {
  static const struct apple_hp_known_krb_realm kKnown[] = {
      {"alexs-mac-mini.local", "LKDC:SHA1.896110981E604592DBD4B2A3A0C367563A38637E"},
  };
  char normalized[512];
  size_t i;

  if (!host || !*host) return;
  if (apple_hp_getenv_first("VNC_APPLE_KRB_REALM", "LIBVNCCLIENT_APPLE_KRB_REALM")) return;
  if (apple_hp_getenv_first("VNC_APPLE_KRB_SERVICE_PRINCIPAL",
                            "LIBVNCCLIENT_APPLE_KRB_SERVICE_PRINCIPAL"))
    return;
  if (apple_hp_getenv_first("VNC_APPLE_KRB_CLIENT_PRINCIPAL",
                            "LIBVNCCLIENT_APPLE_KRB_CLIENT_PRINCIPAL"))
    return;

  apple_hp_normalize_host(host, normalized, sizeof(normalized));
  if (!normalized[0]) return;

  for (i = 0; i < sizeof(kKnown) / sizeof(kKnown[0]); ++i) {
    if (strcmp(normalized, kKnown[i].host) == 0) {
      setenv("VNC_APPLE_KRB_REALM", kKnown[i].realm, 0);
      return;
    }
  }
}

static int apple_hp_simple_1080p_enabled(void) {
  return env_flag_enabled("VNC_APPLE_HP_SIMPLE_1080P");
}

static double apple_hp_input_rect_scale(void) {
  const char *s = getenv("VNC_APPLE_HP_INPUT_RECT_SCALE");
  char *end = NULL;
  double v;

  if (!s || !*s) return 1.0;
  v = strtod(s, &end);
  if (!end || *end != '\0' || v <= 0.0) return 1.0;
  return v;
}

static int apple_hp_pointer_content_offset_x(void) {
  const char *s = getenv("VNC_APPLE_HP_POINTER_OFFSET_X");
  char *end = NULL;
  long v;

  if (!s || !*s) return 0;
  v = strtol(s, &end, 0);
  if (!end || *end != '\0') return 0;
  return (int)v;
}

static int apple_hp_pointer_content_offset_y(void) {
  const char *s = getenv("VNC_APPLE_HP_POINTER_OFFSET_Y");
  char *end = NULL;
  long v;

  if (!s || !*s) return 0;
  v = strtol(s, &end, 0);
  if (!end || *end != '\0') return 0;
  return (int)v;
}

static int apple_hp_scale_coord_round(int pos, int src_extent, int dst_extent) {
  long long num;
  int src_max;
  int dst_max;

  if (dst_extent <= 0 || src_extent <= 0) return 0;
  if (pos <= 0) return 0;
  if (dst_extent == 1 || src_extent == 1) return 0;
  src_max = src_extent - 1;
  dst_max = dst_extent - 1;
  if (pos >= dst_max) return src_max;
  num = (long long)pos * (long long)src_max + (long long)(dst_max / 2);
  return (int)(num / (long long)dst_max);
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
  return -1;
}

static size_t parse_hex_blob(const char *hex, uint8_t *out, size_t out_cap) {
  size_t n = 0;
  int hi = -1;
  for (; *hex; ++hex) {
    int v = hex_nibble(*hex);
    if (v < 0) continue;
    if (hi < 0) {
      hi = v;
      continue;
    }
    if (n >= out_cap) return 0;
    out[n++] = (uint8_t)((hi << 4) | v);
    hi = -1;
  }
  return (hi < 0) ? n : 0;
}

static uint16_t read_be_u16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static void write_be_u16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)((v >> 8) & 0xff);
  p[1] = (uint8_t)(v & 0xff);
}

static void write_be_u32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)((v >> 24) & 0xff);
  p[1] = (uint8_t)((v >> 16) & 0xff);
  p[2] = (uint8_t)((v >> 8) & 0xff);
  p[3] = (uint8_t)(v & 0xff);
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

static uint32_t read_be_u32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
         (uint32_t)p[3];
}

static uint64_t read_be_u64(const uint8_t *p) {
  return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) |
         ((uint64_t)p[3] << 32) | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
         ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static int parse_u32_env(const char *name, uint32_t *out) {
  const char *s = getenv(name);
  char *end = NULL;
  unsigned long v;
  if (!s || !*s) return 0;
  v = strtoul(s, &end, 0);
  if (!end || *end != '\0') return -1;
  *out = (uint32_t)v;
  return 1;
}

static uint32_t apple_hp_dynamic_round_step(void) {
  uint32_t v = 0;
  if (parse_u32_env("VNC_APPLE_HP_DYNAMIC_ROUND_STEP", &v) > 0 && v > 0 && v <= 0xffff)
    return v;
  return 16;
}

static uint32_t apple_hp_dynamic_min_delta(void) {
  uint32_t v = 0;
  if (parse_u32_env("VNC_APPLE_HP_DYNAMIC_MIN_DELTA", &v) > 0 && v > 0 && v <= 0xffff)
    return v;
  return 32;
}

static uint32_t apple_hp_dynamic_timeout_ms(void) {
  uint32_t v = 0;
  if (parse_u32_env("VNC_APPLE_HP_DYNAMIC_TIMEOUT_MS", &v) > 0 && v > 0) return v;
  return 1500;
}

static uint32_t apple_hp_visible_content_pad(void) {
  uint32_t v = 0;
  if (parse_u32_env("VNC_APPLE_HP_VISIBLE_PAD", &v) > 0 && v <= 256) return v;
  return 8;
}

static int apple_hp_visible_crop_enabled(void) {
  /* Dynamic-resolution backing surfaces can carry trailing black padding
   * after the server downsizes the virtual display. Crop detection is
   * therefore on by default for the HP live-view path, with an env opt-out. */
  return env_flag_default_true("VNC_APPLE_HP_VISIBLE_CROP");
}

static uint16_t apple_hp_round_dimension(uint16_t value, uint32_t step) {
  uint32_t rounded = 0;

  if (value == 0) return 0;
  if (step <= 1) return value;
  rounded = (((uint32_t)value + (step / 2u)) / step) * step;
  if (rounded == 0) rounded = step;
  if (rounded > 0xffffu) rounded = 0xffffu;
  return (uint16_t)rounded;
}

static int apple_hp_dynamic_target_materially_diff(uint16_t a_w, uint16_t a_h,
                                                   uint16_t b_w, uint16_t b_h) {
  uint32_t min_delta = apple_hp_dynamic_min_delta();
  uint32_t diff_w;
  uint32_t diff_h;

  if (a_w == 0 || a_h == 0 || b_w == 0 || b_h == 0) return 1;
  diff_w = (a_w > b_w) ? (uint32_t)(a_w - b_w) : (uint32_t)(b_w - a_w);
  diff_h = (a_h > b_h) ? (uint32_t)(a_h - b_h) : (uint32_t)(b_h - a_h);
  return diff_w >= min_delta || diff_h >= min_delta;
}

static uint16_t apple_hp_content_width(rfbClient *client) {
  uint32_t v = 0;
  if (apple_hp_simple_1080p_enabled()) return 1920;
  if (parse_u32_env("VNC_APPLE_HP_REGION_W", &v) > 0 && v <= 0xffff) return (uint16_t)v;
  if (g_hp.display_scaled_w != 0) return g_hp.display_scaled_w;
  if (g_hp.display_ui_w != 0) return g_hp.display_ui_w;
  return client ? (uint16_t)client->width : 0;
}

static uint16_t apple_hp_content_height(rfbClient *client) {
  uint32_t v = 0;
  if (apple_hp_simple_1080p_enabled()) return 1080;
  if (parse_u32_env("VNC_APPLE_HP_REGION_H", &v) > 0 && v <= 0xffff) return (uint16_t)v;
  if (g_hp.display_scaled_h != 0) return g_hp.display_scaled_h;
  if (g_hp.display_ui_h != 0) return g_hp.display_ui_h;
  return client ? (uint16_t)client->height : 0;
}

static uint16_t apple_hp_backing_width(rfbClient *client) {
  if (g_hp.layout_scaled_w != 0) return g_hp.layout_scaled_w;
  if (g_hp.display_ui_w != 0) return g_hp.display_ui_w;
  return apple_hp_content_width(client);
}

static uint16_t apple_hp_backing_height(rfbClient *client) {
  if (g_hp.layout_scaled_h != 0) return g_hp.layout_scaled_h;
  if (g_hp.display_ui_h != 0) return g_hp.display_ui_h;
  return apple_hp_content_height(client);
}

static uint16_t apple_hp_display_width(rfbClient *client) {
  if (apple_hp_simple_1080p_enabled()) return 1920;
  if (g_hp.display_scaled_w != 0) return g_hp.display_scaled_w;
  if (g_hp.display_ui_w != 0) return g_hp.display_ui_w;
  return client ? (uint16_t)client->width : 0;
}

static uint16_t apple_hp_display_height(rfbClient *client) {
  if (apple_hp_simple_1080p_enabled()) return 1080;
  if (g_hp.display_scaled_h != 0) return g_hp.display_scaled_h;
  if (g_hp.display_ui_h != 0) return g_hp.display_ui_h;
  return client ? (uint16_t)client->height : 0;
}

static uint16_t apple_hp_request_width(rfbClient *client) {
  uint32_t v = 0;
  if (parse_u32_env("VNC_APPLE_HP_REGION_W", &v) > 0 && v <= 0xffff) return (uint16_t)v;
  if (g_runtime.apple_hp_mode) {
    uint16_t w = apple_hp_backing_width(client);
    if (w != 0) return w;
  }
#if defined(APPLEHPDEBUG_HAS_SDL)
  if (g_runtime.live_view && g_runtime.apple_hp_mode) {
    uint16_t w = apple_hp_display_width(client);
    if (w != 0) return w;
  }
#endif
  return apple_hp_content_width(client);
}

static uint16_t apple_hp_request_height(rfbClient *client) {
  uint32_t v = 0;
  if (parse_u32_env("VNC_APPLE_HP_REGION_H", &v) > 0 && v <= 0xffff) return (uint16_t)v;
  if (g_runtime.apple_hp_mode) {
    uint16_t h = apple_hp_backing_height(client);
    if (h != 0) return h;
  }
#if defined(APPLEHPDEBUG_HAS_SDL)
  if (g_runtime.live_view && g_runtime.apple_hp_mode) {
    uint16_t h = apple_hp_display_height(client);
    if (h != 0) return h;
  }
#endif
  return apple_hp_content_height(client);
}

static rfbBool apple_hp_resize_framebuffer_if_needed(rfbClient *client, uint16_t width,
                                                     uint16_t height) {
  uint16_t alloc_w;
  uint16_t alloc_h;
  if (!client || width == 0 || height == 0) return TRUE;
  alloc_w = width;
  alloc_h = height;
  if (alloc_w <= (uint16_t)(0xffff - kAppleHPFramebufferSlack))
    alloc_w = (uint16_t)(alloc_w + kAppleHPFramebufferSlack);
  if (alloc_h <= (uint16_t)(0xffff - kAppleHPFramebufferSlack))
    alloc_h = (uint16_t)(alloc_h + kAppleHPFramebufferSlack);
  if (alloc_w <= (uint16_t)client->width && alloc_h <= (uint16_t)client->height) return TRUE;

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
  rfbClientLog("apple-hp: resizing local framebuffer to %ux%u for backing %ux%u from AppleDisplayLayout\n",
               (unsigned)alloc_w, (unsigned)alloc_h, (unsigned)width, (unsigned)height);
  return client->MallocFrameBuffer(client);
}

static int send_blob(rfbClient *client, const void *buf, size_t len, const char *label) {
  if (!client || !buf || !label || len == 0) return 0;
  rfbClientLog("%s: sending %zu bytes\n", label, len);
  if (!WriteToRFBServer(client, (const char *)buf, (unsigned int)len)) return 0;
  return 1;
}

static int send_viewer_info_blob(rfbClient *client) {
  struct apple_hp_viewer_info_message msg;
  size_t len;

  if (!client) return 0;
  msg = apple_hp_make_native_viewer_info();
  len = sizeof(msg);

  rfbClientLog("apple-hp ViewerInfo: sending %zu bytes\n", len);
  if (!WriteToRFBServer(client, (const char *)&msg, (unsigned int)len)) return 0;
  return 1;
}

static int send_display_configuration_blob(rfbClient *client) {
  struct apple_hp_display_configuration_message msg;
  uint8_t *buf = (uint8_t *)&msg;
  size_t len;
  size_t display_offset = 12;
  const size_t kDisplayInfoSizeOff = 0x00;
  uint16_t display_info_size;
  size_t effective_len;

  msg = apple_hp_make_native_display_configuration();
  len = sizeof(msg);
  if (len <= display_offset) {
    rfbClientErr("apple-hp SetDisplayConfiguration: payload too short (%zu)\n", len);
    return 0;
  }

  display_info_size = read_be_u16(buf + display_offset + kDisplayInfoSizeOff);
  if (display_offset + (size_t)display_info_size > len) {
    rfbClientErr("apple-hp SetDisplayConfiguration: unexpected displayInfoSize=%u len=%zu\n",
                 (unsigned)display_info_size, len);
    return 0;
  }

  /* Native encrypted 0x1d stops at the 12-byte message header plus the
   * displayInfoSize payload. */
  effective_len = display_offset + (size_t)display_info_size;

  rfbClientLog("apple-hp SetDisplayConfiguration: sending %zu bytes display_count=1 flags=0x00000000\n",
               effective_len);
  if (!WriteToRFBServer(client, (const char *)buf, (unsigned int)effective_len)) return 0;
  return 1;
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

static int dynamic_resolution_target_matches_display(rfbClient *client,
                                                     uint16_t target_w,
                                                     uint16_t target_h) {
  if (!client || target_w == 0 || target_h == 0) return 0;
  return apple_hp_display_width(client) == target_w &&
         apple_hp_display_height(client) == target_h;
}

static int send_runtime_display_configuration_blob(rfbClient *client,
                                                   uint16_t logical_w,
                                                   uint16_t logical_h,
                                                   const char *reason) {
  struct apple_hp_display_configuration_message msg;
  uint8_t *buf = (uint8_t *)&msg;
  size_t effective_len;

  if (!client || logical_w == 0 || logical_h == 0) return 0;
  if (dynamic_resolution_target_matches_display(client, logical_w, logical_h)) return 1;
  msg = apple_hp_make_native_display_configuration();
  patch_display_configuration_dimensions(&msg, logical_w, logical_h);
  effective_len = sizeof(msg);
  rfbClientLog("apple-hp: sending runtime SetDisplayConfiguration %ux%u reason=%s\n",
               (unsigned)logical_w, (unsigned)logical_h,
               reason ? reason : "unknown");
  if (!WriteToRFBServer(client, (const char *)buf, (unsigned int)effective_len)) return 0;
  g_hp.last_dynamic_request_w = logical_w;
  g_hp.last_dynamic_request_h = logical_h;
  g_hp.dynamic_request_in_flight = 1;
  g_hp.dynamic_refresh_queued_for_request = 0;
  return 1;
}

static int send_native_set_encryption_message(rfbClient *client) {
  struct apple_hp_set_encryption_message msg = apple_hp_make_native_prelude_set_encryption();
  return send_blob(client, &msg, sizeof(msg), "apple-hp SetEncryptionMessage");
}

static int send_native_set_mode_message(rfbClient *client) {
  struct apple_hp_set_mode_message msg = apple_hp_make_native_prelude_set_mode();
  return send_blob(client, &msg, sizeof(msg), "apple-hp SetModeMessage");
}

static int send_post_rekey_set_encryption_stage2(rfbClient *client) {
  struct apple_hp_set_encryption_stage2_message msg = apple_hp_make_post_rekey_set_encryption_stage2();
  return send_blob(client, &msg, sizeof(msg), "apple-hp post-0x44f SetEncryptionMessage");
}

static int send_set_display_message(rfbClient *client) {
  struct apple_hp_set_display_message msg = apple_hp_make_set_display_message(1, 0);
  return send_blob(client, &msg, sizeof(msg), "apple-hp post-rekey hello");
}

static int send_native_scale_factor_message(rfbClient *client) {
  struct apple_hp_scale_factor_message msg = apple_hp_make_native_scale_factor_message();
  return send_blob(client, &msg, sizeof(msg), "apple-hp scale factor");
}

static int send_auto_pasteboard_command(rfbClient *client, uint16_t selector) {
  struct apple_hp_auto_pasteboard_message msg =
      apple_hp_make_auto_pasteboard_message((uint8_t)(selector & 0xff));
  rfbClientLog("apple-hp: sending AutoPasteboard selector=%u\n", (unsigned)selector);
  return WriteToRFBServer(client, (const char *)&msg, sizeof(msg));
}

static int send_native_post_auth_encodings(rfbClient *client) {
  int32_t encodings[(sizeof(kNativePostAuthEncodings) / sizeof(kNativePostAuthEncodings[0])) + 2];
  size_t count = 0;
  size_t i;
  int add_promode = env_flag_enabled("VNC_APPLE_HP_ADD_PROMODE_ENCODING");
  int prefer_promode = env_flag_enabled("VNC_APPLE_HP_PREFER_PROMODE_ENCODING");

  if (!client) return 0;

  if (add_promode && prefer_promode) {
    encodings[count++] = kAppleHPProModeEncoding;
    rfbClientLog("apple-hp: prepending ProMode SetEncodings capability 0x%03x\n",
                 kAppleHPProModeEncoding);
  }

  for (i = 0; i < sizeof(kNativePostAuthEncodings) / sizeof(kNativePostAuthEncodings[0]); ++i) {
    if (add_promode && !prefer_promode && kNativePostAuthEncodings[i] == 0x44c) {
      encodings[count++] = kAppleHPProModeEncoding;
    }
    encodings[count++] = kNativePostAuthEncodings[i];
  }

  if (add_promode && !prefer_promode) {
    rfbClientLog("apple-hp: adding ProMode SetEncodings capability 0x%03x\n",
                 kAppleHPProModeEncoding);
  }

  return SendEncodingsOrdered(client, encodings, count);
}

static void configure_native_post_rekey_pixel_format(rfbClient *client) {
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

static int send_auto_framebuffer_update(rfbClient *client, uint16_t width, uint16_t height) {
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

static int apple_hp_send_post_rekey_setup(rfbClient *client);

static int apple_hp_read_next_record(rfbClient *client, struct apple_hp_transport_state *st) {
  uint8_t hdr[2];
  uint8_t *cipher = NULL;
  uint8_t *plain = NULL;
  uint16_t cipher_len;
  uint16_t body_len;
  size_t moved = 0;
  uint8_t seq_be[4];
  uint8_t digest[CC_SHA1_DIGEST_LENGTH];
  size_t total_min;

  if (!client || !st) return 0;
  if (!raw_read_exact(client, hdr, sizeof(hdr))) return 0;
  cipher_len = read_be_u16(hdr);
  if (cipher_len == 0 || (cipher_len % 16) != 0) {
    rfbClientErr("apple-hp transport: invalid ciphertext length %u\n", (unsigned)cipher_len);
    return 0;
  }

  cipher = (uint8_t *)malloc(cipher_len);
  plain = (uint8_t *)malloc(cipher_len);
  if (!cipher || !plain) goto fail;
  if (!raw_read_exact(client, cipher, cipher_len)) goto fail;
  if (!aes_crypt(kCCDecrypt, 0, st->cbc_key, st->recv_iv, cipher, cipher_len, plain, &moved)) goto fail;
  if (moved != cipher_len || cipher_len < 22) goto fail;

  body_len = read_be_u16(plain);
  total_min = (size_t)body_len + 22u;
  if (total_min > cipher_len) {
    rfbClientErr("apple-hp transport: body len %u exceeds record size %u\n",
                 (unsigned)body_len, (unsigned)cipher_len);
    goto fail;
  }

  write_be_u32(seq_be, st->recv_seq);
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

  if (st->recv_cap < body_len) {
    uint8_t *tmp = (uint8_t *)realloc(st->recv_buf, body_len);
    if (!tmp) goto fail;
    st->recv_buf = tmp;
    st->recv_cap = body_len;
  }
  memcpy(st->recv_buf, plain + 2, body_len);
  st->recv_len = body_len;
  st->recv_off = 0;
  memcpy(st->recv_iv, cipher + cipher_len - 16, 16);
  st->recv_seq++;
  if (g_hp.post_rekey_ready == 1) g_hp.post_rekey_ready = 2;
  g_hp.post_rekey_server_records++;

  free(cipher);
  free(plain);
  return 1;

fail:
  free(cipher);
  free(plain);
  return 0;
}

static rfbBool apple_hp_transport_read(rfbClient *client, char *out, unsigned int n) {
  struct apple_hp_transport_state *st = &g_hp.transport;
  unsigned int copied = 0;

  if (!st->active) return FALSE;
  while (copied < n) {
    size_t avail = st->recv_len - st->recv_off;
    size_t want;

    if (avail == 0) {
      if (!apple_hp_read_next_record(client, st)) return FALSE;
      avail = st->recv_len - st->recv_off;
      if (avail == 0) return FALSE;
    }

    want = (size_t)(n - copied);
    if (want > avail) want = avail;
    memcpy(out + copied, st->recv_buf + st->recv_off, want);
    st->recv_off += want;
    copied += (unsigned int)want;
    if (st->recv_off == st->recv_len) {
      st->recv_off = 0;
      st->recv_len = 0;
    }
  }
  return TRUE;
}

static rfbBool apple_hp_transport_write(rfbClient *client, const char *buf, unsigned int n) {
  struct apple_hp_transport_state *st = &g_hp.transport;
  size_t plain_len;
  size_t filler_len;
  uint8_t *plain = NULL;
  uint8_t *cipher = NULL;
  uint8_t hdr[2];
  uint8_t seq_be[4];
  size_t moved = 0;

  if (!st->active) return FALSE;
  plain_len = ((size_t)n + 22u + 15u) & ~((size_t)15u);
  plain = (uint8_t *)calloc(1, plain_len);
  cipher = (uint8_t *)malloc(plain_len);
  if (!plain || !cipher) goto fail;

  write_be_u16(plain, (uint16_t)n);
  memcpy(plain + 2, buf, n);
  filler_len = plain_len - ((size_t)n + 2u + CC_SHA1_DIGEST_LENGTH);
  /* Native ScreenSharing.framework builds CBC records in a generic transport
   * helper: body length, body bytes, trailing slack, then SHA1(seq || plain[..]).
   * The transport layer does not branch on message type to choose filler bytes.
   * Use deterministic zero-filled slack here instead of replay-era per-message
   * filler tables. */
  (void)filler_len;
  write_be_u32(seq_be, st->send_seq);
  {
    CC_SHA1_CTX ctx;
    CC_SHA1_Init(&ctx);
    CC_SHA1_Update(&ctx, seq_be, sizeof(seq_be));
    CC_SHA1_Update(&ctx, plain, plain_len - CC_SHA1_DIGEST_LENGTH);
    CC_SHA1_Final(plain + plain_len - CC_SHA1_DIGEST_LENGTH, &ctx);
  }
  if (!aes_crypt(kCCEncrypt, 0, st->cbc_key, st->send_iv, plain, plain_len, cipher, &moved)) goto fail;
  write_be_u16(hdr, (uint16_t)moved);
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

static int apple_hp_enable_transport(rfbClient *client, const uint8_t *next_key, const uint8_t *next_iv,
                                     uint32_t counter) {
  struct apple_hp_transport_state *st = &g_hp.transport;

  if (!client || !next_key || !next_iv) return 0;
  memset(st, 0, sizeof(*st));
  memcpy(st->wrap_key, next_key, 16);
  memcpy(st->cbc_key, next_key, 16);
  memcpy(st->send_iv, next_iv, 16);
  memcpy(st->recv_iv, next_iv, 16);
  /* Native pcap evidence shows 0x44f generation/counter=1, then encrypted
   * 0x1d and 0x02 preface records consume send sequences 0 and 1 before the
   * later native 0x0d SetDisplayMessage uses sequence 2. So counter-1 is only
   * the correct starting point if we actually reproduce that encrypted
   * preface. */
  st->send_seq = counter ? (counter - 1) : 0;
  st->recv_seq = counter ? (counter - 1) : 0;
  st->active = 1;
  client->ReadFromTransport = apple_hp_transport_read;
  client->WriteToTransport = apple_hp_transport_write;
  rfbClientLog("apple-hp: enabled CBC transport counter=%u send_seq=%u recv_seq=%u\n",
               counter, st->send_seq, st->recv_seq);
  return 1;
}

static int configure_apple_hp_mode(rfbClient *client) {
  if (!g_runtime.apple_hp_mode || !client) return 1;

  rfbClientEnableARDHighPerf(client, TRUE);
  client->appData.deferInitialSetup = TRUE;
  client->appData.hasClientInitFlags = TRUE;
  client->appData.clientInitFlags = 0xC1;
  rfbClientLog("apple-hp: using ClientInit override 0xC1\n");
  return 1;
}

static int run_apple_hp_setup(rfbClient *client) {
  if (!g_runtime.apple_hp_mode || !client) return 1;

  rfbClientLog("apple-hp: sending cleartext pre-rekey setup\n");
  if (!send_viewer_info_blob(client)) return 0;
  if (!send_native_set_encryption_message(client)) return 0;
  if (!send_native_set_mode_message(client)) return 0;
  return 1;
}

static int apple_hp_send_post_rekey_setup(rfbClient *client) {
  uint16_t region_w;
  uint16_t region_h;

  if (!g_runtime.apple_hp_mode || !client || g_hp.post_rekey_sent) return 1;

  if (g_hp.post_rekey_phase == 0)
    rfbClientLog("apple-hp: sending post-rekey setup phase 1 over CBC transport\n");
  else
    rfbClientLog("apple-hp: sending post-rekey setup phase %d over CBC transport\n",
                 g_hp.post_rekey_phase + 1);
  configure_native_post_rekey_pixel_format(client);
  region_w = apple_hp_request_width(client);
  region_h = apple_hp_request_height(client);
  if (g_hp.post_rekey_phase == 0) {
    if (!send_set_display_message(client)) return 0;
    if (!SendCurrentPixelFormat(client)) return 0;
    if (!send_native_post_auth_encodings(client)) return 0;
    g_hp.post_rekey_phase = 2;
    return 1;
  }
  if (g_hp.post_rekey_phase == 1) g_hp.post_rekey_phase = 2;

  if (!send_auto_pasteboard_command(client, 1)) return 0;
  if (!send_native_scale_factor_message(client)) return 0;
  if (!SendFramebufferUpdateRequest(client, 0, 0, region_w, region_h, FALSE)) return 0;
  g_hp.initial_full_refresh_done = 0;
  g_hp.initial_full_refresh_retries = 3;
  g_hp.displayinfo2_seen = 0;
  if (apple_hp_should_suppress_incremental()) client->suppressNextIncrementalRequest = TRUE;
  rfbClientLog("apple-hp: requested initial full refresh %ux%u and queued %d retries\n",
               (unsigned)region_w, (unsigned)region_h, g_hp.initial_full_refresh_retries);
  if (!send_auto_framebuffer_update(client, region_w, region_h)) return 0;
  g_hp.auto_fbu_active = 1;
  g_hp.post_rekey_phase = 3;
  g_hp.post_rekey_sent = 1;
  return 1;
}

#if defined(APPLEHPDEBUG_HAS_SDL)
struct sdl_button_map {
  int sdl;
  int rfb;
};

static struct sdl_button_map kButtonMapping[] = {
    {1, rfbButton1Mask},
    {2, rfbButton2Mask},
    {3, rfbButton3Mask},
    {4, rfbButton4Mask},
    {5, rfbButton5Mask},
    {0, 0},
};

struct utf8_mask_map {
  char mask;
  int bits_stored;
};

static struct utf8_mask_map kUtf8Mapping[] = {
    {0b00111111, 6},
    {0b01111111, 7},
    {0b00011111, 5},
    {0b00001111, 4},
    {0b00000111, 3},
    {0, 0},
};

static rfbKeySym sdl_key_to_rfb(SDL_KeyboardEvent *e) {
  rfbKeySym k = 0;
  SDL_Keycode sym = e->keysym.sym;

  switch (sym) {
    case SDLK_BACKSPACE: k = XK_BackSpace; break;
    case SDLK_TAB: k = XK_Tab; break;
    case SDLK_CLEAR: k = XK_Clear; break;
    case SDLK_RETURN: k = XK_Return; break;
    case SDLK_PAUSE: k = XK_Pause; break;
    case SDLK_ESCAPE: k = XK_Escape; break;
    case SDLK_DELETE: k = XK_Delete; break;
    case SDLK_KP_0: k = XK_KP_0; break;
    case SDLK_KP_1: k = XK_KP_1; break;
    case SDLK_KP_2: k = XK_KP_2; break;
    case SDLK_KP_3: k = XK_KP_3; break;
    case SDLK_KP_4: k = XK_KP_4; break;
    case SDLK_KP_5: k = XK_KP_5; break;
    case SDLK_KP_6: k = XK_KP_6; break;
    case SDLK_KP_7: k = XK_KP_7; break;
    case SDLK_KP_8: k = XK_KP_8; break;
    case SDLK_KP_9: k = XK_KP_9; break;
    case SDLK_KP_PERIOD: k = XK_KP_Decimal; break;
    case SDLK_KP_DIVIDE: k = XK_KP_Divide; break;
    case SDLK_KP_MULTIPLY: k = XK_KP_Multiply; break;
    case SDLK_KP_MINUS: k = XK_KP_Subtract; break;
    case SDLK_KP_PLUS: k = XK_KP_Add; break;
    case SDLK_KP_ENTER: k = XK_KP_Enter; break;
    case SDLK_KP_EQUALS: k = XK_KP_Equal; break;
    case SDLK_UP: k = XK_Up; break;
    case SDLK_DOWN: k = XK_Down; break;
    case SDLK_RIGHT: k = XK_Right; break;
    case SDLK_LEFT: k = XK_Left; break;
    case SDLK_INSERT: k = XK_Insert; break;
    case SDLK_HOME: k = XK_Home; break;
    case SDLK_END: k = XK_End; break;
    case SDLK_PAGEUP: k = XK_Page_Up; break;
    case SDLK_PAGEDOWN: k = XK_Page_Down; break;
    case SDLK_F1: k = XK_F1; break;
    case SDLK_F2: k = XK_F2; break;
    case SDLK_F3: k = XK_F3; break;
    case SDLK_F4: k = XK_F4; break;
    case SDLK_F5: k = XK_F5; break;
    case SDLK_F6: k = XK_F6; break;
    case SDLK_F7: k = XK_F7; break;
    case SDLK_F8: k = XK_F8; break;
    case SDLK_F9: k = XK_F9; break;
    case SDLK_F10: k = XK_F10; break;
    case SDLK_F11: k = XK_F11; break;
    case SDLK_F12: k = XK_F12; break;
    case SDLK_F13: k = XK_F13; break;
    case SDLK_F14: k = XK_F14; break;
    case SDLK_F15: k = XK_F15; break;
    case SDLK_NUMLOCKCLEAR: k = XK_Num_Lock; break;
    case SDLK_CAPSLOCK: k = XK_Caps_Lock; break;
    case SDLK_SCROLLLOCK: k = XK_Scroll_Lock; break;
    case SDLK_RSHIFT: k = XK_Shift_R; break;
    case SDLK_LSHIFT: k = XK_Shift_L; break;
    case SDLK_RCTRL: k = XK_Control_R; break;
    case SDLK_LCTRL: k = XK_Control_L; break;
    case SDLK_RALT: k = XK_Alt_R; break;
    case SDLK_LALT: k = XK_Alt_L; break;
    case SDLK_LGUI: k = XK_Super_L; break;
    case SDLK_RGUI: k = XK_Super_R; break;
    case SDLK_MODE: k = XK_Mode_switch; break;
    case SDLK_HELP: k = XK_Help; break;
    case SDLK_PRINTSCREEN: k = XK_Print; break;
    case SDLK_SYSREQ: k = XK_Sys_Req; break;
    default: break;
  }
  if (k == 0 && sym > 0x0 && sym < 0x100 && (e->keysym.mod & KMOD_CTRL)) k = sym;
  return k;
}

static rfbKeySym utf8_char_to_rfb(const char chr[4]) {
  int bytes = (int)strlen(chr);
  int shift;
  rfbKeySym codep;
  int i;

  if (bytes <= 0 || bytes > 4) return 0;
  shift = kUtf8Mapping[0].bits_stored * (bytes - 1);
  codep = (*chr & kUtf8Mapping[bytes].mask) << shift;
  chr++;
  for (i = 1; i < bytes; ++i, ++chr) {
    shift -= kUtf8Mapping[0].bits_stored;
    codep |= ((char)*chr & kUtf8Mapping[0].mask) << shift;
  }
  return codep;
}

static void destroy_live_view(void) {
  SDL_Surface *sdl = NULL;
  int i;
  reset_live_view_pending_present();
  invalidate_live_view_runtime_size();
  g_live.last_present_us = 0;
  g_live.needs_clear = 1;
  for (i = 0; i < APPLEHPDEBUG_CURSOR_CACHE_MAX; ++i) {
    if (g_live.cursor_cache[i].texture) {
      SDL_DestroyTexture(g_live.cursor_cache[i].texture);
      g_live.cursor_cache[i].texture = NULL;
    }
    free(g_live.cursor_cache[i].pixels);
    g_live.cursor_cache[i].pixels = NULL;
    g_live.cursor_cache[i].cache_id = 0;
    g_live.cursor_cache[i].width = 0;
    g_live.cursor_cache[i].height = 0;
    g_live.cursor_cache[i].hot_x = 0;
    g_live.cursor_cache[i].hot_y = 0;
  }
  g_live.cursor_current_cache_id = 0;
  g_live.cursor_visible = 0;
  if (g_live.texture) {
    SDL_DestroyTexture(g_live.texture);
    g_live.texture = NULL;
  }
  if (g_live.renderer) {
    SDL_DestroyRenderer(g_live.renderer);
    g_live.renderer = NULL;
  }
  if (g_live.window) {
    SDL_DestroyWindow(g_live.window);
    g_live.window = NULL;
  }
  g_live.window_user_sized = 0;
  SDL_ShowCursor(SDL_ENABLE);
  (void)sdl;
}

static void live_view_target_size(rfbClient *client, int *out_w, int *out_h);
static int compute_live_view_geometry(rfbClient *client, struct apple_hp_live_view_geometry *geom);
static int live_view_runtime_display_size(rfbClient *client, uint16_t *out_w, uint16_t *out_h);
static int maybe_send_dynamic_resolution_update(rfbClient *client, const char *reason, int force);
static int apple_hp_dynamic_resize_ready(rfbClient *client);

static void reset_live_view_crop(void) {
#if defined(APPLEHPDEBUG_HAS_SDL)
  g_live.crop_x = 0;
  g_live.crop_y = 0;
  g_live.crop_w = 0;
  g_live.crop_h = 0;
  g_hp.visible_content_valid = 0;
  g_hp.visible_content_x = 0;
  g_hp.visible_content_y = 0;
  g_hp.visible_content_w = 0;
  g_hp.visible_content_h = 0;
#endif
}

static struct apple_hp_cursor_cache_entry *find_cursor_cache_entry(uint32_t cache_id) {
#if defined(APPLEHPDEBUG_HAS_SDL)
  int i;
  for (i = 0; i < APPLEHPDEBUG_CURSOR_CACHE_MAX; ++i) {
    if (g_live.cursor_cache[i].cache_id == cache_id) return &g_live.cursor_cache[i];
  }
#else
  (void)cache_id;
#endif
  return NULL;
}

static struct apple_hp_cursor_cache_entry *alloc_cursor_cache_entry(uint32_t cache_id) {
#if defined(APPLEHPDEBUG_HAS_SDL)
  int i;
  struct apple_hp_cursor_cache_entry *entry = find_cursor_cache_entry(cache_id);
  if (entry) return entry;
  for (i = 0; i < APPLEHPDEBUG_CURSOR_CACHE_MAX; ++i) {
    if (g_live.cursor_cache[i].cache_id == 0) {
      g_live.cursor_cache[i].cache_id = cache_id;
      return &g_live.cursor_cache[i];
    }
  }
  entry = &g_live.cursor_cache[0];
  if (entry->texture) {
    SDL_DestroyTexture(entry->texture);
    entry->texture = NULL;
  }
  free(entry->pixels);
  memset(entry, 0, sizeof(*entry));
  entry->cache_id = cache_id;
  return entry;
#else
  (void)cache_id;
  return NULL;
#endif
}

static uint8_t scale_channel_u8(uint32_t value, uint32_t max) {
  if (max == 0) return 0;
  if (max >= 255) return (uint8_t)value;
  return (uint8_t)((value * 255U + (max / 2U)) / max);
}

static uint32_t decode_cursor_color32(const rfbClient *client, const uint8_t *src) {
  uint32_t raw;
  uint32_t r, g, b;

  if (!client || !src) return 0;
  if (client->format.bigEndian) {
    raw = ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
          ((uint32_t)src[2] << 8) | (uint32_t)src[3];
  } else {
    raw = (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
          ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
  }
  r = scale_channel_u8((raw >> client->format.redShift) & client->format.redMax,
                       client->format.redMax);
  g = scale_channel_u8((raw >> client->format.greenShift) & client->format.greenMax,
                       client->format.greenMax);
  b = scale_channel_u8((raw >> client->format.blueShift) & client->format.blueMax,
                       client->format.blueMax);
  return (r << 16) | (g << 8) | b;
}

static int inflate_cursor_payload(const uint8_t *src, uint32_t src_len, uint8_t *dst,
                                  size_t expected_len, size_t *out_len, int *out_zret) {
  z_stream zs;
  int zret;

  if (out_len) *out_len = 0;
  if (out_zret) *out_zret = Z_DATA_ERROR;
  if (!src || !dst) return 0;

  memset(&zs, 0, sizeof(zs));
  zs.next_in = (Bytef *)src;
  zs.avail_in = src_len;
  zs.next_out = dst;
  zs.avail_out = (uInt)expected_len;
  zret = inflateInit(&zs);
  if (zret == Z_OK) {
    do {
      zret = inflate(&zs, Z_NO_FLUSH);
    } while (zret == Z_OK && zs.avail_in != 0 && zs.avail_out != 0);
    if (out_len) *out_len = zs.total_out;
    if (out_zret) *out_zret = zret;
    inflateEnd(&zs);
    if ((zret == Z_STREAM_END || zret == Z_OK || zret == Z_BUF_ERROR) &&
        zs.total_out == expected_len)
      return 1;
  }

  memset(&zs, 0, sizeof(zs));
  zs.next_in = (Bytef *)src;
  zs.avail_in = src_len;
  zs.next_out = dst;
  zs.avail_out = (uInt)expected_len;
  zret = inflateInit2(&zs, -MAX_WBITS);
  if (zret == Z_OK) {
    zret = inflate(&zs, Z_FINISH);
    if (out_len) *out_len = zs.total_out;
    if (out_zret) *out_zret = zret;
    inflateEnd(&zs);
    if ((zret == Z_STREAM_END || zret == Z_OK) && zs.total_out == expected_len) return 1;
  }

  return 0;
}

static int apple_hp_store_cursor_image(rfbClient *client, uint32_t cache_id, int hot_x, int hot_y,
                                       int width, int height, const uint8_t *payload,
                                       uint32_t payload_len) {
#if defined(APPLEHPDEBUG_HAS_SDL)
  struct apple_hp_cursor_cache_entry *entry;
  size_t packed_len;
  uint8_t *packed = NULL;
  uint8_t *argb = NULL;
  SDL_Texture *texture = NULL;
  size_t pixel_count;
  size_t i;
  const uint8_t *rgb_plane;
  const uint8_t *alpha_plane;
  int zret = Z_DATA_ERROR;

  if (!client || !g_live.renderer || !payload || width <= 0 || height <= 0) return 0;
  if ((unsigned long long)width * (unsigned long long)height > (1ULL << 24)) return 0;
  if (client->format.bitsPerPixel != 32 || !client->format.trueColour) {
    rfbClientErr("live-view: unsupported cursor pixel format bpp=%u trueColour=%u\n",
                 (unsigned)client->format.bitsPerPixel, (unsigned)client->format.trueColour);
    return 0;
  }

  pixel_count = (size_t)width * (size_t)height;
  packed_len = pixel_count * 5u;
  packed = (uint8_t *)malloc((size_t)packed_len);
  argb = (uint8_t *)malloc(pixel_count * 4u);
  if (!packed || !argb) {
    free(packed);
    free(argb);
    return 0;
  }
  if (!inflate_cursor_payload(payload, payload_len, packed, pixel_count * 5u, &packed_len, &zret)) {
    rfbClientErr("live-view: cursor decode failed cache=%u compressed=%u zret=%d inflated=%zu expected=%zu\n",
                 cache_id, payload_len, zret, packed_len, pixel_count * 5u);
    free(packed);
    free(argb);
    return 0;
  }
  rgb_plane = packed;
  alpha_plane = packed + pixel_count * 4u;
  for (i = 0; i < pixel_count; ++i) {
    uint32_t color = decode_cursor_color32(client, rgb_plane + i * 4u);
    uint32_t pixel = ((uint32_t)alpha_plane[i] << 24) | color;
    argb[i * 4u + 0] = (uint8_t)(pixel & 0xff);
    argb[i * 4u + 1] = (uint8_t)((pixel >> 8) & 0xff);
    argb[i * 4u + 2] = (uint8_t)((pixel >> 16) & 0xff);
    argb[i * 4u + 3] = (uint8_t)((pixel >> 24) & 0xff);
  }

  texture = SDL_CreateTexture(g_live.renderer, SDL_PIXELFORMAT_ARGB8888,
                              SDL_TEXTUREACCESS_STATIC, width, height);
  if (!texture) {
    free(packed);
    free(argb);
    return 0;
  }
  SDL_SetTextureBlendMode(texture, SDL_BLENDMODE_BLEND);
  if (SDL_UpdateTexture(texture, NULL, argb, width * 4) < 0) {
    SDL_DestroyTexture(texture);
    free(packed);
    free(argb);
    return 0;
  }

  entry = alloc_cursor_cache_entry(cache_id);
  if (!entry) {
    SDL_DestroyTexture(texture);
    free(packed);
    free(argb);
    return 0;
  }
  if (entry->texture) SDL_DestroyTexture(entry->texture);
  free(entry->pixels);
  entry->texture = texture;
  entry->pixels = argb;
  entry->cache_id = cache_id;
  entry->hot_x = hot_x;
  entry->hot_y = hot_y;
  entry->width = width;
  entry->height = height;
  g_live.cursor_current_cache_id = cache_id;
  g_live.cursor_visible = 1;
  free(packed);
  return 1;
#else
  (void)client;
  (void)cache_id;
  (void)hot_x;
  (void)hot_y;
  (void)width;
  (void)height;
  (void)payload;
  (void)payload_len;
  return 0;
#endif
}

static void refresh_live_view_layout(rfbClient *client) {
#if defined(APPLEHPDEBUG_HAS_SDL)
  struct apple_hp_live_view_geometry geom;
  int view_width = 1;
  int view_height = 1;
  int current_w = 0;
  int current_h = 0;
  Uint32 window_flags = 0;

  if (!g_runtime.live_view || !client) return;
  if (!g_live.window || !g_live.renderer) return;

  live_view_target_size(client, &view_width, &view_height);
  window_flags = SDL_GetWindowFlags(g_live.window);
  SDL_GetWindowSize(g_live.window, &current_w, &current_h);
  if ((window_flags & SDL_WINDOW_FULLSCREEN_DESKTOP) == 0 &&
      (window_flags & SDL_WINDOW_FULLSCREEN) == 0 &&
      !g_live.window_user_sized &&
      (current_w != view_width || current_h != view_height)) {
    g_live.synthetic_resize_events += 2;
    SDL_SetWindowSize(g_live.window, view_width, view_height);
    invalidate_live_view_runtime_size();
  }
  SDL_RenderSetLogicalSize(g_live.renderer, 0, 0);
  g_live.needs_clear = 1;
  memset(&geom, 0, sizeof(geom));
  compute_live_view_geometry(client, &geom);
#else
  (void)client;
#endif
}

static void invalidate_live_view_runtime_size(void) {
#if defined(APPLEHPDEBUG_HAS_SDL)
  g_live.runtime_size_valid = 0;
#endif
}

static int live_view_runtime_display_size(rfbClient *client, uint16_t *out_w, uint16_t *out_h) {
#if defined(APPLEHPDEBUG_HAS_SDL)
  int window_w = 0;
  int window_h = 0;
  int display_index = 0;
  int w = 0;
  int h = 0;
  Uint32 window_flags = 0;
  SDL_Rect bounds;

  if (!client || !out_w || !out_h) return 0;
  if (g_live.runtime_size_valid &&
      g_live.cached_runtime_w > 0 &&
      g_live.cached_runtime_h > 0) {
    *out_w = g_live.cached_runtime_w;
    *out_h = g_live.cached_runtime_h;
    return 1;
  }
  memset(&bounds, 0, sizeof(bounds));
  if (g_live.window) {
    window_flags = SDL_GetWindowFlags(g_live.window);
    display_index = SDL_GetWindowDisplayIndex(g_live.window);
    if (display_index < 0) display_index = 0;
  }
  if ((window_flags & SDL_WINDOW_FULLSCREEN_DESKTOP) != 0 ||
      (window_flags & SDL_WINDOW_FULLSCREEN) != 0) {
    /* Dynamic-resolution requests should follow the logical window/display
     * size in points, not the HiDPI drawable size in pixels. Using drawable
     * pixels here makes the remote desktop too dense, which shrinks icons/text.
     * For fullscreen, prefer full display bounds instead of usable bounds so
     * we do not under-request height and create local letterboxing. */
    if (SDL_GetDisplayBounds(display_index, &bounds) == 0 &&
        bounds.w > 0 && bounds.h > 0) {
      w = bounds.w;
      h = bounds.h;
    }
  }
  if (g_live.window) SDL_GetWindowSize(g_live.window, &window_w, &window_h);
  if (w <= 0 || h <= 0) {
    w = window_w;
    h = window_h;
  }
  if (w <= 0 || h <= 0) {
    live_view_target_size(client, &w, &h);
  }
  if (w <= 0 || h <= 0) return 0;
  if (w > 0xffff) w = 0xffff;
  if (h > 0xffff) h = 0xffff;
  g_live.cached_runtime_w = (uint16_t)w;
  g_live.cached_runtime_h = (uint16_t)h;
  g_live.runtime_size_valid = 1;
  *out_w = g_live.cached_runtime_w;
  *out_h = g_live.cached_runtime_h;
  return 1;
#else
  (void)client;
  (void)out_w;
  (void)out_h;
  return 0;
#endif
}

static int apple_hp_compute_dynamic_resolution_target(rfbClient *client,
                                                      uint16_t *out_w,
                                                      uint16_t *out_h) {
  uint16_t target_w = 0;
  uint16_t target_h = 0;
  uint32_t round_step = 0;

  if (!client || !out_w || !out_h) return 0;
  if (!live_view_runtime_display_size(client, &target_w, &target_h)) return 0;
  if (target_w == 0 || target_h == 0) return 0;
  round_step = apple_hp_dynamic_round_step();
  target_w = apple_hp_round_dimension(target_w, round_step);
  target_h = apple_hp_round_dimension(target_h, round_step);
  if (target_w == 0 || target_h == 0) return 0;
  *out_w = target_w;
  *out_h = target_h;
  return 1;
}

static int apple_hp_dynamic_resize_ready(rfbClient *client) {
  if (!client || !g_runtime.live_view || !g_runtime.apple_hp_mode) return 0;
  if (!g_hp.rekey_seen || !g_hp.transport.active) return 0;
  if (!g_hp.post_rekey_sent || g_hp.post_rekey_ready != 0) return 0;
  if (!g_hp.displayinfo2_seen) return 0;
  if (!g_hp.initial_full_refresh_done) return 0;
  return 1;
}

static void apple_hp_clear_pending_dynamic_target(void) {
  g_hp.pending_dynamic_target_w = 0;
  g_hp.pending_dynamic_target_h = 0;
}

static void apple_hp_set_pending_dynamic_target(uint16_t target_w, uint16_t target_h,
                                                const char *reason) {
  g_hp.pending_dynamic_target_w = target_w;
  g_hp.pending_dynamic_target_h = target_h;
  rfbClientLog("apple-hp: queued dynamic target %ux%u while request in flight (%s)\n",
               (unsigned)target_w, (unsigned)target_h, reason ? reason : "unspecified");
}

static void apple_hp_clear_dynamic_request_state(int clear_last_request) {
  g_hp.dynamic_request_in_flight = 0;
  g_hp.dynamic_refresh_queued_for_request = 0;
  g_hp.dynamic_request_started_ms = 0;
  if (clear_last_request) {
    g_hp.last_dynamic_request_w = 0;
    g_hp.last_dynamic_request_h = 0;
  }
}

static int maybe_observe_dynamic_resolution_target(rfbClient *client, const char *reason) {
  uint16_t target_w = 0;
  uint16_t target_h = 0;

  if (!client || !g_runtime.live_view || !g_runtime.apple_hp_mode) return 1;
  if (apple_hp_display_width(client) == 0 || apple_hp_display_height(client) == 0) return 1;
  if (!apple_hp_compute_dynamic_resolution_target(client, &target_w, &target_h)) return 1;
  if (target_w == 0 || target_h == 0) return 1;
  if (target_w == g_live.last_runtime_w &&
      target_h == g_live.last_runtime_h) {
    return 1;
  }
  if (!apple_hp_dynamic_resize_ready(client)) return 1;
  rfbClientLog("apple-hp: observed viewport intent %ux%u (%s)\n",
               (unsigned)target_w, (unsigned)target_h, reason ? reason : "unspecified");
  return maybe_send_dynamic_resolution_update(client, reason, FALSE);
}

static int maybe_send_dynamic_resolution_update(rfbClient *client, const char *reason, int force) {
  uint16_t target_w = 0;
  uint16_t target_h = 0;
  uint16_t display_w = 0;
  uint16_t display_h = 0;

  if (!client || !g_runtime.live_view || !g_runtime.apple_hp_mode) return 1;
  if (!force && !apple_hp_dynamic_resize_ready(client)) return 1;
  if (!g_hp.rekey_seen || !g_hp.transport.active) return 1;
  if (!apple_hp_compute_dynamic_resolution_target(client, &target_w, &target_h)) return 1;
  if (target_w == 0 || target_h == 0) return 1;
  display_w = apple_hp_display_width(client);
  display_h = apple_hp_display_height(client);
  if (!force &&
      !apple_hp_dynamic_target_materially_diff(target_w, target_h, display_w, display_h)) {
    g_live.last_runtime_w = target_w;
    g_live.last_runtime_h = target_h;
    return 1;
  }
  if (dynamic_resolution_target_matches_display(client, target_w, target_h)) {
    g_live.last_runtime_w = target_w;
    g_live.last_runtime_h = target_h;
    apple_hp_clear_pending_dynamic_target();
    return 1;
  }
  if (g_hp.dynamic_request_in_flight) {
    if (target_w == g_hp.last_dynamic_request_w &&
        target_h == g_hp.last_dynamic_request_h) {
      return 1;
    }
    if (!force &&
        g_hp.pending_dynamic_target_w == target_w &&
        g_hp.pending_dynamic_target_h == target_h) {
      return 1;
    }
    apple_hp_set_pending_dynamic_target(target_w, target_h, reason);
    g_live.last_runtime_w = target_w;
    g_live.last_runtime_h = target_h;
    return 1;
  }
  if (!force &&
      target_w == g_hp.last_dynamic_request_w &&
      target_h == g_hp.last_dynamic_request_h) {
    return 1;
  }
  if (!send_runtime_display_configuration_blob(client, target_w, target_h, reason)) return 0;
  g_hp.dynamic_request_started_ms = monotonic_ms();
  g_live.last_runtime_w = target_w;
  g_live.last_runtime_h = target_h;
  apple_hp_clear_pending_dynamic_target();
  return 1;
}

static int apple_hp_maybe_handle_dynamic_request_timeout(rfbClient *client) {
  long long elapsed_ms = 0;

  if (!client || !g_hp.dynamic_request_in_flight) return 1;
  if (g_hp.dynamic_request_started_ms <= 0) return 1;
  elapsed_ms = monotonic_ms() - g_hp.dynamic_request_started_ms;
  if (elapsed_ms < 0 || (uint32_t)elapsed_ms < apple_hp_dynamic_timeout_ms()) return 1;

  rfbClientLog("apple-hp: dynamic request %ux%u timed out after %lld ms\n",
               (unsigned)g_hp.last_dynamic_request_w,
               (unsigned)g_hp.last_dynamic_request_h,
               elapsed_ms);
  apple_hp_clear_dynamic_request_state(TRUE);
  if (g_hp.pending_dynamic_target_w != 0 && g_hp.pending_dynamic_target_h != 0) {
    uint16_t pending_w = g_hp.pending_dynamic_target_w;
    uint16_t pending_h = g_hp.pending_dynamic_target_h;
    apple_hp_clear_pending_dynamic_target();
    g_live.last_runtime_w = pending_w;
    g_live.last_runtime_h = pending_h;
    return maybe_send_dynamic_resolution_update(client, "dynamic-timeout", TRUE);
  }
  g_live.pending_dynamic_resize = 1;
  return 1;
}

static int compute_live_view_geometry(rfbClient *client, struct apple_hp_live_view_geometry *geom) {
#if defined(APPLEHPDEBUG_HAS_SDL)
  int display_w = 0;
  int display_h = 0;
  int fit_w = 0;
  int fit_h = 0;
  int fit_src_w = 0;
  int fit_src_h = 0;
  if (!client || !geom || !g_live.renderer) return 0;
  memset(geom, 0, sizeof(*geom));
  if (g_live.window) SDL_GetWindowSize(g_live.window, &geom->window_w, &geom->window_h);
  if (SDL_GetRendererOutputSize(g_live.renderer, &geom->output_w, &geom->output_h) < 0) return 0;
  if (geom->output_w <= 0 || geom->output_h <= 0) return 0;

  display_w = apple_hp_display_width(client);
  display_h = apple_hp_display_height(client);
  if (g_runtime.apple_hp_mode && apple_hp_backing_width(client) > 0 && apple_hp_backing_height(client) > 0) {
    if (g_hp.visible_content_valid &&
        g_hp.visible_content_w > 0 && g_hp.visible_content_h > 0 &&
        g_hp.visible_content_x >= 0 && g_hp.visible_content_y >= 0 &&
        g_hp.visible_content_x + g_hp.visible_content_w <= client->width &&
        g_hp.visible_content_y + g_hp.visible_content_h <= client->height) {
      geom->src.x = g_hp.visible_content_x;
      geom->src.y = g_hp.visible_content_y;
      geom->src.w = g_hp.visible_content_w;
      geom->src.h = g_hp.visible_content_h;
    } else {
      geom->src.x = 0;
      geom->src.y = 0;
      geom->src.w = apple_hp_backing_width(client);
      geom->src.h = apple_hp_backing_height(client);
    }
  } else {
    geom->src.x = g_live.crop_x;
    geom->src.y = g_live.crop_y;
    geom->src.w = g_live.crop_w > 0 ? g_live.crop_w : client->width;
    geom->src.h = g_live.crop_h > 0 ? g_live.crop_h : client->height;
  }
  if (geom->src.w <= 0 || geom->src.h <= 0 ||
      geom->src.x < 0 || geom->src.y < 0 ||
      geom->src.x + geom->src.w > client->width ||
      geom->src.y + geom->src.h > client->height) {
    geom->src.x = 0;
    geom->src.y = 0;
    geom->src.w = client->width > 0 ? client->width : 1;
    geom->src.h = client->height > 0 ? client->height : 1;
  }
  if (g_runtime.apple_hp_mode && geom->src.w > 0 && geom->src.h > 0) {
    if (g_hp.visible_content_valid &&
        geom->src.x == g_hp.visible_content_x &&
        geom->src.y == g_hp.visible_content_y &&
        geom->src.w == g_hp.visible_content_w &&
        geom->src.h == g_hp.visible_content_h) {
      fit_src_w = geom->src.w;
      fit_src_h = geom->src.h;
    } else {
      fit_src_w = display_w > 0 ? display_w : geom->src.w;
      fit_src_h = display_h > 0 ? display_h : geom->src.h;
    }
    fit_w = geom->output_w;
    fit_h = (int)(((long long)fit_w * (long long)fit_src_h) / (long long)fit_src_w);
    if (fit_h > geom->output_h) {
      fit_h = geom->output_h;
      fit_w = (int)(((long long)fit_h * (long long)fit_src_w) / (long long)fit_src_h);
    }
    if (fit_w <= 0) fit_w = 1;
    if (fit_h <= 0) fit_h = 1;
    geom->dst.w = fit_w;
    geom->dst.h = fit_h;
    geom->dst.x = (geom->output_w - geom->dst.w) / 2;
    geom->dst.y = (geom->output_h - geom->dst.h) / 2;
  } else {
    geom->dst.x = 0;
    geom->dst.y = 0;
    geom->dst.w = geom->output_w;
    geom->dst.h = geom->output_h;
  }
  geom->valid = 1;
  return 1;
#else
  (void)client;
  (void)geom;
  return 0;
#endif
}

static void apple_hp_fit_rect_inside(SDL_Rect outer, int inner_w, int inner_h, SDL_Rect *out) {
  int fit_w = outer.w;
  int fit_h = outer.h;

  if (!out) return;
  *out = outer;
  if (outer.w <= 0 || outer.h <= 0 || inner_w <= 0 || inner_h <= 0) return;

  fit_w = outer.w;
  fit_h = (int)(((long long)fit_w * (long long)inner_h) / (long long)inner_w);
  if (fit_h > outer.h) {
    fit_h = outer.h;
    fit_w = (int)(((long long)fit_h * (long long)inner_w) / (long long)inner_h);
  }
  if (fit_w <= 0) fit_w = 1;
  if (fit_h <= 0) fit_h = 1;
  out->w = fit_w;
  out->h = fit_h;
  out->x = outer.x + (outer.w - fit_w) / 2;
  out->y = outer.y + (outer.h - fit_h) / 2;
}

static void apple_hp_control_rect_for_geometry(rfbClient *client,
                                               const struct apple_hp_live_view_geometry *geom,
                                               SDL_Rect *out) {
  double scale;
  int scaled_w;
  int scaled_h;

  if (!out) return;
  memset(out, 0, sizeof(*out));
  if (!geom || !geom->valid) return;
  *out = geom->dst;
  scale = apple_hp_input_rect_scale();
  if (scale == 1.0) return;
  scaled_w = (int)((double)geom->dst.w * scale + 0.5);
  scaled_h = (int)((double)geom->dst.h * scale + 0.5);
  if (scaled_w <= 0) scaled_w = 1;
  if (scaled_h <= 0) scaled_h = 1;
  out->w = scaled_w;
  out->h = scaled_h;
  out->x = geom->dst.x + (geom->dst.w - out->w) / 2;
  out->y = geom->dst.y + (geom->dst.h - out->h) / 2;
}

static int clamp_int(int value, int min_value, int max_value) {
  if (value < min_value) return min_value;
  if (value > max_value) return max_value;
  return value;
}

static void map_live_view_pointer(rfbClient *client, int in_x, int in_y, int *out_x, int *out_y) {
#if defined(APPLEHPDEBUG_HAS_SDL)
  int window_w = 0;
  int window_h = 0;
  int output_w = 0;
  int output_h = 0;
  int output_x = in_x;
  int output_y = in_y;
  int mapped_x = in_x;
  int mapped_y = in_y;
  int display_x = in_x;
  int display_y = in_y;
  int rel_x = 0;
  int rel_y = 0;
  struct apple_hp_live_view_geometry geom;
  SDL_Rect control_rect;
  SDL_Rect input_rect;
  int display_w = 0;
  int display_h = 0;
  int backing_w = 0;
  int backing_h = 0;
  int region_hit = 0;
  int used_simple_scale = 0;

  if (!client || !out_x || !out_y) return;

  if (g_live.window) SDL_GetWindowSize(g_live.window, &window_w, &window_h);
  if (g_live.renderer) SDL_GetRendererOutputSize(g_live.renderer, &output_w, &output_h);
  if (window_w > 0 && output_w > 0)
    output_x = apple_hp_scale_coord_round(in_x, output_w, window_w);
  if (window_h > 0 && output_h > 0)
    output_y = apple_hp_scale_coord_round(in_y, output_h, window_h);

  memset(&geom, 0, sizeof(geom));
  if (compute_live_view_geometry(client, &geom) && geom.valid &&
      geom.src.w > 0 && geom.src.h > 0 && geom.dst.w > 0 && geom.dst.h > 0) {
    display_w = apple_hp_display_width(client);
    display_h = apple_hp_display_height(client);
    backing_w = apple_hp_backing_width(client);
    backing_h = apple_hp_backing_height(client);
    memset(&control_rect, 0, sizeof(control_rect));
    memset(&input_rect, 0, sizeof(input_rect));
    rel_x = output_x - geom.dst.x;
    rel_y = output_y - geom.dst.y;
    rel_x = clamp_int(rel_x, 0, geom.dst.w - 1);
    rel_y = clamp_int(rel_y, 0, geom.dst.h - 1);
    input_rect = geom.dst;
    control_rect = geom.dst;
    g_live.pointer_draw_x = output_x;
    g_live.pointer_draw_y = output_y;
    used_simple_scale = 1;
    if (g_runtime.apple_hp_mode &&
        g_hp.visible_content_valid &&
        geom.src.w > 0 && geom.src.h > 0) {
      int backing_x = geom.src.x + apple_hp_scale_coord_round(rel_x, geom.src.w, geom.dst.w);
      int backing_y = geom.src.y + apple_hp_scale_coord_round(rel_y, geom.src.h, geom.dst.h);
      if (display_w > 0 && display_h > 0 && backing_w > 0 && backing_h > 0) {
        display_x = apple_hp_scale_coord_round(backing_x, display_w, backing_w);
        display_y = apple_hp_scale_coord_round(backing_y, display_h, backing_h);
      } else {
        display_x = backing_x;
        display_y = backing_y;
      }
      region_hit = 1;
    } else if (g_runtime.apple_hp_mode && display_w > 0 && display_h > 0) {
      display_x = apple_hp_scale_coord_round(rel_x, display_w, geom.dst.w);
      display_y = apple_hp_scale_coord_round(rel_y, display_h, geom.dst.h);
      region_hit = 1;
    } else {
      display_x = geom.src.x + apple_hp_scale_coord_round(rel_x, geom.src.w, geom.dst.w);
      display_y = geom.src.y + apple_hp_scale_coord_round(rel_y, geom.src.h, geom.dst.h);
    }
    mapped_x = display_x;
    mapped_y = display_y;
  } else {
    mapped_x = output_x;
    mapped_y = output_y;
    display_x = output_x;
    display_y = output_y;
    g_live.pointer_draw_x = output_x;
    g_live.pointer_draw_y = output_y;
    memset(&input_rect, 0, sizeof(input_rect));
    memset(&control_rect, 0, sizeof(control_rect));
  }

  if (mapped_x < 0) mapped_x = 0;
  if (mapped_y < 0) mapped_y = 0;
  if (g_runtime.apple_hp_mode && display_w > 0 && display_h > 0) {
    if (mapped_x >= display_w) mapped_x = display_w - 1;
    if (mapped_y >= display_h) mapped_y = display_h - 1;
  } else {
    if (mapped_x >= client->width) mapped_x = client->width - 1;
    if (mapped_y >= client->height) mapped_y = client->height - 1;
  }

done:
  *out_x = mapped_x;
  *out_y = mapped_y;
#else
  (void)client;
  if (out_x) *out_x = in_x;
  if (out_y) *out_y = in_y;
#endif
}

static void apple_hp_pointer_send_coords(rfbClient *client,
                                         int logical_x,
                                         int logical_y,
                                         int *out_x,
                                         int *out_y) {
  int send_x = logical_x * 2;
  int send_y = logical_y * 2;
  int display_w = 0;
  int display_h = 0;
  int backing_w = 0;
  int backing_h = 0;

  if (!out_x || !out_y) return;
  if (!client) {
    *out_x = send_x;
    *out_y = send_y;
    return;
  }

  display_w = apple_hp_display_width(client);
  display_h = apple_hp_display_height(client);
  backing_w = apple_hp_backing_width(client);
  backing_h = apple_hp_backing_height(client);

  /* After live dynamic-resolution reconfiguration, the remote starts sending a
   * downsized backing surface. In that mode, the old fixed 2x Retina send path
   * overshoots; logical desktop coordinates track the remote pointer correctly. */
  if (g_runtime.apple_hp_mode &&
      g_hp.last_dynamic_request_w > 0 &&
      g_hp.last_dynamic_request_h > 0 &&
      display_w > 0 && display_h > 0 &&
      backing_w > 0 && backing_h > 0 &&
      backing_w < display_w && backing_h < display_h) {
    send_x = logical_x;
    send_y = logical_y;
  }

  *out_x = send_x;
  *out_y = send_y;
}

static void live_view_target_size(rfbClient *client, int *out_w, int *out_h) {
  int fb_w = client && client->width > 0 ? client->width : 1;
  int fb_h = client && client->height > 0 ? client->height : 1;
  int display_w = client ? apple_hp_display_width(client) : 0;
  int display_h = client ? apple_hp_display_height(client) : 0;
  int w = fb_w;
  int h = fb_h;
#if defined(APPLEHPDEBUG_HAS_SDL)
  SDL_Rect usable_bounds;
#endif

  if (apple_hp_simple_1080p_enabled()) {
    w = 1920;
    h = 1080;
  } else if (g_runtime.apple_hp_mode && display_w > 0 && display_h > 0) {
    w = display_w;
    h = display_h;
  } else if (g_live.crop_w > 0 && g_live.crop_h > 0) {
    w = g_live.crop_w;
    h = g_live.crop_h;
  } else if (g_runtime.apple_hp_mode && client && fb_w <= 1 && fb_h <= 1) {
    w = display_w;
    h = display_h;
  }

#if defined(APPLEHPDEBUG_HAS_SDL)
  if (!apple_hp_simple_1080p_enabled() &&
      w > 0 && h > 0 && SDL_GetDisplayUsableBounds(0, &usable_bounds) == 0 &&
      usable_bounds.w > 0 && usable_bounds.h > 0) {
    if (w > usable_bounds.w || h > usable_bounds.h) {
      int fit_w = usable_bounds.w;
      int fit_h = (int)(((long long)fit_w * (long long)h) / (long long)w);
      if (fit_h > usable_bounds.h) {
        fit_h = usable_bounds.h;
        fit_w = (int)(((long long)fit_h * (long long)w) / (long long)h);
      }
      if (fit_w > 0 && fit_h > 0) {
        w = fit_w;
        h = fit_h;
      }
    }
  }
#endif

  if (out_w) *out_w = w > 0 ? w : 1;
  if (out_h) *out_h = h > 0 ? h : 1;
}

static void maybe_update_live_view_crop(rfbClient *client, int updated_w, int updated_h) {
#if defined(APPLEHPDEBUG_HAS_SDL)
  uint32_t *fb = NULL;
  int fb_w, fb_h, region_w, region_h;
  int left, right, top, bottom;
  int x, y;
  int allow_apply = 1;

  if (!g_runtime.live_view || !client || !client->frameBuffer) return;
  if (client->format.bitsPerPixel != 32) return;
  if (g_runtime.apple_hp_mode && !apple_hp_visible_crop_enabled()) {
    if (g_hp.visible_content_valid) {
      g_hp.visible_content_valid = 0;
      g_hp.visible_content_x = 0;
      g_hp.visible_content_y = 0;
      g_hp.visible_content_w = 0;
      g_hp.visible_content_h = 0;
    }
    return;
  }

  fb_w = client->width;
  fb_h = client->height;
  if (g_runtime.apple_hp_mode && apple_hp_backing_width(client) > 0 && apple_hp_backing_height(client) > 0) {
    region_w = apple_hp_backing_width(client);
    region_h = apple_hp_backing_height(client);
    allow_apply = 0;
  } else {
    region_w = fb_w;
    region_h = fb_h;
  }
  if (region_w <= 0 || region_h <= 0 || region_w > fb_w || region_h > fb_h) return;
  if ((unsigned long long)updated_w * (unsigned long long)updated_h <
      ((unsigned long long)region_w * (unsigned long long)region_h) / 2ULL)
    return;

#define PIXEL_HAS_VISIBLE_RGB(px) ((((px) >> 16) & 0xff) > 8 || (((px) >> 8) & 0xff) > 8 || ((px) & 0xff) > 8)

  fb = (uint32_t *)client->frameBuffer;
  left = 0;
  while (left < region_w) {
    int found = 0;
    for (y = 0; y < region_h; ++y) {
      if (PIXEL_HAS_VISIBLE_RGB(fb[y * fb_w + left])) {
        found = 1;
        break;
      }
    }
    if (found) break;
    left++;
  }

  right = region_w - 1;
  while (right >= left) {
    int found = 0;
    for (y = 0; y < region_h; ++y) {
      if (PIXEL_HAS_VISIBLE_RGB(fb[y * fb_w + right])) {
        found = 1;
        break;
      }
    }
    if (found) break;
    right--;
  }

  top = 0;
  while (top < region_h) {
    int found = 0;
    for (x = left; x <= right; ++x) {
      if (PIXEL_HAS_VISIBLE_RGB(fb[top * fb_w + x])) {
        found = 1;
        break;
      }
    }
    if (found) break;
    top++;
  }

  bottom = region_h - 1;
  while (bottom >= top) {
    int found = 0;
    for (x = left; x <= right; ++x) {
      if (PIXEL_HAS_VISIBLE_RGB(fb[bottom * fb_w + x])) {
        found = 1;
        break;
      }
    }
    if (found) break;
    bottom--;
  }

  if (left > 32 || top > 32 || right < region_w - 33 || bottom < region_h - 33) {
    int pad = (int)apple_hp_visible_content_pad();
    int crop_left = 0;
    int crop_top = 0;
    int crop_right = right;
    int crop_bottom = bottom;
    int crop_w = right - left + 1;
    int crop_h = bottom - top + 1;
    /* Apple HP padding has only shown up on the trailing edges so far.
     * Cropping the leading left/top edge based on pixel darkness is unsafe:
     * real content like the macOS lock screen can legitimately start very dark.
     * Keep the origin pinned at 0,0 and only trim right/bottom padding. */
    if (crop_right < crop_left) crop_right = crop_left;
    if (crop_bottom < crop_top) crop_bottom = crop_top;
    if (pad > 0) {
      crop_right += pad;
      crop_bottom += pad;
      if (crop_right >= region_w) crop_right = region_w - 1;
      if (crop_bottom >= region_h) crop_bottom = region_h - 1;
    }
    crop_w = crop_right - crop_left + 1;
    crop_h = crop_bottom - crop_top + 1;
    if (crop_w > 0 && crop_h > 0) {
      if (g_runtime.apple_hp_mode && !allow_apply) {
        g_hp.visible_content_valid = 1;
        g_hp.visible_content_x = crop_left;
        g_hp.visible_content_y = crop_top;
        g_hp.visible_content_w = crop_w;
        g_hp.visible_content_h = crop_h;
      } else if (g_live.crop_x != crop_left || g_live.crop_y != crop_top ||
                 g_live.crop_w != crop_w || g_live.crop_h != crop_h) {
        g_live.crop_x = crop_left;
        g_live.crop_y = crop_top;
        g_live.crop_w = crop_w;
        g_live.crop_h = crop_h;
        refresh_live_view_layout(client);
      }
    }
  }
#undef PIXEL_HAS_VISIBLE_RGB
#else
  (void)client;
  (void)updated_w;
  (void)updated_h;
#endif
}

static void render_live_cursor(rfbClient *client) {
#if defined(APPLEHPDEBUG_HAS_SDL)
  struct apple_hp_cursor_cache_entry *entry;
  SDL_Rect dst;
  SDL_Rect bar;
  int window_w = 0;
  int window_h = 0;
  int output_w = 0;
  int output_h = 0;
  int scale_w = 1;
  int scale_h = 1;

  if (!client || !g_live.renderer) return;

#if APPLEHPDEBUG_DEBUG_BUILD
  SDL_SetRenderDrawBlendMode(g_live.renderer, SDL_BLENDMODE_BLEND);
  SDL_SetRenderDrawColor(g_live.renderer, 255, 64, 64, 220);
  bar.x = g_live.pointer_draw_x - 8;
  bar.y = g_live.pointer_draw_y;
  bar.w = 17;
  bar.h = 1;
  SDL_RenderFillRect(g_live.renderer, &bar);
  bar.x = g_live.pointer_draw_x;
  bar.y = g_live.pointer_draw_y - 8;
  bar.w = 1;
  bar.h = 17;
  SDL_RenderFillRect(g_live.renderer, &bar);
#else
  (void)bar;
#endif

  if (!g_live.cursor_visible || g_live.cursor_current_cache_id == 0) return;
  entry = find_cursor_cache_entry(g_live.cursor_current_cache_id);
  if (!entry || !entry->texture || entry->width <= 0 || entry->height <= 0) return;

  if (g_live.window) SDL_GetWindowSize(g_live.window, &window_w, &window_h);
  if (SDL_GetRendererOutputSize(g_live.renderer, &output_w, &output_h) == 0 &&
      window_w > 0 && window_h > 0) {
    scale_w = output_w / window_w;
    scale_h = output_h / window_h;
    if (scale_w <= 0) scale_w = 1;
    if (scale_h <= 0) scale_h = 1;
  }

  dst.x = g_live.pointer_draw_x;
  dst.y = g_live.pointer_draw_y;
  dst.w = entry->width * scale_w;
  dst.h = entry->height * scale_h;
  dst.x -= entry->hot_x * scale_w;
  dst.y -= entry->hot_y * scale_h;
  SDL_RenderCopy(g_live.renderer, entry->texture, NULL, &dst);
#else
  (void)client;
#endif
}

static void redraw_live_view(rfbClient *client) {
#if defined(APPLEHPDEBUG_HAS_SDL)
  struct apple_hp_live_view_geometry geom;

  if (!g_runtime.live_view || !client || !g_live.texture || !g_live.renderer) return;
  memset(&geom, 0, sizeof(geom));
  if (!compute_live_view_geometry(client, &geom)) return;
  SDL_SetRenderDrawColor(g_live.renderer, 0, 0, 0, 255);
  if (SDL_RenderClear(g_live.renderer) < 0) return;
  if (SDL_RenderCopy(g_live.renderer, g_live.texture, &geom.src, &geom.dst) < 0) return;
  render_live_cursor(client);
  SDL_RenderPresent(g_live.renderer);
#else
  (void)client;
#endif
}

static rfbBool alloc_live_fb(rfbClient *client) {
  SDL_Surface *sdl = NULL;
  int width = client->width;
  int height = client->height;
  int view_width = width;
  int view_height = height;
  int alloc_width = width > 0 ? width : 1;
  int alloc_height = height > 0 ? height : 1;
  int depth = client->format.bitsPerPixel ? client->format.bitsPerPixel : 32;

  g_live.present_per_rect = env_flag_enabled("VNC_LIVE_VIEW_PRESENT_PER_RECT");

  sdl = (SDL_Surface *)rfbClientGetClientData(client, SDL_Init);
  if (sdl) {
    SDL_FreeSurface(sdl);
    rfbClientSetClientData(client, SDL_Init, NULL);
  }

  sdl = SDL_CreateRGBSurface(0, alloc_width, alloc_height, depth, 0, 0, 0, 0);
  if (!sdl) {
    rfbClientErr("live-view: SDL_CreateRGBSurface failed: %s\n", SDL_GetError());
    return FALSE;
  }

  rfbClientSetClientData(client, SDL_Init, sdl);
  client->width = sdl->pitch / (depth / 8);
  client->height = sdl->h;
  client->frameBuffer = (uint8_t *)sdl->pixels;
  memset(client->frameBuffer, 0, (size_t)sdl->pitch * (size_t)sdl->h);
  reset_live_view_crop();
  invalidate_live_view_runtime_size();

  client->format.bitsPerPixel = sdl->format->BitsPerPixel;
  client->format.redShift = sdl->format->Rshift;
  client->format.greenShift = sdl->format->Gshift;
  client->format.blueShift = sdl->format->Bshift;
  client->format.redMax = sdl->format->Rmask >> client->format.redShift;
  client->format.greenMax = sdl->format->Gmask >> client->format.greenShift;
  client->format.blueMax = sdl->format->Bmask >> client->format.blueShift;

  if (width <= 0 || height <= 0) {
    return TRUE;
  }

  live_view_target_size(client, &view_width, &view_height);

  if (!g_live.window) {
    g_live.window = SDL_CreateWindow(
        client->desktopName ? client->desktopName : "applehpdebug",
        SDL_WINDOWPOS_UNDEFINED,
        SDL_WINDOWPOS_UNDEFINED,
        view_width,
        view_height,
        SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
    if (!g_live.window) {
      rfbClientErr("live-view: SDL_CreateWindow failed: %s\n", SDL_GetError());
      SDL_FreeSurface(sdl);
      rfbClientSetClientData(client, SDL_Init, NULL);
      return FALSE;
    }
    g_live.window_user_sized = 0;
  } else {
    Uint32 window_flags = SDL_GetWindowFlags(g_live.window);
    int current_w = 0;
    int current_h = 0;
    SDL_GetWindowSize(g_live.window, &current_w, &current_h);
    if ((window_flags & SDL_WINDOW_FULLSCREEN_DESKTOP) == 0 &&
        (window_flags & SDL_WINDOW_FULLSCREEN) == 0 &&
        !g_live.window_user_sized &&
        (current_w != view_width || current_h != view_height)) {
      /* The initial non-HP framebuffer can be a transient ultra-wide size.
       * Once AppleDisplayLayout arrives, keep the live-view window aligned
       * with the new target aspect instead of preserving the stale shell. */
      g_live.synthetic_resize_events += 2;
      SDL_SetWindowSize(g_live.window, view_width, view_height);
    }
    if (client->desktopName) SDL_SetWindowTitle(g_live.window, client->desktopName);
  }

  if (!g_live.renderer) {
    Uint32 renderer_flags = SDL_RENDERER_ACCELERATED;
    if (g_runtime.live_view_vsync) renderer_flags |= SDL_RENDERER_PRESENTVSYNC;
    g_live.renderer = SDL_CreateRenderer(g_live.window, -1, renderer_flags);
    if (!g_live.renderer && renderer_flags != SDL_RENDERER_ACCELERATED) {
      g_live.renderer = SDL_CreateRenderer(g_live.window, -1, SDL_RENDERER_ACCELERATED);
    }
    if (!g_live.renderer) {
      rfbClientErr("live-view: SDL_CreateRenderer failed: %s\n", SDL_GetError());
      return FALSE;
    }
    SDL_SetHint(SDL_HINT_RENDER_SCALE_QUALITY, "nearest");
  }
  SDL_ShowCursor(SDL_DISABLE);
  SDL_RenderSetLogicalSize(g_live.renderer, 0, 0);

  if (g_live.texture) {
    SDL_DestroyTexture(g_live.texture);
    g_live.texture = NULL;
  }
  g_live.texture = SDL_CreateTexture(g_live.renderer,
                                    SDL_PIXELFORMAT_ARGB8888,
                                    SDL_TEXTUREACCESS_STREAMING,
                                    client->width,
                                    client->height);
  if (!g_live.texture) {
    rfbClientErr("live-view: SDL_CreateTexture failed: %s\n", SDL_GetError());
    return FALSE;
  }

  /* Zero-initialize the texture to avoid artifacts from uninitialized GPU memory */
  {
    void *pixels;
    int pitch;
    if (SDL_LockTexture(g_live.texture, NULL, &pixels, &pitch) == 0) {
      memset(pixels, 0, (size_t)pitch * (size_t)client->height);
      SDL_UnlockTexture(g_live.texture);
    }
  }

  reset_live_view_pending_present();
  g_live.last_present_us = 0;
  g_live.needs_clear = 1;
  rfbClientLog("live-view ready: framebuffer=%dx%d view=%dx%d\n",
               width, height, view_width, view_height);
  return TRUE;
}

static rfbBool handle_live_view_event(rfbClient *client, SDL_Event *e) {
  switch (e->type) {
    case SDL_WINDOWEVENT:
      switch (e->window.event) {
        case SDL_WINDOWEVENT_EXPOSED:
          invalidate_live_view_runtime_size();
          refresh_live_view_layout(client);
          g_live.pending_dynamic_resize = 1;
          queue_live_view_present(0, 0, client->width, client->height);
          present_live_view(client, 0, 0, client->width, client->height);
          SendFramebufferUpdateRequest(client, 0, 0,
                                       apple_hp_request_width(client),
                                       apple_hp_request_height(client), FALSE);
          break;
        case SDL_WINDOWEVENT_RESIZED:
        case SDL_WINDOWEVENT_SIZE_CHANGED:
        case SDL_WINDOWEVENT_MAXIMIZED:
        case SDL_WINDOWEVENT_RESTORED:
        case SDL_WINDOWEVENT_SHOWN:
          invalidate_live_view_runtime_size();
          refresh_live_view_layout(client);
          redraw_live_view(client);
          if (g_live.synthetic_resize_events > 0) {
            g_live.synthetic_resize_events--;
          } else {
            if (e->window.event != SDL_WINDOWEVENT_SHOWN) {
              g_live.window_user_sized = 1;
            }
            g_live.pending_dynamic_resize = 1;
          }
          SendFramebufferUpdateRequest(client, 0, 0,
                                       apple_hp_request_width(client),
                                       apple_hp_request_height(client), FALSE);
          break;
        case SDL_WINDOWEVENT_FOCUS_LOST:
          if (g_live.right_alt_key_down) {
            SendKeyEvent(client, XK_Alt_R, FALSE);
            g_live.right_alt_key_down = 0;
          }
          if (g_live.left_alt_key_down) {
            SendKeyEvent(client, XK_Alt_L, FALSE);
            g_live.left_alt_key_down = 0;
          }
          break;
        default:
          break;
      }
      break;
    case SDL_MOUSEWHEEL:
      note_live_view_input();
      if (e->wheel.y > 0) {
        int steps;
        for (steps = 0; steps < e->wheel.y; ++steps) {
          int send_x = 0;
          int send_y = 0;
          apple_hp_pointer_send_coords(client, g_live.pointer_x, g_live.pointer_y, &send_x, &send_y);
          SendPointerEvent(client, send_x, send_y, rfbButton4Mask);
          SendPointerEvent(client, send_x, send_y, 0);
        }
      }
      if (e->wheel.y < 0) {
        int steps;
        for (steps = 0; steps > e->wheel.y; --steps) {
          int send_x = 0;
          int send_y = 0;
          apple_hp_pointer_send_coords(client, g_live.pointer_x, g_live.pointer_y, &send_x, &send_y);
          SendPointerEvent(client, send_x, send_y, rfbButton5Mask);
          SendPointerEvent(client, send_x, send_y, 0);
        }
      }
      break;
    case SDL_MOUSEBUTTONUP:
    case SDL_MOUSEBUTTONDOWN:
    case SDL_MOUSEMOTION: {
      note_live_view_input();
      int raw_x = 0;
      int raw_y = 0;
      int state = 0;
      int i;
      if (e->type == SDL_MOUSEMOTION) {
        raw_x = e->motion.x;
        raw_y = e->motion.y;
      } else {
        raw_x = e->button.x;
        raw_y = e->button.y;
        state = e->button.button;
        for (i = 0; kButtonMapping[i].sdl; i++) {
          if (state == kButtonMapping[i].sdl) {
            state = kButtonMapping[i].rfb;
            if (e->type == SDL_MOUSEBUTTONDOWN) {
              g_live.button_mask |= state;
            } else {
              g_live.button_mask &= ~state;
            }
            break;
          }
        }
      }
      map_live_view_pointer(client, raw_x, raw_y, &g_live.pointer_x, &g_live.pointer_y);
      {
        int send_x = 0;
        int send_y = 0;
        apple_hp_pointer_send_coords(client, g_live.pointer_x, g_live.pointer_y, &send_x, &send_y);
        SendPointerEvent(client, send_x, send_y, g_live.button_mask);
      }
      redraw_live_view(client);
      g_live.button_mask &= ~(rfbButton4Mask | rfbButton5Mask);
      break;
    }
    case SDL_KEYUP:
    case SDL_KEYDOWN: {
      rfbKeySym key = sdl_key_to_rfb(&e->key);
      note_live_view_input();
      if (key) SendKeyEvent(client, key, e->type == SDL_KEYDOWN ? TRUE : FALSE);
      if (e->key.keysym.sym == SDLK_RALT) g_live.right_alt_key_down = e->type == SDL_KEYDOWN;
      if (e->key.keysym.sym == SDLK_LALT) g_live.left_alt_key_down = e->type == SDL_KEYDOWN;
      break;
    }
    case SDL_TEXTINPUT: {
      rfbKeySym sym = utf8_char_to_rfb(e->text.text);
      note_live_view_input();
      if (sym) {
        SendKeyEvent(client, sym, TRUE);
        SendKeyEvent(client, sym, FALSE);
      }
      break;
    }
    case SDL_QUIT:
      g_stop = 1;
      return FALSE;
    default:
      break;
  }
  return TRUE;
}

static void present_live_view(rfbClient *client, int x, int y, int w, int h) {
  SDL_Rect r;
  struct apple_hp_live_view_geometry geom;
  SDL_Surface *sdl;
  if (!g_runtime.live_view || !client || !g_live.texture || !g_live.renderer) return;
  if (w <= 0 || h <= 0) return;
  sdl = (SDL_Surface *)rfbClientGetClientData(client, SDL_Init);
  if (!sdl) return;

  /* Strict bounds check to prevent texture update overflow/crash */
  if (x < 0) { w += x; x = 0; }
  if (y < 0) { h += y; y = 0; }
  if (x >= client->width || y >= client->height) return;
  if (x + w > client->width) w = client->width - x;
  if (y + h > client->height) h = client->height - y;
  if (w <= 0 || h <= 0) return;

  r.x = x;
  r.y = y;
  r.w = w;
  r.h = h;
  if (SDL_UpdateTexture(g_live.texture, &r,
                        (const uint8_t *)sdl->pixels + y * sdl->pitch + x * 4,
                        sdl->pitch) < 0) {
    rfbClientErr("live-view: SDL_UpdateTexture failed: %s\n", SDL_GetError());
    return;
  }
  maybe_update_live_view_crop(client, w, h);
  memset(&geom, 0, sizeof(geom));
  if (!compute_live_view_geometry(client, &geom)) return;
  if (g_live.needs_clear) {
    SDL_SetRenderDrawColor(g_live.renderer, 0, 0, 0, 255);
    if (SDL_RenderClear(g_live.renderer) < 0) {
      rfbClientErr("live-view: SDL_RenderClear failed: %s\n", SDL_GetError());
      return;
    }
    g_live.needs_clear = 0;
  }
  if (SDL_RenderCopy(g_live.renderer, g_live.texture, &geom.src, &geom.dst) < 0) {
    rfbClientErr("live-view: SDL_RenderCopy failed: %s\n", SDL_GetError());
    return;
  }
  render_live_cursor(client);
  SDL_RenderPresent(g_live.renderer);
  g_live.last_present_us = monotonic_us();
  reset_live_view_pending_present();
}
#endif

static int kHighPerfProbeEncodings[] = {0x44f, 0x450, 0x451, 0x453, 0x455, 0x456, 0x3f2, 0};

static const char *apple_hp_rect_encoding_name(int32_t encoding) {
  switch (encoding) {
    case 0x3f2: return "RFBMediaStream";
    case 0x450: return "CursorImage";
    case 0x44f: return "EncodeEncryptionInfo";
    case 0x451: return "AppleDisplayLayout";
    case 0x453: return "VendorKeysymEncoding";
    case 0x455: return "KeyboardInputSource";
    case 0x456: return "DeviceInfo";
    default: return "Unknown";
  }
}

static rfbBool handle_hp_probe_encoding(rfbClient *client, rfbFramebufferUpdateRectHeader *rect) {
  g_live.skip_next_fb_update = 1;
  uint8_t buf[36];
  uint8_t hdr[2];
  uint8_t cursor_hdr[8];
  uint8_t *payload = NULL;
  uint32_t counter;
  uint32_t cursor_cache_id;
  uint32_t cursor_zlib_len;
  uint16_t prev_display_w;
  uint16_t prev_display_h;
  uint16_t prev_backing_w;
  uint16_t prev_backing_h;
  uint16_t scaled_w;
  uint16_t scaled_h;
  uint16_t ui_w;
  uint16_t ui_h;
  uint8_t next_key[16];
  uint8_t next_iv[16];
  uint16_t payload_len;
  uint16_t media_msg_version;
  size_t total_len;
  char label[96];

  if (!client || !rect) return FALSE;
  if ((uint32_t)rect->encoding == 0x44f) {
    const uint8_t *session_key = NULL;
    size_t session_key_len = 0;
    if (!ReadFromRFBServer(client, (char *)buf, sizeof(buf))) return FALSE;

    g_hp.rekey_seen = 1;
    if (!rfbClientGetARDSessionKey(client, &session_key, &session_key_len) || session_key_len < 16) {
      rfbClientErr("apple-hp: no ARD session key available; cannot decrypt 0x44f\n");
      return FALSE;
    }

    counter = read_be_u32(buf);
    if (!aes_ecb_decrypt_block(session_key, buf + 4, next_key)) return FALSE;
    if (!aes_ecb_decrypt_block(session_key, buf + 20, next_iv)) return FALSE;
    if (!send_post_rekey_set_encryption_stage2(client)) return FALSE;
    memset(client->ardSessionKey, 0, sizeof(client->ardSessionKey));
    memcpy(client->ardSessionKey, next_key, 16);
    client->ardSessionKeyLen = 16;
    client->ardSessionKeyReady = TRUE;
    client->suppressNextIncrementalRequest = TRUE;
    if (!apple_hp_enable_transport(client, next_key, next_iv, counter)) return FALSE;
    if (!send_display_configuration_blob(client)) return FALSE;
    if (!send_native_post_auth_encodings(client)) return FALSE;
    g_hp.post_rekey_ready = 1;
    g_hp.post_rekey_server_records = 0;
    g_hp.post_rekey_phase = 0;
    return TRUE;
  }

  if ((uint32_t)rect->encoding == 0x450) {
    if (!ReadFromRFBServer(client, (char *)cursor_hdr, sizeof(cursor_hdr))) return FALSE;
    cursor_cache_id = read_be_u32(cursor_hdr);
    cursor_zlib_len = read_be_u32(cursor_hdr + 4);
    snprintf(label, sizeof(label), "apple-hp rect 0x450 CursorImage cache=%u zlib=%u",
             cursor_cache_id, cursor_zlib_len);
    if (cursor_zlib_len != 0) {
      if (cursor_zlib_len > (16U * 1024U * 1024U)) {
        rfbClientErr("apple-hp: refusing oversized cursor payload %u for cache=%u\n",
                     cursor_zlib_len, cursor_cache_id);
        return FALSE;
      }
      payload = (uint8_t *)malloc(cursor_zlib_len);
      if (!payload) return FALSE;
      if (!ReadFromRFBServer(client, (char *)payload, cursor_zlib_len)) {
        free(payload);
        return FALSE;
      }
      snprintf(label, sizeof(label), "apple-hp rect 0x450 CursorImage payload cache=%u",
               cursor_cache_id);
      apple_hp_store_cursor_image(client, cursor_cache_id, rect->r.x, rect->r.y,
                                  rect->r.w, rect->r.h, payload, cursor_zlib_len);
      free(payload);
    } else {
      if (find_cursor_cache_entry(cursor_cache_id)) {
        g_live.cursor_current_cache_id = cursor_cache_id;
        g_live.cursor_visible = 1;
      } else {
        g_live.cursor_visible = 0;
      }
    }
    return TRUE;
  }

  if ((uint32_t)rect->encoding != 0x3f2 && (uint32_t)rect->encoding != 0x451 &&
      (uint32_t)rect->encoding != 0x453 && (uint32_t)rect->encoding != 0x455 &&
      (uint32_t)rect->encoding != 0x456)
    return FALSE;

  if (!ReadFromRFBServer(client, (char *)hdr, sizeof(hdr))) return FALSE;
  payload_len = read_be_u16(hdr);
  total_len = (size_t)payload_len + sizeof(hdr);
  payload = (uint8_t *)malloc(total_len);
  if (!payload) return FALSE;
  memcpy(payload, hdr, sizeof(hdr));
  if (payload_len != 0 && !ReadFromRFBServer(client, (char *)(payload + sizeof(hdr)), payload_len)) {
    free(payload);
    return FALSE;
  }
  snprintf(label, sizeof(label), "apple-hp rect 0x%03x %s",
           (unsigned)rect->encoding, apple_hp_rect_encoding_name(rect->encoding));
  if ((uint32_t)rect->encoding == 0x3f2 && total_len >= 4) {
    media_msg_version = read_be_u16(payload + 2);
    (void)media_msg_version;
  }
  if ((uint32_t)rect->encoding == 0x451 && total_len >= 12) {
    int first_display_layout = !g_hp.displayinfo2_seen;
    g_hp.displayinfo2_seen = 1;
    prev_display_w = g_hp.display_scaled_w;
    prev_display_h = g_hp.display_scaled_h;
    prev_backing_w = g_hp.layout_scaled_w;
    prev_backing_h = g_hp.layout_scaled_h;
    scaled_w = read_be_u16(payload + 4);
    scaled_h = read_be_u16(payload + 6);
    ui_w = read_be_u16(payload + 8);
    ui_h = read_be_u16(payload + 10);
    if (scaled_w != 0 && scaled_h != 0) {
      g_hp.display_scaled_w = scaled_w;
      g_hp.display_scaled_h = scaled_h;
    }
    if (ui_w != 0 && ui_h != 0) {
      g_hp.layout_scaled_w = ui_w;
      g_hp.layout_scaled_h = ui_h;
    }
    if (client && apple_hp_backing_width(client) != 0 && apple_hp_backing_height(client) != 0 &&
        ((uint32_t)apple_hp_backing_width(client) + kAppleHPFramebufferSlack > (uint32_t)client->width ||
         (uint32_t)apple_hp_backing_height(client) + kAppleHPFramebufferSlack > (uint32_t)client->height)) {
      if (!apple_hp_resize_framebuffer_if_needed(client,
                                                 apple_hp_backing_width(client),
                                                 apple_hp_backing_height(client))) {
        free(payload);
        return FALSE;
      }
    }
    if (client && first_display_layout) {
      uint16_t request_w = apple_hp_request_width(client);
      uint16_t request_h = apple_hp_request_height(client);
      if (!apple_hp_request_full_refresh_now(client, request_w, request_h, "first-display-layout")) {
        free(payload);
        return FALSE;
      }
      g_hp.initial_full_refresh_done = 0;
      g_hp.initial_full_refresh_retries = 0;
    }
    if (client && scaled_w != 0 && scaled_h != 0 &&
        (scaled_w != prev_display_w || scaled_h != prev_display_h ||
         ui_w != prev_backing_w || ui_h != prev_backing_h ||
         g_hp.last_dynamic_request_w == 0 || g_hp.last_dynamic_request_h == 0)) {
      uint16_t request_w = apple_hp_request_width(client);
      uint16_t request_h = apple_hp_request_height(client);
      uint16_t pending_target_w = g_hp.pending_dynamic_target_w;
      uint16_t pending_target_h = g_hp.pending_dynamic_target_h;
      reset_live_view_crop();
      refresh_live_view_layout(client);
      if (g_hp.dynamic_request_in_flight &&
          scaled_w == g_hp.last_dynamic_request_w &&
          scaled_h == g_hp.last_dynamic_request_h) {
        rfbClientLog("apple-hp: confirmed dynamic target %ux%u from AppleDisplayLayout\n",
                     (unsigned)scaled_w, (unsigned)scaled_h);
        apple_hp_clear_dynamic_request_state(FALSE);
        if (pending_target_w != 0 &&
            pending_target_h != 0 &&
            apple_hp_dynamic_target_materially_diff(pending_target_w, pending_target_h,
                                                    scaled_w, scaled_h)) {
          apple_hp_clear_pending_dynamic_target();
          g_live.last_runtime_w = pending_target_w;
          g_live.last_runtime_h = pending_target_h;
          if (!maybe_send_dynamic_resolution_update(client, "layout-confirmed-pending", TRUE)) {
            free(payload);
            return FALSE;
          }
        } else if (!g_hp.dynamic_refresh_queued_for_request) {
          apple_hp_clear_pending_dynamic_target();
          g_hp.pending_refresh_w = request_w;
          g_hp.pending_refresh_h = request_h;
          g_hp.initial_full_refresh_retries = 0;
          g_hp.dynamic_refresh_queued_for_request = 1;
        }
      } else {
        g_hp.pending_refresh_w = request_w;
        g_hp.pending_refresh_h = request_h;
        g_hp.initial_full_refresh_retries = 0;
      }
    }
  }
  free(payload);
  return TRUE;
}

static rfbBool handle_hp_probe_message(rfbClient *client, rfbServerToClientMsg *message) {
  uint8_t payload[7];

  (void)client;
  if (!message) return FALSE;

  if (message->type == 0x14) {
    if (!ReadFromRFBServer(client, (char *)payload, sizeof(payload))) return FALSE;
    return TRUE;
  }
  return FALSE;
}

static rfbClientProtocolExtension kHighPerfProbeExt = {
    kHighPerfProbeEncodings, handle_hp_probe_encoding, handle_hp_probe_message, NULL, NULL, NULL};

static void on_sigint(int sig) {
  (void)sig;
  g_stop = 1;
}

static void configure_auth_schemes(rfbClient *client) {
  const char *env = getenv("VNC_AUTH_SCHEMES");
  if (env && *env) {
    uint32_t auth_schemes[32];
    char *tmp = strdup(env);
    char *tok = NULL;
    char *save = NULL;
    int i = 0;

    if (!tmp) return;
    for (tok = strtok_r(tmp, ",", &save); tok && i < 31;
         tok = strtok_r(NULL, ",", &save)) {
      while (*tok == ' ' || *tok == '\t') tok++;
      if (!*tok) continue;
      auth_schemes[i++] = (uint32_t)strtoul(tok, NULL, 0);
    }
    auth_schemes[i] = 0;
    if (i > 0) {
      SetClientAuthSchemes(client, auth_schemes, -1);
      rfbClientLog("using VNC_AUTH_SCHEMES='%s'\n", env);
      free(tmp);
      return;
    }
    free(tmp);
  }

  /* Default preference order for ARD servers: strongest Apple auth first.
   * Kerberos (35) requires either an explicit realm or a fully-qualified principal. */
  {
    uint32_t auth_schemes[6];
    int i = 0;
    const char *realm = apple_hp_getenv_first("VNC_APPLE_KRB_REALM", "LIBVNCCLIENT_APPLE_KRB_REALM");
    const char *principal = apple_hp_getenv_first("VNC_APPLE_KRB_CLIENT_PRINCIPAL",
                                                  "LIBVNCCLIENT_APPLE_KRB_CLIENT_PRINCIPAL");
    const char *user = getenv("VNC_USER");
    int kerb_ready = 0;

    if ((realm && *realm) || (principal && *principal) || (user && strchr(user, '@'))) kerb_ready = 1;
    if (kerb_ready) auth_schemes[i++] = rfbAppleAuthKerberos;
    auth_schemes[i++] = rfbAppleAuthDirectSrp;
    auth_schemes[i++] = rfbAppleAuthRSA_SRP;
    auth_schemes[i++] = rfbARD;
    auth_schemes[i] = 0;
    SetClientAuthSchemes(client, auth_schemes, -1);
  }
}

static rfbCredential *get_credential(rfbClient *client, int credentialType) {
  (void)client;
  rfbCredential *c = calloc(1, sizeof(*c));
  if (!c) return NULL;

  if (credentialType == rfbCredentialTypeUser) {
    const char *user = getenv("VNC_USER");
    const char *pass = getenv("VNC_PASS");
    char user_buf[512];
    char pass_buf[512];

    if (!user) {
      fprintf(stderr, "VNC username: ");
      if (!fgets(user_buf, sizeof(user_buf), stdin)) {
        free(c);
        return NULL;
      }
      user_buf[strcspn(user_buf, "\n")] = '\0';
      user = user_buf;
    }

    if (!pass) {
      fprintf(stderr, "VNC password: ");
      if (!fgets(pass_buf, sizeof(pass_buf), stdin)) {
        free(c);
        return NULL;
      }
      pass_buf[strcspn(pass_buf, "\n")] = '\0';
      pass = pass_buf;
    }

    c->userCredential.username = strdup(user);
    c->userCredential.password = strdup(pass);
    if (!c->userCredential.username || !c->userCredential.password) {
      free(c->userCredential.username);
      free(c->userCredential.password);
      free(c);
      return NULL;
    }
    return c;
  }

  /* Keep X509 empty so system CAs are used; caller can extend if needed. */
  if (credentialType == rfbCredentialTypeX509) return c;

  free(c);
  return NULL;
}

static rfbBool malloc_fb(rfbClient *client) {
#if defined(APPLEHPDEBUG_HAS_SDL)
  if (g_runtime.live_view) return alloc_live_fb(client);
#endif
  size_t size = (size_t)client->width * (size_t)client->height *
                (size_t)(client->format.bitsPerPixel / 8);
  free(client->frameBuffer);
  client->frameBuffer = (uint8_t *)malloc(size);
  if (!client->frameBuffer) {
    rfbClientErr("malloc framebuffer failed (%zu bytes)\n", size);
    return FALSE;
  }
  memset(client->frameBuffer, 0, size);
  rfbClientLog("framebuffer allocated: %dx%d bpp=%d (%zu bytes)\n",
               client->width, client->height, client->format.bitsPerPixel, size);
  return TRUE;
}

static void on_fb_update(rfbClient *client, int x, int y, int w, int h) {
  if (g_live.skip_next_fb_update) {
    g_live.skip_next_fb_update = 0;
    return;
  }
  if (!client || w <= 0 || h <= 0) return;

  /* Safety: clamp and validate coordinates against actual allocated dimensions */
  if (x < 0) { w += x; x = 0; }
  if (y < 0) { h += y; y = 0; }
  if (x >= client->width || y >= client->height) return;
  if (x + w > client->width) w = client->width - x;
  if (y + h > client->height) h = client->height - y;
  if (w <= 0 || h <= 0) return;

  unsigned long long px = 0;
  unsigned long long bytes = 0;
  int bpp = client ? client->format.bitsPerPixel : 0;
  if (w > 0 && h > 0) px = (unsigned long long)w * (unsigned long long)h;
  if (bpp > 0) bytes = px * (unsigned long long)bpp / 8ULL;
  g_frame.rects++;
  g_frame.frame_pixels += px;
  g_frame.pixels += px;
  g_frame.bytes_est += bytes;
  if (client && apple_hp_should_suppress_incremental()) {
    /* Native HP sessions transition to auto-update; suppress libvncclient's
     * default incremental polling after each completed framebuffer update. */
    client->suppressNextIncrementalRequest = TRUE;
  }
#if defined(APPLEHPDEBUG_HAS_SDL)
  if (g_runtime.live_view && g_runtime.apple_hp_mode && !g_hp.displayinfo2_seen) {
    return;
  }
  if (g_runtime.live_view) {
    queue_live_view_present(x, y, w, h);
    if (g_live.present_per_rect) present_live_view(client, x, y, w, h);
  }
#endif
}

static void on_fb_update_done(rfbClient *client) {
  long long now_ms = monotonic_ms();
  uint16_t repaint_w = 0;
  uint16_t repaint_h = 0;
  g_frame.frames++;
  if (g_frame.first_frame_ms == 0) g_frame.first_frame_ms = now_ms;
  g_frame.last_frame_ms = now_ms;

  if (client && g_runtime.apple_hp_mode) {
    repaint_w = apple_hp_backing_width(client);
    repaint_h = apple_hp_backing_height(client);
  } else if (client) {
    repaint_w = apple_hp_content_width(client);
    repaint_h = apple_hp_content_height(client);
  }

  if (!g_hp.initial_full_refresh_done && g_hp.displayinfo2_seen && client &&
      repaint_w > 0 && repaint_h > 0) {
    unsigned long long screen_px =
        (unsigned long long)repaint_w *
        (unsigned long long)repaint_h;
    if (g_frame.frame_pixels >= screen_px / 4ULL) {
      g_hp.initial_full_refresh_done = 1;
      g_hp.initial_full_refresh_retries = 0;
      rfbClientLog("apple-hp: initial repaint satisfied frame_pixels=%llu threshold=%llu\n",
                   g_frame.frame_pixels, screen_px / 4ULL);
    }
  }

#if defined(APPLEHPDEBUG_HAS_SDL)
  if (g_runtime.live_view) maybe_present_live_view_if_due(client, FALSE);
#endif

  g_frame.frame_pixels = 0;
}

static int apple_hp_maybe_retry_initial_full_refresh(rfbClient *client) {
  if (!g_runtime.apple_hp_mode || !client) return 1;
  if (g_hp.initial_full_refresh_done || g_hp.initial_full_refresh_retries <= 0) return 1;
  if (client->width <= 0 || client->height <= 0) return 1;

  if (!SendFramebufferUpdateRequest(client, 0, 0,
                                    apple_hp_request_width(client),
                                    apple_hp_request_height(client), FALSE)) return 0;
  if (apple_hp_should_suppress_incremental()) client->suppressNextIncrementalRequest = TRUE;
  g_hp.initial_full_refresh_retries--;
  rfbClientLog("apple-hp: retrying initial full refresh %ux%u remaining=%d\n",
               (unsigned)apple_hp_request_width(client),
               (unsigned)apple_hp_request_height(client),
               g_hp.initial_full_refresh_retries);
  return 1;
}

static int apple_hp_request_full_refresh_now(rfbClient *client, uint16_t w, uint16_t h,
                                             const char *reason) {
  if (!g_runtime.apple_hp_mode || !client) return 1;
  if (w == 0 || h == 0) return 1;
  if (g_hp.auto_fbu_active && !send_auto_framebuffer_update(client, w, h)) return 0;
  if (!SendFramebufferUpdateRequest(client, 0, 0, w, h, FALSE)) return 0;
  if (apple_hp_should_suppress_incremental()) client->suppressNextIncrementalRequest = TRUE;
  rfbClientLog("apple-hp: requested full refresh %ux%u (%s)\n",
               (unsigned)w, (unsigned)h, reason ? reason : "unspecified");
  return 1;
}

static int apple_hp_maybe_request_pending_region_refresh(rfbClient *client) {
  uint16_t w = g_hp.pending_refresh_w;
  uint16_t h = g_hp.pending_refresh_h;

  if (!g_runtime.apple_hp_mode || !client) return 1;
  if (w == 0 || h == 0) return 1;

  g_hp.pending_refresh_w = 0;
  g_hp.pending_refresh_h = 0;
  return apple_hp_request_full_refresh_now(client, w, h, "AppleDisplayLayout");
}

static void on_cut_text(rfbClient *client, const char *text, int textlen) {
  (void)client;
  (void)text;
  (void)textlen;
}

static void on_cursor_shape(rfbClient *client, int xhot, int yhot, int width,
                            int height, int bytesPerPixel) {
  (void)client;
  (void)xhot;
  (void)yhot;
  (void)width;
  (void)height;
  (void)bytesPerPixel;
}

int main(int argc, char **argv) {
  rfbClient *client;
  time_t start;
  int seconds = 120;
  int port = 5900;
  char hostspec[1024];
  const char *host = NULL;

  if (argc < 2) {
    fprintf(stderr, "usage: %s <host> [port] [seconds]\n", argv[0]);
    return 2;
  }

  signal(SIGINT, on_sigint);
  g_runtime.live_view = env_flag_enabled("VNC_LIVE_VIEW");
  g_runtime.live_view_vsync = env_flag_enabled("VNC_LIVE_VIEW_VSYNC");
  g_runtime.low_latency_input = env_flag_default_true("VNC_LIVE_VIEW_LOW_LATENCY_INPUT");
  g_runtime.log_input = env_flag_enabled("VNC_LOG_INPUT");
  g_runtime.apple_hp_mode = env_flag_enabled("VNC_APPLE_HP");

#if defined(APPLEHPDEBUG_HAS_SDL)
  if (g_runtime.live_view) {
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_NOPARACHUTE) != 0) {
      fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
      return 1;
    }
    SDL_StartTextInput();
    atexit(SDL_Quit);
  }
#else
  if (g_runtime.live_view) {
    fprintf(stderr, "VNC_LIVE_VIEW requested, but SDL headers were not available at build time\n");
    return 1;
  }
#endif

  client = rfbGetClient(8, 3, 4);
  if (!client) {
    fprintf(stderr, "rfbGetClient failed\n");
    return 1;
  }

  client->MallocFrameBuffer = malloc_fb;
  client->canHandleNewFBSize = TRUE;
  client->GotFrameBufferUpdate = on_fb_update;
  client->FinishedFrameBufferUpdate = on_fb_update_done;
  client->GotXCutText = on_cut_text;
  client->GotCursorShape = on_cursor_shape;
  client->GetCredential = get_credential;
  rfbClientRegisterExtension(&kHighPerfProbeExt);
  if (!configure_apple_hp_mode(client)) return 1;

  configure_auth_schemes(client);

  host = argv[1];
  if (argc >= 3) {
    port = atoi(argv[2]);
    if (port <= 0) port = 5900;
  }
  if (argc >= 4) {
    seconds = atoi(argv[3]);
    if (seconds <= 0) seconds = 120;
  }

  apple_hp_seed_known_auth35_realm(host);

  /* libvncclient expects a single host[:port] positional target. */
  if (argc >= 3) {
    if (strchr(host, ':') && host[0] != '[') {
      snprintf(hostspec, sizeof(hostspec), "[%s]:%d", host, port);
    } else {
      snprintf(hostspec, sizeof(hostspec), "%s:%d", host, port);
    }
    argv[1] = hostspec;
    argc = 2;
  }

  if (!getenv("VNC_ENCODINGS")) {
    client->appData.encodingsString =
        "copyrect tight zrle hextile zlib corre rre raw";
  } else {
    client->appData.encodingsString = getenv("VNC_ENCODINGS");
  }

  if (!rfbInitClient(client, &argc, argv)) {
    return 1;
  }

  rfbClientLog("connected host=%s port=%d desktop='%s'\n",
               client->serverHost ? client->serverHost : "(null)",
               client->serverPort,
               client->desktopName ? client->desktopName : "(null)");
  rfbClientLog("encodings='%s'\n",
               client->appData.encodingsString ? client->appData.encodingsString : "(null)");

  if (!run_apple_hp_setup(client)) {
    rfbClientErr("apple-hp: setup failed\n");
    rfbClientCleanup(client);
#if defined(APPLEHPDEBUG_HAS_SDL)
    destroy_live_view();
#endif
    return 1;
  }

  start = time(NULL);
  while (!g_stop && (time(NULL) - start) < seconds) {
#if defined(APPLEHPDEBUG_HAS_SDL)
    if (g_runtime.live_view) {
      SDL_Event e;
      while (SDL_PollEvent(&e)) {
        if (!handle_live_view_event(client, &e)) break;
      }
    if (g_live.pending_dynamic_resize) {
        if (apple_hp_dynamic_resize_ready(client)) {
          if (!maybe_send_dynamic_resolution_update(client, "window-event", FALSE)) break;
          g_live.pending_dynamic_resize = 0;
        }
      }
    }
#endif
    int n = 0;
    n = WaitForMessage(client, main_loop_wait_usecs());
    if (n < 0) break;
    if (n > 0) {
      if (!HandleRFBServerMessage(client)) break;
    }
    if (n == 0 && g_hp.post_rekey_ready == 2 && g_hp.post_rekey_server_records > 1 &&
        g_hp.post_rekey_phase == 0 && !g_hp.post_rekey_sent) {
      if (!apple_hp_send_post_rekey_setup(client)) break;
    }
    if (n == 0 && g_hp.post_rekey_ready == 2 && g_hp.post_rekey_server_records > 2 &&
        g_hp.post_rekey_phase == 1 && !g_hp.post_rekey_sent) {
      if (!apple_hp_send_post_rekey_setup(client)) break;
    }
    if (n == 0 && g_hp.post_rekey_ready == 2 && g_hp.post_rekey_phase == 2 &&
        !g_hp.post_rekey_sent) {
      if (!apple_hp_send_post_rekey_setup(client)) break;
      g_hp.post_rekey_ready = 0;
    }
    if (n == 0 && !apple_hp_maybe_handle_dynamic_request_timeout(client)) break;
    if (n == 0 && !apple_hp_maybe_request_pending_region_refresh(client)) break;
    if (n == 0 && !apple_hp_maybe_retry_initial_full_refresh(client)) break;
#if defined(APPLEHPDEBUG_HAS_SDL)
    if (g_runtime.live_view && !maybe_present_live_view_if_due(client, FALSE)) break;
#endif
  }

  rfbClientCleanup(client);
#if defined(APPLEHPDEBUG_HAS_SDL)
  destroy_live_view();
#endif
  return 0;
}
