#include <rfb/rfbclient.h>

#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <CommonCrypto/CommonRandom.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif

#if defined(__has_include)
#if __has_include(<openssl/bn.h>)
#include <openssl/bn.h>
#define LIBVNCCLIENT_APPLE_HAS_OPENSSL_BN 1
#endif
#endif

#include "apple.h"

static void write_be_u16(uint8_t *out, uint16_t value)
{
  out[0] = (uint8_t)((value >> 8) & 0xff);
  out[1] = (uint8_t)(value & 0xff);
}

static void write_be_u32(uint8_t *out, uint32_t value)
{
  out[0] = (uint8_t)((value >> 24) & 0xff);
  out[1] = (uint8_t)((value >> 16) & 0xff);
  out[2] = (uint8_t)((value >> 8) & 0xff);
  out[3] = (uint8_t)(value & 0xff);
}

static uint16_t read_be_u16(const uint8_t *p)
{
  return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t read_be_u32(const uint8_t *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
         (uint32_t)p[3];
}

static uint64_t read_be_u64(const uint8_t *p)
{
  return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) |
         ((uint64_t)p[3] << 32) | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
         ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

void rfbClientResetAppleAuth(rfbClient* client)
{
  if (!client) return;

  client->appleAuthType = 0;
  client->appleSessionKeyReady = FALSE;
  client->appleSessionKeyLen = 0;
  memset(client->appleSessionKey, 0, sizeof(client->appleSessionKey));
}

void rfbClientEnableAppleHighPerf(rfbClient* client, rfbBool enable)
{
  if (!client) return;
  client->enableAppleHighPerf = enable;
}

rfbBool rfbClientGetAppleSessionKey(const rfbClient* client, const uint8_t **key, size_t *len)
{
  if (!client || !client->appleSessionKeyReady) return FALSE;
  if (key) *key = client->appleSessionKey;
  if (len) *len = client->appleSessionKeyLen;
  return TRUE;
}

static void FreeAppleUserCredential(rfbCredential *cred)
{
  if (!cred) return;
  free(cred->userCredential.username);
  free(cred->userCredential.password);
  free(cred);
}

static rfbBool read_length_prefixed_blob(rfbClient *client, uint8_t **outbuf,
                                         uint32_t *outlen, const char *what)
{
  uint8_t inhdr[4];
  uint8_t *buf = NULL;
  uint32_t n = 0;

  if (!outbuf || !outlen) return FALSE;
  *outbuf = NULL;
  *outlen = 0;
  if (!ReadFromRFBServer(client, (char *)inhdr, 4)) {
    rfbClientErr("apple auth: failed reading %s length\n", what);
    return FALSE;
  }
  n = read_be_u32(inhdr);
  if (n == 0 || n > (1u << 20)) {
    rfbClientErr("apple auth: suspicious %s length=%u\n", what, (unsigned)n);
    return FALSE;
  }
  buf = (uint8_t *)malloc(n);
  if (!buf) return FALSE;
  if (!ReadFromRFBServer(client, (char *)buf, n)) {
    free(buf);
    return FALSE;
  }
  *outbuf = buf;
  *outlen = n;
  return TRUE;
}

static rfbBool maybe_consume_auth33_server_final(rfbClient *client)
{
  uint8_t hdr[4];
  uint32_t n = 0;
  uint8_t *buf = NULL;
  int wm = WaitForMessage(client, 1500000);
  ssize_t r;

  if (wm <= 0) return TRUE;
  r = recv(client->sock, (char *)hdr, sizeof(hdr), MSG_PEEK);
  if (r < 4) return TRUE;
  n = read_be_u32(hdr);
  if (n < 16 || n > 4096) return TRUE;
  if (!ReadFromRFBServer(client, (char *)hdr, 4)) return FALSE;
  buf = (uint8_t *)malloc(n);
  if (!buf) return FALSE;
  if (!ReadFromRFBServer(client, (char *)buf, n)) {
    free(buf);
    return FALSE;
  }
  free(buf);
  return TRUE;
}

struct auth33_challenge_fields {
  uint8_t cflag;
  const uint8_t *N;
  size_t N_len;
  const uint8_t *g;
  size_t g_len;
  const uint8_t *salt;
  size_t salt_len;
  const uint8_t *B;
  size_t B_len;
  uint64_t iterations;
  const uint8_t *options;
  size_t options_len;
};

static int auth33_parse_challenge_fields(const uint8_t *buf, size_t n,
                                         struct auth33_challenge_fields *out)
{
  size_t off = 10;
  uint16_t field_len;

  if (!buf || !out || n < 11) return 0;
  memset(out, 0, sizeof(*out));
  if (off + 1 > n) return 0;
  out->cflag = buf[off++];
  if (off + 2 > n) return 0;
  field_len = read_be_u16(buf + off);
  off += 2;
  if (off + field_len > n) return 0;
  out->N = buf + off;
  out->N_len = field_len;
  off += field_len;
  if (off + 2 > n) return 0;
  field_len = read_be_u16(buf + off);
  off += 2;
  if (off + field_len > n) return 0;
  out->g = buf + off;
  out->g_len = field_len;
  off += field_len;
  if (off + 1 > n) return 0;
  field_len = buf[off++];
  if (off + field_len > n) return 0;
  out->salt = buf + off;
  out->salt_len = field_len;
  off += field_len;
  if (off + 2 > n) return 0;
  field_len = read_be_u16(buf + off);
  off += 2;
  if (off + field_len > n) return 0;
  out->B = buf + off;
  out->B_len = field_len;
  off += field_len;
  if (off + 8 > n) return 0;
  out->iterations = read_be_u64(buf + off);
  off += 8;
  if (off + 2 > n) return 0;
  field_len = read_be_u16(buf + off);
  off += 2;
  if (off + field_len > n) return 0;
  out->options = buf + off;
  out->options_len = field_len;
  return 1;
}

#if defined(__APPLE__)
static int auth33_sha512_parts(uint8_t out[CC_SHA512_DIGEST_LENGTH], const void **parts,
                               const size_t *part_lens, size_t part_count)
{
  CC_SHA512_CTX ctx;
  size_t i;

  if (!out) return 0;
  CC_SHA512_Init(&ctx);
  for (i = 0; i < part_count; ++i) {
    if (parts[i] && part_lens[i] != 0) CC_SHA512_Update(&ctx, parts[i], (CC_LONG)part_lens[i]);
  }
  CC_SHA512_Final(out, &ctx);
  return 1;
}

static int auth33_sha512_2(uint8_t out[CC_SHA512_DIGEST_LENGTH], const void *a, size_t a_len,
                           const void *b, size_t b_len)
{
  const void *parts[2] = {a, b};
  const size_t lens[2] = {a_len, b_len};
  return auth33_sha512_parts(out, parts, lens, 2);
}

static int auth33_pbkdf2_sha512(const uint8_t *password, size_t password_len, const uint8_t *salt,
                                size_t salt_len, uint32_t rounds, uint8_t *out, size_t out_len)
{
  if (!password || !salt || !out || out_len == 0) return 0;
  return CCKeyDerivationPBKDF(kCCPBKDF2, (const char *)password, password_len, salt, salt_len,
                              kCCPRFHmacAlgSHA512, rounds ? rounds : 1, out, out_len) == kCCSuccess;
}

static uint8_t *auth33_utf16_bytes(const char *s, int big_endian, size_t *out_len)
{
  size_t i;
  size_t in_len;
  uint8_t *out;

  if (!s || !out_len) return NULL;
  in_len = strlen(s);
  out = (uint8_t *)malloc(in_len * 2);
  if (!out) return NULL;
  for (i = 0; i < in_len; ++i) {
    if (big_endian) {
      out[i * 2] = 0;
      out[i * 2 + 1] = (uint8_t)s[i];
    } else {
      out[i * 2] = (uint8_t)s[i];
      out[i * 2 + 1] = 0;
    }
  }
  *out_len = in_len * 2;
  return out;
}

static void release_cfref(CFTypeRef ref)
{
  if (ref) CFRelease(ref);
}
#endif

#if defined(__APPLE__) && defined(LIBVNCCLIENT_APPLE_HAS_OPENSSL_BN)
static int auth33_bn_to_pad(const BIGNUM *bn, uint8_t *out, size_t out_len)
{
  if (!bn || !out || out_len == 0) return 0;
  return BN_bn2binpad(bn, out, (int)out_len) == (int)out_len;
}

static int auth33_random_bigint(BIGNUM *out, int bits)
{
  int byte_len;
  uint8_t *buf;

  if (!out) return 0;
  if (bits < 64) bits = 64;
  byte_len = (bits + 7) / 8;
  buf = (uint8_t *)malloc((size_t)byte_len);
  if (!buf) return 0;
  if (CCRandomGenerateBytes(buf, (size_t)byte_len) != kCCSuccess) {
    free(buf);
    return 0;
  }
  if (bits % 8) buf[0] &= (uint8_t)((1u << (bits % 8)) - 1u);
  if (BN_bin2bn(buf, byte_len, out) == NULL) {
    free(buf);
    return 0;
  }
  free(buf);
  return 1;
}
#endif

static int build_auth33_rsa1_key_request_packet(uint8_t *out, size_t out_len, uint16_t packet_version)
{
  if (!out || out_len < 14) return 0;
  memset(out, 0, 14);
  write_be_u32(out, 10);
  write_be_u16(out + 4, packet_version);
  memcpy(out + 6, "RSA1", 4);
  return 1;
}

static int build_auth33_rsa1_init_packet(uint8_t *out, size_t out_len, uint16_t packet_version,
                                         uint16_t auth_type, uint16_t aux_type,
                                         const uint8_t *key_material, size_t key_material_len)
{
  if (!out || !key_material || out_len < 654 || key_material_len != 256) return 0;
  memset(out, 0, 654);
  write_be_u32(out, 650);
  write_be_u16(out + 4, packet_version);
  memcpy(out + 6, "RSA1", 4);
  write_be_u16(out + 10, auth_type);
  write_be_u16(out + 12, aux_type);
  memcpy(out + 14, key_material, key_material_len);
  return 1;
}

static int build_auth33_init_plaintext(const char *username, uint8_t *out, size_t out_len,
                                       size_t *plaintext_len)
{
  size_t user_len;
  size_t total_plain_len;
  uint8_t *p;

  if (!username || !out || !plaintext_len) return 0;
  user_len = strlen(username);
  if (user_len > 0xffffu) return 0;
  total_plain_len = 11 + user_len;
  if (out_len < total_plain_len) return 0;
  memset(out, 0, out_len);
  write_be_u32(out, (uint32_t)(total_plain_len - 4));
  write_be_u16(out + 4, 0);
  write_be_u16(out + 6, (uint16_t)user_len);
  memcpy(out + 8, username, user_len);
  p = out + 8 + user_len;
  write_be_u16(p, 0);
  p += 2;
  *p = 0;
  *plaintext_len = total_plain_len;
  return 1;
}

#if defined(__APPLE__)
static rfbBool build_auth33_init_key_material(const char *username, const uint8_t *type0_reply,
                                              uint32_t type0_reply_len, uint8_t *outbuf,
                                              size_t outcap, size_t *outlen)
{
  uint32_t der_len;
  uint8_t plaintext[512];
  size_t plaintext_len = 0;
  const uint8_t *der;
  CFDataRef der_data = NULL;
  CFDataRef plain_data = NULL;
  CFDataRef cipher_data = NULL;
  CFDictionaryRef attrs = NULL;
  CFNumberRef key_bits = NULL;
  SecKeyRef key = NULL;
  CFErrorRef error = NULL;
  int bits = 2048;
  const void *keys[3];
  const void *values[3];

  if (!username || !type0_reply || type0_reply_len < 6 || !outbuf || !outlen) return FALSE;
  der_len = read_be_u32(type0_reply + 2);
  if (6u + der_len > type0_reply_len) return FALSE;
  der = type0_reply + 6;
  if (!build_auth33_init_plaintext(username, plaintext, sizeof(plaintext), &plaintext_len)) return FALSE;

  der_data = CFDataCreate(kCFAllocatorDefault, der, (CFIndex)der_len);
  plain_data = CFDataCreate(kCFAllocatorDefault, plaintext, (CFIndex)plaintext_len);
  key_bits = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);
  keys[0] = kSecAttrKeyType;
  values[0] = kSecAttrKeyTypeRSA;
  keys[1] = kSecAttrKeyClass;
  values[1] = kSecAttrKeyClassPublic;
  keys[2] = kSecAttrKeySizeInBits;
  values[2] = key_bits;
  attrs = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 3, &kCFTypeDictionaryKeyCallBacks,
                             &kCFTypeDictionaryValueCallBacks);
  if (!der_data || !plain_data || !key_bits || !attrs) goto fail;

  key = SecKeyCreateWithData(der_data, attrs, &error);
  if (!key) goto fail;
  if (!SecKeyIsAlgorithmSupported(key, kSecKeyOperationTypeEncrypt,
                                  kSecKeyAlgorithmRSAEncryptionPKCS1)) {
    goto fail;
  }
  cipher_data = SecKeyCreateEncryptedData(key, kSecKeyAlgorithmRSAEncryptionPKCS1, plain_data,
                                          &error);
  if (!cipher_data) goto fail;

  *outlen = (size_t)CFDataGetLength(cipher_data);
  if (*outlen != 256 || *outlen > outcap) goto fail;
  memcpy(outbuf, CFDataGetBytePtr(cipher_data), *outlen);

  release_cfref(cipher_data);
  release_cfref(key);
  release_cfref(attrs);
  release_cfref(key_bits);
  release_cfref(plain_data);
  release_cfref(der_data);
  release_cfref(error);
  return TRUE;

fail:
  release_cfref(cipher_data);
  release_cfref(key);
  release_cfref(attrs);
  release_cfref(key_bits);
  release_cfref(plain_data);
  release_cfref(der_data);
  release_cfref(error);
  return FALSE;
}
#else
static rfbBool build_auth33_init_key_material(const char *username, const uint8_t *type0_reply,
                                              uint32_t type0_reply_len, uint8_t *outbuf,
                                              size_t outcap, size_t *outlen)
{
  (void)username;
  (void)type0_reply;
  (void)type0_reply_len;
  (void)outbuf;
  (void)outcap;
  (void)outlen;
  return FALSE;
}
#endif

static int auth33_build_packet2_candidate(rfbClient *client, const char *password,
                                          const uint8_t *challenge, uint32_t challenge_len,
                                          uint8_t *outbuf, size_t outcap, size_t *outlen)
{
#if !defined(__APPLE__) || !defined(LIBVNCCLIENT_APPLE_HAS_OPENSSL_BN)
  (void)client;
  (void)password;
  (void)challenge;
  (void)challenge_len;
  (void)outbuf;
  (void)outcap;
  (void)outlen;
  return FALSE;
#else
  static const uint8_t empty_user_hash[CC_SHA512_DIGEST_LENGTH] = {
      0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28,
      0x50, 0xd6, 0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57,
      0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47,
      0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2,
      0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a,
      0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e};
  struct auth33_challenge_fields parsed;
  BIGNUM *N = NULL;
  BIGNUM *g = NULL;
  BIGNUM *B = NULL;
  BIGNUM *a = NULL;
  BIGNUM *A = NULL;
  BIGNUM *x = NULL;
  BIGNUM *v = NULL;
  BIGNUM *k = NULL;
  BIGNUM *u = NULL;
  BIGNUM *ux = NULL;
  BIGNUM *exp = NULL;
  BIGNUM *tmp = NULL;
  BIGNUM *base = NULL;
  BIGNUM *S = NULL;
  BN_CTX *bn_ctx = NULL;
  uint8_t *Np = NULL;
  uint8_t *gp = NULL;
  uint8_t *Ap = NULL;
  uint8_t *Bp = NULL;
  uint8_t *K = NULL;
  uint8_t *nonce16 = NULL;
  uint8_t *inner = NULL;
  uint8_t *wrapped = NULL;
  uint8_t *pbkdf2_pass = NULL;
  uint8_t *pw_utf16le = NULL;
  uint8_t *pw_utf16be = NULL;
  uint8_t *x_bytes = NULL;
  uint8_t *Sp = NULL;
  uint8_t hN[CC_SHA512_DIGEST_LENGTH];
  uint8_t hg[CC_SHA512_DIGEST_LENGTH];
  uint8_t hu[CC_SHA512_DIGEST_LENGTH];
  uint8_t xor_ng[CC_SHA512_DIGEST_LENGTH];
  uint8_t m1[CC_SHA512_DIGEST_LENGTH];
  uint8_t digest[CC_SHA512_DIGEST_LENGTH];
  uint8_t digest2[CC_SHA512_DIGEST_LENGTH];
  size_t pad_len;
  size_t password_len;
  size_t x_len;
  size_t opt_len;
  size_t inner_len;
  size_t wrapped_len;
  size_t wrapped_body_len;
  size_t k_len;
  int ok = FALSE;

  (void)pw_utf16le;
  (void)pw_utf16be;
  if (!client || !password || !*password || !challenge || !challenge_len || !outbuf || !outlen) return FALSE;
  if (!auth33_parse_challenge_fields(challenge, challenge_len, &parsed)) return FALSE;
  password_len = strlen(password);
  pad_len = parsed.N_len;
  N = BN_bin2bn(parsed.N, (int)parsed.N_len, NULL);
  g = BN_bin2bn(parsed.g, (int)parsed.g_len, NULL);
  B = BN_bin2bn(parsed.B, (int)parsed.B_len, NULL);
  a = BN_new();
  A = BN_new();
  x = BN_new();
  v = BN_new();
  k = BN_new();
  u = BN_new();
  ux = BN_new();
  exp = BN_new();
  tmp = BN_new();
  base = BN_new();
  S = BN_new();
  bn_ctx = BN_CTX_new();
  Np = (uint8_t *)malloc(pad_len);
  gp = (uint8_t *)malloc(pad_len);
  Ap = (uint8_t *)malloc(pad_len);
  Bp = (uint8_t *)malloc(pad_len);
  if (!N || !g || !B || !a || !A || !x || !v || !k || !u || !ux || !exp || !tmp || !base || !S ||
      !bn_ctx || !Np || !gp || !Ap || !Bp) goto done;
  if (!auth33_random_bigint(a, 512) || !BN_mod_exp(A, g, a, N, bn_ctx) ||
      !auth33_bn_to_pad(N, Np, pad_len) || !auth33_bn_to_pad(g, gp, pad_len) ||
      !auth33_bn_to_pad(B, Bp, pad_len) || !auth33_bn_to_pad(A, Ap, pad_len)) {
    goto done;
  }

  pbkdf2_pass = (uint8_t *)malloc(128);
  if (!pbkdf2_pass) goto done;
  if (!auth33_pbkdf2_sha512((const uint8_t *)password, password_len, parsed.salt, parsed.salt_len,
                            (uint32_t)parsed.iterations, pbkdf2_pass, 128)) {
    goto done;
  }
  pw_utf16le = auth33_utf16_bytes(password, 0, &x_len);
  pw_utf16be = auth33_utf16_bytes(password, 1, &x_len);
  free(pw_utf16le);
  free(pw_utf16be);
  {
    const void *parts[2] = {":", pbkdf2_pass};
    const size_t lens[2] = {1, 128};
    auth33_sha512_parts(digest, parts, lens, 2);
  }
  {
    const void *parts[2] = {parsed.salt, digest};
    const size_t lens[2] = {parsed.salt_len, sizeof(digest)};
    auth33_sha512_parts(digest2, parts, lens, 2);
  }
  x_len = sizeof(digest2);
  x_bytes = (uint8_t *)malloc(x_len);
  if (!x_bytes) goto done;
  memcpy(x_bytes, digest2, x_len);
  if (!BN_bin2bn(x_bytes, (int)x_len, x)) goto done;

  auth33_sha512_2(digest, Np, pad_len, gp, pad_len);
  if (!BN_bin2bn(digest, sizeof(digest), k)) goto done;

  auth33_sha512_2(digest, Ap, pad_len, Bp, pad_len);
  if (!BN_bin2bn(digest, sizeof(digest), u)) goto done;
  if (!BN_mod_exp(v, g, x, N, bn_ctx) || !BN_mod_mul(tmp, k, v, N, bn_ctx) ||
      !BN_mod_sub(base, B, tmp, N, bn_ctx) || !BN_mul(ux, u, x, bn_ctx) ||
      !BN_add(exp, a, ux) || !BN_mod_exp(S, base, exp, N, bn_ctx)) goto done;

  Sp = (uint8_t *)malloc(pad_len);
  if (!Sp || !auth33_bn_to_pad(S, Sp, pad_len)) goto done;
  auth33_sha512_2(digest, Sp, pad_len, NULL, 0);
  K = (uint8_t *)malloc(sizeof(digest));
  if (!K) goto done;
  memcpy(K, digest, sizeof(digest));
  k_len = sizeof(digest);
  auth33_sha512_2(hN, Np, pad_len, NULL, 0);
  auth33_sha512_2(hg, gp, pad_len, NULL, 0);
  memcpy(hu, empty_user_hash, sizeof(hu));
  {
    size_t i;
    for (i = 0; i < sizeof(xor_ng); ++i) xor_ng[i] = hN[i] ^ hg[i];
  }
  {
    const void *parts[6] = {xor_ng, hu, parsed.salt, Ap, Bp, K};
    const size_t lens[6] = {sizeof(xor_ng), sizeof(hu), parsed.salt_len, pad_len, pad_len, k_len};
    auth33_sha512_parts(m1, parts, lens, 6);
  }

  opt_len = parsed.options_len;
  nonce16 = (uint8_t *)malloc(16);
  inner_len = 2 + pad_len + 1 + sizeof(m1) + 2 + opt_len + 1 + 16;
  wrapped_body_len = 4 + inner_len;
  wrapped_len = wrapped_body_len + 384;
  inner = (uint8_t *)malloc(inner_len);
  wrapped = (uint8_t *)calloc(1, wrapped_len);
  if (!nonce16 || !inner || !wrapped) goto done;
  if (CCRandomGenerateBytes(nonce16, 16) != kCCSuccess) goto done;
  {
    size_t off = 0;
    write_be_u16(inner + off, (uint16_t)pad_len);
    off += 2;
    memcpy(inner + off, Ap, pad_len);
    off += pad_len;
    inner[off++] = (uint8_t)sizeof(m1);
    memcpy(inner + off, m1, sizeof(m1));
    off += sizeof(m1);
    write_be_u16(inner + off, (uint16_t)opt_len);
    off += 2;
    memcpy(inner + off, parsed.options, opt_len);
    off += opt_len;
    inner[off++] = 16;
    memcpy(inner + off, nonce16, 16);
  }
  write_be_u16(wrapped + 0, 0);
  write_be_u16(wrapped + 2, (uint16_t)inner_len);
  memcpy(wrapped + 4, inner, inner_len);
  if (outcap < 14 + wrapped_len + 4) goto done;
  write_be_u32(outbuf, (uint32_t)(10 + wrapped_len));
  write_be_u16(outbuf + 4, 0x0100);
  memcpy(outbuf + 6, "RSA1", 4);
  write_be_u16(outbuf + 10, 0x0002);
  write_be_u16(outbuf + 12, (uint16_t)wrapped_body_len);
  memcpy(outbuf + 14, wrapped, wrapped_len);
  *outlen = 14 + wrapped_len;
  CC_SHA256(K, (CC_LONG)k_len, digest);
  memset(client->appleSessionKey, 0, sizeof(client->appleSessionKey));
  memcpy(client->appleSessionKey, digest, 16);
  client->appleSessionKeyLen = 16;
  client->appleSessionKeyReady = TRUE;
  client->appleAuthType = rfbAppleAuthRSA_SRP;
  ok = TRUE;

done:
  BN_free(N);
  BN_free(g);
  BN_free(B);
  BN_free(a);
  BN_free(A);
  BN_free(x);
  BN_free(v);
  BN_free(k);
  BN_free(u);
  BN_free(ux);
  BN_free(exp);
  BN_free(tmp);
  BN_free(base);
  BN_free(S);
  BN_CTX_free(bn_ctx);
  free(Np);
  free(gp);
  free(Ap);
  free(Bp);
  free(K);
  free(nonce16);
  free(inner);
  free(wrapped);
  free(pbkdf2_pass);
  free(x_bytes);
  free(Sp);
  return ok;
#endif
}

static rfbBool HandleAppleAuth33(rfbClient *client)
{
  uint8_t outbuf[8192];
  uint8_t keyreq[14];
  uint8_t init_key_material[256];
  uint8_t typebuf[2];
  uint8_t *type0_reply = NULL;
  uint8_t *inbuf = NULL;
  size_t init_key_len = 0;
  size_t outlen = 654;
  uint32_t type0_reply_len = 0;
  uint32_t inlen = 0;
  uint16_t packet_version = 0x0100;
  uint16_t auth_type = 0x0002;
  uint16_t aux_type = 0x0100;
  uint16_t selector_type = 0x0021;
  rfbCredential *cred = NULL;
  rfbBool ok = FALSE;

  if (!client->GetCredential) {
    rfbClientErr("apple auth33: GetCredential callback is not set\n");
    return FALSE;
  }
  cred = client->GetCredential(client, rfbCredentialTypeUser);
  if (!cred || !cred->userCredential.username || !cred->userCredential.password) {
    rfbClientErr("apple auth33: reading credential failed\n");
    FreeAppleUserCredential(cred);
    return FALSE;
  }

  memset(outbuf, 0, sizeof(outbuf));
  typebuf[0] = (uint8_t)(selector_type & 0xff);
  if (!WriteToRFBServer(client, (const char *)typebuf, 1)) goto done;

  if (!build_auth33_rsa1_key_request_packet(keyreq, sizeof(keyreq), packet_version)) goto done;
  if (!WriteToRFBServer(client, (const char *)keyreq, sizeof(keyreq))) goto done;
  if (!read_length_prefixed_blob(client, &type0_reply, &type0_reply_len, "auth33 type0 reply")) goto done;

  memset(init_key_material, 0, sizeof(init_key_material));
  if (!build_auth33_init_key_material(cred->userCredential.username, type0_reply, type0_reply_len,
                                      init_key_material, sizeof(init_key_material), &init_key_len)) {
    goto done;
  }
  free(type0_reply);
  type0_reply = NULL;

  if (!build_auth33_rsa1_init_packet(outbuf, sizeof(outbuf), packet_version, auth_type, aux_type,
                                     init_key_material, sizeof(init_key_material))) {
    goto done;
  }
  if (!WriteToRFBServer(client, (const char *)outbuf, (unsigned int)outlen)) goto done;

  if (!read_length_prefixed_blob(client, &inbuf, &inlen, "auth33 challenge")) goto done;
  if (!auth33_build_packet2_candidate(client, cred->userCredential.password, inbuf, inlen,
                                      outbuf, sizeof(outbuf), &outlen)) {
    goto done;
  }
  free(inbuf);
  inbuf = NULL;
  if (!WriteToRFBServer(client, (const char *)outbuf, (unsigned int)outlen)) goto done;
  if (!maybe_consume_auth33_server_final(client)) goto done;

  ok = TRUE;

done:
  FreeAppleUserCredential(cred);
  free(type0_reply);
  free(inbuf);
  if (!ok) rfbClientResetAppleAuth(client);
  return ok;
}

rfbBool rfbClientHandleAppleAuth(rfbClient* client, uint32_t authScheme)
{
  if (!client) return FALSE;

  rfbClientResetAppleAuth(client);
  switch (authScheme) {
  case rfbAppleAuthRSA_SRP:
    return HandleAppleAuth33(client);
  case rfbAppleAuthKerberos:
    rfbClientErr("Apple auth type 35 (Kerberos GSS-API) is not implemented in libvncclient yet\n");
    return FALSE;
  case rfbAppleAuthDirectSrp:
    rfbClientErr("Apple auth type 36 (direct SRP) is not implemented in libvncclient yet\n");
    return FALSE;
  default:
    return FALSE;
  }
}
