/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"
#include "py/objstr.h"

#include "vendor/secp256k1-zkp/include/secp256k1.h"
#include "vendor/secp256k1-zkp/include/secp256k1_ecdh.h"
#include "vendor/secp256k1-zkp/include/secp256k1_preallocated.h"
#include "vendor/secp256k1-zkp/include/secp256k1_rangeproof.h"
#include "vendor/secp256k1-zkp/include/secp256k1_recovery.h"
#include "vendor/secp256k1-zkp/include/secp256k1_surjectionproof.h"

// TODO: check `n_args` before accessing args.
// TODO: use consistent pointer style ("int *" vs "int*") => clang-tidy?.
// TODO: use consistent size_t/mp_int_t convention.
// TODO: use correct exception type for runtime issues (and not ValueError for everything).

// The minimum buffer size can vary in future secp256k1-zkp revisions.
// It can always be determined by a call to
// secp256k1_context_preallocated_size(...) as below.
STATIC uint8_t g_buffer[(1UL << (ECMULT_WINDOW_SIZE + 4)) + 208] = {0};

void secp256k1_default_illegal_callback_fn(const char *str, void *data) {
  (void)data;
  mp_raise_ValueError(str);
  return;
}

void secp256k1_default_error_callback_fn(const char *str, void *data) {
  (void)data;
  __fatal_error(NULL, str, __FILE__, __LINE__, __func__);
  return;
}

STATIC const secp256k1_context *mod_trezorcrypto_secp256k1_context(void) {
  static secp256k1_context *ctx;
  if (ctx == NULL) {
    size_t sz = secp256k1_context_preallocated_size(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
    if (sz > sizeof g_buffer) {
      mp_raise_ValueError("secp256k1 context is too large");
    }
    void *buf = (void *)g_buffer;
    ctx = secp256k1_context_preallocated_create(
        buf, SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    uint8_t rand[32];
    random_buffer(rand, 32);
    int ret = secp256k1_context_randomize(ctx, rand);
    if (ret != 1) {
      mp_raise_msg(&mp_type_RuntimeError, "secp256k1_context_randomize failed");
    }
  }
  return ctx;
}

/// package: trezorcrypto.secp256k1_zkp

/// def generate_secret() -> bytes:
///     """
///     Generate secret key.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_zkp_generate_secret() {
  uint8_t out[32];
  for (;;) {
    random_buffer(out, 32);
    // check whether secret > 0 && secret < curve_order
    if (0 == memcmp(out,
                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00",
                    32))
      continue;
    if (0 <= memcmp(out,
                    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                    "\xFF\xFF\xFE\xBA\xAE\xDC\xE6\xAF\x48\xA0\x3B\xBF\xD2"
                    "\x5E\x8C\xD0\x36\x41\x41",
                    32))
      continue;
    break;
  }
  return mp_obj_new_bytes(out, sizeof(out));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(
    mod_trezorcrypto_secp256k1_zkp_generate_secret_obj,
    mod_trezorcrypto_secp256k1_zkp_generate_secret);

/// def publickey(secret_key: bytes, compressed: bool = True) -> bytes:
///     """
///     Computes public key from secret key.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_zkp_publickey(size_t n_args,
                                                         const mp_obj_t *args) {
  const secp256k1_context *ctx = mod_trezorcrypto_secp256k1_context();
  mp_buffer_info_t sk;
  mp_get_buffer_raise(args[0], &sk, MP_BUFFER_READ);
  secp256k1_pubkey pk;
  if (sk.len != 32) {
    mp_raise_ValueError("Invalid length of secret key");
  }
  if (!secp256k1_ec_pubkey_create(ctx, &pk, (const unsigned char *)sk.buf)) {
    mp_raise_ValueError("Invalid secret key");
  }

  bool compressed = n_args < 2 || args[1] == mp_const_true;
  uint8_t out[65];
  size_t outlen = sizeof(out);
  secp256k1_ec_pubkey_serialize(
      ctx, out, &outlen, &pk,
      compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
  return mp_obj_new_bytes(out, outlen);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_zkp_publickey_obj, 1, 2,
    mod_trezorcrypto_secp256k1_zkp_publickey);

/// def sign(
///     secret_key: bytes, digest: bytes, compressed: bool = True
/// ) -> bytes:
///     """
///     Uses secret key to produce the signature of the digest.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_zkp_sign(size_t n_args,
                                                    const mp_obj_t *args) {
  const secp256k1_context *ctx = mod_trezorcrypto_secp256k1_context();
  mp_buffer_info_t sk, dig;
  mp_get_buffer_raise(args[0], &sk, MP_BUFFER_READ);
  mp_get_buffer_raise(args[1], &dig, MP_BUFFER_READ);
  bool compressed = n_args < 3 || args[2] == mp_const_true;
  if (sk.len != 32) {
    mp_raise_ValueError("Invalid length of secret key");
  }
  if (dig.len != 32) {
    mp_raise_ValueError("Invalid length of digest");
  }
  secp256k1_ecdsa_recoverable_signature sig;
  uint8_t out[65];
  int pby;
  if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig, (const uint8_t *)dig.buf,
                                        (const uint8_t *)sk.buf, NULL, NULL)) {
    mp_raise_ValueError("Signing failed");
  }
  secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, &out[1], &pby,
                                                          &sig);
  out[0] = 27 + pby + compressed * 4;
  return mp_obj_new_bytes(out, sizeof(out));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_zkp_sign_obj, 2, 3,
    mod_trezorcrypto_secp256k1_zkp_sign);

/// def verify(public_key: bytes, signature: bytes, digest: bytes) -> bool:
///     """
///     Uses public key to verify the signature of the digest.
///     Returns True on success.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_zkp_verify(mp_obj_t public_key,
                                                      mp_obj_t signature,
                                                      mp_obj_t digest) {
  const secp256k1_context *ctx = mod_trezorcrypto_secp256k1_context();
  mp_buffer_info_t pk, sig, dig;
  mp_get_buffer_raise(public_key, &pk, MP_BUFFER_READ);
  mp_get_buffer_raise(signature, &sig, MP_BUFFER_READ);
  mp_get_buffer_raise(digest, &dig, MP_BUFFER_READ);
  if (pk.len != 33 && pk.len != 65) {
    return mp_const_false;
  }
  if (sig.len != 64 && sig.len != 65) {
    return mp_const_false;
  }
  int offset = sig.len - 64;
  if (dig.len != 32) {
    return mp_const_false;
  }
  secp256k1_ecdsa_signature ec_sig;
  if (!secp256k1_ecdsa_signature_parse_compact(
          ctx, &ec_sig, (const uint8_t *)sig.buf + offset)) {
    return mp_const_false;
  }
  secp256k1_pubkey ec_pk;
  if (!secp256k1_ec_pubkey_parse(ctx, &ec_pk, (const uint8_t *)pk.buf,
                                 pk.len)) {
    return mp_const_false;
  }
  return mp_obj_new_bool(1 == secp256k1_ecdsa_verify(ctx, &ec_sig,
                                                     (const uint8_t *)dig.buf,
                                                     &ec_pk));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(mod_trezorcrypto_secp256k1_zkp_verify_obj,
                                 mod_trezorcrypto_secp256k1_zkp_verify);

/// def verify_recover(signature: bytes, digest: bytes) -> bytes:
///     """
///     Uses signature of the digest to verify the digest and recover the public
///     key. Returns public key on success, None if the signature is invalid.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_zkp_verify_recover(
    mp_obj_t signature, mp_obj_t digest) {
  const secp256k1_context *ctx = mod_trezorcrypto_secp256k1_context();
  mp_buffer_info_t sig, dig;
  mp_get_buffer_raise(signature, &sig, MP_BUFFER_READ);
  mp_get_buffer_raise(digest, &dig, MP_BUFFER_READ);
  if (sig.len != 65) {
    return mp_const_none;
  }
  if (dig.len != 32) {
    return mp_const_none;
  }
  int recid = ((const uint8_t *)sig.buf)[0] - 27;
  if (recid >= 8) {
    return mp_const_none;
  }
  bool compressed = (recid >= 4);
  recid &= 3;

  secp256k1_ecdsa_recoverable_signature ec_sig;
  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
          ctx, &ec_sig, (const uint8_t *)sig.buf + 1, recid)) {
    return mp_const_none;
  }
  secp256k1_pubkey pk;
  if (!secp256k1_ecdsa_recover(ctx, &pk, &ec_sig, (const uint8_t *)dig.buf)) {
    return mp_const_none;
  }
  uint8_t out[65];
  size_t pklen = sizeof(out);
  secp256k1_ec_pubkey_serialize(
      ctx, out, &pklen, &pk,
      compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
  return mp_obj_new_bytes(out, pklen);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(
    mod_trezorcrypto_secp256k1_zkp_verify_recover_obj,
    mod_trezorcrypto_secp256k1_zkp_verify_recover);

static int secp256k1_ecdh_hash_passthrough(uint8_t *output, const uint8_t *x,
                                           const uint8_t *y, void *data) {
  output[0] = 0x04;
  memcpy(&output[1], x, 32);
  memcpy(&output[33], y, 32);
  (void)data;
  return 1;
}

/// def multiply(secret_key: bytes, public_key: bytes) -> bytes:
///     """
///     Multiplies point defined by public_key with scalar defined by
///     secret_key. Useful for ECDH.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_zkp_multiply(mp_obj_t secret_key,
                                                        mp_obj_t public_key) {
  const secp256k1_context *ctx = mod_trezorcrypto_secp256k1_context();
  mp_buffer_info_t sk, pk;
  mp_get_buffer_raise(secret_key, &sk, MP_BUFFER_READ);
  mp_get_buffer_raise(public_key, &pk, MP_BUFFER_READ);
  if (sk.len != 32) {
    mp_raise_ValueError("Invalid length of secret key");
  }
  if (pk.len != 33 && pk.len != 65) {
    mp_raise_ValueError("Invalid length of public key");
  }
  secp256k1_pubkey ec_pk;
  if (!secp256k1_ec_pubkey_parse(ctx, &ec_pk, (const uint8_t *)pk.buf,
                                 pk.len)) {
    mp_raise_ValueError("Invalid public key");
  }
  uint8_t out[65];
  if (!secp256k1_ecdh(ctx, out, &ec_pk, (const uint8_t *)sk.buf,
                      secp256k1_ecdh_hash_passthrough, NULL)) {
    mp_raise_ValueError("Multiply failed");
  }
  return mp_obj_new_bytes(out, sizeof(out));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_secp256k1_zkp_multiply_obj,
                                 mod_trezorcrypto_secp256k1_zkp_multiply);

/// def ecdh(secret_key: bytes, public_key: bytes) -> bytes:
///     '''
///     Use ECDH to compute a shared 32-byte secret (elliptic curve multiplication followed by a SHA-256).
///     '''
STATIC mp_obj_t mod_trezorcrypto_secp256k1_zkp_ecdh(mp_obj_t secret_key,
                                                    mp_obj_t public_key) {
  const secp256k1_context *ctx = mod_trezorcrypto_secp256k1_context();
  mp_buffer_info_t sk, pk;
  mp_get_buffer_raise(secret_key, &sk, MP_BUFFER_READ);
  mp_get_buffer_raise(public_key, &pk, MP_BUFFER_READ);
  if (sk.len != 32) {
    mp_raise_ValueError("Invalid length of secret key");
  }
  if (pk.len != 33 && pk.len != 65) {
    mp_raise_ValueError("Invalid length of public key");
  }
  secp256k1_pubkey ec_pk;
  if (!secp256k1_ec_pubkey_parse(ctx, &ec_pk, (const uint8_t *)pk.buf,
                                 pk.len)) {
    mp_raise_ValueError("Invalid public key");
  }
  uint8_t out[32];
  if (!secp256k1_ecdh(ctx, out, &ec_pk, (const uint8_t *)sk.buf,
                      NULL, NULL)) {
    mp_raise_ValueError("ECDH failed");
  }
  return mp_obj_new_bytes(out, sizeof(out));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_secp256k1_zkp_ecdh_obj,
                                 mod_trezorcrypto_secp256k1_zkp_ecdh);

/// blind_generator(asset, asset_blind) -> gen
/// def blind_generator(asset: bytes, blinding_factor: bytes) -> bytes:
///     '''
///
///     '''
STATIC mp_obj_t mod_trezorcrypto_secp256k1_zkp_blind_generator(mp_obj_t asset_obj,
                                                               mp_obj_t blind_obj) {
  const secp256k1_context *ctx = mod_trezorcrypto_secp256k1_context();

  mp_buffer_info_t asset;
  mp_get_buffer_raise(asset_obj, &asset, MP_BUFFER_READ);
  if (asset.len != 32) {
    mp_raise_ValueError("Invalid length of asset");
  }
  mp_buffer_info_t blind;
  mp_get_buffer_raise(blind_obj, &blind, MP_BUFFER_READ);
  if (blind.len != 32) {
    mp_raise_ValueError("Invalid length of blinding factor");
  }
  secp256k1_generator gen;
  if (!secp256k1_generator_generate_blinded(ctx, &gen, asset.buf, blind.buf)) {
    mp_raise_ValueError("Generator blinding failed");
  }
  byte out[33] = {0};
  secp256k1_generator_serialize(ctx, out, &gen);
  return mp_obj_new_bytes(out, sizeof(out));
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_secp256k1_zkp_blind_generator_obj,
                                 mod_trezorcrypto_secp256k1_zkp_blind_generator);

// TODO: this code is copied from modtrezorcrypto-monero.h - find a better way to handle the conversion.
static uint64_t _mp_obj_get_uint64(mp_const_obj_t arg) {
  if (MP_OBJ_IS_SMALL_INT(arg)) {
    return MP_OBJ_SMALL_INT_VALUE(arg);
  } else if (MP_OBJ_IS_TYPE(arg, &mp_type_int)) {
    byte buff[8];
    uint64_t res = 0;
    mp_obj_t *o = MP_OBJ_TO_PTR(arg);

    #if MICROPY_LONGINT_IMPL != MICROPY_LONGINT_IMPL_MPZ
    #error "MPZ supported only"
    #endif
    mp_obj_int_to_bytes_impl(o, true, 8, buff);
    for (int i = 0; i < 8; i++) {
      res <<= i > 0 ? 8 : 0;
      res |= (uint64_t)(buff[i] & 0xff);
    }
    return res;
  } else {
    if (MICROPY_ERROR_REPORTING == MICROPY_ERROR_REPORTING_TERSE) {
      mp_raise_TypeError("can't convert to int");
    } else {
      nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_TypeError,
                                              "can't convert %s to int",
                                              mp_obj_get_type_str(arg)));
    }
  }
}

/// def pedersen_commit(value: long, blinding_factor: bytes, gen: bytes) -> bytes:
///     '''
///     Commit to specified integer value, using given 32-byte blinding factor.
///     '''
STATIC mp_obj_t mod_trezorcrypto_secp256k1_zkp_pedersen_commit(mp_obj_t value_obj,
                                                               mp_obj_t blind_obj,
                                                               mp_obj_t gen_obj) {
  const secp256k1_context *ctx = mod_trezorcrypto_secp256k1_context();
  const uint64_t value = _mp_obj_get_uint64(value_obj);

  mp_buffer_info_t blind;
  mp_get_buffer_raise(blind_obj, &blind, MP_BUFFER_READ);
  if (blind.len != 32) {
    mp_raise_ValueError("Invalid length of blinding factor");
  }
  mp_buffer_info_t gen;
  mp_get_buffer_raise(gen_obj, &gen, MP_BUFFER_READ);
  if (gen.len != 33) {
    mp_raise_ValueError("Invalid length of generator");
  }
  secp256k1_generator generator;
  if (!secp256k1_generator_parse(ctx, &generator, gen.buf)) {
    mp_raise_ValueError("Generator parsing failed");
  }

  secp256k1_pedersen_commitment commit;
  if (!secp256k1_pedersen_commit(ctx, &commit, blind.buf, value, &generator)) {
    mp_raise_ValueError("Pedersen commit failed");
  }

  byte output[33] = {0};
  secp256k1_pedersen_commitment_serialize(ctx, output, &commit);
  return mp_obj_new_bytes(output, sizeof(output));
}

STATIC MP_DEFINE_CONST_FUN_OBJ_3(mod_trezorcrypto_secp256k1_zkp_pedersen_commit_obj,
                                 mod_trezorcrypto_secp256k1_zkp_pedersen_commit);

STATIC uint8_t g_scratch_buffer[MAX(MAX(
  5134,  // for rangeproof_sign()
  4096), // for rangeproof_rewind()
  sizeof(secp256k1_surjectionproof))  // for surjection_proof()
] = {0};

/// def rangeproof_sign(value: int, commit: bytes, blind: bytes, nonce: bytes, message: bytes, extra_commit: bytes, gen: bytes) -> memoryview:
///     '''
///     Build a range proof for specified value.
///     '''
STATIC mp_obj_t mod_trezorcrypto_secp256k1_zkp_rangeproof_sign(size_t n_args, const mp_obj_t *args) {
  mp_obj_t value_obj = args[0];
  mp_obj_t commit_obj = args[1];
  mp_obj_t blind_obj = args[2];
  mp_obj_t nonce_obj = args[3];
  mp_obj_t message_obj = args[4];
  mp_obj_t extra_commit_obj = args[5];
  mp_obj_t gen_obj = args[6];

  const secp256k1_context *ctx = mod_trezorcrypto_secp256k1_context();
  const uint64_t VALUE_MIN = 1;  // TODO: allow setting to 0?
  const int EXPONENT = 0;
  const int BITS = 32;
  const uint64_t value = _mp_obj_get_uint64(value_obj);

  mp_buffer_info_t commit;
  mp_get_buffer_raise(commit_obj, &commit, MP_BUFFER_READ);
  if (commit.len != 33) {
    mp_raise_ValueError("Invalid length of commitment");
  }
  secp256k1_pedersen_commitment commitment;
  if (secp256k1_pedersen_commitment_parse(ctx, &commitment, commit.buf) != 1) {
    mp_raise_ValueError("Invalid Pedersen commitment");
  }

  mp_buffer_info_t blind;
  mp_get_buffer_raise(blind_obj, &blind, MP_BUFFER_READ);
  if (blind.len != 32) {
    mp_raise_ValueError("Invalid length of blinding factor");
  }

  mp_buffer_info_t nonce;
  mp_get_buffer_raise(nonce_obj, &nonce, MP_BUFFER_READ);
  if (nonce.len != 32) {
    mp_raise_ValueError("Invalid length of nonce");
  }

  mp_buffer_info_t message;
  mp_get_buffer_raise(message_obj, &message, MP_BUFFER_READ);

  mp_buffer_info_t extra_commit;
  mp_get_buffer_raise(extra_commit_obj, &extra_commit, MP_BUFFER_READ);

  mp_buffer_info_t gen;
  mp_get_buffer_raise(gen_obj, &gen, MP_BUFFER_READ);
  if (gen.len != 33) {
    mp_raise_ValueError("Invalid length of generator");
  }
  secp256k1_generator generator;
  if (!secp256k1_generator_parse(ctx, &generator, gen.buf)) {
    mp_raise_ValueError("Generator parsing failed");
  }

  size_t rangeproof_len = sizeof(g_scratch_buffer);
  if (!secp256k1_rangeproof_sign(
    ctx, g_scratch_buffer, &rangeproof_len, VALUE_MIN, &commitment, blind.buf, nonce.buf, EXPONENT, BITS,
    value, message.buf, message.len, extra_commit.buf, extra_commit.len, &generator)) {
    mp_raise_ValueError("Rangeproof sign failed");
  }

  uint64_t min_value = 0;
  uint64_t max_value = 0;
  if (!secp256k1_rangeproof_verify(
    ctx, &min_value, &max_value, &commitment, g_scratch_buffer, rangeproof_len, extra_commit.buf, extra_commit.len, &generator)) {
    mp_raise_ValueError("Rangeproof verification failed");
  }

  // Returns a memoryview to the scratch buffer (must not be overwritten).
  return mp_obj_new_memoryview('B', rangeproof_len, g_scratch_buffer);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_zkp_rangeproof_sign_obj, 7, 7,
    mod_trezorcrypto_secp256k1_zkp_rangeproof_sign);

/// def rangeproof_rewind(conf_value: bytes, conf_asset: bytes, nonce: bytes, range_proof: bytes, extra_commit: bytes, asset_message_len: int) -> (value: long, blind: bytes, asset_message: bytes):
///     '''
///     Rewind a range proof to get the value, blinding factor and message.
///     '''
STATIC mp_obj_t mod_trezorcrypto_secp256k1_zkp_rangeproof_rewind(size_t n_args, const mp_obj_t *args) {
  mp_obj_t conf_value_obj = args[0];
  mp_obj_t conf_asset_obj = args[1];
  mp_obj_t nonce_obj = args[2];
  mp_obj_t range_proof_obj = args[3];
  mp_obj_t extra_commit_obj = args[4];
  size_t asset_message_len = mp_obj_get_int(args[5]);
  asset_message_len = MIN(asset_message_len, sizeof(g_scratch_buffer));

  const secp256k1_context *ctx = mod_trezorcrypto_secp256k1_context();

  mp_buffer_info_t conf_value;
  mp_get_buffer_raise(conf_value_obj, &conf_value, MP_BUFFER_READ);
  secp256k1_pedersen_commitment commitment;
  if (!secp256k1_pedersen_commitment_parse(ctx, &commitment, conf_value.buf)) {
    mp_raise_ValueError("Invalid Pedersen commitment");
  }

  mp_buffer_info_t gen;
  mp_get_buffer_raise(conf_asset_obj, &gen, MP_BUFFER_READ);
  if (gen.len != 33) {
    mp_raise_ValueError("Invalid length of confidential asset");
  }
  secp256k1_generator generator;
  if (!secp256k1_generator_parse(ctx, &generator, gen.buf)) {
    mp_raise_ValueError("Generator parsing failed");
  }

  mp_buffer_info_t nonce;
  mp_get_buffer_raise(nonce_obj, &nonce, MP_BUFFER_READ);

  mp_buffer_info_t range_proof;
  mp_get_buffer_raise(range_proof_obj, &range_proof, MP_BUFFER_READ);

  mp_buffer_info_t extra_commit;
  mp_get_buffer_raise(extra_commit_obj, &extra_commit, MP_BUFFER_READ);

  byte value_blind[32] = {0};
  uint64_t value = 0;
  uint64_t min_value = 0;
  uint64_t max_value = 0;
  if (!secp256k1_rangeproof_rewind(ctx,
    value_blind, &value, g_scratch_buffer, &asset_message_len, nonce.buf, &min_value, &max_value,
    &commitment, range_proof.buf, range_proof.len, extra_commit.buf, extra_commit.len, &generator)) {
    mp_raise_ValueError("Rangeproof rewind failed");
  }

  mp_obj_tuple_t *result = MP_OBJ_TO_PTR(mp_obj_new_tuple(3, NULL));
  result->items[0] = mp_obj_new_int_from_ull(value);
  result->items[1] = mp_obj_new_bytes(value_blind, sizeof(value_blind));
  result->items[2] = mp_obj_new_bytes(g_scratch_buffer, asset_message_len);
  return result;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_zkp_rangeproof_rewind_obj, 6, 6,
    mod_trezorcrypto_secp256k1_zkp_rangeproof_rewind);

// TODO: benchmark stack usage to see the effect of SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS.

/// def surjection_proof(output_asset: bytes, output_asset_blind: bytes,
///                      input_assets: bytes, input_assets_blinds: bytes, input_assets_len: int,
///                      random_seed32: bytes):
///     '''
///     Generate a surjection proof for specified input assets.
///     '''
STATIC mp_obj_t mod_trezorcrypto_secp256k1_zkp_surjection_proof(size_t n_args, const mp_obj_t *args) {
  mp_obj_t output_asset_obj = args[0];
  mp_obj_t output_asset_blind_obj = args[1];
  mp_obj_t input_assets_obj = args[2];
  mp_obj_t input_assets_blinds_obj = args[3];
  const size_t input_assets_len = mp_obj_get_int(args[4]);
  mp_obj_t random_seed32_obj = args[5];

  secp256k1_surjectionproof* proof = (secp256k1_surjectionproof *) g_scratch_buffer;
  const secp256k1_context *ctx = mod_trezorcrypto_secp256k1_context();

  mp_buffer_info_t output_asset; // 32-byte output asset tag
  mp_get_buffer_raise(output_asset_obj, &output_asset, MP_BUFFER_READ);

  if (output_asset.len != sizeof(secp256k1_fixed_asset_tag)) {
    mp_raise_ValueError("Invalid output asset size");
  }

  mp_buffer_info_t output_asset_blind; // 32-byte output asset blinding factor
  mp_get_buffer_raise(output_asset_blind_obj, &output_asset_blind, MP_BUFFER_READ);
  if (output_asset_blind.len != 32) {
    mp_raise_ValueError("Invalid output asset blind size");
  }

  mp_buffer_info_t input_assets; // (32*input_assets_len)-byte concatenated input asset tags
  mp_get_buffer_raise(input_assets_obj, &input_assets, MP_BUFFER_READ);
  if (input_assets.len != input_assets_len * sizeof(secp256k1_fixed_asset_tag)) {
    mp_raise_ValueError("Invalid input assets size");
  }
  const secp256k1_fixed_asset_tag* input_assets_tags = (const secp256k1_fixed_asset_tag *) input_assets.buf;

  mp_buffer_info_t input_assets_blinds; // (32*input_assets_len)-byte concatenated input asset blinding factors
  mp_get_buffer_raise(input_assets_blinds_obj, &input_assets_blinds, MP_BUFFER_READ);
  if (input_assets_blinds.len != input_assets_len * 32) {
    mp_raise_ValueError("Invalid input assets size");
  }

  mp_buffer_info_t random_seed32; // 32-byte randomness for choosing input asset index
  mp_get_buffer_raise(random_seed32_obj, &random_seed32, MP_BUFFER_READ);
  if (random_seed32.len != 32) {
    mp_raise_ValueError("Invalid surjection random seed size");
  }

  // Initialize surjection proof & choose the input asset index to be mapped to the output
  size_t input_index = 0;
  const size_t input_assets_to_use = MIN(3, input_assets_len);
  const size_t n_max_iterations = 100;
  if (!secp256k1_surjectionproof_initialize(
    ctx, proof, &input_index, input_assets_tags, input_assets_len, input_assets_to_use,
    output_asset.buf, n_max_iterations, random_seed32.buf)) {
    mp_raise_ValueError("Surjection proof initialization failed");
  }

  // Re-create the inputs' and output's blinded asset generators using the assets' tags and their blinding factors
  secp256k1_generator output_generator;
  if (!secp256k1_generator_generate_blinded(ctx, &output_generator, output_asset.buf, output_asset_blind.buf)) {
    mp_raise_ValueError("Surjection proof output generator generation failed");
  }

  secp256k1_generator *input_generators = m_new(secp256k1_generator, input_assets_len);
  for (size_t i = 0; i < input_assets_len; ++i) {
    const uint8_t *input_asset_key = input_assets_tags[i].data;
    const uint8_t *input_asset_blind = (const uint8_t *)(input_assets_blinds.buf) + i*32;
    if (!secp256k1_generator_generate_blinded(ctx, input_generators + i, input_asset_key, input_asset_blind)) {
      mp_raise_ValueError("Surjection proof output generator generation failed");
    }
  }

  // Generate surjection proof for the chosen input and output assets
  const uint8_t *input_asset_blind = (const uint8_t *)(input_assets_blinds.buf) + input_index*32;
  if (!secp256k1_surjectionproof_generate(
    ctx, proof, input_generators, input_assets_len, &output_generator,
    input_index, input_asset_blind, output_asset_blind.buf)) {
    mp_raise_ValueError("Surjection proof generation failed");
  }
  m_del(secp256k1_generator, input_generators, input_assets_len);
  input_generators = NULL;

  size_t output_len = secp256k1_surjectionproof_serialized_size(ctx, proof);
  byte output[output_len]; // NOTE: allocates serialized proof on stack
  if (!secp256k1_surjectionproof_serialize(ctx, output, &output_len, proof)) {
    mp_raise_ValueError("Surjection proof serialization failed");
  }
  return mp_obj_new_bytes(output, output_len);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_zkp_surjection_proof_obj, 6, 6,
    mod_trezorcrypto_secp256k1_zkp_surjection_proof);

/// def balance_blinds(values: Tuple[long], value_blinds: bytearray, asset_blinds: bytes, num_of_inputs: int):
///     '''
///     Balance value blinds (by updating value_blinds in-place).
///     '''
STATIC mp_obj_t mod_trezorcrypto_secp256k1_zkp_balance_blinds(size_t n_args, const mp_obj_t *args) {
  const secp256k1_context *ctx = mod_trezorcrypto_secp256k1_context();
  mp_obj_t values_obj = args[0];
  mp_obj_t value_blinds_obj = args[1];
  mp_obj_t asset_blinds_obj = args[2];
  mp_obj_t num_of_inputs_obj = args[3];

  size_t values_len = 0;
  mp_obj_t *values_objs = NULL;
  mp_obj_tuple_get(values_obj, &values_len, &values_objs);

  mp_buffer_info_t value_blinds; // 32-byte value blinding factors
  mp_get_buffer_raise(value_blinds_obj, &value_blinds, MP_BUFFER_RW);
  if (value_blinds.len != 32 * values_len) {
    mp_raise_ValueError("Invalid value blind size");
  }

  mp_buffer_info_t asset_blinds; // 32-byte asset blinding factor
  mp_get_buffer_raise(asset_blinds_obj, &asset_blinds, MP_BUFFER_READ);
  if (asset_blinds.len != 32 * values_len) {
    mp_raise_ValueError("Invalid asset blind size");
  }

  size_t num_of_inputs = mp_obj_get_int(num_of_inputs_obj);
  if (num_of_inputs <= 0 || num_of_inputs >= values_len) {
    mp_raise_ValueError("incorrect num_of_inputs");
  }

  uint64_t values[values_len];
  byte* value_blinds_ptrs[values_len];
  const byte* asset_blinds_ptrs[values_len];

  for (size_t i = 0; i < values_len; ++i) {
    values[i] = _mp_obj_get_uint64(values_objs[i]);
  }
  for (size_t i = 0; i < values_len; ++i) {
    value_blinds_ptrs[i] = ((byte*) value_blinds.buf) + (i*32);
  }
  for (size_t i = 0; i < values_len; ++i) {
    asset_blinds_ptrs[i] = ((const byte*) asset_blinds.buf) + (i*32);
  }

  if (!secp256k1_pedersen_blind_generator_blind_sum(ctx, values, asset_blinds_ptrs, value_blinds_ptrs, values_len, num_of_inputs)) {
    mp_raise_ValueError("Balancing blinding factors failed");
  }

  return mp_const_none;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_zkp_balance_blinds_obj, 4, 4,
    mod_trezorcrypto_secp256k1_zkp_balance_blinds);

STATIC const mp_rom_map_elem_t
    mod_trezorcrypto_secp256k1_zkp_globals_table[] = {
        {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_secp256k1_zkp)},
        {MP_ROM_QSTR(MP_QSTR_generate_secret),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_zkp_generate_secret_obj)},
        {MP_ROM_QSTR(MP_QSTR_publickey),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_zkp_publickey_obj)},
        {MP_ROM_QSTR(MP_QSTR_sign),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_zkp_sign_obj)},
        {MP_ROM_QSTR(MP_QSTR_verify),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_zkp_verify_obj)},
        {MP_ROM_QSTR(MP_QSTR_verify_recover),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_zkp_verify_recover_obj)},
        {MP_ROM_QSTR(MP_QSTR_multiply),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_zkp_multiply_obj)},
        {MP_ROM_QSTR(MP_QSTR_ecdh),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_zkp_ecdh_obj)},
        {MP_ROM_QSTR(MP_QSTR_blind_generator),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_zkp_blind_generator_obj)},
        {MP_ROM_QSTR(MP_QSTR_pedersen_commit),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_zkp_pedersen_commit_obj)},
        {MP_ROM_QSTR(MP_QSTR_rangeproof_sign),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_zkp_rangeproof_sign_obj)},
        {MP_ROM_QSTR(MP_QSTR_rangeproof_rewind),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_zkp_rangeproof_rewind_obj)},
        {MP_ROM_QSTR(MP_QSTR_surjection_proof),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_zkp_surjection_proof_obj)},
        {MP_ROM_QSTR(MP_QSTR_balance_blinds),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_zkp_balance_blinds_obj)},
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_secp256k1_zkp_globals,
                            mod_trezorcrypto_secp256k1_zkp_globals_table);

STATIC const mp_obj_module_t mod_trezorcrypto_secp256k1_zkp_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mod_trezorcrypto_secp256k1_zkp_globals,
};
