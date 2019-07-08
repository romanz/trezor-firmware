/*
 * This file is part of the Trezor project, https://trezor.io/
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

#include "embed/extmod/trezorobj.h"

#include "vendor/secp256k1-zkp/include/secp256k1.h"
#include "vendor/secp256k1-zkp/include/secp256k1_ecdh.h"
#include "vendor/secp256k1-zkp/include/secp256k1_preallocated.h"
#include "vendor/secp256k1-zkp/include/secp256k1_rangeproof.h"
#include "vendor/secp256k1-zkp/include/secp256k1_recovery.h"
#include "vendor/secp256k1-zkp/include/secp256k1_surjectionproof.h"

#define RANGEPROOF_SIGN_BUFFER_SIZE 5134

#define RANGEPROOF_REWIND_MESSAGE_SIZE 4096

#define SURJECTIONPROOF_STRUCT_SIZE (sizeof(secp256k1_surjectionproof))

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

/// package: trezorcrypto.secp256k1_zkp

/// class RangeProofConfig:
///     """
///     Range proof configuration.
///     """
///
typedef struct _mp_obj_range_proof_config_t {
  mp_obj_base_t base;
  uint64_t min_value;
  size_t exponent;
  size_t bits;
} mp_obj_range_proof_config_t;

/// def __init__(self, min_value: int, exponent: int, bits: int):
///     """
///     Initialize range proof configuration.
///     """
STATIC mp_obj_t mod_trezorcrypto_range_proof_config_make_new(
    const mp_obj_type_t *type, size_t n_args, size_t n_kw,
    const mp_obj_t *args) {
  STATIC const mp_arg_t allowed_args[] = {
      {MP_QSTR_min_value,
       MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ,
       {.u_obj = mp_const_none}},
      {MP_QSTR_exponent,
       MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ,
       {.u_obj = mp_const_none}},
      {MP_QSTR_bits,
       MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ,
       {.u_obj = mp_const_none}},
  };
  mp_arg_val_t vals[MP_ARRAY_SIZE(allowed_args)];
  mp_arg_parse_all_kw_array(n_args, n_kw, args, MP_ARRAY_SIZE(allowed_args),
                            allowed_args, vals);

  mp_obj_range_proof_config_t *o = m_new_obj(mp_obj_range_proof_config_t);
  o->base.type = type;
  o->min_value = trezor_obj_get_uint(vals[0].u_obj);
  o->exponent = trezor_obj_get_uint(vals[1].u_obj);
  o->bits = trezor_obj_get_uint(vals[2].u_obj);
  return MP_OBJ_FROM_PTR(o);
}

STATIC const mp_obj_type_t mod_trezorcrypto_range_proof_config_type = {
    {&mp_type_type},
    .name = MP_QSTR_RangeProofConfig,
    .make_new = mod_trezorcrypto_range_proof_config_make_new,
};

/// class Context:
///     """
///     Owns a secp256k1 context.
///     Can be allocated once and re-used between subsequent operations.
///     """
///
typedef struct _mp_obj_secp256k1_context_t {
  mp_obj_base_t base;
  secp256k1_context *secp256k1_ctx;
  size_t secp256k1_ctx_size;
  uint8_t secp256k1_ctx_buf[0];  // to be allocate via m_new_obj_var_maybe().
} mp_obj_secp256k1_context_t;

/// def __init__(self):
///     """
///     Allocate and initialize secp256k1_context.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_context_make_new(
    const mp_obj_type_t *type, size_t n_args, size_t n_kw,
    const mp_obj_t *args) {
  mp_arg_check_num(n_args, n_kw, 0, 0, false);

  const size_t secp256k1_ctx_size = secp256k1_context_preallocated_size(
      SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

  mp_obj_secp256k1_context_t *o = m_new_obj_var_maybe(
      mp_obj_secp256k1_context_t, uint8_t, secp256k1_ctx_size);
  if (!o) {
    mp_raise_ValueError("secp256k1_zkp context is too large");
  }
  o->base.type = type;
  o->secp256k1_ctx_size = secp256k1_ctx_size;
  o->secp256k1_ctx = secp256k1_context_preallocated_create(
      o->secp256k1_ctx_buf, SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

  uint8_t rand[32] = {0};
  random_buffer(rand, 32);
  int ret = secp256k1_context_randomize(o->secp256k1_ctx, rand);
  if (ret != 1) {
    mp_raise_msg(&mp_type_RuntimeError, "secp256k1_context_randomize failed");
  }

  return MP_OBJ_FROM_PTR(o);
}

/// def __del__(self):
///     """
///     Destructor.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_context___del__(mp_obj_t self) {
  mp_obj_secp256k1_context_t *o = MP_OBJ_TO_PTR(self);
  secp256k1_context_preallocated_destroy(o->secp256k1_ctx);
  memzero(o->secp256k1_ctx_buf, o->secp256k1_ctx_size);
  return mp_const_none;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_secp256k1_context___del___obj,
                                 mod_trezorcrypto_secp256k1_context___del__);

/// def size(self):
///     """
///     Return the size in bytes of the internal secp256k1_ctx_buf buffer.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_context_size(mp_obj_t self) {
  mp_obj_secp256k1_context_t *o = MP_OBJ_TO_PTR(self);
  return mp_obj_new_int_from_uint(o->secp256k1_ctx_size);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_secp256k1_context_size_obj,
                                 mod_trezorcrypto_secp256k1_context_size);

static const secp256k1_context *mod_trezorcrypto_get_secp256k1_context(
    mp_obj_t self) {
  mp_obj_secp256k1_context_t *o = MP_OBJ_TO_PTR(self);
  return o->secp256k1_ctx;
}

/// def generate_secret(self) -> bytes:
///     """
///     Generate secret key.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_zkp_generate_secret(mp_obj_t self) {
  const secp256k1_context *ctx = mod_trezorcrypto_get_secp256k1_context(self);
  uint8_t out[32] = {0};
  for (;;) {
    random_buffer(out, 32);
    // check whether secret > 0 && secret < curve_order
    if (secp256k1_ec_seckey_verify(ctx, out) == 1) {
      break;
    }
  }
  return mp_obj_new_bytes(out, sizeof(out));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(
    mod_trezorcrypto_secp256k1_zkp_generate_secret_obj,
    mod_trezorcrypto_secp256k1_zkp_generate_secret);

/// def publickey(self, secret_key: bytes, compressed: bool = True) -> bytes:
///     """
///     Computes public key from secret key.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_context_publickey(
    size_t n_args, const mp_obj_t *args) {
  const secp256k1_context *ctx =
      mod_trezorcrypto_get_secp256k1_context(args[0]);
  mp_buffer_info_t sk;
  mp_get_buffer_raise(args[1], &sk, MP_BUFFER_READ);
  secp256k1_pubkey pk;
  if (sk.len != 32) {
    mp_raise_ValueError("Invalid length of secret key");
  }
  if (!secp256k1_ec_pubkey_create(ctx, &pk, (const unsigned char *)sk.buf)) {
    mp_raise_ValueError("Invalid secret key");
  }

  bool compressed = n_args < 3 || args[2] == mp_const_true;
  uint8_t out[65];
  size_t outlen = sizeof(out);
  secp256k1_ec_pubkey_serialize(
      ctx, out, &outlen, &pk,
      compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
  return mp_obj_new_bytes(out, outlen);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_context_publickey_obj, 2, 3,
    mod_trezorcrypto_secp256k1_context_publickey);

/// def sign(
///     self, secret_key: bytes, digest: bytes, compressed: bool = True
/// ) -> bytes:
///     """
///     Uses secret key to produce the signature of the digest.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_context_sign(size_t n_args,
                                                        const mp_obj_t *args) {
  const secp256k1_context *ctx =
      mod_trezorcrypto_get_secp256k1_context(args[0]);
  mp_buffer_info_t sk, dig;
  mp_get_buffer_raise(args[1], &sk, MP_BUFFER_READ);
  mp_get_buffer_raise(args[2], &dig, MP_BUFFER_READ);
  bool compressed = n_args < 4 || args[3] == mp_const_true;
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
    mod_trezorcrypto_secp256k1_context_sign_obj, 3, 4,
    mod_trezorcrypto_secp256k1_context_sign);

/// def verify(
///     self, public_key: bytes, signature: bytes, digest: bytes
/// ) -> bool:
///     """
///     Uses public key to verify the signature of the digest.
///     Returns True on success.
///     """
STATIC mp_obj_t
mod_trezorcrypto_secp256k1_context_verify(size_t n_args, const mp_obj_t *args) {
  const secp256k1_context *ctx =
      mod_trezorcrypto_get_secp256k1_context(args[0]);
  mp_buffer_info_t pk, sig, dig;
  mp_get_buffer_raise(args[1], &pk, MP_BUFFER_READ);
  mp_get_buffer_raise(args[2], &sig, MP_BUFFER_READ);
  mp_get_buffer_raise(args[3], &dig, MP_BUFFER_READ);
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
  bool ret = (1 == secp256k1_ecdsa_verify(ctx, &ec_sig,
                                          (const uint8_t *)dig.buf, &ec_pk));
  return mp_obj_new_bool(ret);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_context_verify_obj, 4, 4,
    mod_trezorcrypto_secp256k1_context_verify);

/// def verify_recover(self, signature: bytes, digest: bytes) -> bytes:
///     """
///     Uses signature of the digest to verify the digest and recover the public
///     key. Returns public key on success, None if the signature is invalid.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_context_verify_recover(
    mp_obj_t self, mp_obj_t signature, mp_obj_t digest) {
  const secp256k1_context *ctx = mod_trezorcrypto_get_secp256k1_context(self);
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
STATIC MP_DEFINE_CONST_FUN_OBJ_3(
    mod_trezorcrypto_secp256k1_context_verify_recover_obj,
    mod_trezorcrypto_secp256k1_context_verify_recover);

static int secp256k1_ecdh_hash_passthrough(uint8_t *output, const uint8_t *x,
                                           const uint8_t *y, void *data) {
  output[0] = SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
  memcpy(&output[1], x, 32);
  memcpy(&output[33], y, 32);
  (void)data;
  return 1;
}

/// def multiply(
///     self, secret_key: bytes, public_key: bytes, compressed_result: bool =
///     False
/// ) -> bytes:
///     """
///     Multiplies point defined by public_key with scalar defined by
///     secret_key. Useful for ECDH. The resulting point is serialized in
///     compressed format if `compressed_result` is True.
///     """
STATIC mp_obj_t mod_trezorcrypto_secp256k1_context_multiply(
    size_t n_args, const mp_obj_t *args) {
  const secp256k1_context *ctx =
      mod_trezorcrypto_get_secp256k1_context(args[0]);
  mp_buffer_info_t sk, pk;
  mp_get_buffer_raise(args[1], &sk, MP_BUFFER_READ);
  mp_get_buffer_raise(args[2], &pk, MP_BUFFER_READ);
  bool compressed_result = n_args == 4 && args[3] == mp_const_true;

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
  size_t outlen = sizeof(out);
  if (!secp256k1_ecdh(ctx, out, &ec_pk, (const uint8_t *)sk.buf,
                      secp256k1_ecdh_hash_passthrough, NULL)) {
    mp_raise_ValueError("Multiply failed");
  }
  if (compressed_result) {
    // EC pubkey is big-endian, so we test the least significant byte of y.
    out[0] = (out[outlen - 1] & 1) ? SECP256K1_TAG_PUBKEY_ODD
                                   : SECP256K1_TAG_PUBKEY_EVEN;
    outlen = 33;
  }
  return mp_obj_new_bytes(out, outlen);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_context_multiply_obj, 3, 4,
    mod_trezorcrypto_secp256k1_context_multiply);

/// def blind_generator(asset: bytes, blinding_factor: bytes) -> bytes:
///     '''
///     Generate blinded generator for the specified confidential asset.
///     '''
STATIC mp_obj_t mod_trezorcrypto_secp256k1_context_blind_generator(
    mp_obj_t self, mp_obj_t asset_obj, mp_obj_t blind_obj) {
  const secp256k1_context *ctx = mod_trezorcrypto_get_secp256k1_context(self);

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

STATIC MP_DEFINE_CONST_FUN_OBJ_3(
    mod_trezorcrypto_secp256k1_context_blind_generator_obj,
    mod_trezorcrypto_secp256k1_context_blind_generator);

STATIC void parse_generator(const secp256k1_context *ctx,
                            secp256k1_generator *generator, mp_obj_t obj) {
  mp_buffer_info_t gen;
  mp_get_buffer_raise(obj, &gen, MP_BUFFER_READ);
  if (gen.len != 33) {
    mp_raise_ValueError("Invalid length of generator");
  }
  if (!secp256k1_generator_parse(ctx, generator, gen.buf)) {
    mp_raise_ValueError("Generator parsing failed");
  }
}

/// def pedersen_commit(self, value: long, blinding_factor: bytes, gen: bytes)
/// -> bytes:
///     '''
///     Commit to specified integer value, using given 32-byte blinding factor.
///     '''
STATIC mp_obj_t mod_trezorcrypto_secp256k1_context_pedersen_commit(
    size_t n_args, const mp_obj_t *args) {
  const secp256k1_context *ctx =
      mod_trezorcrypto_get_secp256k1_context(args[0]);

  const uint64_t value = trezor_obj_get_uint64(args[1]);

  mp_buffer_info_t blind;
  mp_get_buffer_raise(args[2], &blind, MP_BUFFER_READ);
  if (blind.len != 32) {
    mp_raise_ValueError("Invalid length of blinding factor");
  }

  secp256k1_generator generator;
  parse_generator(ctx, &generator, args[3]);

  secp256k1_pedersen_commitment commit;
  if (!secp256k1_pedersen_commit(ctx, &commit, blind.buf, value, &generator)) {
    mp_raise_ValueError("Pedersen commit failed");
  }

  byte output[33];
  secp256k1_pedersen_commitment_serialize(ctx, output, &commit);
  return mp_obj_new_bytes(output, sizeof(output));
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_context_pedersen_commit_obj, 4, 4,
    mod_trezorcrypto_secp256k1_context_pedersen_commit);

STATIC void parse_commitment(const secp256k1_context *ctx,
                             secp256k1_pedersen_commitment *commitment,
                             mp_obj_t obj) {
  mp_buffer_info_t commit;
  mp_get_buffer_raise(obj, &commit, MP_BUFFER_READ);
  if (commit.len != 33) {
    mp_raise_ValueError("Invalid length of commitment");
  }
  if (secp256k1_pedersen_commitment_parse(ctx, commitment, commit.buf) != 1) {
    mp_raise_ValueError("Invalid Pedersen commitment");
  }
}

/// def rangeproof_sign(self, config: RangeProofConfig, value: int,
///                     commit: bytes, blind: bytes, nonce: bytes,
///                     message: bytes, extra_commit: bytes,
///                     gen: bytes, proof_buffer: bytearray) -> memoryview:
///     '''
///     Return a range proof for specified value (as a memoryview of the
///     specified bytearray).
///     '''
STATIC mp_obj_t mod_trezorcrypto_secp256k1_context_rangeproof_sign(
    size_t n_args, const mp_obj_t *args) {
  const secp256k1_context *ctx =
      mod_trezorcrypto_get_secp256k1_context(args[0]);

  mp_obj_range_proof_config_t *config = MP_OBJ_TO_PTR(args[1]);

  const uint64_t value = trezor_obj_get_uint64(args[2]);

  secp256k1_pedersen_commitment commitment;
  parse_commitment(ctx, &commitment, args[3]);

  mp_buffer_info_t blind;
  mp_get_buffer_raise(args[4], &blind, MP_BUFFER_READ);
  if (blind.len != 32) {
    mp_raise_ValueError("Invalid length of blinding factor");
  }

  mp_buffer_info_t nonce;
  mp_get_buffer_raise(args[5], &nonce, MP_BUFFER_READ);
  if (nonce.len != 32) {
    mp_raise_ValueError("Invalid length of nonce");
  }

  mp_buffer_info_t message;
  mp_get_buffer_raise(args[6], &message, MP_BUFFER_READ);

  mp_buffer_info_t extra_commit;
  mp_get_buffer_raise(args[7], &extra_commit, MP_BUFFER_READ);

  secp256k1_generator generator;
  parse_generator(ctx, &generator, args[8]);

  mp_buffer_info_t proof_buffer;
  mp_get_buffer_raise(args[9], &proof_buffer, MP_BUFFER_WRITE);
  if (proof_buffer.len < RANGEPROOF_SIGN_BUFFER_SIZE) {
    mp_raise_ValueError("Invalid length of output buffer");
  }

  size_t rangeproof_len = proof_buffer.len;
  if (!secp256k1_rangeproof_sign(
          ctx, proof_buffer.buf, &rangeproof_len, config->min_value,
          &commitment, blind.buf, nonce.buf, config->exponent, config->bits,
          value, message.buf, message.len, extra_commit.buf, extra_commit.len,
          &generator)) {
    mp_raise_ValueError("Rangeproof sign failed");
  }
  return mp_obj_new_memoryview('B', rangeproof_len, proof_buffer.buf);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_context_rangeproof_sign_obj, 10, 10,
    mod_trezorcrypto_secp256k1_context_rangeproof_sign);

/// def rangeproof_rewind(self, conf_value: bytes, conf_asset: bytes,
///                       nonce: bytes, range_proof: bytes,
///                       extra_commit: bytes, message: bytearray) ->
///                       (value: long, blind: bytes):
///     '''
///     Rewind a range proof to get the value, blinding factor and message.
///     '''
STATIC mp_obj_t mod_trezorcrypto_secp256k1_context_rangeproof_rewind(
    size_t n_args, const mp_obj_t *args) {
  const secp256k1_context *ctx =
      mod_trezorcrypto_get_secp256k1_context(args[0]);

  secp256k1_pedersen_commitment commitment;
  parse_commitment(ctx, &commitment, args[1]);

  secp256k1_generator generator;
  parse_generator(ctx, &generator, args[2]);

  mp_buffer_info_t nonce;
  mp_get_buffer_raise(args[3], &nonce, MP_BUFFER_READ);

  mp_buffer_info_t range_proof;
  mp_get_buffer_raise(args[4], &range_proof, MP_BUFFER_READ);

  mp_buffer_info_t extra_commit;
  mp_get_buffer_raise(args[5], &extra_commit, MP_BUFFER_READ);

  mp_buffer_info_t message;
  mp_get_buffer_raise(args[6], &message, MP_BUFFER_WRITE);
  if (message.len < RANGEPROOF_REWIND_MESSAGE_SIZE) {
    mp_raise_ValueError("Message buffer is too small");
  }

  size_t message_len = message.len;
  byte value_blind[32];
  uint64_t value;
  uint64_t min_value;
  uint64_t max_value;
  if (!secp256k1_rangeproof_rewind(
          ctx, value_blind, &value, message.buf, &message_len, nonce.buf,
          &min_value, &max_value, &commitment, range_proof.buf, range_proof.len,
          extra_commit.buf, extra_commit.len, &generator)) {
    mp_raise_ValueError("Rangeproof rewind failed");
  }

  mp_obj_tuple_t *result = MP_OBJ_TO_PTR(mp_obj_new_tuple(2, NULL));
  result->items[0] = mp_obj_new_int_from_ull(value);
  result->items[1] = mp_obj_new_bytes(value_blind, sizeof(value_blind));
  return result;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_context_rangeproof_rewind_obj, 7, 7,
    mod_trezorcrypto_secp256k1_context_rangeproof_rewind);

/// def surjection_proof(self, output_asset: bytes, output_asset_blind: bytes,
///                      input_assets: bytes, input_assets_blinds: bytes,
///                      input_assets_len: int, random_seed32: bytes,
///                      proof_buffer: bytearray) -> bytes:
///     '''
///     Generate a surjection proof for specified input assets.
///     '''
STATIC mp_obj_t mod_trezorcrypto_secp256k1_context_surjection_proof(
    size_t n_args, const mp_obj_t *args) {
  const secp256k1_context *ctx =
      mod_trezorcrypto_get_secp256k1_context(args[0]);

  mp_buffer_info_t output_asset;  // 32-byte output asset tag
  mp_get_buffer_raise(args[1], &output_asset, MP_BUFFER_READ);

  if (output_asset.len != sizeof(secp256k1_fixed_asset_tag)) {
    mp_raise_ValueError("Invalid output asset size");
  }

  mp_buffer_info_t output_asset_blind;  // 32-byte output asset blinding factor
  mp_get_buffer_raise(args[2], &output_asset_blind, MP_BUFFER_READ);
  if (output_asset_blind.len != 32) {
    mp_raise_ValueError("Invalid output asset blind size");
  }

  mp_buffer_info_t
      input_assets;  // (32*input_assets_len)-byte concatenated input asset tags
  mp_get_buffer_raise(args[3], &input_assets, MP_BUFFER_READ);

  mp_buffer_info_t
      input_assets_blinds;  // (32*input_assets_len)-byte concatenated input
                            // asset blinding factors
  mp_get_buffer_raise(args[4], &input_assets_blinds, MP_BUFFER_READ);

  const size_t input_assets_len = mp_obj_get_int(args[5]);

  if (input_assets.len !=
      input_assets_len * sizeof(secp256k1_fixed_asset_tag)) {
    mp_raise_ValueError("Invalid input assets size");
  }
  const secp256k1_fixed_asset_tag *input_assets_tags =
      (const secp256k1_fixed_asset_tag *)input_assets.buf;

  if (input_assets_blinds.len != input_assets_len * 32) {
    mp_raise_ValueError("Invalid input assets size");
  }

  mp_buffer_info_t
      random_seed32;  // 32-byte randomness for choosing input asset index
  mp_get_buffer_raise(args[6], &random_seed32, MP_BUFFER_READ);
  if (random_seed32.len != 32) {
    mp_raise_ValueError("Invalid surjection random seed size");
  }

  mp_buffer_info_t proof_buffer;
  mp_get_buffer_raise(args[7], &proof_buffer, MP_BUFFER_RW);
  if (proof_buffer.len < SURJECTIONPROOF_STRUCT_SIZE) {
    mp_raise_ValueError("Invalid surjection proof state buffer");
  }
  secp256k1_surjectionproof *proof =
      (secp256k1_surjectionproof *)proof_buffer.buf;

  // Initialize surjection proof & choose the input asset index to be mapped to
  // the output
  size_t input_index = 0;
  const size_t input_assets_to_use = MIN(3, input_assets_len);
  const size_t n_max_iterations = 100;
  if (!secp256k1_surjectionproof_initialize(
          ctx, proof, &input_index, input_assets_tags, input_assets_len,
          input_assets_to_use, output_asset.buf, n_max_iterations,
          random_seed32.buf)) {
    mp_raise_ValueError("Surjection proof initialization failed");
  }

  // Re-create the inputs' and output's blinded asset generators using the
  // assets' tags and their blinding factors
  secp256k1_generator output_generator;
  if (!secp256k1_generator_generate_blinded(
          ctx, &output_generator, output_asset.buf, output_asset_blind.buf)) {
    mp_raise_ValueError("Surjection proof output generator generation failed");
  }

  secp256k1_generator *input_generators =
      m_new(secp256k1_generator, input_assets_len);
  for (size_t i = 0; i < input_assets_len; ++i) {
    const uint8_t *input_asset_key = input_assets_tags[i].data;
    const uint8_t *input_asset_blind =
        (const uint8_t *)(input_assets_blinds.buf) + i * 32;
    if (!secp256k1_generator_generate_blinded(
            ctx, input_generators + i, input_asset_key, input_asset_blind)) {
      mp_raise_ValueError(
          "Surjection proof output generator generation failed");
    }
  }

  // Generate surjection proof for the chosen input and output assets
  const uint8_t *input_asset_blind =
      (const uint8_t *)(input_assets_blinds.buf) + input_index * 32;
  if (!secp256k1_surjectionproof_generate(
          ctx, proof, input_generators, input_assets_len, &output_generator,
          input_index, input_asset_blind, output_asset_blind.buf)) {
    mp_raise_ValueError("Surjection proof generation failed");
  }

  m_del(secp256k1_generator, input_generators, input_assets_len);
  input_generators = NULL;

  size_t output_len = secp256k1_surjectionproof_serialized_size(ctx, proof);
  uint8_t *output = m_new(uint8_t, output_len);
  if (!secp256k1_surjectionproof_serialize(ctx, output, &output_len, proof)) {
    mp_raise_ValueError("Surjection proof serialization failed");
  }
  return mp_obj_new_bytes(output, output_len);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_context_surjection_proof_obj, 8, 8,
    mod_trezorcrypto_secp256k1_context_surjection_proof);

/// def balance_blinds(self, values: Tuple[long], value_blinds: bytearray,
///                    asset_blinds: bytes, num_of_inputs: int):
///     '''
///     Balance value blinds (by updating value_blinds in-place).
///     '''
STATIC mp_obj_t mod_trezorcrypto_secp256k1_context_balance_blinds(
    size_t n_args, const mp_obj_t *args) {
  const secp256k1_context *ctx =
      mod_trezorcrypto_get_secp256k1_context(args[0]);

  size_t values_len = 0;
  mp_obj_t *values_objs = NULL;
  mp_obj_tuple_get(args[1], &values_len, &values_objs);

  mp_buffer_info_t value_blinds;  // 32-byte value blinding factors
  mp_get_buffer_raise(args[2], &value_blinds, MP_BUFFER_RW);
  if (value_blinds.len != 32 * values_len) {
    mp_raise_ValueError("Invalid value blind size");
  }

  mp_buffer_info_t asset_blinds;  // 32-byte asset blinding factor
  mp_get_buffer_raise(args[3], &asset_blinds, MP_BUFFER_READ);
  if (asset_blinds.len != 32 * values_len) {
    mp_raise_ValueError("Invalid asset blind size");
  }

  size_t num_of_inputs = mp_obj_get_int(args[4]);
  if (num_of_inputs <= 0 || num_of_inputs >= values_len) {
    mp_raise_ValueError("incorrect num_of_inputs");
  }

  uint64_t values[values_len];
  byte *value_blinds_ptrs[values_len];
  const byte *asset_blinds_ptrs[values_len];

  for (size_t i = 0; i < values_len; ++i) {
    values[i] = trezor_obj_get_uint64(values_objs[i]);
  }
  for (size_t i = 0; i < values_len; ++i) {
    value_blinds_ptrs[i] = ((byte *)value_blinds.buf) + (i * 32);
  }
  for (size_t i = 0; i < values_len; ++i) {
    asset_blinds_ptrs[i] = ((const byte *)asset_blinds.buf) + (i * 32);
  }

  if (!secp256k1_pedersen_blind_generator_blind_sum(
          ctx, values, asset_blinds_ptrs, value_blinds_ptrs, values_len,
          num_of_inputs)) {
    mp_raise_ValueError("Balancing blinding factors failed");
  }

  return mp_const_none;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_context_balance_blinds_obj, 5, 5,
    mod_trezorcrypto_secp256k1_context_balance_blinds);

/// def verify_balance(self, commitments: Tuple[bytes], num_of_inputs: int)
///     '''
///     Verify that Pedersen commitments are balanced.
///     '''
STATIC mp_obj_t mod_trezorcrypto_secp256k1_context_verify_balance(
    size_t n_args, const mp_obj_t *args) {
  const secp256k1_context *ctx =
      mod_trezorcrypto_get_secp256k1_context(args[0]);

  size_t n_commitments = 0;
  mp_obj_t *commitments_objs = NULL;
  mp_obj_tuple_get(args[1], &n_commitments, &commitments_objs);

  const secp256k1_pedersen_commitment *commitments[n_commitments];
  for (int i = 0; i < n_commitments; ++i) {
    secp256k1_pedersen_commitment *commit =
        m_new_obj(secp256k1_pedersen_commitment);
    parse_commitment(ctx, commit, commitments_objs[i]);
    commitments[i] = commit;
  };

  const size_t num_of_inputs = mp_obj_get_int(args[2]);
  if (num_of_inputs < 1 || num_of_inputs >= n_commitments) {
    mp_raise_ValueError("Invalid number of inputs");
  }

  if (!secp256k1_pedersen_verify_tally(ctx, commitments, num_of_inputs,
                                       commitments + num_of_inputs,
                                       n_commitments - num_of_inputs)) {
    mp_raise_ValueError("Pedersen commitments are not balanced");
  }

  for (int i = 0; i < n_commitments; ++i) {
    m_del_obj(secp256k1_pedersen_commitment, (void *)(commitments[i]));
  }
  return mp_const_none;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_context_verify_balance_obj, 3, 3,
    mod_trezorcrypto_secp256k1_context_verify_balance);

#ifndef USE_REDUCED_SURJECTION_PROOF_SIZE

/// def verify_surjection_proof(
///     self, proof: bytes, output_generator: bytes, input_generators:
///     Tuple[bytes]
/// ) -> bytes:
///     '''
///     Verify a surjection proof for specified blinded assets.
///     '''
STATIC mp_obj_t mod_trezorcrypto_secp256k1_context_verify_surjection_proof(
    size_t n_args, const mp_obj_t *args) {
  const secp256k1_context *ctx =
      mod_trezorcrypto_get_secp256k1_context(args[0]);

  mp_buffer_info_t proof_obj;
  mp_get_buffer_raise(args[1], &proof_obj, MP_BUFFER_READ);
  secp256k1_surjectionproof proof;
  if (!secp256k1_surjectionproof_parse(ctx, &proof, proof_obj.buf,
                                       proof_obj.len)) {
    mp_raise_ValueError("Surjection proof parsing failed");
  }
  secp256k1_generator output_generator;
  parse_generator(ctx, &output_generator, args[2]);

  size_t inputs_len = 0;
  mp_obj_t *inputs_objs = NULL;
  mp_obj_tuple_get(args[3], &inputs_len, &inputs_objs);

  secp256k1_generator *input_generators =
      m_new(secp256k1_generator, inputs_len);
  for (int i = 0; i < inputs_len; ++i) {
    parse_generator(ctx, input_generators + i, inputs_objs[i]);
  }

  if (!secp256k1_surjectionproof_verify(ctx, &proof, input_generators,
                                        inputs_len, &output_generator)) {
    mp_raise_ValueError("Surjection proof verification failed");
  }
  m_del(secp256k1_generator, input_generators, inputs_len);
  return mp_const_true;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_secp256k1_context_verify_surjection_proof_obj, 4, 4,
    mod_trezorcrypto_secp256k1_context_verify_surjection_proof);

#endif

STATIC const mp_rom_map_elem_t
    mod_trezorcrypto_secp256k1_context_locals_dict_table[] = {
        {MP_ROM_QSTR(MP_QSTR___del__),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_context___del___obj)},
        {MP_ROM_QSTR(MP_QSTR_size),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_context_size_obj)},
        {MP_ROM_QSTR(MP_QSTR_generate_secret),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_zkp_generate_secret_obj)},
        {MP_ROM_QSTR(MP_QSTR_publickey),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_context_publickey_obj)},
        {MP_ROM_QSTR(MP_QSTR_sign),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_context_sign_obj)},
        {MP_ROM_QSTR(MP_QSTR_verify),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_context_verify_obj)},
        {MP_ROM_QSTR(MP_QSTR_verify_recover),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_context_verify_recover_obj)},
        {MP_ROM_QSTR(MP_QSTR_multiply),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_context_multiply_obj)},
        {MP_ROM_QSTR(MP_QSTR_blind_generator),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_context_blind_generator_obj)},
        {MP_ROM_QSTR(MP_QSTR_pedersen_commit),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_context_pedersen_commit_obj)},
        {MP_ROM_QSTR(MP_QSTR_rangeproof_sign),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_context_rangeproof_sign_obj)},
        {MP_ROM_QSTR(MP_QSTR_rangeproof_rewind),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_context_rangeproof_rewind_obj)},
        {MP_ROM_QSTR(MP_QSTR_surjection_proof),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_context_surjection_proof_obj)},
        {MP_ROM_QSTR(MP_QSTR_balance_blinds),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_context_balance_blinds_obj)},
        {MP_ROM_QSTR(MP_QSTR_verify_balance),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_context_verify_balance_obj)},
#ifndef USE_REDUCED_SURJECTION_PROOF_SIZE
        {MP_ROM_QSTR(MP_QSTR_verify_surjection_proof),
         MP_ROM_PTR(
             &mod_trezorcrypto_secp256k1_context_verify_surjection_proof_obj)},
#endif
};

STATIC MP_DEFINE_CONST_DICT(
    mod_trezorcrypto_secp256k1_context_locals_dict,
    mod_trezorcrypto_secp256k1_context_locals_dict_table);

STATIC const mp_obj_type_t mod_trezorcrypto_secp256k1_context_type = {
    {&mp_type_type},
    .name = MP_QSTR_Context,
    .make_new = mod_trezorcrypto_secp256k1_context_make_new,
    .locals_dict = (void *)&mod_trezorcrypto_secp256k1_context_locals_dict,
};

#define PROOF_BUFFER_SIZE \
  (MAX(RANGEPROOF_SIGN_BUFFER_SIZE, SURJECTIONPROOF_STRUCT_SIZE))

#if USE_PREALLOCATED_SECP256K1_ZKP_PROOF_BUFFER
static uint8_t
    preallocated_secp256k1_zkp_proof_buf[PROOF_BUFFER_SIZE];  // ~8.26kB
#endif

/// def allocate_proof_buffer() -> bytearray
///     '''
///     Allocate a buffer, large enough for holding a range proof / reduced size
///     surjection proof.
///     '''
STATIC mp_obj_t mod_trezorcrypto_secp256k1_zkp_allocate_proof_buffer() {
#if USE_PREALLOCATED_SECP256K1_ZKP_PROOF_BUFFER
  uint8_t *proof_buffer = preallocated_secp256k1_zkp_proof_buf;
#else
  uint8_t *proof_buffer = m_new(uint8_t, PROOF_BUFFER_SIZE);
#endif
  return mp_obj_new_bytearray_by_ref(PROOF_BUFFER_SIZE, proof_buffer);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_0(
    mod_trezorcrypto_secp256k1_zkp_allocate_proof_buffer_obj,
    mod_trezorcrypto_secp256k1_zkp_allocate_proof_buffer);

STATIC const mp_rom_map_elem_t
    mod_trezorcrypto_secp256k1_zkp_globals_table[] = {
        {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_secp256k1_zkp)},
        {MP_ROM_QSTR(MP_QSTR_RangeProofConfig),
         MP_ROM_PTR(&mod_trezorcrypto_range_proof_config_type)},
        {MP_ROM_QSTR(MP_QSTR_Context),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_context_type)},
        {MP_ROM_QSTR(MP_QSTR_allocate_proof_buffer),
         MP_ROM_PTR(&mod_trezorcrypto_secp256k1_zkp_allocate_proof_buffer_obj)},
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_secp256k1_zkp_globals,
                            mod_trezorcrypto_secp256k1_zkp_globals_table);

STATIC const mp_obj_module_t mod_trezorcrypto_secp256k1_zkp_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mod_trezorcrypto_secp256k1_zkp_globals,
};
