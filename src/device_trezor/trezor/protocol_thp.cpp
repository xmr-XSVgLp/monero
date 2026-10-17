// Copyright (c) 2026, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#include "protocol_thp.hpp"

#include <fstream>
#include <sys/stat.h>
#include <boost/crc.hpp>
#include <boost/filesystem.hpp>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <sodium.h>
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "common/util.h"
#include "file_io_utils.h"
#include "string_tools.h"
#include "messages/messages-thp.pb.h"
#include "messages/messages-common.pb.h"
#include "messages/messages-management.pb.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "device.trezor.thp"

namespace hw {
namespace trezor {
namespace thp {

  namespace {
    // Control bytes
    constexpr uint8_t CTRL_CONTINUATION = 0x80;
    constexpr uint8_t CTRL_CHANNEL_ALLOCATION_REQ = 0x40;
    constexpr uint8_t CTRL_CHANNEL_ALLOCATION_RES = 0x41;
    constexpr uint8_t CTRL_ERROR = 0x42;
    constexpr uint8_t CTRL_ACK = 0x20;
    constexpr uint8_t ACK_MASK = 0xF7;
    constexpr uint8_t DATA_MASK = 0xE7;
    constexpr uint8_t DATA_DETECT_MASK = 0xE0;
    constexpr uint8_t SEQ_BIT = 0x10;
    constexpr uint8_t ACK_BIT = 0x08;
    constexpr uint8_t HANDSHAKE_INIT_REQ = 0x00;
    constexpr uint8_t HANDSHAKE_INIT_RES = 0x01;
    constexpr uint8_t HANDSHAKE_COMP_REQ = 0x02;
    constexpr uint8_t HANDSHAKE_COMP_RES = 0x03;
    constexpr uint8_t ENCRYPTED_TRANSPORT = 0x04;

    constexpr size_t INIT_HEADER_SIZE = 5;
    constexpr size_t CONT_HEADER_SIZE = 3;
    constexpr size_t CHECKSUM_SIZE = 4;

    // THP application message types (messages-thp.proto, ThpMessageType)
    constexpr uint16_t MT_ButtonRequest = 26;
    constexpr uint16_t MT_ButtonAck = 27;
    constexpr uint16_t MT_Failure = 3;

    const char NOISE_PROTOCOL_NAME[] = "Noise_XX_25519_AESGCM_SHA256\0\0\0\0";

    std::string be16(uint16_t v){
      std::string r(2, '\0');
      r[0] = static_cast<char>(v >> 8);
      r[1] = static_cast<char>(v & 0xff);
      return r;
    }

    uint16_t read_be16(const std::string & s, size_t off){
      return static_cast<uint16_t>((static_cast<uint8_t>(s[off]) << 8) | static_cast<uint8_t>(s[off + 1]));
    }

    std::string be32(uint32_t v){
      std::string r(4, '\0');
      for (int i = 0; i < 4; ++i) r[i] = static_cast<char>((v >> (24 - 8 * i)) & 0xff);
      return r;
    }

    std::string wiped(const epee::wipeable_string & s){
      return std::string(s.data(), s.size());
    }

    void wipe(std::string & s){
      if (!s.empty()) memwipe(&s[0], s.size());
    }

    struct bn_ctx_deleter { void operator()(BN_CTX * c) const { BN_CTX_free(c); } };
    struct bn_deleter { void operator()(BIGNUM * b) const { BN_clear_free(b); } };
    using bn_ptr = std::unique_ptr<BIGNUM, bn_deleter>;

    bn_ptr bn_new(){
      BIGNUM * b = BN_new();
      CHECK_AND_ASSERT_THROW_MES(b, "BN_new failed");
      return bn_ptr(b);
    }

    bn_ptr bn_dec(const char * dec){
      BIGNUM * b = nullptr;
      CHECK_AND_ASSERT_THROW_MES(BN_dec2bn(&b, dec) > 0, "BN_dec2bn failed");
      return bn_ptr(b);
    }
  }

  namespace crypto {

    std::string random_bytes(size_t n){
      std::string r(n, '\0');
      randombytes_buf(&r[0], n);
      return r;
    }

    std::string sha256(const std::string & data){
      std::string r(crypto_hash_sha256_BYTES, '\0');
      crypto_hash_sha256(reinterpret_cast<unsigned char*>(&r[0]), reinterpret_cast<const unsigned char*>(data.data()), data.size());
      return r;
    }

    std::string sha512(const std::string & data){
      std::string r(crypto_hash_sha512_BYTES, '\0');
      crypto_hash_sha512(reinterpret_cast<unsigned char*>(&r[0]), reinterpret_cast<const unsigned char*>(data.data()), data.size());
      return r;
    }

    std::string hmac_sha256(const std::string & key, const std::string & data){
      crypto_auth_hmacsha256_state st;
      std::string r(crypto_auth_hmacsha256_BYTES, '\0');
      crypto_auth_hmacsha256_init(&st, reinterpret_cast<const unsigned char*>(key.data()), key.size());
      crypto_auth_hmacsha256_update(&st, reinterpret_cast<const unsigned char*>(data.data()), data.size());
      crypto_auth_hmacsha256_final(&st, reinterpret_cast<unsigned char*>(&r[0]));
      memwipe(&st, sizeof(st));
      return r;
    }

    std::string x25519(const std::string & scalar, const std::string & point){
      CHECK_AND_ASSERT_THROW_MES(scalar.size() == 32 && point.size() == 32, "Invalid X25519 input size");
      std::string r(32, '\0');
      if (crypto_scalarmult(reinterpret_cast<unsigned char*>(&r[0]), reinterpret_cast<const unsigned char*>(scalar.data()),
                            reinterpret_cast<const unsigned char*>(point.data())) != 0){
        throw exc::SecurityException("THP: X25519 produced an invalid shared secret");
      }
      return r;
    }

    std::string x25519_base(const std::string & scalar){
      CHECK_AND_ASSERT_THROW_MES(scalar.size() == 32, "Invalid X25519 scalar size");
      std::string r(32, '\0');
      crypto_scalarmult_base(reinterpret_cast<unsigned char*>(&r[0]), reinterpret_cast<const unsigned char*>(scalar.data()));
      return r;
    }

    // map_to_curve_elligator2_curve25519 from RFC 9380, section G.2.1
    std::string elligator2(const std::string & input){
      CHECK_AND_ASSERT_THROW_MES(input.size() == 32, "Invalid elligator2 input size");
      std::unique_ptr<BN_CTX, bn_ctx_deleter> ctx(BN_CTX_new());
      CHECK_AND_ASSERT_THROW_MES(ctx, "BN_CTX_new failed");
      BN_CTX * c = ctx.get();

      bn_ptr p = bn_new(), J = bn_dec("486662");
      bn_ptr c3 = bn_dec("19681161376707505956807079304988542015446066515923890162744021073123829784752");
      bn_ptr c4 = bn_dec("7237005577332262213973186563042994240829374041602535252466099000494570602493");
      BN_set_bit(p.get(), 255);
      BN_sub_word(p.get(), 19);

      // decodeUCoordinate: little-endian, clear the top bit, reduce mod p
      unsigned char be[32];
      for (size_t i = 0; i < 32; ++i) be[i] = static_cast<unsigned char>(input[31 - i]);
      be[0] &= 0x7f;
      bn_ptr u = bn_new();
      BN_bin2bn(be, 32, u.get());
      BN_nnmod(u.get(), u.get(), p.get(), c);
      memwipe(be, sizeof(be));

      bn_ptr tv1 = bn_new(), tv2 = bn_new(), tv3 = bn_new(), xd = bn_new(), x1n = bn_new(), gxd = bn_new(), gx1 = bn_new();
      bn_ptr y11 = bn_new(), y12 = bn_new(), x2n = bn_new(), tmp = bn_new(), x = bn_new(), pm2 = bn_new();

      BN_mod_sqr(tv1.get(), u.get(), p.get(), c);                       // tv1 = u^2
      BN_mod_add(tv1.get(), tv1.get(), tv1.get(), p.get(), c);          // tv1 = 2 * tv1
      BN_copy(xd.get(), tv1.get()); BN_add_word(xd.get(), 1);           // xd = tv1 + 1
      BN_nnmod(xd.get(), xd.get(), p.get(), c);
      BN_mod_sub(x1n.get(), p.get(), J.get(), p.get(), c);              // x1n = -J
      BN_mod_sqr(tv2.get(), xd.get(), p.get(), c);                      // tv2 = xd^2
      BN_mod_mul(gxd.get(), tv2.get(), xd.get(), p.get(), c);           // gxd = tv2 * xd
      BN_mod_mul(gx1.get(), J.get(), tv1.get(), p.get(), c);            // gx1 = J * tv1
      BN_mod_mul(gx1.get(), gx1.get(), x1n.get(), p.get(), c);          // gx1 = gx1 * x1n
      BN_mod_add(gx1.get(), gx1.get(), tv2.get(), p.get(), c);          // gx1 = gx1 + tv2
      BN_mod_mul(gx1.get(), gx1.get(), x1n.get(), p.get(), c);          // gx1 = gx1 * x1n
      BN_mod_sqr(tv3.get(), gxd.get(), p.get(), c);                     // tv3 = gxd^2
      BN_mod_sqr(tv2.get(), tv3.get(), p.get(), c);                     // tv2 = tv3^2
      BN_mod_mul(tv3.get(), tv3.get(), gxd.get(), p.get(), c);          // tv3 = tv3 * gxd
      BN_mod_mul(tv3.get(), tv3.get(), gx1.get(), p.get(), c);          // tv3 = tv3 * gx1
      BN_mod_mul(tv2.get(), tv2.get(), tv3.get(), p.get(), c);          // tv2 = tv2 * tv3
      BN_mod_exp(y11.get(), tv2.get(), c4.get(), p.get(), c);           // y11 = tv2^c4
      BN_mod_mul(y11.get(), y11.get(), tv3.get(), p.get(), c);          // y11 = y11 * tv3
      BN_mod_mul(y12.get(), y11.get(), c3.get(), p.get(), c);           // y12 = y11 * c3
      BN_mod_sqr(tv2.get(), y11.get(), p.get(), c);                     // tv2 = y11^2
      BN_mod_mul(tv2.get(), tv2.get(), gxd.get(), p.get(), c);          // tv2 = tv2 * gxd
      const bool e1 = BN_cmp(tv2.get(), gx1.get()) == 0;
      BIGNUM * y1 = e1 ? y11.get() : y12.get();
      BN_mod_mul(x2n.get(), x1n.get(), tv1.get(), p.get(), c);          // x2n = x1n * tv1
      BN_mod_sqr(tv2.get(), y1, p.get(), c);                            // tv2 = y1^2
      BN_mod_mul(tv2.get(), tv2.get(), gxd.get(), p.get(), c);          // tv2 = tv2 * gxd
      const bool e3 = BN_cmp(tv2.get(), gx1.get()) == 0;
      BIGNUM * xn = e3 ? x1n.get() : x2n.get();
      BN_copy(pm2.get(), p.get()); BN_sub_word(pm2.get(), 2);
      BN_mod_exp(tmp.get(), xd.get(), pm2.get(), p.get(), c);           // 1 / xd
      BN_mod_mul(x.get(), xn, tmp.get(), p.get(), c);                   // x = xn / xd

      unsigned char out_be[32];
      CHECK_AND_ASSERT_THROW_MES(BN_bn2binpad(x.get(), out_be, 32) == 32, "BN_bn2binpad failed");
      std::string r(32, '\0');
      for (size_t i = 0; i < 32; ++i) r[i] = static_cast<char>(out_be[31 - i]);
      memwipe(out_be, sizeof(out_be));
      return r;
    }

    static std::string gcm_iv(uint64_t nonce){
      std::string iv(12, '\0');
      for (int i = 0; i < 8; ++i) iv[4 + i] = static_cast<char>((nonce >> (56 - 8 * i)) & 0xff);
      return iv;
    }

    struct evp_deleter { void operator()(EVP_CIPHER_CTX * c) const { EVP_CIPHER_CTX_free(c); } };

    std::string aes_gcm_encrypt(const std::string & key, uint64_t nonce, const std::string & ad, const std::string & plaintext){
      CHECK_AND_ASSERT_THROW_MES(key.size() == 32, "Invalid AES key size");
      std::unique_ptr<EVP_CIPHER_CTX, evp_deleter> ctx(EVP_CIPHER_CTX_new());
      CHECK_AND_ASSERT_THROW_MES(ctx, "EVP_CIPHER_CTX_new failed");
      const std::string iv = gcm_iv(nonce);
      int len = 0;
      std::string out(plaintext.size() + TAG_SIZE, '\0');
      auto * o = reinterpret_cast<unsigned char*>(&out[0]);
      bool ok = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
          && EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1
          && EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data())) == 1;
      if (ok && !ad.empty())
        ok = EVP_EncryptUpdate(ctx.get(), nullptr, &len, reinterpret_cast<const unsigned char*>(ad.data()), (int)ad.size()) == 1;
      int total = 0;
      if (ok && !plaintext.empty()){
        ok = EVP_EncryptUpdate(ctx.get(), o, &len, reinterpret_cast<const unsigned char*>(plaintext.data()), (int)plaintext.size()) == 1;
        total = len;
      }
      ok = ok && EVP_EncryptFinal_ex(ctx.get(), o + total, &len) == 1;
      ok = ok && EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, o + plaintext.size()) == 1;
      CHECK_AND_ASSERT_THROW_MES(ok, "AES-GCM encryption failed");
      return out;
    }

    bool aes_gcm_decrypt(const std::string & key, uint64_t nonce, const std::string & ad, const std::string & ciphertext, std::string & plaintext){
      CHECK_AND_ASSERT_THROW_MES(key.size() == 32, "Invalid AES key size");
      if (ciphertext.size() < TAG_SIZE) return false;
      std::unique_ptr<EVP_CIPHER_CTX, evp_deleter> ctx(EVP_CIPHER_CTX_new());
      CHECK_AND_ASSERT_THROW_MES(ctx, "EVP_CIPHER_CTX_new failed");
      const std::string iv = gcm_iv(nonce);
      const size_t ct_len = ciphertext.size() - TAG_SIZE;
      std::string tag = ciphertext.substr(ct_len);
      int len = 0;
      plaintext.assign(ct_len, '\0');
      auto * o = reinterpret_cast<unsigned char*>(&plaintext[0]);
      bool ok = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
          && EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1
          && EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data())) == 1;
      if (ok && !ad.empty())
        ok = EVP_DecryptUpdate(ctx.get(), nullptr, &len, reinterpret_cast<const unsigned char*>(ad.data()), (int)ad.size()) == 1;
      int total = 0;
      if (ok && ct_len > 0){
        ok = EVP_DecryptUpdate(ctx.get(), o, &len, reinterpret_cast<const unsigned char*>(ciphertext.data()), (int)ct_len) == 1;
        total = len;
      }
      ok = ok && EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE, &tag[0]) == 1;
      ok = ok && EVP_DecryptFinal_ex(ctx.get(), o + total, &len) == 1;
      if (!ok){
        wipe(plaintext);
        plaintext.clear();
      }
      return ok;
    }

    uint32_t crc32(const std::string & data){
      boost::crc_32_type crc;
      crc.process_bytes(data.data(), data.size());
      return crc.checksum();
    }
  }

  /* ======================================================================= */
  /*                              Noise handshake                            */
  /* ======================================================================= */

  NoiseHandshake::NoiseHandshake(const std::string & prologue)
    : m_h(NOISE_PROTOCOL_NAME, 32), m_ck(NOISE_PROTOCOL_NAME, 32), m_n(0)
  {
    mix_hash(prologue);
  }

  void NoiseHandshake::mix_hash(const std::string & data){
    m_h = crypto::sha256(m_h + data);
  }

  void NoiseHandshake::mix_key(const std::string & ikm){
    std::string temp = crypto::hmac_sha256(m_ck, ikm);
    std::string out1 = crypto::hmac_sha256(temp, std::string(1, '\x01'));
    std::string out2 = crypto::hmac_sha256(temp, out1 + std::string(1, '\x02'));
    wipe(temp);
    wipe(m_ck);
    wipe(m_k);
    m_ck = out1;
    m_k = out2;
    m_n = 0;
  }

  std::string NoiseHandshake::write_message1(const std::string & payload){
    std::string e = crypto::random_bytes(32);
    m_e_priv = epee::wipeable_string(e.data(), e.size());
    m_e_pub = crypto::x25519_base(e);
    wipe(e);
    mix_hash(m_e_pub);
    mix_hash(payload);  // no key yet, payload is sent in plaintext
    return m_e_pub + payload;
  }

  void NoiseHandshake::read_message2(const std::string & msg){
    if (msg.size() != 32 + 32 + TAG_SIZE + TAG_SIZE){
      throw exc::ProtocolException("THP: invalid handshake init response size");
    }
    const std::string e_priv = wiped(m_e_priv);
    m_re = msg.substr(0, 32);
    mix_hash(m_re);
    mix_key(crypto::x25519(e_priv, m_re));

    const std::string enc_static = msg.substr(32, 48);
    if (!crypto::aes_gcm_decrypt(m_k, m_n++, m_h, enc_static, m_rs) || m_rs.size() != 32){
      throw exc::SecurityException("THP: cannot decrypt Trezor static key");
    }
    mix_hash(enc_static);
    mix_key(crypto::x25519(e_priv, m_rs));

    const std::string tag = msg.substr(80, TAG_SIZE);
    std::string empty;
    if (!crypto::aes_gcm_decrypt(m_k, m_n++, m_h, tag, empty) || !empty.empty()){
      throw exc::SecurityException("THP: handshake tag verification failed");
    }
    mix_hash(tag);
  }

  std::string NoiseHandshake::write_message3(const epee::wipeable_string & host_static_privkey, const std::string & payload){
    std::string s_priv = wiped(host_static_privkey);
    const std::string s_pub = crypto::x25519_base(s_priv);
    const std::string enc_static = crypto::aes_gcm_encrypt(m_k, m_n++, m_h, s_pub);
    mix_hash(enc_static);
    mix_key(crypto::x25519(s_priv, m_re));
    wipe(s_priv);
    const std::string enc_payload = crypto::aes_gcm_encrypt(m_k, m_n++, m_h, payload);
    mix_hash(enc_payload);
    m_e_priv.wipe();
    return enc_static + enc_payload;
  }

  void NoiseHandshake::split(std::string & key_request, std::string & key_response){
    std::string temp = crypto::hmac_sha256(m_ck, std::string());
    key_request = crypto::hmac_sha256(temp, std::string(1, '\x01'));
    key_response = crypto::hmac_sha256(temp, key_request + std::string(1, '\x02'));
    wipe(temp);
    wipe(m_ck);
    wipe(m_k);
  }

  bool credential_matches(const Credential & cred, const std::string & trezor_ephemeral, const std::string & trezor_masked_static){
    if (cred.trezor_static_pubkey.size() != 32) return false;
    const std::string mask = crypto::sha256(cred.trezor_static_pubkey + trezor_ephemeral);
    try {
      return crypto::x25519(mask, cred.trezor_static_pubkey) == trezor_masked_static;
    } catch (const std::exception &) {
      return false;
    }
  }

  void cpace_host(const std::string & code, const std::string & handshake_hash, const std::string & trezor_pubkey,
                  std::string & host_pubkey, std::string & shared_secret){
    CHECK_AND_ASSERT_THROW_MES(code.size() == 6 && handshake_hash.size() == 32, "Invalid CPace input");
    // prefix || code || padding || handshake_hash || 0x00, see THP spec, Code Entry pairing
    std::string gen;
    gen.append(1, '\x08').append("CPace255").append(1, '\x06').append(code)
       .append(1, '\x6f').append(111, '\0')
       .append(1, '\x20').append(handshake_hash)
       .append(1, '\0');
    std::string pregen = crypto::sha512(gen).substr(0, 32);
    wipe(gen);
    const std::string generator = crypto::elligator2(pregen);
    wipe(pregen);
    std::string priv = crypto::random_bytes(32);
    host_pubkey = crypto::x25519(priv, generator);
    shared_secret = crypto::x25519(priv, trezor_pubkey);
    wipe(priv);
  }

  uint32_t code_entry_code(const std::string & handshake_hash, const std::string & secret, const std::string & challenge){
    const std::string h = crypto::sha256(std::string(1, static_cast<char>(messages::thp::CodeEntry)) + handshake_hash + secret + challenge);
    uint64_t r = 0;
    for (unsigned char b : h) r = (r * 256 + b) % 1000000;
    return static_cast<uint32_t>(r);
  }

  /* ======================================================================= */
  /*                            Credential storage                           */
  /* ======================================================================= */

  FileCredentialStore::FileCredentialStore(std::string path): m_path(std::move(path)) {}

  std::string FileCredentialStore::default_path(){
    return (boost::filesystem::path(tools::get_default_data_dir()) / "trezor-thp-credentials.json").string();
  }

  std::vector<Credential> FileCredentialStore::load(){
    std::vector<Credential> res;
    std::string contents;
    if (!boost::filesystem::exists(m_path) || !epee::file_io_utils::load_file_to_string(m_path, contents)){
      return res;
    }

    rapidjson::Document doc;
    if (doc.Parse(contents.c_str()).HasParseError() || !doc.IsArray()){
      MWARNING("THP: ignoring malformed credential file " << m_path);
      wipe(contents);
      return res;
    }

    for (const auto & it : doc.GetArray()){
      if (!it.IsObject() || !it.HasMember("trezor_pubkey") || !it.HasMember("host_privkey") || !it.HasMember("credential")){
        continue;
      }
      std::string tp, hp, cr;
      if (!epee::string_tools::parse_hexstr_to_binbuff(std::string(it["trezor_pubkey"].GetString()), tp)
          || !epee::string_tools::parse_hexstr_to_binbuff(std::string(it["host_privkey"].GetString()), hp)
          || !epee::string_tools::parse_hexstr_to_binbuff(std::string(it["credential"].GetString()), cr)){
        continue;
      }
      Credential c;
      c.trezor_static_pubkey = tp;
      c.host_static_privkey = epee::wipeable_string(hp.data(), hp.size());
      c.credential = cr;
      wipe(hp);
      res.push_back(std::move(c));
    }
    wipe(contents);
    return res;
  }

  void FileCredentialStore::save(const Credential & cred){
    std::vector<Credential> creds = load();
    // A Trezor keeps one credential per host key; replace entries for the same device.
    creds.erase(std::remove_if(creds.begin(), creds.end(), [&](const Credential & c){
      return c.trezor_static_pubkey == cred.trezor_static_pubkey;
    }), creds.end());
    creds.push_back(cred);

    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    writer.StartArray();
    for (const auto & c : creds){
      writer.StartObject();
      writer.Key("trezor_pubkey");
      writer.String(epee::string_tools::buff_to_hex_nodelimer(c.trezor_static_pubkey).c_str());
      writer.Key("host_privkey");
      epee::wipeable_string hp_hex = epee::to_hex::wipeable_string(epee::span<const uint8_t>(reinterpret_cast<const uint8_t*>(c.host_static_privkey.data()), c.host_static_privkey.size()));
      writer.String(hp_hex.data(), hp_hex.size());
      writer.Key("credential");
      writer.String(epee::string_tools::buff_to_hex_nodelimer(c.credential).c_str());
      writer.EndObject();
    }
    writer.EndArray();

    const boost::filesystem::path p(m_path);
    if (p.has_parent_path()){
      boost::system::error_code ec;
      boost::filesystem::create_directories(p.parent_path(), ec);
    }

    const std::string tmp = m_path + ".tmp";
    {
      std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
      CHECK_AND_ASSERT_THROW_MES(f.good(), "THP: cannot write credential file " << tmp);
#ifndef _WIN32
      chmod(tmp.c_str(), S_IRUSR | S_IWUSR);
#endif
      f.write(sb.GetString(), sb.GetSize());
      CHECK_AND_ASSERT_THROW_MES(f.good(), "THP: cannot write credential file " << tmp);
    }
    boost::filesystem::rename(tmp, m_path);
    memwipe(const_cast<char*>(sb.GetString()), sb.GetSize());
  }
}

  /* ======================================================================= */
  /*                                ProtocolThp                              */
  /* ======================================================================= */

  using namespace thp;

  class ThpTransportException : public exc::ProtocolException {
  public:
    using exc::ProtocolException::ProtocolException;
  };

  static std::string transport_error_name(uint8_t code){
    switch(code){
      case TRANSPORT_BUSY: return "TRANSPORT_BUSY";
      case UNALLOCATED_CHANNEL: return "UNALLOCATED_CHANNEL";
      case DECRYPTION_FAILED: return "DECRYPTION_FAILED";
      case DEVICE_LOCKED: return "DEVICE_LOCKED";
      default: return std::string("error ") + std::to_string(code);
    }
  }

  ProtocolThp::ProtocolThp()
    : m_cid(BROADCAST_CID), m_connected(false), m_seq_send(false), m_seq_recv(false),
      m_session_id(0), m_session_counter(0), m_pairing_state(PairingState::Unpaired),
      m_nonce_request(0), m_nonce_response(0) {}

  void ProtocolThp::close(){
    m_connected = false;
    m_cid = BROADCAST_CID;
    m_seq_send = m_seq_recv = false;
    m_session_id = 0;
    m_session_counter = 0;
    m_noise.reset();
    m_host_static_privkey.wipe();
    m_key_request.wipe();
    m_key_response.wipe();
    m_nonce_request = m_nonce_response = 0;
  }

  uint8_t ProtocolThp::next_session_id(){
    m_session_counter = static_cast<uint8_t>(m_session_counter == 0xff ? 1 : m_session_counter + 1);
    return m_session_counter;
  }

  void ProtocolThp::write_packets(Transport & transport, uint8_t ctrl, uint16_t cid, const std::string & payload){
    if (payload.size() + CHECKSUM_SIZE > 0xffff){
      throw exc::EncodingException("THP: message too long");
    }
    std::string msg;
    msg.reserve(INIT_HEADER_SIZE + payload.size() + CHECKSUM_SIZE);
    msg.append(1, static_cast<char>(ctrl)).append(be16(cid)).append(be16(static_cast<uint16_t>(payload.size() + CHECKSUM_SIZE))).append(payload);
    msg.append(be32(crypto::crc32(msg)));

    const size_t psize = transport.packet_size();
    std::string chunk(psize, '\0');
    size_t off = std::min(msg.size(), psize);
    memcpy(&chunk[0], msg.data(), off);
    transport.write_chunk(chunk.data(), psize);

    const std::string cont_header = std::string(1, static_cast<char>(CTRL_CONTINUATION)) + be16(cid);
    while (off < msg.size()){
      const size_t n = std::min(msg.size() - off, psize - CONT_HEADER_SIZE);
      std::fill(chunk.begin(), chunk.end(), '\0');
      memcpy(&chunk[0], cont_header.data(), CONT_HEADER_SIZE);
      memcpy(&chunk[CONT_HEADER_SIZE], msg.data() + off, n);
      transport.write_chunk(chunk.data(), psize);
      off += n;
    }
    wipe(chunk);
    wipe(msg);
  }

  void ProtocolThp::read_packets(Transport & transport, uint8_t & ctrl, uint16_t & cid, std::string & payload){
    const size_t psize = transport.packet_size();
    std::string chunk(psize, '\0');
    bool have_chunk = false;
    while (true){
      if (!have_chunk){
        const size_t n = transport.read_chunk(&chunk[0], psize);
        if (n != psize){
          throw exc::CommunicationException("THP: read chunk has invalid size");
        }
      }
      have_chunk = false;

      const uint8_t c = static_cast<uint8_t>(chunk[0]);
      if (c & CTRL_CONTINUATION){
        MDEBUG("THP: skipping unexpected continuation packet");
        continue;
      }

      const uint16_t pcid = read_be16(chunk, 1);
      const uint16_t len = read_be16(chunk, 3);
      if (len < CHECKSUM_SIZE){
        MWARNING("THP: message too short, ignoring");
        continue;
      }

      std::string data = chunk.substr(INIT_HEADER_SIZE);
      while (data.size() < len){
        const size_t n = transport.read_chunk(&chunk[0], psize);
        if (n != psize){
          throw exc::CommunicationException("THP: read chunk has invalid size");
        }
        if (static_cast<uint8_t>(chunk[0]) != CTRL_CONTINUATION){
          MWARNING("THP: expected continuation packet, restarting");
          have_chunk = true;
          break;
        }
        if (read_be16(chunk, 1) != pcid){
          MDEBUG("THP: ignoring packet for another channel");
          continue;
        }
        data.append(chunk, CONT_HEADER_SIZE, std::string::npos);
      }
      if (have_chunk){
        continue;
      }

      data.resize(len);
      const std::string body = data.substr(0, len - CHECKSUM_SIZE);
      const std::string header = std::string(1, static_cast<char>(c)) + be16(pcid) + be16(len);
      if (be32(crypto::crc32(header + body)) != data.substr(len - CHECKSUM_SIZE)){
        MWARNING("THP: invalid checksum, ignoring message");
        continue;
      }

      ctrl = c;
      cid = pcid;
      payload = body;
      wipe(data);
      return;
    }
  }

  void ProtocolThp::send_ack(Transport & transport, bool seq){
    write_packets(transport, static_cast<uint8_t>(CTRL_ACK | (seq ? ACK_BIT : 0)), m_cid, std::string());
  }

  void ProtocolThp::send_data(Transport & transport, uint8_t ctrl, const std::string & payload){
    // ACK bit stays 0: on handshake init it tells the firmware not to piggyback ACKs.
    const uint8_t c = static_cast<uint8_t>(ctrl | (m_seq_send ? SEQ_BIT : 0));
    write_packets(transport, c, m_cid, payload);

    while (true){
      uint8_t rctrl; uint16_t rcid; std::string rpayload;
      read_packets(transport, rctrl, rcid, rpayload);
      if (rcid != m_cid){
        continue;
      }
      if (rctrl == CTRL_ERROR){
        const uint8_t code = rpayload.empty() ? 0 : static_cast<uint8_t>(rpayload[0]);
        throw ThpTransportException("THP transport error: " + transport_error_name(code));
      }
      if ((rctrl & ACK_MASK) == CTRL_ACK){
        if (((rctrl & ACK_BIT) != 0) == m_seq_send){
          break;
        }
        MDEBUG("THP: ACK with unexpected sequence bit");
        continue;
      }
      // The peer will retransmit data it sent before acknowledging ours.
      MDEBUG("THP: ignoring data message while waiting for ACK");
    }
    m_seq_send = !m_seq_send;
  }

  void ProtocolThp::recv_data(Transport & transport, uint8_t & ctrl, std::string & payload){
    while (true){
      uint8_t rctrl; uint16_t rcid;
      read_packets(transport, rctrl, rcid, payload);
      if (rcid != m_cid){
        continue;
      }
      if (rctrl == CTRL_ERROR){
        const uint8_t code = payload.empty() ? 0 : static_cast<uint8_t>(payload[0]);
        if (code == UNALLOCATED_CHANNEL || code == DECRYPTION_FAILED){
          m_connected = false;
        }
        throw ThpTransportException("THP transport error: " + transport_error_name(code));
      }
      if ((rctrl & ACK_MASK) == CTRL_ACK){
        continue;  // stray ACK
      }
      if ((rctrl & DATA_DETECT_MASK) != 0){
        MDEBUG("THP: ignoring non-data message " << (int)rctrl);
        continue;
      }
      const bool seq = (rctrl & SEQ_BIT) != 0;
      send_ack(transport, seq);
      if (seq != m_seq_recv){
        MDEBUG("THP: duplicate message, ignoring");
        continue;
      }
      m_seq_recv = !m_seq_recv;
      ctrl = static_cast<uint8_t>(rctrl & DATA_MASK);
      return;
    }
  }

  void ProtocolThp::allocate_channel(Transport & transport){
    const std::string nonce = crypto::random_bytes(8);
    write_packets(transport, CTRL_CHANNEL_ALLOCATION_REQ, BROADCAST_CID, nonce);
    for (int i = 0; i < 32; ++i){
      uint8_t ctrl; uint16_t cid; std::string payload;
      read_packets(transport, ctrl, cid, payload);
      if (cid != BROADCAST_CID || ctrl != CTRL_CHANNEL_ALLOCATION_RES){
        continue;
      }
      if (payload.size() < 10 || payload.substr(0, 8) != nonce){
        MDEBUG("THP: channel allocation nonce mismatch");
        continue;
      }
      m_cid = read_be16(payload, 8);
      m_device_properties = payload.substr(10);
      messages::thp::ThpDeviceProperties props;
      if (!props.ParseFromString(m_device_properties)){
        throw exc::ProtocolException("THP: invalid device properties");
      }
      m_internal_model = props.internal_model();
      m_pairing_methods.clear();
      for (int k = 0; k < props.pairing_methods_size(); ++k){
        m_pairing_methods.push_back(props.pairing_methods(k));
      }
      m_seq_send = m_seq_recv = false;
      MDEBUG("THP: allocated channel " << m_cid << ", model " << m_internal_model
             << ", protocol " << props.protocol_version_major() << "." << props.protocol_version_minor());
      return;
    }
    throw exc::ProtocolException("THP: channel allocation failed");
  }

  void ProtocolThp::handshake(Transport & transport, CredentialStore & store, std::vector<Credential> & creds){
    m_noise.reset(new NoiseHandshake(m_device_properties));

    // try_to_unlock = 1: a locked Trezor shows the PIN entry instead of failing
    send_data(transport, HANDSHAKE_INIT_REQ, m_noise->write_message1(std::string(1, '\x01')));
    uint8_t ctrl; std::string payload;
    recv_data(transport, ctrl, payload);
    if (ctrl != HANDSHAKE_INIT_RES){
      throw exc::ProtocolException("THP: unexpected handshake init response");
    }
    m_noise->read_message2(payload);

    messages::thp::ThpHandshakeCompletionReqNoisePayload noise_payload;
    const Credential * found = nullptr;
    for (const auto & c : creds){
      if (credential_matches(c, m_noise->remote_ephemeral(), m_noise->remote_static_masked())){
        found = &c;
        break;
      }
    }
    if (found){
      MDEBUG("THP: using stored pairing credential");
      m_host_static_privkey = found->host_static_privkey;
      noise_payload.set_host_pairing_credential(found->credential);
    } else {
      std::string k = crypto::random_bytes(32);
      m_host_static_privkey = epee::wipeable_string(k.data(), k.size());
      wipe(k);
    }

    send_data(transport, HANDSHAKE_COMP_REQ, m_noise->write_message3(m_host_static_privkey, noise_payload.SerializeAsString()));
    recv_data(transport, ctrl, payload);
    if (ctrl != HANDSHAKE_COMP_RES){
      throw exc::ProtocolException("THP: unexpected handshake completion response");
    }

    std::string kreq, kresp, state;
    m_noise->split(kreq, kresp);
    m_key_request = epee::wipeable_string(kreq.data(), kreq.size());
    m_key_response = epee::wipeable_string(kresp.data(), kresp.size());
    if (!crypto::aes_gcm_decrypt(kresp, 0, std::string(), payload, state) || state.size() != 1){
      throw exc::SecurityException("THP: cannot decrypt Trezor state");
    }
    wipe(kreq); wipe(kresp);
    m_nonce_request = 0;
    m_nonce_response = 1;
    m_pairing_state = static_cast<PairingState>(static_cast<uint8_t>(state[0]));
    MDEBUG("THP: handshake done, pairing state " << (int)state[0]);
  }

  void ProtocolThp::write_app(Transport & transport, uint16_t msg_type, const google::protobuf::Message & msg){
    std::string plain = std::string(1, static_cast<char>(m_session_id)) + be16(msg_type) + msg.SerializeAsString();
    const std::string ct = crypto::aes_gcm_encrypt(wiped(m_key_request), m_nonce_request++, std::string(), plain);
    wipe(plain);
    send_data(transport, ENCRYPTED_TRANSPORT, ct);
  }

  void ProtocolThp::read_app(Transport & transport, uint16_t & msg_type, std::string & data){
    while (true){
      uint8_t ctrl; std::string payload, plain;
      recv_data(transport, ctrl, payload);
      if (ctrl != ENCRYPTED_TRANSPORT){
        throw exc::ProtocolException("THP: expected encrypted transport message");
      }
      if (!crypto::aes_gcm_decrypt(wiped(m_key_response), m_nonce_response++, std::string(), payload, plain) || plain.size() < 3){
        m_connected = false;
        throw exc::SecurityException("THP: cannot decrypt message");
      }
      const uint8_t sid = static_cast<uint8_t>(plain[0]);
      msg_type = read_be16(plain, 1);
      data = plain.substr(3);
      wipe(plain);
      if (sid != m_session_id){
        MWARNING("THP: dropping message for session " << (int)sid << " (active " << (int)m_session_id << ")");
        continue;
      }
      return;
    }
  }

  template<class T>
  T ProtocolThp::call_app(Transport & transport, const Callbacks & callbacks, uint16_t req_type,
                          const google::protobuf::Message & req, uint16_t resp_type){
    write_app(transport, req_type, req);
    bool button = false;
    while (true){
      uint16_t type; std::string data;
      read_app(transport, type, data);
      if (button && callbacks.on_button_pressed){
        callbacks.on_button_pressed();
      }
      button = false;

      if (type == MT_ButtonRequest){
        messages::common::ButtonRequest br;
        br.ParseFromString(data);
        if (callbacks.on_button_request) callbacks.on_button_request(br.code());
        write_app(transport, MT_ButtonAck, messages::common::ButtonAck());
        button = true;
        continue;
      }
      if (type == MT_Failure){
        messages::common::Failure f;
        f.ParseFromString(data);
        throw_failure_exception(&f);
      }
      if (type != resp_type){
        throw exc::ProtocolException("THP: unexpected message " + std::to_string(type) + ", expected " + std::to_string(resp_type));
      }
      T resp;
      if (!resp.ParseFromString(data)){
        throw exc::EncodingException("THP: cannot parse message " + std::to_string(type));
      }
      return resp;
    }
  }

  void ProtocolThp::pairing(Transport & transport, const Callbacks & callbacks, CredentialStore & store,
                            const std::string & host_name, const std::string & app_name){
    namespace t = messages::thp;
    if (std::find(m_pairing_methods.begin(), m_pairing_methods.end(), (uint32_t)t::CodeEntry) == m_pairing_methods.end()){
      throw exc::ProtocolException("THP: Trezor does not offer Code Entry pairing");
    }

    t::ThpPairingRequest req;
    req.set_host_name(host_name);
    req.set_app_name(app_name);
    call_app<t::ThpPairingRequestApproved>(transport, callbacks, t::ThpMessageType_ThpPairingRequest, req, t::ThpMessageType_ThpPairingRequestApproved);

    t::ThpSelectMethod sel;
    sel.set_selected_pairing_method(t::CodeEntry);
    const auto commitment = call_app<t::ThpCodeEntryCommitment>(transport, callbacks, t::ThpMessageType_ThpSelectMethod, sel, t::ThpMessageType_ThpCodeEntryCommitment);

    t::ThpCodeEntryChallenge chal;
    chal.set_challenge(crypto::random_bytes(16));
    const auto cpace_trezor = call_app<t::ThpCodeEntryCpaceTrezor>(transport, callbacks, t::ThpMessageType_ThpCodeEntryChallenge, chal, t::ThpMessageType_ThpCodeEntryCpaceTrezor);

    boost::optional<std::string> code;
    if (callbacks.on_pairing_code_request){
      code = callbacks.on_pairing_code_request();
    }
    if (!code){
      throw exc::proto::CancelledException("THP: pairing cancelled, no code entered");
    }
    std::string code_str;
    for (char ch : code.get()) if (ch >= '0' && ch <= '9') code_str.push_back(ch);
    if (code_str.size() != 6){
      throw exc::ProtocolException("THP: the pairing code must have 6 digits");
    }

    const std::string & hh = m_noise->handshake_hash();
    std::string host_pub, shared;
    cpace_host(code_str, hh, cpace_trezor.cpace_trezor_public_key(), host_pub, shared);
    t::ThpCodeEntryCpaceHostTag tag;
    tag.set_cpace_host_public_key(host_pub);
    tag.set_tag(crypto::sha256(shared));
    wipe(shared);
    const auto secret = call_app<t::ThpCodeEntrySecret>(transport, callbacks, t::ThpMessageType_ThpCodeEntryCpaceHostTag, tag, t::ThpMessageType_ThpCodeEntrySecret);

    if (crypto::sha256(secret.secret()) != commitment.commitment()){
      throw exc::SecurityException("THP: pairing commitment mismatch");
    }
    if (code_entry_code(hh, secret.secret(), chal.challenge()) != static_cast<uint32_t>(std::stoul(code_str))){
      throw exc::SecurityException("THP: pairing code mismatch");
    }

    t::ThpCredentialRequest creq;
    creq.set_host_static_public_key(crypto::x25519_base(wiped(m_host_static_privkey)));
    const auto cresp = call_app<t::ThpCredentialResponse>(transport, callbacks, t::ThpMessageType_ThpCredentialRequest, creq, t::ThpMessageType_ThpCredentialResponse);

    Credential cred;
    cred.trezor_static_pubkey = cresp.trezor_static_public_key();
    cred.host_static_privkey = m_host_static_privkey;
    cred.credential = cresp.credential();
    try {
      store.save(cred);
    } catch (const std::exception & e){
      MERROR("THP: cannot store pairing credential: " << e.what());
    }
    m_pairing_state = PairingState::Paired;
  }

  void ProtocolThp::end_credential_phase(Transport & transport, const Callbacks & callbacks){
    namespace t = messages::thp;
    call_app<t::ThpEndResponse>(transport, callbacks, t::ThpMessageType_ThpEndRequest, t::ThpEndRequest(), t::ThpMessageType_ThpEndResponse);
  }

  void ProtocolThp::connect(Transport & transport, const Callbacks & callbacks, CredentialStore & store,
                            const std::string & host_name, const std::string & app_name){
    close();
    std::vector<Credential> creds = store.load();
    allocate_channel(transport);
    handshake(transport, store, creds);
    m_session_id = 0;
    if (m_pairing_state == PairingState::Unpaired){
      pairing(transport, callbacks, store, host_name, app_name);
    }
    end_credential_phase(transport, callbacks);
    m_connected = true;
  }

  void ProtocolThp::write(Transport & transport, const google::protobuf::Message & req){
    if (!m_connected){
      throw exc::NotConnectedException("THP channel is not open");
    }
    write_app(transport, static_cast<uint16_t>(MessageMapper::get_message_wire_number(req)), req);
  }

  void ProtocolThp::read(Transport & transport, std::shared_ptr<google::protobuf::Message> & msg, messages::MessageType * msg_type){
    if (!m_connected){
      throw exc::NotConnectedException("THP channel is not open");
    }
    uint16_t type; std::string data;
    read_app(transport, type, data);
    std::shared_ptr<google::protobuf::Message> msg_wrap(MessageMapper::get_message(type));
    if (!msg_wrap->ParseFromString(data)){
      wipe(data);
      throw exc::CommunicationException("Message could not be parsed");
    }
    wipe(data);
    if (msg_type){
      *msg_type = static_cast<messages::MessageType>(type);
    }
    msg = msg_wrap;
  }

  bool is_thp_device(Transport & transport){
    ProtocolV1 v1;
    messages::management::Cancel cancel;
    v1.write(transport, cancel);
    std::shared_ptr<google::protobuf::Message> resp;
    messages::MessageType type;
    v1.read(transport, resp, &type);
    if (type == messages::MessageType_Failure){
      // Failure_InvalidProtocol (17) is newer than the bundled definitions, so the
      // code lands in unknown fields; legacy firmware always sets a known code here.
      auto f = std::dynamic_pointer_cast<messages::common::Failure>(resp);
      if (f && !f->has_code()){
        return true;
      }
    }
    return false;
  }

}}
