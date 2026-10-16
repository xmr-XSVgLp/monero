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

#ifndef MONERO_PROTOCOL_THP_H
#define MONERO_PROTOCOL_THP_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <boost/optional.hpp>
#include "wipeable_string.h"
#include "transport.hpp"

namespace hw {
namespace trezor {
namespace thp {

  // Trezor-Host Protocol (THP) v2, used by Trezor Safe 7 and newer.
  // Specification: https://docs.trezor.io/trezor-firmware/common/thp/specification.html

  constexpr uint16_t BROADCAST_CID = 0xFFFF;
  constexpr size_t PACKET_SIZE = 64;
  constexpr size_t KEY_SIZE = 32;
  constexpr size_t TAG_SIZE = 16;
  constexpr uint16_t MT_THP_CREATE_NEW_SESSION = 1000;  // MessageType_ThpCreateNewSession

  enum class PairingState : uint8_t {
    Unpaired = 0,
    Paired = 1,
    PairedAutoconnect = 2,
  };

  enum TransportError : uint8_t {
    TRANSPORT_BUSY = 1,
    UNALLOCATED_CHANNEL = 2,
    DECRYPTION_FAILED = 3,
    DEVICE_LOCKED = 5,
  };

  // Pairing credential issued by the Trezor, lets the host skip pairing next time.
  struct Credential {
    std::string trezor_static_pubkey;           // 32 B
    epee::wipeable_string host_static_privkey;  // 32 B
    std::string credential;                     // opaque blob
  };

  class CredentialStore {
  public:
    virtual ~CredentialStore() = default;
    virtual std::vector<Credential> load() = 0;
    virtual void save(const Credential & cred) = 0;
  };

  // Stores credentials as a JSON file readable only by the current user.
  class FileCredentialStore : public CredentialStore {
  public:
    explicit FileCredentialStore(std::string path);
    std::vector<Credential> load() override;
    void save(const Credential & cred) override;
    static std::string default_path();
  private:
    std::string m_path;
  };

  struct Callbacks {
    // Asks the user to rewrite the 6-digit code shown on the Trezor.
    std::function<boost::optional<std::string>()> on_pairing_code_request;
    std::function<void(uint64_t)> on_button_request;
    std::function<void()> on_button_pressed;
  };

  namespace crypto {
    std::string random_bytes(size_t n);
    std::string sha256(const std::string & data);
    std::string sha512(const std::string & data);
    std::string hmac_sha256(const std::string & key, const std::string & data);
    std::string x25519(const std::string & scalar, const std::string & point);
    std::string x25519_base(const std::string & scalar);
    std::string elligator2(const std::string & input);
    // Noise AES-GCM: IV = 0^32 || BE64(nonce)
    std::string aes_gcm_encrypt(const std::string & key, uint64_t nonce, const std::string & ad, const std::string & plaintext);
    bool aes_gcm_decrypt(const std::string & key, uint64_t nonce, const std::string & ad, const std::string & ciphertext, std::string & plaintext);
    uint32_t crc32(const std::string & data);
  }

  // Host side of the Noise_XX_25519_AESGCM_SHA256 handshake as profiled by THP.
  class NoiseHandshake {
  public:
    NoiseHandshake(const std::string & prologue);
    // -> e, payload(try_to_unlock)
    std::string write_message1(const std::string & payload);
    // <- e, ee, s, es, payload(empty). Stores remote ephemeral and masked static key.
    void read_message2(const std::string & msg);
    // -> s, se, payload
    std::string write_message3(const epee::wipeable_string & host_static_privkey, const std::string & payload);
    // Derives transport keys after message 3.
    void split(std::string & key_request, std::string & key_response);

    const std::string & handshake_hash() const { return m_h; }
    const std::string & remote_ephemeral() const { return m_re; }
    const std::string & remote_static_masked() const { return m_rs; }
  private:
    void mix_hash(const std::string & data);
    void mix_key(const std::string & ikm);
    std::string m_h, m_ck, m_k;
    uint64_t m_n;
    epee::wipeable_string m_e_priv;
    std::string m_e_pub, m_re, m_rs;
  };

  // Matches a stored credential to the masked static key sent in the handshake.
  bool credential_matches(const Credential & cred, const std::string & trezor_ephemeral, const std::string & trezor_masked_static);

  // CPace (CPACE-X25519-SHA512) host step for Code Entry pairing.
  void cpace_host(const std::string & code, const std::string & handshake_hash, const std::string & trezor_pubkey,
                  std::string & host_pubkey, std::string & shared_secret);

  uint32_t code_entry_code(const std::string & handshake_hash, const std::string & secret, const std::string & challenge);
}

  class ProtocolThp : public Protocol {
  public:
    ProtocolThp();
    ~ProtocolThp() override = default;

    // Allocates a channel, performs the handshake and pairing (or uses a stored credential).
    void connect(Transport & transport, const thp::Callbacks & callbacks, thp::CredentialStore & store,
                 const std::string & host_name, const std::string & app_name);
    bool is_connected() const { return m_connected; }
    void close();

    void write(Transport & transport, const google::protobuf::Message & req) override;
    void read(Transport & transport, std::shared_ptr<google::protobuf::Message> & msg, messages::MessageType * msg_type=nullptr) override;

    // Session 0 is seedless; wallet sessions are created with ThpCreateNewSession.
    uint8_t session_id() const { return m_session_id; }
    void set_session_id(uint8_t id) { m_session_id = id; }
    uint8_t next_session_id();

    const std::string & internal_model() const { return m_internal_model; }
    uint16_t channel_id() const { return m_cid; }

    // Raw application-layer exchange used by pairing; message types are THP wire numbers.
    void write_app(Transport & transport, uint16_t msg_type, const google::protobuf::Message & msg);
    void read_app(Transport & transport, uint16_t & msg_type, std::string & data);

  private:
    void allocate_channel(Transport & transport);
    void handshake(Transport & transport, thp::CredentialStore & store, std::vector<thp::Credential> & creds);
    void pairing(Transport & transport, const thp::Callbacks & callbacks, thp::CredentialStore & store,
                 const std::string & host_name, const std::string & app_name);
    void end_credential_phase(Transport & transport, const thp::Callbacks & callbacks);

    template<class T> T call_app(Transport & transport, const thp::Callbacks & callbacks, uint16_t req_type,
                                 const google::protobuf::Message & req, uint16_t resp_type);

    // Transport layer (L2)
    void write_packets(Transport & transport, uint8_t ctrl, uint16_t cid, const std::string & payload);
    void read_packets(Transport & transport, uint8_t & ctrl, uint16_t & cid, std::string & payload);
    void send_data(Transport & transport, uint8_t ctrl, const std::string & payload);
    void recv_data(Transport & transport, uint8_t & ctrl, std::string & payload);
    void send_ack(Transport & transport, bool seq);

    uint16_t m_cid;
    bool m_connected;
    bool m_seq_send;
    bool m_seq_recv;
    uint8_t m_session_id;
    uint8_t m_session_counter;
    std::string m_device_properties;
    std::string m_internal_model;
    std::vector<uint32_t> m_pairing_methods;

    std::unique_ptr<thp::NoiseHandshake> m_noise;
    thp::PairingState m_pairing_state;
    epee::wipeable_string m_host_static_privkey;
    epee::wipeable_string m_key_request;
    epee::wipeable_string m_key_response;
    uint64_t m_nonce_request;
    uint64_t m_nonce_response;
  };

  // Probes whether the device speaks THP: legacy firmware answers a codec v1 Cancel normally,
  // THP firmware answers with Failure(InvalidProtocol).
  bool is_thp_device(Transport & transport);

}}

#endif //MONERO_PROTOCOL_THP_H
