// Copyright (c) 2017-2022, The Monero Project
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

#include "device_trezor_base.hpp"
#include "memwipe.h"
#include "hex.h"
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/regex.hpp>
#include <boost/asio/ip/host_name.hpp>
#include "trezor/messages/messages-thp.pb.h"

namespace hw {
namespace trezor {

#ifdef WITH_DEVICE_TREZOR

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "device.trezor"
#define TREZOR_BIP44_HARDENED_ZERO 0x80000000

    const uint32_t device_trezor_base::DEFAULT_BIP44_PATH[] = {0x8000002c, 0x80000080};

    device_trezor_base::device_trezor_base(): m_callback(nullptr), m_last_msg_type(messages::MessageType_Success),
                                              m_reply_with_empty_passphrase(false),
                                              m_always_use_empty_passphrase(false),
                                              m_seen_passphrase_entry_message(false),
                                              m_thp_session_ready(false),
                                              m_thp_gen(0),
                                              m_thp_cur_gen(0),
                                              m_thp_app_name("Monero") {
#ifdef WITH_TREZOR_DEBUGGING
      m_debug = false;
#endif
    }

    device_trezor_base::~device_trezor_base() {
      try {
        disconnect();
        release();
      } catch(std::exception const& e){
        MERROR("Could not disconnect and release: " << e.what());
      }
    }

    /* ======================================================================= */
    /*                              SETUP/TEARDOWN                             */
    /* ======================================================================= */

    bool device_trezor_base::reset() {
      return false;
    }

    bool device_trezor_base::set_name(const std::string & name) {
      this->m_full_name = name;
      this->name = "";

      auto delim = name.find(':');
      if (delim != std::string::npos && delim + 1 < name.length()) {
        this->name = name.substr(delim + 1);
      }

      return true;
    }

    const std::string device_trezor_base::get_name() const {
      if (this->m_full_name.empty()) {
        return std::string("<disconnected:").append(this->name).append(">");
      }
      return this->m_full_name;
    }

    bool device_trezor_base::init() {
      if (!release()){
        MERROR("Release failed");
        return false;
      }

      return true;
    }

    bool device_trezor_base::release() {
      try {
        disconnect();
        return true;

      } catch(std::exception const& e){
        MERROR("Release exception: " << e.what());
        return false;
      }
    }

    // What is known of each Trezor connected since the app started, by transport path
    static std::mutex s_known_devices_mutex;
    static std::map<std::string, device_trezor_base::device_info> s_known_devices;
    static std::string s_last_device_path;

    bool device_trezor_base::connect() {
      // a wallet created as "Trezor:<path>" asks for that Trezor, otherwise the one the user picked
      return connect_path(!this->name.empty() ? this->name : get_preferred_path());
    }

    bool device_trezor_base::connect_path(const std::string & spec) {
      disconnect();

      // Enumerate all available devices
      TREZOR_AUTO_LOCK_DEVICE();
      try {
        hw::trezor::t_transport_vect trans;

        MDEBUG("Enumerating Trezor devices...");
        enumerate(trans, boost::starts_with(spec, "ble:"));
        sort_transports_by_env(trans);

        MDEBUG("Enumeration yielded " << trans.size() << " Trezor devices");
        for (auto &cur : trans) {
          MDEBUG("  device: " << *(cur.get()));
        }

        for (auto &cur : trans) {
          std::string cur_path = cur->get_path();
          if (boost::starts_with(cur_path, spec)) {
            MDEBUG("Device Match: " << cur_path);
            m_transport = cur;
            break;
          }
        }

        if (!m_transport) {
          MERROR("No matching Trezor device found. Device specifier: \"" + spec + "\"");
          return false;
        }

        try {
          m_transport->open();
        } catch (const std::exception & e) {
          // the Bluetooth Trezor seen before went away: look for Trezors again with a real scan
          if (!boost::starts_with(m_transport->get_path(), "ble:"))
            throw;
          MDEBUG("Known Bluetooth Trezor did not answer, scanning again: " << e.what());
          forget_ble_device();
          m_transport = nullptr;
          trans.clear();
          enumerate(trans, true);
          sort_transports_by_env(trans);
          for (auto &cur : trans) {
            if (boost::starts_with(cur->get_path(), spec)) {
              m_transport = cur;
              break;
            }
          }
          if (!m_transport) {
            MERROR("No matching Trezor device found. Device specifier: \"" + spec + "\"");
            return false;
          }
          m_transport->open();
        }
        {
          std::lock_guard<std::mutex> lock(s_known_devices_mutex);
          s_last_device_path = m_transport->get_path();
        }

        // Bridge transport has no raw protocol access, THP needs direct USB/UDP/Bluetooth
        if (m_transport->get_protocol() && (m_transport->requires_thp() || is_thp_device(*m_transport))) {
          MDEBUG("Device uses the Trezor-Host Protocol");
          thp_connect();
        }

#ifdef WITH_TREZOR_DEBUGGING
        setup_debug();
#endif
        return true;

      } catch(std::exception const& e){
        MERROR("Open exception: " << e.what());
        return false;
      }
    }

    bool device_trezor_base::disconnect() {
      TREZOR_AUTO_LOCK_DEVICE();
      m_device_session_id.clear();
      m_features.reset();
      m_seen_passphrase_entry_message = false;
      m_reply_with_empty_passphrase = false;
      m_always_use_empty_passphrase = false;
      m_thp_session_ready = false;
      if (m_thp){
        // keep an open channel: a wallet parked in the background may come back to its session on it
        if (m_thp->is_connected() && m_transport){
          auto & kept = m_thp_kept[m_transport->get_path()];
          if (kept.first && kept.first != m_thp) kept.first->close();
          kept = std::make_pair(m_thp, m_thp_cur_gen);
        } else {
          m_thp->close();
        }
        m_thp = nullptr;
      }

      if (m_transport){
        try {
          m_transport->close();
          m_transport = nullptr;

        } catch(std::exception const& e){
          MERROR("Disconnect exception: " << e.what());
          m_transport = nullptr;
          return false;
        }
      }

#ifdef WITH_TREZOR_DEBUGGING
      if (m_debug_callback) {
        m_debug_callback->on_disconnect();
        m_debug_callback = nullptr;
      }
#endif
      return true;
    }

    /* ======================================================================= */
    /*  LOCKER                                                                 */
    /* ======================================================================= */

    //lock the device for a long sequence
    void device_trezor_base::lock() {
      MTRACE("Ask for LOCKING for device " << this->name << " in thread ");
      device_locker.lock();
      MTRACE("Device " << this->name << " LOCKed");
    }

    //lock the device for a long sequence
    bool device_trezor_base::try_lock() {
      MTRACE("Ask for LOCKING(try) for device " << this->name << " in thread ");
      bool r = device_locker.try_lock();
      if (r) {
        MTRACE("Device " << this->name << " LOCKed(try)");
      } else {
        MDEBUG("Device " << this->name << " not LOCKed(try)");
      }
      return r;
    }

    //unlock the device
    void device_trezor_base::unlock() {
      MTRACE("Ask for UNLOCKING for device " << this->name << " in thread ");
      device_locker.unlock();
      MTRACE("Device " << this->name << " UNLOCKed");
    }

    /* ======================================================================= */
    /*  Helpers                                                                */
    /* ======================================================================= */

    void device_trezor_base::require_connected() const {
      if (!m_transport){
        throw exc::NotConnectedException();
      }
    }

    void device_trezor_base::require_initialized() const {
      if (!m_features){
        throw exc::TrezorException("Device state not initialized");
      }

      if (m_features->has_bootloader_mode() && m_features->bootloader_mode()){
        throw exc::TrezorException("Device is in the bootloader mode");
      }

      if (m_features->has_firmware_present() && !m_features->firmware_present()){
        throw exc::TrezorException("Device has no firmware loaded");
      }

      // Hard requirement on initialized field, has to be there.
      if (!m_features->has_initialized() || !m_features->initialized()){
        throw exc::TrezorException("Device is not initialized");
      }
    }

    void device_trezor_base::call_ping_unsafe(){
      auto pingMsg = std::make_shared<messages::management::Ping>();
      pingMsg->set_message("PING");

      auto success = this->client_exchange<messages::common::Success>(pingMsg);  // messages::MessageType_Success
      MDEBUG("Ping response " << success->message());
      (void)success;
    }

    void device_trezor_base::test_ping(){
      require_connected();

      try {
        this->call_ping_unsafe();

      } catch(exc::TrezorException const& e){
        MINFO("Trezor does not respond: " << e.what());
        throw exc::DeviceNotResponsiveException(std::string("Trezor not responding: ") + e.what());
      }
    }

    void device_trezor_base::write_raw(const google::protobuf::Message * msg){
      require_connected();
      CHECK_AND_ASSERT_THROW_MES(msg, "Empty message");
      this->get_transport()->write(*msg);
    }

    GenericMessage device_trezor_base::read_raw(){
      require_connected();
      std::shared_ptr<google::protobuf::Message> msg_resp;
      hw::trezor::messages::MessageType msg_resp_type;

      this->get_transport()->read(msg_resp, &msg_resp_type);
      return GenericMessage(msg_resp_type, msg_resp);
    }

    GenericMessage device_trezor_base::call_raw(const google::protobuf::Message * msg) {
      write_raw(msg);
      return read_raw();
    }

    bool device_trezor_base::message_handler(GenericMessage & input){
      // Later if needed this generic message handler can be replaced by a pointer to
      // a protocol message handler which by default points to the device class which implements
      // the default handler.

      if (m_last_msg_type == messages::MessageType_ButtonRequest){
        on_button_pressed();
      }
      m_last_msg_type = input.m_type;

      switch(input.m_type){
        case messages::MessageType_ButtonRequest:
          on_button_request(input, dynamic_cast<const messages::common::ButtonRequest*>(input.m_msg.get()));
          return true;
        case messages::MessageType_PassphraseRequest:
          on_passphrase_request(input, dynamic_cast<const messages::common::PassphraseRequest*>(input.m_msg.get()));
          return true;
        // Required for firmware using the legacy passphrase-state protocol.
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
        case messages::MessageType_Deprecated_PassphraseStateRequest:
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
          on_passphrase_state_request(input, dynamic_cast<const messages::common::Deprecated_PassphraseStateRequest*>(input.m_msg.get()));
          return true;
        case messages::MessageType_PinMatrixRequest:
          on_pin_request(input, dynamic_cast<const messages::common::PinMatrixRequest*>(input.m_msg.get()));
          return true;
        default:
          return false;
      }
    }

    void device_trezor_base::ensure_derivation_path() noexcept {
      if (m_wallet_deriv_path.empty()){
        m_wallet_deriv_path.push_back(TREZOR_BIP44_HARDENED_ZERO);  // default 0'
      }
    }

    void device_trezor_base::set_derivation_path(const std::string &deriv_path){
      this->m_wallet_deriv_path.clear();

      if (deriv_path.empty() || deriv_path == "-"){
        ensure_derivation_path();
        return;
      }

      CHECK_AND_ASSERT_THROW_MES(deriv_path.size() <= 255, "Derivation path is too long");

      std::vector<std::string> fields;
      boost::split(fields, deriv_path, boost::is_any_of("/"));
      CHECK_AND_ASSERT_THROW_MES(fields.size() <= 10, "Derivation path is too long");

      boost::regex rgx("^([0-9]+)'?$");
      boost::cmatch match;

      this->m_wallet_deriv_path.reserve(fields.size());
      for(const std::string & cur : fields){
        const bool ok = boost::regex_match(cur.c_str(), match, rgx);
        CHECK_AND_ASSERT_THROW_MES(ok, "Invalid wallet code: " << deriv_path << ". Invalid path element: " << cur);
        CHECK_AND_ASSERT_THROW_MES(match[0].length() > 0, "Invalid wallet code: " << deriv_path << ". Invalid path element: " << cur);

        const unsigned long cidx = std::stoul(match[0].str()) | TREZOR_BIP44_HARDENED_ZERO;
        this->m_wallet_deriv_path.push_back((unsigned int)cidx);
      }
    }

    /* ======================================================================= */
    /*                              TREZOR PROTOCOL                            */
    /* ======================================================================= */

    bool device_trezor_base::ping() {
      TREZOR_AUTO_LOCK_CMD();
      if (!m_transport){
        MINFO("Ping failed, device not connected");
        return false;
      }

      try {
        this->call_ping_unsafe();
        return true;

      } catch(std::exception const& e) {
        MERROR("Ping failed, exception thrown " << e.what());
      } catch(...){
        MERROR("Ping failed, general exception thrown" << boost::current_exception_diagnostic_information());
      }

      return false;
    }

    void device_trezor_base::device_state_initialize_unsafe()
    {
      require_connected();
      if (m_thp){
        if (!m_thp->is_connected()){
          thp_connect();
        }
        // Features come from the seedless session 0, wallet calls go to our own session
        const uint8_t wallet_session = m_thp->session_id();
        m_thp->set_session_id(0);
        try {
          m_features = this->client_exchange<messages::management::Features>(std::make_shared<messages::management::GetFeatures>());
        } catch(...) {
          m_thp->set_session_id(wallet_session);
          throw;
        }
        m_thp->set_session_id(wallet_session);
        remember_device_unsafe();
        if (!m_thp_session_ready){
          thp_create_session();
        }
        return;
      }

      auto initMsg = std::make_shared<messages::management::Initialize>();
      const auto data_cleaner = epee::misc_utils::create_scope_leave_handler([&]() {
        if (initMsg->has_session_id())
          memwipe(&(*initMsg->mutable_session_id())[0], initMsg->mutable_session_id()->size());
      });

      if(!m_device_session_id.empty()) {
        initMsg->set_allocated_session_id(new std::string(m_device_session_id.data(), m_device_session_id.size()));
      }

      m_features = this->client_exchange<messages::management::Features>(initMsg);
      if (m_features->has_session_id()){
        m_device_session_id = m_features->session_id();
      } else {
        m_device_session_id.clear();
      }
      remember_device_unsafe();
    }

    void device_trezor_base::remember_device_unsafe()
    {
      if (!m_transport || !m_features)
        return;
      device_info info;
      info.path = m_transport->get_path();
      info.name = m_transport->get_display_name();
      info.label = m_features->has_label() ? m_features->label() : "";
      info.model = m_features->has_model() ? m_features->model() : "";
      info.last_used = false;
      std::lock_guard<std::mutex> lock(s_known_devices_mutex);
      s_known_devices[info.path] = info;
    }

    std::vector<device_trezor_base::device_info> device_trezor_base::list_devices(bool bluetooth)
    {
      hw::trezor::t_transport_vect trans;
      enumerate(trans, bluetooth);
      std::vector<device_info> res;
      std::lock_guard<std::mutex> lock(s_known_devices_mutex);
      for (const auto & t : trans){
        device_info info;
        const auto known = s_known_devices.find(t->get_path());
        if (known != s_known_devices.end())
          info = known->second;
        info.path = t->get_path();
        if (!t->get_display_name().empty())
          info.name = t->get_display_name();
        info.last_used = info.path == s_last_device_path;
        res.push_back(info);
      }
      return res;
    }

    void device_trezor_base::device_state_reset()
    {
      TREZOR_AUTO_LOCK_CMD();
      device_state_initialize_unsafe();
    }

#ifdef WITH_TREZOR_DEBUGGING
#define TREZOR_CALLBACK_GET_DEBUG(VAR, method, ...) do { \
  if (m_debug_callback) VAR = m_debug_callback->method(__VA_ARGS__); \
} while(0)
#else
#define TREZOR_CALLBACK_GET_DEBUG(VAR, method, ...) do { } while(0)
#endif

    void device_trezor_base::thp_connect()
    {
      require_connected();
      // reuse the channel kept from the last connection to this Trezor, so the sessions on it stay valid
      const auto kept = m_thp_kept.find(m_transport->get_path());
      if (kept != m_thp_kept.end()){
        const auto channel = kept->second;
        m_thp_kept.erase(kept);
        if (!m_thp && channel.first && channel.first->is_connected()){
          m_thp = channel.first;
          m_thp_cur_gen = channel.second;
          m_transport->set_protocol(m_thp);
          m_thp->set_session_id(0);
          m_thp_session_ready = false;
          try {
            m_features = this->client_exchange<messages::management::Features>(std::make_shared<messages::management::GetFeatures>());
            remember_device_unsafe();
            MDEBUG("THP: reusing channel " << m_thp->channel_id());
            return;
          } catch (const std::exception & e) {
            MDEBUG("THP: kept channel is gone, opening a new one: " << e.what());
            m_thp->close();
            m_thp = nullptr;
          }
        } else if (channel.first && channel.first != m_thp){
          channel.first->close();
        }
      }
      m_thp_cur_gen = ++m_thp_gen;
      if (!m_thp){
        m_thp = std::make_shared<ProtocolThp>();
        m_transport->set_protocol(m_thp);
      }
      m_thp_session_ready = false;

      thp::Callbacks callbacks;
      callbacks.on_pairing_code_request = [this]() -> boost::optional<std::string> {
        boost::optional<std::string> code;
        TREZOR_CALLBACK_GET_DEBUG(code, on_pairing_code_request);
        if (m_callback) code = m_callback->on_pairing_code_request();
        return code;
      };
      callbacks.on_button_request = [this](uint64_t code) {
        if (m_callback) m_callback->on_button_request(code);
      };
      callbacks.on_button_pressed = [this]() {
        if (m_callback) m_callback->on_button_pressed();
      };

      const char * cred_path = getenv("MONERO_TREZOR_THP_CREDENTIALS");
      thp::FileCredentialStore store(cred_path && *cred_path ? std::string(cred_path) : thp::FileCredentialStore::default_path());

      std::string host_name = "Monero host";
      try {
        host_name = boost::asio::ip::host_name();
      } catch(const std::exception & e) {
        MDEBUG("Cannot determine host name: " << e.what());
      }

      m_thp->connect(*m_transport, callbacks, store, host_name, m_thp_app_name);
    }

    std::string device_trezor_base::session_handle()
    {
      TREZOR_AUTO_LOCK_DEVICE();
      if (m_thp){
        if (!m_thp_session_ready || !m_thp->is_connected())
          return "";
        return "thp:" + std::to_string(m_thp_cur_gen) + ":" + std::to_string(m_thp->session_id()) + "|" + (m_transport ? m_transport->get_path() : "");
      }
      if (m_device_session_id.empty())
        return "";
      return "v1:" + epee::to_hex::string({reinterpret_cast<const uint8_t*>(m_device_session_id.data()), m_device_session_id.size()})
          + "|" + (m_transport ? m_transport->get_path() : "");
    }

    bool device_trezor_base::resume_session(const std::string & handle)
    {
      TREZOR_AUTO_LOCK_DEVICE();
      try {
        // "<kind>:<session>|<transport path>"
        const auto bar = handle.find('|');
        const std::string session = handle.substr(0, bar);
        const std::string path = bar == std::string::npos ? "" : handle.substr(bar + 1);

        // the session lives on the Trezor this wallet used, which is not always the one connected now
        if (!path.empty() && (!m_transport || m_transport->get_path() != path)){
          if (this->name.empty())
            set_preferred_path(path);
          if (!connect_path(path))
            return false;
        } else if (!m_transport && !connect()){
          return false;
        }

        if (boost::starts_with(session, "thp:")){
          std::vector<std::string> parts;
          boost::split(parts, session, boost::is_any_of(":"));
          if (parts.size() != 3)
            return false;
          const unsigned long gen = std::stoul(parts[1]);
          const unsigned long sid = std::stoul(parts[2]);
          if (sid == 0 || sid > 0xff)
            return false;
          if (!m_thp || !m_thp->is_connected() || gen != m_thp_cur_gen)
            return false;
          m_thp->set_session_id(static_cast<uint8_t>(sid));
          m_thp_session_ready = true;
          MDEBUG("THP: resumed wallet session " << sid);
          return true;
        }
        if (boost::starts_with(session, "v1:")){
          std::string sid;
          if (!epee::from_hex::to_string(sid, boost::string_ref(session).substr(3)))
            return false;
          if (m_thp)
            return false;
          m_device_session_id = epee::wipeable_string(sid);
          return true;
        }
      } catch (const std::exception & e) {
        MERROR("Could not resume the device session: " << e.what());
      }
      return false;
    }

    boost::optional<epee::wipeable_string> device_trezor_base::resolve_passphrase(bool & on_device)
    {
      bool device_entry = false;
      if (m_features){
        for (auto it = m_features->capabilities().begin(); it != m_features->capabilities().end(); it++) {
          if (*it == messages::management::Features::Capability_PassphraseEntry){
            device_entry = true;
          }
        }
      }

      on_device = false;
      if (m_reply_with_empty_passphrase || m_always_use_empty_passphrase) {
        return epee::wipeable_string("");
      }
      if (m_passphrase) {
        MWARNING("Answering passphrase prompt with a stored passphrase (do not use; passphrase can be seen by a potential malware / attacker)");
        return m_passphrase;
      }

      on_device = device_entry;
      boost::optional<epee::wipeable_string> passphrase;
      TREZOR_CALLBACK_GET_DEBUG(passphrase, on_passphrase_request, on_device);
      if (m_callback) passphrase = m_callback->on_passphrase_request(on_device);
      if (!device_entry) on_device = false;
      return passphrase;
    }

    void device_trezor_base::thp_create_session()
    {
      CHECK_AND_ASSERT_THROW_MES(m_thp && m_features, "THP channel is not ready");
      messages::thp::ThpCreateNewSession req;
      const auto data_cleaner = epee::misc_utils::create_scope_leave_handler([&]() {
        if (req.has_passphrase())
          memwipe(&(*req.mutable_passphrase())[0], req.mutable_passphrase()->size());
      });

      if (m_features->has_passphrase_protection() && m_features->passphrase_protection()){
        m_seen_passphrase_entry_message = true;
        bool on_device = false;
        auto passphrase = resolve_passphrase(on_device);
        if (on_device){
          req.set_on_device(true);
        } else {
          req.set_passphrase(passphrase ? std::string(passphrase->data(), passphrase->size()) : std::string());
        }
      }

      const uint8_t sid = m_thp->next_session_id();
      m_thp->set_session_id(sid);
      m_thp->write_app(*m_transport, thp::MT_THP_CREATE_NEW_SESSION, req);

      auto resp = read_raw();
      while (message_handler(resp)) { }
      if (resp.m_type == messages::MessageType_Failure){
        throw_failure_exception(dynamic_cast<messages::common::Failure *>(resp.m_msg.get()));
      } else if (resp.m_type != messages::MessageType_Success){
        throw exc::UnexpectedMessageException(resp.m_type, resp.m_msg);
      }
      m_thp_session_ready = true;
      MDEBUG("THP wallet session " << (int)sid << " created");
    }

#ifdef WITH_TREZOR_DEBUGGING
#define TREZOR_CALLBACK(method, ...) do { \
  if (m_debug_callback) m_debug_callback->method(__VA_ARGS__); \
  if (m_callback) m_callback->method(__VA_ARGS__);             \
}while(0)
#define TREZOR_CALLBACK_GET(VAR, method, ...) do { \
  if (m_debug_callback) VAR = m_debug_callback->method(__VA_ARGS__); \
  if (m_callback) VAR = m_callback->method(__VA_ARGS__);             \
}while(0)

    void device_trezor_base::setup_debug(){
      if (!m_debug){
        return;
      }

      if (!m_debug_callback){
        CHECK_AND_ASSERT_THROW_MES(m_transport, "Transport does not exist");
        auto debug_transport = m_transport->find_debug();
        if (debug_transport) {
          m_debug_callback = std::make_shared<trezor_debug_callback>(debug_transport);
        } else {
          MDEBUG("Transport does not have debug link option");
        }
      }
    }

#else
#define TREZOR_CALLBACK(method, ...) do { if (m_callback) m_callback->method(__VA_ARGS__); } while(0)
#define TREZOR_CALLBACK_GET(VAR, method, ...) VAR = (m_callback ? m_callback->method(__VA_ARGS__) : boost::none)
#endif

    void device_trezor_base::on_button_request(GenericMessage & resp, const messages::common::ButtonRequest * msg)
    {
      CHECK_AND_ASSERT_THROW_MES(msg, "Empty message");
      MDEBUG("on_button_request, code: " << msg->code());

      TREZOR_CALLBACK(on_button_request, msg->code());

      messages::common::ButtonAck ack;
      write_raw(&ack);

      // the app's Cancel button can give up this wait (e.g. the Trezor froze)
      set_read_abortable(true);
      try {
        resp = read_raw();
      } catch (const exc::ReadAbortedException &) {
        MINFO("Device confirmation cancelled from the app");
        // tell the Trezor too, so it leaves the confirmation screen and the protocol stays in step
        try {
          messages::management::Cancel cancel;
          write_raw(&cancel);
          set_read_deadline(5000);
          for (int i = 0; i < 8; ++i) {
            GenericMessage r = read_raw();
            if (r.m_type == messages::MessageType_Failure || r.m_type == messages::MessageType_Success) {
              break;
            }
          }
        } catch (const std::exception & e) {
          MWARNING("Trezor did not answer the cancel: " << e.what());
        }
        set_read_deadline(0);
        set_read_abortable(false);
        m_last_msg_type = messages::MessageType_Failure;
        on_button_pressed();
        throw exc::proto::CancelledException();
      } catch (...) {
        set_read_abortable(false);
        throw;
      }
      set_read_abortable(false);
    }

    void device_trezor_base::on_button_pressed()
    {
      TREZOR_CALLBACK(on_button_pressed);
    }

    void device_trezor_base::on_pin_request(GenericMessage & resp, const messages::common::PinMatrixRequest * msg)
    {
      MDEBUG("on_pin_request");
      CHECK_AND_ASSERT_THROW_MES(msg, "Empty message");

      boost::optional<epee::wipeable_string> pin;
      TREZOR_CALLBACK_GET(pin, on_pin_request);

      if (!pin && m_pin){
        pin = m_pin;
      }

      messages::common::PinMatrixAck m;
      if (pin) {
        m.set_allocated_pin(new std::string(pin->data(), pin->size()));
      }

      const auto data_cleaner = epee::misc_utils::create_scope_leave_handler([&]() {
        if (m.has_pin())
          memwipe(&(*m.mutable_pin())[0], m.mutable_pin()->size());
      });

      resp = call_raw(&m);
    }

    void device_trezor_base::on_passphrase_request(GenericMessage & resp, const messages::common::PassphraseRequest * msg)
    {
      CHECK_AND_ASSERT_THROW_MES(msg, "Empty message");
      MDEBUG("on_passhprase_request");

      // Deprecated wire fields must remain readable for older Trezor firmware.
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
      // Backward compatibility, migration clause.
      if (msg->has__on_device() && msg->_on_device()){
        messages::common::PassphraseAck m;
        resp = call_raw(&m);
        return;
      }

      m_seen_passphrase_entry_message = true;
      bool on_device = true;
      if (msg->has__on_device() && !msg->_on_device()){
        on_device = false;  // do not enter on device, old devices.
      }

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

      if (on_device && m_features && m_features->capabilities_size() > 0){
        on_device = false;
        for (auto it = m_features->capabilities().begin(); it != m_features->capabilities().end(); it++) {
          if (*it == messages::management::Features::Capability_PassphraseEntry){
            on_device = true;
          }
        }
      }

      boost::optional<epee::wipeable_string> passphrase;
      if (m_reply_with_empty_passphrase || m_always_use_empty_passphrase) {
        MDEBUG("Answering passphrase prompt with an empty passphrase, always use empty: " << m_always_use_empty_passphrase);
        on_device = false;
        passphrase = epee::wipeable_string("");
      } else if (m_passphrase){
        MWARNING("Answering passphrase prompt with a stored passphrase (do not use; passphrase can be seen by a potential malware / attacker)");
        on_device = false;
        passphrase = epee::wipeable_string(m_passphrase.get());
      } else {
        TREZOR_CALLBACK_GET(passphrase, on_passphrase_request, on_device);
      }

      messages::common::PassphraseAck m;
      m.set_on_device(on_device);
      if (!on_device) {
        if (passphrase) {
          m.set_allocated_passphrase(new std::string(passphrase->data(), passphrase->size()));
        }
      }

      const auto data_cleaner = epee::misc_utils::create_scope_leave_handler([&]() {
        if (m.has_passphrase())
          memwipe(&(*m.mutable_passphrase())[0], m.mutable_passphrase()->size());
      });

      resp = call_raw(&m);
    }

    void device_trezor_base::on_passphrase_state_request(GenericMessage & resp, const messages::common::Deprecated_PassphraseStateRequest * msg)
    {
      MDEBUG("on_passhprase_state_request");
      CHECK_AND_ASSERT_THROW_MES(msg, "Empty message");

      if (msg->has_state()) {
        m_device_session_id = msg->state();
      }
      messages::common::Deprecated_PassphraseStateAck m;
      resp = call_raw(&m);
    }

#ifdef WITH_TREZOR_DEBUGGING
    void device_trezor_base::wipe_device()
    {
      auto msg = std::make_shared<messages::management::WipeDevice>();
      auto ret = client_exchange<messages::common::Success>(msg);
      (void)ret;
      init_device();
    }

    void device_trezor_base::init_device()
    {
      auto msg = std::make_shared<messages::management::Initialize>();
      m_features = client_exchange<messages::management::Features>(msg);
    }

    void device_trezor_base::load_device(const std::string & mnemonic, const std::string & pin,
        bool passphrase_protection, const std::string & label, const std::string & language,
        bool skip_checksum, bool expand)
    {
      if (m_features && m_features->initialized()){
        throw std::runtime_error("Device is initialized already. Call device.wipe() and try again.");
      }

      auto msg = std::make_shared<messages::management::LoadDevice>();
      msg->add_mnemonics(mnemonic);
      msg->set_pin(pin);
      msg->set_passphrase_protection(passphrase_protection);
      msg->set_label(label);
      msg->set_language(language);
      msg->set_skip_checksum(skip_checksum);
      auto ret = client_exchange<messages::common::Success>(msg);
      (void)ret;

      init_device();
    }

    trezor_debug_callback::trezor_debug_callback(std::shared_ptr<Transport> & debug_transport){
      m_debug_link = std::make_shared<DebugLink>();
      m_debug_link->init(debug_transport);
    }

    void trezor_debug_callback::on_button_request(uint64_t code) {
      if (m_debug_link) m_debug_link->press_yes();
    }

    boost::optional<epee::wipeable_string> trezor_debug_callback::on_pin_request() {
      return boost::none;
    }

    boost::optional<epee::wipeable_string> trezor_debug_callback::on_passphrase_request(bool & on_device) {
      on_device = true;
      return boost::none;
    }

    void trezor_debug_callback::on_passphrase_state_request(const std::string &state) {

    }

    void trezor_debug_callback::on_disconnect(){
      if (m_debug_link) m_debug_link->close();
    }
#endif

#endif //WITH_DEVICE_TREZOR
}}
