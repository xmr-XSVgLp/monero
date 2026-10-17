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

// Manual test tool for Trezor devices using the Trezor-Host Protocol (Safe 7).
// Connects (pairing if needed), prints the device model and the Monero address.
//
//   thp_tool [device path, e.g. udp:127.0.0.1:21324, webusb or ble]
//   Bluetooth (macOS): MONERO_TREZOR_BLE=1 thp_tool ble   (scans even with a cable connected)
//   Emulator Bluetooth interface: MONERO_TREZOR_UDP_BLE=1 thp_tool udp
//
// The pairing code is read from stdin, or from the file named by THP_CODE_FILE
// when it appears (used for automated emulator tests).

#include <fstream>
#include <iostream>
#include <thread>
#include <boost/filesystem.hpp>
#include "device_trezor/device_trezor.hpp"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "misc_log_ex.h"
#include "string_tools.h"

namespace {
  class tool_callback : public hw::i_device_callback {
  public:
    void on_button_request(uint64_t code) override { std::cout << "[device] confirm on the Trezor (button request " << code << ")" << std::endl; }
    void on_button_pressed() override { std::cout << "[device] confirmed" << std::endl; }
    boost::optional<epee::wipeable_string> on_passphrase_request(bool & on_device) override {
      const char * pp = getenv("THP_PASSPHRASE");
      std::cout << "[device] passphrase requested, using " << (pp ? "THP_PASSPHRASE" : "an empty passphrase") << std::endl;
      on_device = false;
      return epee::wipeable_string(pp ? pp : "");
    }
    boost::optional<std::string> on_pairing_code_request() override {
      const char * f = getenv("THP_CODE_FILE");
      if (f && *f) {
        std::cout << "[device] waiting for pairing code in " << f << std::endl;
        for (int i = 0; i < 600; ++i) {
          std::ifstream in(f);
          std::string code;
          if (in >> code && code.size() == 6) {
            std::cout << "[device] pairing code " << code << std::endl;
            boost::filesystem::remove(f);
            return code;
          }
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return boost::none;
      }
      std::cout << "Enter the 6-digit pairing code shown on the Trezor: " << std::flush;
      std::string code;
      if (!std::getline(std::cin, code)) return boost::none;
      return code;
    }
  };
}

int main(int argc, char ** argv)
{
  mlog_configure("", true);
  mlog_set_log(getenv("THP_LOG") ? getenv("THP_LOG") : "1,device.trezor*:DEBUG");

  if (argc > 2 && std::string(argv[1]) == "--elligator2") {
    std::string in;
    epee::string_tools::parse_hexstr_to_binbuff(std::string(argv[2]), in);
    std::cout << epee::string_tools::buff_to_hex_nodelimer(hw::trezor::thp::crypto::elligator2(in)) << std::endl;
    return 0;
  }

  const std::string path = argc > 1 ? argv[1] : "";
  tool_callback cb;
  hw::trezor::device_trezor dev;
  dev.set_name(std::string("Trezor:") + path);
  dev.set_network_type(cryptonote::MAINNET);
  dev.set_callback(&cb);

  try {
    if (!dev.init() || !dev.connect()) {
      std::cerr << "FAIL: could not connect" << std::endl;
      return 1;
    }
    std::cout << "connected, THP: " << (dev.is_thp() ? "yes" : "no") << std::endl;

    if (getenv("THP_OPEN_FLOW")) {
      // Same steps as wallet2 when opening a Trezor wallet: empty passphrase first, then the real one
      cryptonote::account_public_address a0, a1;
      if (!dev.get_public_address_with_no_passphrase(a0)) { std::cerr << "FAIL: no-passphrase address" << std::endl; return 1; }
      dev.reset_session();
      if (!dev.get_public_address(a1)) { std::cerr << "FAIL: passphrase address" << std::endl; return 1; }
      std::cout << "address (empty passphrase): " << cryptonote::get_account_address_as_str(cryptonote::MAINNET, false, a0) << std::endl;
      std::cout << "address (passphrase):       " << cryptonote::get_account_address_as_str(cryptonote::MAINNET, false, a1) << std::endl;
    }

    dev.device_state_reset();
    cryptonote::account_public_address addr;
    if (!dev.get_public_address(addr)) {
      std::cerr << "FAIL: could not get address" << std::endl;
      return 1;
    }
    std::cout << "address: " << cryptonote::get_account_address_as_str(cryptonote::MAINNET, false, addr) << std::endl;

    // Second call reuses the channel and the wallet session
    auto view = dev.get_view_key();
    std::cout << "view key received: " << (view && view->has_watch_key() ? "yes" : "no") << std::endl;

    dev.disconnect();
    std::cout << "OK" << std::endl;
    return 0;
  } catch (const std::exception & e) {
    std::cerr << "FAIL: " << e.what() << std::endl;
    return 1;
  }
}
