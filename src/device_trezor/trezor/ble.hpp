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

#ifndef MONERO_TREZOR_BLE_HPP
#define MONERO_TREZOR_BLE_HPP

// Minimal Bluetooth LE access to a Trezor (Safe 7) for the THP transport.
// Plain C++ interface; the macOS implementation (CoreBluetooth) lives in ble_macos.mm.
//
// Trezor GATT service (trezor-firmware nordic/trezor/trezor-ble/src/ble/ble_internal.h):
//   service 8c000001-a59b-4d58-a9ad-073df69fa1b1
//   8c000002-...  host -> device, write
//   8c000003-...  device -> host, notify
// Every attribute needs an encrypted link, so the first subscription makes macOS ask the
// user to pair (LE Secure Connections, numeric comparison on the Trezor screen).

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace hw {
namespace trezor {
namespace ble {

  constexpr size_t PACKET_SIZE = 244;

  struct DeviceInfo {
    std::string id;    // CoreBluetooth peripheral identifier (UUID string)
    std::string name;  // advertised name, may be empty
  };

  // Lists Trezors that are connected to this Mac or advertising nearby.
  // Scans for at most `seconds`. Throws std::runtime_error when Bluetooth is off or not allowed.
  std::vector<DeviceInfo> scan(double seconds);

  class Connection {
  public:
    virtual ~Connection() = default;
    // Sends one packet (write with response). Throws std::runtime_error on failure.
    virtual void write(const void * data, size_t size) = 0;
    // Waits for one notification packet and returns its size (<= `size`).
    // timeout_ms < 0 waits until data arrives or the link drops. Throws on disconnect.
    virtual size_t read(void * data, size_t size, int timeout_ms) = 0;
    virtual void close() = 0;
  };

  // Connects, subscribes to notifications (pairing with the OS on first use).
  // Throws std::runtime_error with a readable reason on failure.
  std::unique_ptr<Connection> open(const std::string & device_id);

}}}

#endif // MONERO_TREZOR_BLE_HPP
