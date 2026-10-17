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

// Bluetooth LE transport for Trezor (Safe 7) on macOS, built on CoreBluetooth.
// Compiled as Objective-C++ with ARC. All CoreBluetooth calls and delegate callbacks run on
// one private serial queue; the blocking C++ API below waits on a condition variable.

#import <Foundation/Foundation.h>
#import <CoreBluetooth/CoreBluetooth.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

#include "ble.hpp"

#if !__has_feature(objc_arc)
#error "ble_macos.mm must be compiled with -fobjc-arc"
#endif

namespace {

  struct LinkState {
    // central
    bool central_ready = false;
    CBManagerState central_state = CBManagerStateUnknown;
    // scan results, by peripheral identifier
    std::map<std::string, std::string> found;
    NSMutableDictionary<NSUUID *, CBPeripheral *> * peripherals = nil;
    // the single active connection
    CBPeripheral * active = nil;
    bool connected = false;
    bool disconnected = false;
    std::string error;           // last error of the step being waited for
    bool step_done = false;
    NSInteger step_code = 0;     // error code of the step, 0 on success
    NSString * step_domain = nil;
    CBCharacteristic * write_char = nil;
    CBCharacteristic * notify_char = nil;
    std::deque<std::string> inbox;
  };

  std::mutex g_mutex;
  std::condition_variable g_cv;
  LinkState g_state;

  CBUUID * service_uuid() { return [CBUUID UUIDWithString:@"8C000001-A59B-4D58-A9AD-073DF69FA1B1"]; }
  CBUUID * write_uuid()   { return [CBUUID UUIDWithString:@"8C000002-A59B-4D58-A9AD-073DF69FA1B1"]; }
  CBUUID * notify_uuid()  { return [CBUUID UUIDWithString:@"8C000003-A59B-4D58-A9AD-073DF69FA1B1"]; }

  std::string to_std(NSString * s) { return s ? std::string([s UTF8String]) : std::string(); }

  void finish_step(NSError * error) {
    // caller holds g_mutex
    g_state.step_done = true;
    g_state.step_code = error ? error.code : 0;
    g_state.step_domain = error ? error.domain : nil;
    g_state.error = error ? to_std(error.localizedDescription) : std::string();
  }
}

@interface MoneroTrezorBleDelegate : NSObject <CBCentralManagerDelegate, CBPeripheralDelegate>
@end

@implementation MoneroTrezorBleDelegate

- (void)centralManagerDidUpdateState:(CBCentralManager *)central {
  std::lock_guard<std::mutex> lock(g_mutex);
  g_state.central_state = central.state;
  g_state.central_ready = central.state != CBManagerStateUnknown && central.state != CBManagerStateResetting;
  if (central.state != CBManagerStatePoweredOn && g_state.active) {
    g_state.disconnected = true;
  }
  g_cv.notify_all();
}

- (void)centralManager:(CBCentralManager *)central didDiscoverPeripheral:(CBPeripheral *)peripheral
     advertisementData:(NSDictionary<NSString *, id> *)advertisementData RSSI:(NSNumber *)RSSI {
  std::lock_guard<std::mutex> lock(g_mutex);
  NSString * name = advertisementData[CBAdvertisementDataLocalNameKey] ?: peripheral.name;
  g_state.peripherals[peripheral.identifier] = peripheral;
  g_state.found[to_std(peripheral.identifier.UUIDString)] = to_std(name);
  g_cv.notify_all();
}

- (void)centralManager:(CBCentralManager *)central didConnectPeripheral:(CBPeripheral *)peripheral {
  std::lock_guard<std::mutex> lock(g_mutex);
  if (peripheral != g_state.active) return;
  g_state.connected = true;
  finish_step(nil);
  g_cv.notify_all();
}

- (void)centralManager:(CBCentralManager *)central didFailToConnectPeripheral:(CBPeripheral *)peripheral error:(NSError *)error {
  std::lock_guard<std::mutex> lock(g_mutex);
  if (peripheral != g_state.active) return;
  finish_step(error ?: [NSError errorWithDomain:CBErrorDomain code:CBErrorUnknown userInfo:nil]);
  g_cv.notify_all();
}

- (void)centralManager:(CBCentralManager *)central didDisconnectPeripheral:(CBPeripheral *)peripheral error:(NSError *)error {
  std::lock_guard<std::mutex> lock(g_mutex);
  if (peripheral != g_state.active) return;
  g_state.connected = false;
  g_state.disconnected = true;
  if (error) g_state.error = to_std(error.localizedDescription);
  g_cv.notify_all();
}

- (void)peripheral:(CBPeripheral *)peripheral didDiscoverServices:(NSError *)error {
  std::lock_guard<std::mutex> lock(g_mutex);
  finish_step(error);
  g_cv.notify_all();
}

- (void)peripheral:(CBPeripheral *)peripheral didDiscoverCharacteristicsForService:(CBService *)service error:(NSError *)error {
  std::lock_guard<std::mutex> lock(g_mutex);
  if (!error) {
    for (CBCharacteristic * c in service.characteristics) {
      if ([c.UUID isEqual:write_uuid()]) g_state.write_char = c;
      if ([c.UUID isEqual:notify_uuid()]) g_state.notify_char = c;
    }
  }
  finish_step(error);
  g_cv.notify_all();
}

- (void)peripheral:(CBPeripheral *)peripheral didUpdateNotificationStateForCharacteristic:(CBCharacteristic *)characteristic
             error:(NSError *)error {
  std::lock_guard<std::mutex> lock(g_mutex);
  finish_step(error);
  g_cv.notify_all();
}

- (void)peripheral:(CBPeripheral *)peripheral didWriteValueForCharacteristic:(CBCharacteristic *)characteristic error:(NSError *)error {
  std::lock_guard<std::mutex> lock(g_mutex);
  finish_step(error);
  g_cv.notify_all();
}

- (void)peripheral:(CBPeripheral *)peripheral didUpdateValueForCharacteristic:(CBCharacteristic *)characteristic error:(NSError *)error {
  if (error || ![characteristic.UUID isEqual:notify_uuid()]) return;
  NSData * value = characteristic.value;
  if (!value) return;
  std::lock_guard<std::mutex> lock(g_mutex);
  g_state.inbox.emplace_back(static_cast<const char *>(value.bytes), value.length);
  g_cv.notify_all();
}

@end

namespace {

  dispatch_queue_t g_queue = nil;
  CBCentralManager * g_central = nil;
  MoneroTrezorBleDelegate * g_delegate = nil;

  void run_async(void (^block)(void)) { dispatch_async(g_queue, block); }
  void run_sync(void (^block)(void)) { dispatch_sync(g_queue, block); }

  // Waits (holding `lock`) until `pred` is true; false on timeout.
  template<class P> bool wait_for(std::unique_lock<std::mutex> & lock, double seconds, P pred) {
    return g_cv.wait_for(lock, std::chrono::milliseconds(static_cast<long>(seconds * 1000)), pred);
  }

  void ensure_central() {
    static std::once_flag once;
    std::call_once(once, [] {
      g_state.peripherals = [NSMutableDictionary dictionary];
      g_queue = dispatch_queue_create("org.monero.trezor.ble", DISPATCH_QUEUE_SERIAL);
      g_delegate = [MoneroTrezorBleDelegate new];
      // The first use shows the macOS Bluetooth permission prompt; the app needs
      // NSBluetoothAlwaysUsageDescription in its Info.plist.
      g_central = [[CBCentralManager alloc] initWithDelegate:g_delegate queue:g_queue
                                                     options:@{CBCentralManagerOptionShowPowerAlertKey: @NO}];
    });

    std::unique_lock<std::mutex> lock(g_mutex);
    wait_for(lock, 5.0, [] { return g_state.central_ready; });
    switch (g_state.central_state) {
      case CBManagerStatePoweredOn:
        return;
      case CBManagerStatePoweredOff:
        throw std::runtime_error("Bluetooth is turned off on this Mac");
      case CBManagerStateUnauthorized:
        throw std::runtime_error("This app is not allowed to use Bluetooth (System Settings > Privacy & Security > Bluetooth)");
      case CBManagerStateUnsupported:
        throw std::runtime_error("This Mac does not support Bluetooth LE");
      default:
        throw std::runtime_error("Bluetooth is not ready");
    }
  }

  CBPeripheral * lookup(NSUUID * uuid) {
    __block CBPeripheral * p = nil;
    run_sync(^{
      {
        std::lock_guard<std::mutex> lock(g_mutex);
        p = g_state.peripherals[uuid];
      }
      if (!p) {
        p = [[g_central retrievePeripheralsWithIdentifiers:@[uuid]] firstObject];
      }
    });
    return p;
  }

  bool is_pairing_error(NSString * domain, NSInteger code) {
    if ([domain isEqualToString:CBATTErrorDomain]) {
      return code == CBATTErrorInsufficientAuthentication || code == CBATTErrorInsufficientEncryption;
    }
    if ([domain isEqualToString:CBErrorDomain]) {
      return code == CBErrorEncryptionTimedOut;
    }
    return false;
  }

  class MacConnection : public hw::trezor::ble::Connection {
  public:
    explicit MacConnection(CBPeripheral * p) : m_peripheral(p), m_closed(false) {}
    ~MacConnection() override { try { close(); } catch (...) {} }

    void write(const void * data, size_t size) override {
      NSData * value = [NSData dataWithBytes:data length:size];
      std::unique_lock<std::mutex> lock(g_mutex);
      check_link();
      CBCharacteristic * c = g_state.write_char;
      g_state.step_done = false;
      CBPeripheral * p = m_peripheral;
      run_async(^{ [p writeValue:value forCharacteristic:c type:CBCharacteristicWriteWithResponse]; });
      if (!wait_for(lock, 10.0, [] { return g_state.step_done || g_state.disconnected; })) {
        throw std::runtime_error("Bluetooth write timed out");
      }
      check_link();
      if (g_state.step_code != 0) {
        throw std::runtime_error("Bluetooth write failed: " + g_state.error);
      }
    }

    size_t read(void * data, size_t size, int timeout_ms) override {
      std::unique_lock<std::mutex> lock(g_mutex);
      auto ready = [] { return !g_state.inbox.empty() || g_state.disconnected; };
      if (timeout_ms < 0) {
        g_cv.wait(lock, ready);
      } else if (!g_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), ready)) {
        return 0;
      }
      if (g_state.inbox.empty()) {
        check_link();
      }
      std::string packet = std::move(g_state.inbox.front());
      g_state.inbox.pop_front();
      const size_t n = std::min(size, packet.size());
      memcpy(data, packet.data(), n);
      return n;
    }

    void close() override {
      if (m_closed) return;
      m_closed = true;
      CBPeripheral * p = m_peripheral;
      CBCharacteristic * c = nil;
      {
        std::lock_guard<std::mutex> lock(g_mutex);
        c = g_state.notify_char;
        g_state.active = nil;
        g_state.inbox.clear();
        g_state.write_char = nil;
        g_state.notify_char = nil;
      }
      run_async(^{
        if (c && p.state == CBPeripheralStateConnected) [p setNotifyValue:NO forCharacteristic:c];
        [g_central cancelPeripheralConnection:p];
      });
    }

  private:
    void check_link() {
      // caller holds g_mutex
      if (g_state.disconnected || !g_state.connected) {
        throw std::runtime_error("Bluetooth connection to the Trezor was lost" +
                                 (g_state.error.empty() ? std::string() : ": " + g_state.error));
      }
    }

    CBPeripheral * m_peripheral;
    bool m_closed;
  };
}

namespace hw {
namespace trezor {
namespace ble {

  std::vector<DeviceInfo> scan(double seconds) {
    ensure_central();
    {
      std::lock_guard<std::mutex> lock(g_mutex);
      g_state.found.clear();
    }
    run_async(^{
      // Trezors already connected to this Mac (bonded) do not always advertise.
      NSArray<CBPeripheral *> * connected = [g_central retrieveConnectedPeripheralsWithServices:@[service_uuid()]];
      {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (CBPeripheral * p in connected) {
          g_state.peripherals[p.identifier] = p;
          g_state.found[to_std(p.identifier.UUIDString)] = to_std(p.name);
        }
        g_cv.notify_all();
      }
      [g_central scanForPeripheralsWithServices:@[service_uuid()] options:nil];
    });

    std::vector<DeviceInfo> res;
    {
      std::unique_lock<std::mutex> lock(g_mutex);
      // stop early once something answered, but give other devices a moment
      if (wait_for(lock, seconds, [] { return !g_state.found.empty(); })) {
        wait_for(lock, std::min(seconds, 0.5), [] { return false; });
      }
      for (const auto & kv : g_state.found) {
        res.push_back(DeviceInfo{kv.first, kv.second});
      }
    }
    run_sync(^{ [g_central stopScan]; });
    return res;
  }

  std::unique_ptr<Connection> open(const std::string & device_id) {
    ensure_central();
    NSUUID * uuid = [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String:device_id.c_str()]];
    if (!uuid) {
      throw std::runtime_error("Invalid Bluetooth device id: " + device_id);
    }
    CBPeripheral * p = lookup(uuid);
    if (!p) {
      scan(5.0);
      p = lookup(uuid);
    }
    if (!p) {
      throw std::runtime_error("Trezor not found over Bluetooth: turn it on and keep it close to the Mac");
    }

    std::unique_lock<std::mutex> lock(g_mutex);
    if (g_state.active && g_state.active != p) {
      throw std::runtime_error("Another Bluetooth Trezor connection is already open");
    }
    g_state.active = p;
    g_state.connected = false;
    g_state.disconnected = false;
    g_state.inbox.clear();
    g_state.write_char = nil;
    g_state.notify_char = nil;
    g_state.error.clear();
    std::unique_ptr<MacConnection> conn(new MacConnection(p));

    // 1. connect
    g_state.step_done = false;
    run_async(^{
      p.delegate = g_delegate;
      [g_central connectPeripheral:p options:nil];
    });
    if (!wait_for(lock, 20.0, [] { return g_state.step_done; }) || g_state.step_code != 0) {
      const std::string why = g_state.error;
      lock.unlock();
      conn->close();
      throw std::runtime_error("Could not connect to the Trezor over Bluetooth" + (why.empty() ? std::string() : ": " + why));
    }

    auto step = [&](const char * what, double seconds, void (^block)(void)) {
      g_state.step_done = false;
      run_async(block);
      if (!wait_for(lock, seconds, [] { return g_state.step_done || g_state.disconnected; })) {
        throw std::runtime_error(std::string("Bluetooth: timed out while ") + what);
      }
      if (g_state.disconnected) {
        throw std::runtime_error(std::string("Bluetooth: connection lost while ") + what);
      }
    };

    try {
      // 2. find the Trezor service and its two characteristics
      step("discovering services", 15.0, ^{ [p discoverServices:@[service_uuid()]]; });
      if (g_state.step_code != 0) throw std::runtime_error("Bluetooth service discovery failed: " + g_state.error);
      CBService * service = nil;
      for (CBService * s in p.services) {
        if ([s.UUID isEqual:service_uuid()]) service = s;
      }
      if (!service) throw std::runtime_error("This Bluetooth device is not a Trezor");
      step("discovering characteristics", 15.0, ^{
        [p discoverCharacteristics:@[write_uuid(), notify_uuid()] forService:service];
      });
      if (g_state.step_code != 0 || !g_state.write_char || !g_state.notify_char) {
        throw std::runtime_error("Trezor Bluetooth characteristics not found");
      }

      // 3. subscribe; on an unpaired link this fails with an authentication error while macOS
      //    shows the pairing dialog, so retry until the user has confirmed the code.
      CBCharacteristic * notify = g_state.notify_char;
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(120);
      while (true) {
        step("subscribing (confirm the pairing code on the Trezor and on the Mac)", 60.0, ^{
          [p setNotifyValue:YES forCharacteristic:notify];
        });
        if (g_state.step_code == 0) break;
        if (!is_pairing_error(g_state.step_domain, g_state.step_code) || std::chrono::steady_clock::now() > deadline) {
          if ([g_state.step_domain isEqualToString:CBErrorDomain] && g_state.step_code == CBErrorPeerRemovedPairingInformation) {
            throw std::runtime_error("The Trezor forgot this Mac: remove it in System Settings > Bluetooth and pair again");
          }
          throw std::runtime_error("Bluetooth pairing with the Trezor failed: " + g_state.error);
        }
        wait_for(lock, 1.0, [] { return g_state.disconnected; });
        if (g_state.disconnected) throw std::runtime_error("Bluetooth: connection lost during pairing");
      }

      // THP over Bluetooth uses 244-byte packets, which needs an ATT MTU of at least 247.
      const NSUInteger mtu_payload = [p maximumWriteValueLengthForType:CBCharacteristicWriteWithoutResponse];
      NSLog(@"Trezor Bluetooth connected, max write without response: %lu bytes", (unsigned long)mtu_payload);
    } catch (...) {
      lock.unlock();
      conn->close();
      throw;
    }

    return std::unique_ptr<Connection>(conn.release());
  }

}}}
