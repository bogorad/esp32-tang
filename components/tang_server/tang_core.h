#pragma once

#include <cstdint>
#include <string>

#include "tang_crypto.h"
#include "tang_platform.h"
#include "tang_request.h"
#include "tang_response.h"
#include "tang_storage.h"

class TangServerCore {
 public:
  static constexpr uint32_t kDefaultKeyLifetimeMs = 3600000;

  TangServerCore(TangStorage *storage, TangClock *clock, TangLogger *logger);

  bool setup(const char *initial_password);
  void loop();
  TangResponse handle_request(const TangRequest &request);

  bool is_active() const;

 private:
  TangResponse handle_adv();
  TangResponse handle_pub();
  TangResponse handle_activate(const TangRequest &request);
  TangResponse handle_deactivate(const TangRequest &request);
  TangResponse handle_recovery(const TangRequest &request);

  void deactivate_server();
  bool load_admin_key();
  bool initialize_storage(const char *initial_password);

  TangStorage *storage_;
  TangClock *clock_;
  TangLogger *logger_;
  tang::TangRngContext rng_;
  bool initialized_;
  bool active_;
  uint32_t activation_timestamp_;
  uint8_t tang_private_key_[tang::kEcPrivateKeySize];
  uint8_t tang_public_key_[tang::kEcPublicKeySize];
  uint8_t admin_private_key_[tang::kEcPrivateKeySize];
  uint8_t admin_public_key_[tang::kEcPublicKeySize];
};
