#include "tang_server.h"

#include "esphome/core/log.h"
#include "tang_http_handler.h"

#ifdef USE_BINARY_SENSOR
#include "esphome/components/binary_sensor/binary_sensor.h"
#endif
#ifdef USE_SENSOR
#include "esphome/components/sensor/sensor.h"
#endif
#ifdef USE_TEXT_SENSOR
#include "esphome/components/text_sensor/text_sensor.h"
#endif

namespace esphome {
namespace tang_server {

static const char *const TAG = "tang_server";
// Bounded so a request flood cannot grow memory without limit.
static constexpr size_t kMaxQueuedEvents = 32;

namespace {

void wipe_string(std::string *s) {
  volatile char *p = s->empty() ? nullptr : &(*s)[0];
  for (size_t i = 0; p != nullptr && i < s->size(); ++i) {
    p[i] = '\0';
  }
  s->clear();
}

}  // namespace

float TangServerComponent::get_setup_priority() const {
  // After preferences and the network stack are available.
  return setup_priority::AFTER_WIFI;
}

void TangServerComponent::setup() {
  this->handler_ = new TangHttpHandler(this);  // NOLINT(cppcoreguidelines-owning-memory)
  // The core has consumed the secrets. Do not keep RAM copies in the component.
  wipe_string(&this->initial_password_);
  wipe_string(&this->seed_);
  for (auto &old : this->old_seeds_) {
    wipe_string(&old);
  }
  this->old_seeds_.clear();

  // Register the handler even when the core failed: requests then get a clear
  // 503 instead of an unexplained connection failure.
  web_server_base::global_web_server_base->add_handler(this->handler_);

  if (!this->handler_->ready()) {
    ESP_LOGE(TAG, "Tang core failed to start (see errors above); every request answers 503");
    this->status_set_error();
  } else {
    ESP_LOGI(TAG, "Tang server ready (%s mode)", this->unattended_ ? "unattended" : "password");
  }

#ifdef USE_BINARY_SENSOR
  if (this->active_binary_sensor_ != nullptr) {
    this->active_binary_sensor_->publish_state(this->handler_->active());
  }
#endif
#ifdef USE_SENSOR
  if (this->request_count_sensor_ != nullptr) {
    this->request_count_sensor_->publish_state(this->request_count_);
  }
  if (this->activation_count_sensor_ != nullptr) {
    this->activation_count_sensor_->publish_state(this->activation_count_);
  }
  if (this->recovery_count_sensor_ != nullptr) {
    this->recovery_count_sensor_->publish_state(this->recovery_count_);
  }
#endif
}

void TangServerComponent::loop() {
  if (this->handler_ == nullptr) {
    return;
  }

  // Key expiry runs here, on the main loop.
  if (this->handler_->loop()) {
    this->fire_deactivate();
  }

  // Drain events posted by the httpd task. Sensor and automation code must
  // only run on the main loop.
  std::deque<RequestEvent> pending;
  {
    std::lock_guard<std::mutex> lock(this->event_mutex_);
    pending.swap(this->events_);
  }
  for (const auto &event : pending) {
    this->process_event_(event);
  }
}

void TangServerComponent::post_request_event(const std::string &path, const std::string &method, int status) {
  std::lock_guard<std::mutex> lock(this->event_mutex_);
  if (this->events_.size() >= kMaxQueuedEvents) {
    this->events_.pop_front();
    ESP_LOGW(TAG, "Event queue full; dropped the oldest request event");
  }
  this->events_.push_back({path, method, status});
}

void TangServerComponent::process_event_(const RequestEvent &event) {
  const bool success = event.status >= 200 && event.status < 300;
  this->fire_request(event.path, event.method, event.status);
  if (event.path == "/activate") {
    this->fire_activate(success);
  } else if (event.path == "/deactivate" && success) {
    this->fire_deactivate();
  } else if (event.path == "/rec" || event.path.rfind("/rec/", 0) == 0) {
    this->fire_recovery(success);
  }
}

void TangServerComponent::set_unattended(bool value) { this->unattended_ = value; }
void TangServerComponent::set_seed(const std::string &value) { this->seed_ = value; }
void TangServerComponent::add_old_seed(const std::string &value) { this->old_seeds_.push_back(value); }
void TangServerComponent::set_initial_password(const std::string &value) { this->initial_password_ = value; }
void TangServerComponent::set_key_lifetime_ms(uint64_t ms) { this->key_lifetime_ms_ = ms; }
void TangServerComponent::set_reset_token(uint32_t token) { this->reset_token_ = token; }
void TangServerComponent::set_notify_requests(bool value) { this->notify_requests_ = value; }

void TangServerComponent::set_active_binary_sensor(binary_sensor::BinarySensor *sensor) {
  this->active_binary_sensor_ = sensor;
}

void TangServerComponent::set_request_count_sensor(sensor::Sensor *sensor) { this->request_count_sensor_ = sensor; }

void TangServerComponent::set_activation_count_sensor(sensor::Sensor *sensor) { this->activation_count_sensor_ = sensor; }

void TangServerComponent::set_recovery_count_sensor(sensor::Sensor *sensor) { this->recovery_count_sensor_ = sensor; }

void TangServerComponent::set_last_status_sensor(sensor::Sensor *sensor) { this->last_status_sensor_ = sensor; }

void TangServerComponent::set_last_path_text_sensor(text_sensor::TextSensor *sensor) { this->last_path_text_sensor_ = sensor; }

void TangServerComponent::set_last_method_text_sensor(text_sensor::TextSensor *sensor) {
  this->last_method_text_sensor_ = sensor;
}

void TangServerComponent::set_last_error_text_sensor(text_sensor::TextSensor *sensor) { this->last_error_text_sensor_ = sensor; }

bool TangServerComponent::unattended() const { return this->unattended_; }
const std::string &TangServerComponent::seed() const { return this->seed_; }
const std::vector<std::string> &TangServerComponent::old_seeds() const { return this->old_seeds_; }
const std::string &TangServerComponent::initial_password() const { return this->initial_password_; }
uint64_t TangServerComponent::key_lifetime_ms() const { return this->key_lifetime_ms_; }
uint32_t TangServerComponent::reset_token() const { return this->reset_token_; }

void TangServerComponent::fire_request(const std::string &path, const std::string &method, int status) {
  this->request_count_++;
#ifdef USE_SENSOR
  if (this->request_count_sensor_ != nullptr) {
    this->request_count_sensor_->publish_state(this->request_count_);
  }
  if (this->last_status_sensor_ != nullptr) {
    this->last_status_sensor_->publish_state(status);
  }
#endif
#ifdef USE_TEXT_SENSOR
  if (this->last_path_text_sensor_ != nullptr) {
    this->last_path_text_sensor_->publish_state(path);
  }
  if (this->last_method_text_sensor_ != nullptr) {
    this->last_method_text_sensor_->publish_state(method);
  }
  if (this->last_error_text_sensor_ != nullptr) {
    this->last_error_text_sensor_->publish_state(status >= 400 ? std::to_string(status) : "");
  }
#endif
  this->request_callback_.call(path, method, status);
}

void TangServerComponent::fire_activate(bool success) {
  if (success) {
    this->activation_count_++;
#ifdef USE_SENSOR
    if (this->activation_count_sensor_ != nullptr) {
      this->activation_count_sensor_->publish_state(this->activation_count_);
    }
#endif
#ifdef USE_BINARY_SENSOR
    if (this->active_binary_sensor_ != nullptr) {
      this->active_binary_sensor_->publish_state(true);
    }
#endif
  }
  this->activate_callback_.call(success);
}

void TangServerComponent::fire_deactivate() {
#ifdef USE_BINARY_SENSOR
  if (this->active_binary_sensor_ != nullptr) {
    this->active_binary_sensor_->publish_state(false);
  }
#endif
  this->deactivate_callback_.call();
}

void TangServerComponent::fire_recovery(bool success) {
  if (success) {
    this->recovery_count_++;
#ifdef USE_SENSOR
    if (this->recovery_count_sensor_ != nullptr) {
      this->recovery_count_sensor_->publish_state(this->recovery_count_);
    }
#endif
  }
  this->recovery_callback_.call(success);
}

}  // namespace tang_server
}  // namespace esphome
