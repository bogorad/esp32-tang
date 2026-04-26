#include "tang_server.h"

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

void TangServerComponent::setup() {
  web_server_base::global_web_server_base->add_handler(new TangHttpHandler(this));
#ifdef USE_BINARY_SENSOR
  if (this->active_binary_sensor_ != nullptr) {
    this->active_binary_sensor_->publish_state(false);
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

void TangServerComponent::loop() {}

void TangServerComponent::set_initial_password(const std::string &value) { this->initial_password_ = value; }

void TangServerComponent::set_key_lifetime(uint32_t ms) { this->key_lifetime_ = ms; }

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

const std::string &TangServerComponent::initial_password() const { return this->initial_password_; }

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
