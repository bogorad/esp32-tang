#include "tang_body_buffer.h"

void TangBodyBuffer::reset() {
  body_.clear();
  expected_ = 0;
  complete_ = false;
  malformed_ = false;
  too_large_ = false;
}

void TangBodyBuffer::on_chunk(const uint8_t *data, size_t len, size_t index,
                              size_t total) {
  if (index == 0) {
    reset();
    expected_ = total;
  }

  if (too_large_ || malformed_) {
    return;  // sticky until a new body starts at index 0
  }
  if (total > kTangMaxBodySize || index > kTangMaxBodySize ||
      len > kTangMaxBodySize || index + len > kTangMaxBodySize) {
    too_large_ = true;
    body_.clear();
    return;
  }
  if ((data == nullptr && len > 0) || index != body_.size() ||
      index + len > total || expected_ != total) {
    malformed_ = true;
    body_.clear();
    return;
  }

  body_.append(reinterpret_cast<const char *>(data), len);
  complete_ = (index + len == total);
}

TangBodyBuffer::Status TangBodyBuffer::status(size_t content_length) const {
  if (content_length > kTangMaxBodySize || too_large_) {
    return Status::kTooLarge;
  }
  if (malformed_ || expected_ != content_length) {
    return Status::kMalformed;
  }
  if (!complete_ || body_.size() != content_length) {
    return Status::kIncomplete;
  }
  return Status::kOk;
}

std::string TangBodyBuffer::take() {
  std::string out;
  out.swap(body_);
  reset();
  return out;
}
