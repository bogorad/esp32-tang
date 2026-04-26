#pragma once

#include <string>

struct TangResponse {
  int status = 500;
  std::string content_type = "text/plain";
  std::string body;
};
