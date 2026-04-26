#pragma once

#include <string>

struct TangRequest {
  std::string method;
  std::string path;
  std::string body;
};
