#include "test_util.h"

#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <cstring>

namespace tt {

std::string run_command(const std::string &cmd, const std::string &input,
                        int *status) {
  // Feed stdin through a temporary file to keep popen single-direction.
  char path[] = "/tmp/tang-test-in-XXXXXX";
  const int fd = mkstemp(path);
  if (fd < 0) {
    if (status != nullptr) *status = -1;
    return "";
  }
  FILE *f = fdopen(fd, "w");
  std::fwrite(input.data(), 1, input.size(), f);
  std::fclose(f);

  const std::string full = "(" + cmd + ") < " + path + " 2>/dev/null";
  FILE *p = popen(full.c_str(), "r");
  std::string out;
  if (p == nullptr) {
    std::remove(path);
    if (status != nullptr) *status = -1;
    return "";
  }
  char buf[4096];
  size_t n;
  while ((n = std::fread(buf, 1, sizeof(buf), p)) > 0) {
    out.append(buf, n);
  }
  const int rc = pclose(p);
  std::remove(path);
  if (status != nullptr) *status = rc;
  return out;
}

bool have_tool(const char *name) {
  int status = -1;
  run_command(std::string("command -v ") + name, "", &status);
  return status == 0;
}

std::string hex_encode(const uint8_t *data, size_t len) {
  static const char *kDigits = "0123456789abcdef";
  std::string out;
  for (size_t i = 0; i < len; ++i) {
    out.push_back(kDigits[data[i] >> 4]);
    out.push_back(kDigits[data[i] & 15]);
  }
  return out;
}

std::vector<uint8_t> hex_decode(const std::string &hex) {
  std::vector<uint8_t> out;
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(static_cast<uint8_t>(
        std::strtoul(hex.substr(i, 2).c_str(), nullptr, 16)));
  }
  return out;
}

std::string trim(const std::string &s) {
  size_t b = 0;
  size_t e = s.size();
  while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
  while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
  return s.substr(b, e - b);
}

}  // namespace tt
