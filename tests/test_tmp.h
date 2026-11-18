#pragma once

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace tt {

// Temp files removed on destruction.
class TempFiles {
 public:
  ~TempFiles() {
    for (const auto &p : paths_) std::remove(p.c_str());
  }
  std::string write(const std::string &content) {
    char path[] = "/tmp/tang-test-XXXXXX";
    const int fd = mkstemp(path);
    if (fd < 0) return "";
    FILE *f = fdopen(fd, "w");
    std::fwrite(content.data(), 1, content.size(), f);
    std::fclose(f);
    paths_.push_back(path);
    return path;
  }

 private:
  std::vector<std::string> paths_;
};

}  // namespace tt
