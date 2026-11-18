#pragma once

#include <string>

struct TangRequest {
  std::string method;
  std::string path;
  std::string body;
};

// Normalize a request path before routing. Clevis builds request URLs by plain
// concatenation ("$url/adv/$thp"), so a base URL with a trailing slash yields
// "//adv/<thp>", and an empty thumbprint yields "/adv/". tangd accepts these.
//   - drop any query string or fragment;
//   - collapse every run of '/' into one '/';
//   - drop one trailing '/' unless the path is just "/".
// A path that does not start with '/' is returned unchanged (it matches no
// route). The function is idempotent.
inline std::string normalize_tang_path(const std::string &raw) {
  const size_t cut = raw.find_first_of("?#");
  const std::string path = cut == std::string::npos ? raw : raw.substr(0, cut);
  if (path.empty() || path[0] != '/') {
    return path;
  }
  std::string out;
  out.reserve(path.size());
  for (char c : path) {
    if (c == '/' && !out.empty() && out.back() == '/') {
      continue;
    }
    out.push_back(c);
  }
  if (out.size() > 1 && out.back() == '/') {
    out.pop_back();
  }
  return out;
}
