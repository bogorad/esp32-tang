// Tiny HTTP shim that serves the Tang core over TCP on 127.0.0.1, for the
// Clevis round-trip tests. Single-threaded, test use only.
//
//   tang_shim --seed HEX [--old-seed HEX]... [--port N]
//
// Binds port N (default 0 = ephemeral) and prints "PORT <n>" on stdout.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "tang_core.h"

namespace {

class SteadyClock : public TangClock {
 public:
  uint64_t millis() const override {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  }
};

class StderrLogger : public TangLogger {
 public:
  void debug(const char *m) override { std::fprintf(stderr, "[shim debug] %s\n", m); }
  void warn(const char *m) override { std::fprintf(stderr, "[shim warn] %s\n", m); }
  void error(const char *m) override { std::fprintf(stderr, "[shim error] %s\n", m); }
};

const char *reason(int status) {
  switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    default: return "Error";
  }
}

bool read_request(int fd, TangRequest *req) {
  std::string data;
  char buf[2048];
  size_t header_end = std::string::npos;
  while (header_end == std::string::npos) {
    const ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) return false;
    data.append(buf, static_cast<size_t>(n));
    header_end = data.find("\r\n\r\n");
    if (data.size() > 65536) return false;
  }
  const std::string head = data.substr(0, header_end);
  const size_t sp1 = head.find(' ');
  const size_t sp2 = head.find(' ', sp1 + 1);
  if (sp1 == std::string::npos || sp2 == std::string::npos) return false;
  req->method = head.substr(0, sp1);
  req->path = head.substr(sp1 + 1, sp2 - sp1 - 1);

  size_t content_length = 0;
  size_t pos = 0;
  while ((pos = head.find("\r\n", pos)) != std::string::npos) {
    pos += 2;
    const size_t eol = head.find("\r\n", pos);
    std::string line = head.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
    for (char &c : line) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (line.rfind("content-length:", 0) == 0) {
      content_length = static_cast<size_t>(std::strtoul(line.c_str() + 15, nullptr, 10));
    }
  }
  std::string body = data.substr(header_end + 4);
  while (body.size() < content_length) {
    const ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) return false;
    body.append(buf, static_cast<size_t>(n));
  }
  req->body = body.substr(0, content_length);
  return true;
}

}  // namespace

int main(int argc, char **argv) {
  TangConfig config;
  config.unattended = true;
  std::string seed;
  int port = 0;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "--seed" && i + 1 < argc) {
      seed = argv[++i];
    } else if (a == "--old-seed" && i + 1 < argc) {
      config.old_seeds_hex.push_back(argv[++i]);
    } else if (a == "--port" && i + 1 < argc) {
      port = std::atoi(argv[++i]);
    } else {
      std::fprintf(stderr, "usage: tang_shim --seed HEX [--old-seed HEX]... [--port N]\n");
      return 2;
    }
  }
  config.seed_hex = seed.c_str();

  SteadyClock clock;
  StderrLogger logger;
  TangServerCore core(nullptr, &clock, &logger);  // unattended: no storage
  if (!core.setup(config)) {
    std::fprintf(stderr, "tang_shim: core setup failed\n");
    return 1;
  }

  const int listener = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(static_cast<uint16_t>(port));
  if (bind(listener, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0 ||
      listen(listener, 16) != 0) {
    std::perror("tang_shim: bind/listen");
    return 1;
  }
  socklen_t len = sizeof(addr);
  getsockname(listener, reinterpret_cast<sockaddr *>(&addr), &len);
  std::printf("PORT %d\n", ntohs(addr.sin_port));
  std::fflush(stdout);

  for (;;) {
    const int fd = accept(listener, nullptr, nullptr);
    if (fd < 0) continue;
    TangRequest req;
    if (read_request(fd, &req)) {
      const TangResponse resp = core.handle_request(req);
      std::fprintf(stderr, "[shim] %s %s -> %d\n", req.method.c_str(), req.path.c_str(), resp.status);
      const std::string out = "HTTP/1.1 " + std::to_string(resp.status) + " " +
                              reason(resp.status) + "\r\nContent-Type: " +
                              resp.content_type + "\r\nContent-Length: " +
                              std::to_string(resp.body.size()) +
                              "\r\nConnection: close\r\n\r\n" + resp.body;
      size_t sent = 0;
      while (sent < out.size()) {
        const ssize_t n = send(fd, out.data() + sent, out.size() - sent, 0);
        if (n <= 0) break;
        sent += static_cast<size_t>(n);
      }
    }
    close(fd);
  }
}
