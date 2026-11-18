// End-to-end: real Clevis against the core, served by tang_shim.
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "test_support.h"
#include "test_tmp.h"

#ifndef TANG_SHIM_PATH
#error "TANG_SHIM_PATH must be defined by CMake"
#endif

namespace {

class Shim {
 public:
  // Starts the shim; port 0 = ephemeral. Check ok() afterwards.
  Shim(const std::string &seed, const std::vector<std::string> &old_seeds, int port = 0) {
    int out_pipe[2];
    if (pipe(out_pipe) != 0) return;
    pid_ = fork();
    if (pid_ == 0) {
      dup2(out_pipe[1], STDOUT_FILENO);
      close(out_pipe[0]);
      close(out_pipe[1]);
      std::vector<std::string> args = {TANG_SHIM_PATH, "--seed", seed, "--port", std::to_string(port)};
      for (const auto &o : old_seeds) {
        args.push_back("--old-seed");
        args.push_back(o);
      }
      std::vector<char *> argv;
      for (auto &a : args) argv.push_back(const_cast<char *>(a.c_str()));
      argv.push_back(nullptr);
      execv(argv[0], argv.data());
      _exit(127);
    }
    close(out_pipe[1]);
    char buf[64] = {0};
    size_t n = 0;
    while (n < sizeof(buf) - 1) {
      const ssize_t r = read(out_pipe[0], buf + n, 1);
      if (r <= 0 || buf[n] == '\n') break;
      ++n;
    }
    close(out_pipe[0]);
    if (std::sscanf(buf, "PORT %d", &port_) != 1) port_ = 0;
  }
  ~Shim() { stop(); }
  void stop() {
    if (pid_ > 0) {
      kill(pid_, SIGTERM);
      int st;
      waitpid(pid_, &st, 0);
      pid_ = -1;
    }
  }
  bool ok() const { return pid_ > 0 && port_ > 0; }
  int port() const { return port_; }
  std::string url() const { return "http://127.0.0.1:" + std::to_string(port_); }

 private:
  pid_t pid_{-1};
  int port_{0};
};

std::string clevis_encrypt(const std::string &config, const std::string &plain, int *status) {
  return tt::run_command("clevis encrypt tang '" + config + "' -y", plain, status);
}

std::string clevis_decrypt(const std::string &jwe, int *status) {
  return tt::run_command("clevis decrypt", jwe, status);
}

}  // namespace

TEST(e2e_clevis_round_trip_unattended) {
  REQUIRE(tt::have_tool("clevis"));
  REQUIRE(tt::have_tool("curl"));
  Shim shim(tt::seed_a(), {});
  REQUIRE(shim.ok());
  int status = -1;
  const std::string jwe = clevis_encrypt("{\"url\":\"" + shim.url() + "\"}", "hi\n", &status);
  REQUIRE(status == 0);
  CHECK(!jwe.empty());
  // Clevis 17+ sets the JWE kid to the SHA-256 thumbprint of the exchange key
  // (the same value it then POSTs to /rec/<kid>).
  const std::string header = tt::run_command("cut -d. -f1 | jose b64 dec -i-", jwe, &status);
  CHECK(header.find("\"kid\":\"gufGivW1KaP_REkAUWcAJOTopy-V2t6JxcJhUZtvdc0\"") != std::string::npos);
  const std::string plain = clevis_decrypt(jwe, &status);
  CHECK_EQ(status, 0);
  CHECK_EQ(plain, std::string("hi\n"));
}

TEST(e2e_clevis_thp_pinned_sha256_and_sha1) {
  REQUIRE(tt::have_tool("clevis"));
  Shim shim(tt::seed_a(), {});
  REQUIRE(shim.ok());
  tt::DerivedKeys k;
  REQUIRE(tt::derive_keys(tt::seed_a(), &k));
  for (const char *thp : {"V-UCOWj-XdflqBPu-vZHIhZlJ6eThQ2pWHCo-nu5oPI", "17jvBLzbE5AKcoQ35T6xQWXBaMk"}) {
    int status = -1;
    const std::string jwe = clevis_encrypt(
        "{\"url\":\"" + shim.url() + "\",\"thp\":\"" + thp + "\"}", "pinned\n", &status);
    CHECK_EQ(status, 0);
    CHECK_EQ(clevis_decrypt(jwe, &status), std::string("pinned\n"));
  }
  // A wrong thumbprint must make encryption fail.
  int status = 0;
  clevis_encrypt("{\"url\":\"" + shim.url() + "\",\"thp\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}", "x\n", &status);
  CHECK(status != 0);
}

TEST(e2e_identity_persists_across_restart_with_same_seed) {
  REQUIRE(tt::have_tool("clevis"));
  std::string jwe;
  int port = 0;
  {
    Shim first(tt::seed_a(), {});
    REQUIRE(first.ok());
    port = first.port();
    int status = -1;
    jwe = clevis_encrypt("{\"url\":\"" + first.url() + "\"}", "secret\n", &status);
    REQUIRE(status == 0);
  }
  {
    Shim second(tt::seed_a(), {}, port);  // same seed, same address, fresh process
    REQUIRE(second.ok());
    int status = -1;
    CHECK_EQ(clevis_decrypt(jwe, &status), std::string("secret\n"));
    CHECK_EQ(status, 0);
  }
  {
    Shim other(tt::seed_c(), {}, port);  // negative control: different seed
    REQUIRE(other.ok());
    int status = 0;
    clevis_decrypt(jwe, &status);
    CHECK(status != 0);
  }
}

TEST(e2e_rotation_old_jwe_still_decrypts_with_old_seeds) {
  REQUIRE(tt::have_tool("clevis"));
  std::string jwe;
  std::string jwe_pinned_old_signer;
  int port = 0;
  tt::DerivedKeys a;
  REQUIRE(tt::derive_keys(tt::seed_a(), &a));
  {
    Shim first(tt::seed_a(), {});
    REQUIRE(first.ok());
    port = first.port();
    int status = -1;
    jwe = clevis_encrypt("{\"url\":\"" + first.url() + "\"}", "old\n", &status);
    REQUIRE(status == 0);
  }
  {
    // Rotated: B is current, A is an old seed.
    Shim rotated(tt::seed_b(), {tt::seed_a()}, port);
    REQUIRE(rotated.ok());
    int status = -1;
    CHECK_EQ(clevis_decrypt(jwe, &status), std::string("old\n"));
    CHECK_EQ(status, 0);

    // New bindings use the new current key.
    const std::string fresh = clevis_encrypt("{\"url\":\"" + rotated.url() + "\"}", "new\n", &status);
    CHECK_EQ(status, 0);
    CHECK_EQ(clevis_decrypt(fresh, &status), std::string("new\n"));

    // A client that still pins the OLD signing key can re-fetch /adv/<thp>.
    char t[64];
    size_t tl = 0;
    tang::compute_ec_jwk_thumbprint(a.sign_pub, tang::ThumbprintHash::kSha256, t, sizeof(t), &tl);
    const std::string pinned = clevis_encrypt(
        "{\"url\":\"" + rotated.url() + "\",\"thp\":\"" + std::string(t, tl) + "\"}", "pin\n", &status);
    CHECK_EQ(status, 0);
  }
  {
    // Negative control: rotation WITHOUT old_seeds loses the old binding.
    Shim no_old(tt::seed_b(), {}, port);
    REQUIRE(no_old.ok());
    int status = 0;
    clevis_decrypt(jwe, &status);
    CHECK(status != 0);
  }
}

// Clevis builds "$url/adv/$thp" and "$url/rec/$kid" by string concatenation, so
// a base URL with a trailing slash (or several) yields "//adv/..." paths.
TEST(e2e_clevis_url_with_trailing_slashes) {
  REQUIRE(tt::have_tool("clevis"));
  Shim shim(tt::seed_a(), {});
  REQUIRE(shim.ok());
  for (const char *suffix : {"/", "//", "///"}) {
    int status = -1;
    const std::string jwe =
        clevis_encrypt("{\"url\":\"" + shim.url() + suffix + "\"}", "slash\n", &status);
    CHECK_EQ(status, 0);
    CHECK(!jwe.empty());
    status = -1;
    CHECK_EQ(clevis_decrypt(jwe, &status), std::string("slash\n"));
    CHECK_EQ(status, 0);
  }
}
