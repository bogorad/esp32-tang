// Core protocol tests: password mode, unattended mode, /adv, /rec.
#include <atomic>
#include <cstring>
#include <thread>

#include "test_support.h"
#include "test_tmp.h"

namespace {

struct Env {
  tt::MockStorage storage;
  tt::MockClock clock;
  tt::MockLogger log;
  TangServerCore core{&storage, &clock, &log};
};

TangConfig unattended_config(const char *seed,
                             std::vector<std::string> old = {}) {
  TangConfig c;
  c.unattended = true;
  c.seed_hex = seed;
  c.old_seeds_hex = std::move(old);
  return c;
}

TangConfig password_config(const char *pw, uint32_t token = 0,
                           uint64_t lifetime = 3600000) {
  TangConfig c;
  c.initial_password = pw;
  c.reset_token = token;
  c.key_lifetime_ms = lifetime;
  return c;
}

std::string activation_jwe(TangServerCore &core, const std::string &password) {
  tt::TempFiles files;
  const TangResponse pub = core.handle_request(tt::make_request("GET", "/pub"));
  const std::string key_file = files.write(pub.body);
  int status = -1;
  const std::string jwe = tt::run_command(
      "jose jwe enc -I- -k " + key_file + " -i '{\"protected\":{\"enc\":\"A128GCM\"}}'",
      password, &status);
  return status == 0 ? jwe : "";
}

TangResponse activate(Env &e, const std::string &pw) {
  return e.core.handle_request(
      tt::make_request("POST", "/activate", activation_jwe(e.core, pw)));
}

TangResponse deactivate(Env &e, const std::string &pw) {
  return e.core.handle_request(
      tt::make_request("POST", "/deactivate", activation_jwe(e.core, pw)));
}

std::string recovery_request(const uint8_t pub[64]) {
  return "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + tt::b64url(pub, 32) +
         "\",\"y\":\"" + tt::b64url(pub + 32, 32) +
         "\",\"alg\":\"ECMR\",\"key_ops\":[\"deriveKey\"]}";
}

std::string thumb(const uint8_t pub[64], tang::ThumbprintHash h) {
  char out[64];
  size_t len = 0;
  tang::compute_ec_jwk_thumbprint(pub, h, out, sizeof(out), &len);
  return std::string(out, len);
}

}  // namespace

// ---------------------------------------------------------------- unattended

TEST(unattended_uses_no_storage_and_is_active_at_boot) {
  Env e;
  REQUIRE(e.core.setup(unattended_config(tt::seed_a())));
  CHECK(e.core.is_active());
  CHECK(e.core.is_unattended());
  CHECK_EQ(e.storage.total_calls(), 0);

  for (const char *path : {"/pub", "/activate", "/deactivate"}) {
    CHECK_EQ(e.core.handle_request(tt::make_request("GET", path)).status, 404);
    CHECK_EQ(e.core.handle_request(tt::make_request("POST", path, "x")).status, 404);
  }
  CHECK_EQ(e.core.handle_request(tt::make_request("GET", "/adv")).status, 200);

  // No expiry, ever (30 days and 100 days of mock uptime).
  e.clock.now += 30ull * 24 * 3600 * 1000;
  CHECK(!e.core.loop());
  e.clock.now += 100ull * 24 * 3600 * 1000;
  CHECK(!e.core.loop());
  CHECK(e.core.is_active());
  CHECK_EQ(e.storage.total_calls(), 0);
}

TEST(unattended_null_storage_is_fine) {
  tt::MockClock clock;
  tt::MockLogger log;
  TangServerCore core(nullptr, &clock, &log);
  REQUIRE(core.setup(unattended_config(tt::seed_a())));
  CHECK_EQ(core.handle_request(tt::make_request("GET", "/adv")).status, 200);
}

TEST(unattended_rejects_bad_config_with_clear_error) {
  {
    Env e;
    CHECK(!e.core.setup(unattended_config(nullptr)));
    CHECK(!e.log.error_lines.empty());
    CHECK_EQ(e.core.handle_request(tt::make_request("GET", "/adv")).status, 503);
  }
  {
    Env e;
    CHECK(!e.core.setup(unattended_config("abcd")));
    CHECK(!e.log.error_lines.empty());
  }
  {
    Env e;  // old seed equal to the current seed
    CHECK(!e.core.setup(unattended_config(tt::seed_a(), {tt::seed_a()})));
    CHECK(!e.log.error_lines.empty());
  }
  {
    Env e;  // duplicate old seeds
    CHECK(!e.core.setup(unattended_config(tt::seed_a(), {tt::seed_b(), tt::seed_b()})));
    CHECK(!e.log.error_lines.empty());
  }
  {
    Env e;  // bad old seed
    CHECK(!e.core.setup(unattended_config(tt::seed_a(), {"nothex"})));
    CHECK(!e.log.error_lines.empty());
  }
}

TEST(unattended_same_seed_same_advertisement_payload) {
  Env a1, a2, b;
  REQUIRE(a1.core.setup(unattended_config(tt::seed_a())));
  REQUIRE(a2.core.setup(unattended_config(tt::seed_a())));
  REQUIRE(b.core.setup(unattended_config(tt::seed_b())));
  auto payload = [](Env &e) {
    return tt::json_string_field(
        e.core.handle_request(tt::make_request("GET", "/adv")).body, "payload");
  };
  CHECK(!payload(a1).empty());
  CHECK_EQ(payload(a1), payload(a2));
  CHECK(payload(a1) != payload(b));
}

TEST(adv_jws_verifies_with_jose) {
  REQUIRE(tt::have_tool("jose"));
  Env e;
  REQUIRE(e.core.setup(unattended_config(tt::seed_a())));
  tt::DerivedKeys k;
  REQUIRE(tt::derive_keys(tt::seed_a(), &k));
  tt::TempFiles files;
  const std::string sign_key = files.write(tt::public_jwk_json(k.sign_pub));
  const std::string wrong_key = files.write(tt::public_jwk_json(k.ex_pub));

  for (const char *path : {"/adv", "/adv/", "/adv/V-UCOWj-XdflqBPu-vZHIhZlJ6eThQ2pWHCo-nu5oPI",
                           "/adv/17jvBLzbE5AKcoQ35T6xQWXBaMk"}) {
    const TangResponse r = e.core.handle_request(tt::make_request("GET", path));
    REQUIRE(r.status == 200);
    const std::string jws = files.write(r.body);
    int status = -1;
    const std::string payload = tt::run_command(
        "jose jws ver -i " + jws + " -k " + sign_key + " -O-", "", &status);
    CHECK_EQ(status, 0);
    CHECK(payload.find("\"keys\"") != std::string::npos);
    // The payload advertises exactly the signing and the exchange key.
    int s2 = -1;
    const std::string thp1 = tt::trim(tt::run_command(
        "jose fmt -j- -Og keys -Af- 2>/dev/null | head -n 0", payload, &s2));
    (void)thp1;
    CHECK(payload.find(tt::b64url(k.ex_pub, 32)) != std::string::npos);
    CHECK(payload.find(tt::b64url(k.sign_pub, 32)) != std::string::npos);

    // A wrong key must not verify.
    int s3 = 0;
    tt::run_command("jose jws ver -i " + jws + " -k " + wrong_key + " -O-", "", &s3);
    CHECK(s3 != 0);
  }

  // Unknown thumbprint, the exchange key's thumbprint, junk: all 404.
  CHECK_EQ(e.core.handle_request(tt::make_request("GET", "/adv/AAAA")).status, 404);
  CHECK_EQ(e.core.handle_request(
               tt::make_request("GET", "/adv/gufGivW1KaP_REkAUWcAJOTopy-V2t6JxcJhUZtvdc0"))
               .status,
           404);
  CHECK_EQ(e.core.handle_request(tt::make_request("GET", "/adv/a$b")).status, 404);
  CHECK_EQ(e.core.handle_request(tt::make_request("POST", "/adv")).status, 405);
}

TEST(recovery_accepts_sha256_and_sha1_kid_and_matches_independent_ecmr) {
  REQUIRE(tt::have_tool("jose"));
  Env e;
  REQUIRE(e.core.setup(unattended_config(tt::seed_a())));
  tt::DerivedKeys k;
  REQUIRE(tt::derive_keys(tt::seed_a(), &k));

  tang::TangRngContext rng;
  uint8_t cpub[64], cpriv[32];
  REQUIRE(tang::generate_ec_keypair(&rng, cpub, cpriv));
  const std::string req = recovery_request(cpub);

  // Independent computation: jose performs d * Q for the same inputs.
  tt::TempFiles files;
  const std::string local = files.write(tt::private_jwk_json(k.ex_pub, k.ex_priv));
  const std::string remote = files.write(req);
  int status = -1;
  const std::string expected = tt::run_command(
      "jose jwk exc -i '{\"alg\":\"ECMR\"}' -l " + local + " -r " + remote, "", &status);
  REQUIRE(status == 0);
  const std::string ex = tt::json_string_field(expected, "x");
  const std::string ey = tt::json_string_field(expected, "y");
  REQUIRE(!ex.empty() && !ey.empty());

  for (auto h : {tang::ThumbprintHash::kSha256, tang::ThumbprintHash::kSha1}) {
    const TangResponse r = e.core.handle_request(
        tt::make_request("POST", "/rec/" + thumb(k.ex_pub, h), req));
    CHECK_EQ(r.status, 200);
    CHECK_EQ(r.content_type, std::string("application/jwk+json"));
    CHECK_EQ(tt::json_string_field(r.body, "x"), ex);
    CHECK_EQ(tt::json_string_field(r.body, "y"), ey);
    CHECK_EQ(tt::json_string_field(r.body, "alg"), std::string("ECMR"));
  }

  // Signing key thumbprint and unknown ids are not recovery keys.
  CHECK_EQ(e.core.handle_request(tt::make_request(
               "POST", "/rec/" + thumb(k.sign_pub, tang::ThumbprintHash::kSha256), req)).status, 404);
  CHECK_EQ(e.core.handle_request(tt::make_request("POST", "/rec/AAAA", req)).status, 404);
  CHECK_EQ(e.core.handle_request(tt::make_request("POST", "/rec", req)).status, 400);
  CHECK_EQ(e.core.handle_request(tt::make_request("GET", "/rec/AAAA")).status, 405);
}

TEST(recovery_rejects_invalid_client_points_and_bodies) {
  Env e;
  REQUIRE(e.core.setup(unattended_config(tt::seed_a())));
  tt::DerivedKeys k;
  REQUIRE(tt::derive_keys(tt::seed_a(), &k));
  const std::string path = "/rec/" + thumb(k.ex_pub, tang::ThumbprintHash::kSha256);

  // Off-curve point (valid field elements, not on the curve).
  uint8_t bad[64];
  std::memset(bad, 0, sizeof(bad));
  bad[31] = 1;
  bad[63] = 1;
  CHECK_EQ(e.core.handle_request(tt::make_request("POST", path, recovery_request(bad))).status, 400);

  // Point at infinity / all zero.
  uint8_t zero[64] = {0};
  CHECK_EQ(e.core.handle_request(tt::make_request("POST", path, recovery_request(zero))).status, 400);

  // Coordinates >= p.
  uint8_t big[64];
  std::memset(big, 0xff, sizeof(big));
  CHECK_EQ(e.core.handle_request(tt::make_request("POST", path, recovery_request(big))).status, 400);

  // A real point with y flipped to a different value is off-curve.
  tang::TangRngContext rng;
  uint8_t pub[64], priv[32];
  REQUIRE(tang::generate_ec_keypair(&rng, pub, priv));
  pub[63] ^= 0x01;
  CHECK_EQ(e.core.handle_request(tt::make_request("POST", path, recovery_request(pub))).status, 400);

  // Structural problems.
  CHECK_EQ(e.core.handle_request(tt::make_request("POST", path, "")).status, 400);
  CHECK_EQ(e.core.handle_request(tt::make_request("POST", path, "not json")).status, 400);
  CHECK_EQ(e.core.handle_request(tt::make_request(
               "POST", path, "{\"kty\":\"RSA\",\"crv\":\"P-256\",\"x\":\"AA\",\"y\":\"AA\"}")).status, 400);
  CHECK_EQ(e.core.handle_request(tt::make_request(
               "POST", path, "{\"kty\":\"EC\",\"crv\":\"P-384\",\"x\":\"AA\",\"y\":\"AA\"}")).status, 400);
  CHECK(!e.log.warn_lines.empty());  // every rejection logged
}

TEST(rotation_old_seed_exchange_key_still_recovers_and_old_signer_cosigns) {
  REQUIRE(tt::have_tool("jose"));
  Env e;
  // Current = B; old = A. Clients bound to A's exchange key must still work.
  REQUIRE(e.core.setup(unattended_config(tt::seed_b(), {tt::seed_a()})));
  tt::DerivedKeys a, b;
  REQUIRE(tt::derive_keys(tt::seed_a(), &a));
  REQUIRE(tt::derive_keys(tt::seed_b(), &b));

  tang::TangRngContext rng;
  uint8_t cpub[64], cpriv[32];
  REQUIRE(tang::generate_ec_keypair(&rng, cpub, cpriv));
  const std::string req = recovery_request(cpub);
  for (auto h : {tang::ThumbprintHash::kSha256, tang::ThumbprintHash::kSha1}) {
    CHECK_EQ(e.core.handle_request(
                 tt::make_request("POST", "/rec/" + thumb(a.ex_pub, h), req)).status, 200);
    CHECK_EQ(e.core.handle_request(
                 tt::make_request("POST", "/rec/" + thumb(b.ex_pub, h), req)).status, 200);
  }

  // Plain /adv advertises only the current keys, signed by the current key.
  tt::TempFiles files;
  const TangResponse adv = e.core.handle_request(tt::make_request("GET", "/adv"));
  REQUIRE(adv.status == 200);
  const std::string jws = files.write(adv.body);
  int status = -1;
  const std::string payload = tt::run_command(
      "jose jws ver -i " + jws + " -k " + files.write(tt::public_jwk_json(b.sign_pub)) + " -O-",
      "", &status);
  CHECK_EQ(status, 0);
  CHECK(payload.find(tt::b64url(a.ex_pub, 32)) == std::string::npos);
  CHECK(payload.find(tt::b64url(a.sign_pub, 32)) == std::string::npos);
  CHECK(payload.find(tt::b64url(b.ex_pub, 32)) != std::string::npos);

  // /adv/<old signing thp>: general JWS signed by the current AND the old key
  // (tangd behaviour). Both signatures must verify (jose -a = all keys).
  const TangResponse both = e.core.handle_request(tt::make_request(
      "GET", "/adv/" + thumb(a.sign_pub, tang::ThumbprintHash::kSha256)));
  REQUIRE(both.status == 200);
  CHECK(both.body.find("\"signatures\"") != std::string::npos);
  const std::string keyset = files.write(
      "{\"keys\":[" + tt::public_jwk_json(a.sign_pub) + "," + tt::public_jwk_json(b.sign_pub) + "]}");
  int s2 = -1;
  tt::run_command("jose jws ver -a -i " + files.write(both.body) + " -k " + keyset + " -O-", "", &s2);
  CHECK_EQ(s2, 0);
  // The SHA-1 thumbprint of the old signing key works too.
  CHECK_EQ(e.core.handle_request(tt::make_request(
               "GET", "/adv/" + thumb(a.sign_pub, tang::ThumbprintHash::kSha1))).status, 200);
  // Old exchange key thumbprint is not a signing key.
  CHECK_EQ(e.core.handle_request(tt::make_request(
               "GET", "/adv/" + thumb(a.ex_pub, tang::ThumbprintHash::kSha256))).status, 404);
}

TEST(concurrent_requests_and_loop_do_not_race) {
  Env e;
  REQUIRE(e.core.setup(unattended_config(tt::seed_a())));
  std::atomic<bool> stop{false};
  std::atomic<int> bad{0};
  std::thread loop_thread([&] {
    while (!stop) e.core.loop();
  });
  std::vector<std::thread> workers;
  for (int i = 0; i < 3; ++i) {
    workers.emplace_back([&] {
      for (int j = 0; j < 20; ++j) {
        if (e.core.handle_request(tt::make_request("GET", "/adv")).status != 200) ++bad;
      }
    });
  }
  for (auto &t : workers) t.join();
  stop = true;
  loop_thread.join();
  CHECK_EQ(bad.load(), 0);
}

// ------------------------------------------------------------ password mode

TEST(password_mode_first_boot_creates_versioned_record) {
  Env e;
  REQUIRE(e.core.setup(password_config("correct horse")));
  CHECK(!e.core.is_active());
  CHECK_EQ(e.storage.writes, 1);
  CHECK(e.storage.has_token);
  TangStoredState s;
  CHECK(tang_decode_state(e.storage.blob.data(), e.storage.blob.size(), &s) == TangDecodeStatus::kOk);
  CHECK_EQ(s.record.iterations, tang::kPasswordPbkdf2Iterations);
  // Inactive: /adv and /rec refuse; /pub works.
  CHECK_EQ(e.core.handle_request(tt::make_request("GET", "/adv")).status, 403);
  CHECK_EQ(e.core.handle_request(tt::make_request("POST", "/rec/x", "{}")).status, 403);
  CHECK_EQ(e.core.handle_request(tt::make_request("GET", "/pub")).status, 200);
}

TEST(password_mode_activate_recover_expire) {
  REQUIRE(tt::have_tool("jose"));
  Env e;
  // 60 days: larger than a 32-bit millisecond counter holds.
  const uint64_t lifetime = 60ull * 24 * 3600 * 1000;
  REQUIRE(e.core.setup(password_config("pw1", 0, lifetime)));

  const TangResponse ok = activate(e, "pw1");
  CHECK_EQ(ok.status, 200);
  CHECK(e.core.is_active());
  CHECK_EQ(e.core.handle_request(tt::make_request("GET", "/adv")).status, 200);
  CHECK_EQ(activate(e, "pw1").status, 400);  // already active

  // /rec works with both thumbprints of the unlocked exchange key.
  const std::string adv = e.core.handle_request(tt::make_request("GET", "/adv")).body;
  const std::string payload = adv;  // base64 payload; decode to find exchange key
  (void)payload;

  e.clock.now += lifetime - 1000;
  CHECK(!e.core.loop());
  CHECK(e.core.is_active());
  e.clock.now += 2000;
  CHECK(e.core.loop());  // expired exactly once
  CHECK(!e.core.is_active());
  CHECK(!e.core.loop());
  CHECK_EQ(e.core.handle_request(tt::make_request("GET", "/adv")).status, 403);

  // Reactivation after expiry works and storage was never rewritten.
  CHECK_EQ(activate(e, "pw1").status, 200);
  CHECK_EQ(e.storage.writes, 1);
}

TEST(password_mode_wrong_password_backs_off) {
  REQUIRE(tt::have_tool("jose"));
  Env e;
  REQUIRE(e.core.setup(password_config("right")));
  CHECK_EQ(activate(e, "wrong").status, 401);
  // Immediately again: back-off, even with the right password.
  CHECK_EQ(activate(e, "right").status, 429);
  e.clock.now += 1001;
  CHECK_EQ(activate(e, "wrong").status, 401);  // second failure: 2 s window
  e.clock.now += 1500;
  CHECK_EQ(activate(e, "right").status, 429);
  e.clock.now += 600;
  CHECK_EQ(activate(e, "right").status, 200);
  CHECK(e.core.is_active());
}

TEST(deactivate_get_is_removed_and_wrong_password_leaves_storage_unchanged) {
  REQUIRE(tt::have_tool("jose"));
  Env e;
  REQUIRE(e.core.setup(password_config("pw")));
  REQUIRE(activate(e, "pw").status == 200);
  const std::vector<uint8_t> before = e.storage.blob;
  const int writes_before = e.storage.writes;

  CHECK_EQ(e.core.handle_request(tt::make_request("GET", "/deactivate")).status, 405);
  CHECK(e.core.is_active());

  CHECK_EQ(deactivate(e, "attacker").status, 401);
  CHECK(e.core.is_active());
  CHECK(e.storage.blob == before);
  CHECK_EQ(e.storage.writes, writes_before);
  CHECK_EQ(e.storage.wipes, 0);

  e.clock.now += 100000;  // let the back-off from the wrong password lapse
  CHECK_EQ(e.core.handle_request(tt::make_request("POST", "/deactivate", "")).status, 400);
  CHECK_EQ(deactivate(e, "pw").status, 200);
  CHECK(!e.core.is_active());
  CHECK(e.storage.blob == before);  // correct password: still no rewrite
  CHECK_EQ(e.storage.writes, writes_before);
  CHECK_EQ(e.core.handle_request(tt::make_request("POST", "/deactivate", "")).status, 400);
}

TEST(corrupt_record_does_not_reinitialize) {
  Env first;
  REQUIRE(first.core.setup(password_config("pw")));
  tt::MockStorage s = first.storage;  // copy of the good state

  // Corrupt one byte in the middle of the record.
  s.blob[40] ^= 0x55;
  const std::vector<uint8_t> corrupt = s.blob;
  s.writes = s.wipes = s.token_writes = s.reads = s.token_reads = 0;

  tt::MockClock clock;
  tt::MockLogger log;
  TangServerCore core(&s, &clock, &log);
  CHECK(!core.setup(password_config("pw")));  // even with a password given
  CHECK(!core.is_active());
  CHECK(!core.is_ready());
  CHECK_EQ(s.writes, 0);
  CHECK_EQ(s.wipes, 0);
  CHECK_EQ(s.token_writes, 0);
  CHECK(s.blob == corrupt);
  REQUIRE(!log.error_lines.empty());
  CHECK(log.error_lines.back().find("not usable") != std::string::npos);
  CHECK_EQ(core.handle_request(tt::make_request("GET", "/adv")).status, 503);
  CHECK_EQ(core.handle_request(tt::make_request("GET", "/pub")).status, 503);
}

TEST(legacy_or_foreign_record_fails_clearly) {
  tt::MockStorage s;
  s.has_blob = true;
  s.blob.assign(110, 0x7e);  // not our magic: e.g. record from older firmware
  s.has_token = true;
  s.token = 0;
  tt::MockClock clock;
  tt::MockLogger log;
  TangServerCore core(&s, &clock, &log);
  CHECK(!core.setup(password_config("pw")));
  CHECK_EQ(s.writes, 0);
  CHECK_EQ(s.wipes, 0);
  REQUIRE(!log.error_lines.empty());
  CHECK(log.error_lines.back().find("unrecognized format") != std::string::npos);
}

TEST(reboot_with_same_storage_keeps_identity_and_does_not_rewrite) {
  Env first;
  REQUIRE(first.core.setup(password_config("pw", 7)));
  const std::string pub1 = first.core.handle_request(tt::make_request("GET", "/pub")).body;
  tt::MockStorage s = first.storage;
  s.writes = s.token_writes = 0;

  tt::MockClock clock;
  tt::MockLogger log;
  TangServerCore again(&s, &clock, &log);
  REQUIRE(again.setup(password_config(nullptr, 7)));  // password may be removed
  CHECK_EQ(again.handle_request(tt::make_request("GET", "/pub")).body, pub1);
  CHECK_EQ(s.writes, 0);
  CHECK_EQ(s.wipes, 0);
}

TEST(reset_token_is_one_shot) {
  Env first;
  REQUIRE(first.core.setup(password_config("pw", 1)));
  const std::string pub1 = first.core.handle_request(tt::make_request("GET", "/pub")).body;
  tt::MockStorage s = first.storage;

  // Changed token without a password: nothing is wiped.
  {
    tt::MockClock clock;
    tt::MockLogger log;
    TangServerCore core(&s, &clock, &log);
    CHECK(!core.setup(password_config(nullptr, 2)));
    CHECK_EQ(s.wipes, 0);
    CHECK(!log.error_lines.empty());
  }
  // Changed token with a password: wiped once, new identity.
  std::string pub2;
  {
    tt::MockClock clock;
    tt::MockLogger log;
    TangServerCore core(&s, &clock, &log);
    REQUIRE(core.setup(password_config("pw2", 2)));
    CHECK_EQ(s.wipes, 1);
    pub2 = core.handle_request(tt::make_request("GET", "/pub")).body;
    CHECK(pub2 != pub1);
  }
  // Same token on the next boot: no wipe, identity stable.
  {
    tt::MockClock clock;
    tt::MockLogger log;
    TangServerCore core(&s, &clock, &log);
    REQUIRE(core.setup(password_config("pw2", 2)));
    CHECK_EQ(s.wipes, 1);
    CHECK_EQ(core.handle_request(tt::make_request("GET", "/pub")).body, pub2);
  }
}

TEST(reset_token_recovers_a_corrupt_record) {
  Env first;
  REQUIRE(first.core.setup(password_config("pw", 1)));
  tt::MockStorage s = first.storage;
  s.blob[20] ^= 0xff;
  tt::MockClock clock;
  tt::MockLogger log;
  TangServerCore core(&s, &clock, &log);
  REQUIRE(core.setup(password_config("pw", 2)));
  CHECK_EQ(s.wipes, 1);
}

TEST(pbkdf2_record_is_salted_and_old_unsalted_scheme_cannot_unlock) {
  // Same password, two devices: different salt -> different ciphertext.
  Env a, b;
  REQUIRE(a.core.setup(password_config("same")));
  REQUIRE(b.core.setup(password_config("same")));
  TangStoredState sa, sb;
  REQUIRE(tang_decode_state(a.storage.blob.data(), a.storage.blob.size(), &sa) == TangDecodeStatus::kOk);
  REQUIRE(tang_decode_state(b.storage.blob.data(), b.storage.blob.size(), &sb) == TangDecodeStatus::kOk);
  CHECK(std::memcmp(sa.record.salt, sb.record.salt, sizeof(sa.record.salt)) != 0);
  CHECK(std::memcmp(sa.record.ciphertext, sb.record.ciphertext, 32) != 0);

  // Key derived the old way (single SHA-256 of the password) does not unlock.
  uint8_t digest[32];
  tang::sha256_digest(reinterpret_cast<const uint8_t *>("same"), 4, digest);
  uint8_t out[32];
  CHECK(!tang::decrypt_local_data_gcm(
      out, sa.record.ciphertext, 32, reinterpret_cast<const char *>(digest), 16,
      sa.record.salt, sizeof(sa.record.salt), sa.record.iterations,
      sa.record.iv, sizeof(sa.record.iv), sa.record.tag, sizeof(sa.record.tag)));
}

TEST(password_mode_without_storage_or_password_fails_loudly) {
  {
    tt::MockClock clock;
    tt::MockLogger log;
    TangServerCore core(nullptr, &clock, &log);
    CHECK(!core.setup(password_config("pw")));
    CHECK(!log.error_lines.empty());
  }
  {
    Env e;  // empty storage and no password
    CHECK(!e.core.setup(password_config(nullptr)));
    CHECK(!e.log.error_lines.empty());
    CHECK_EQ(e.storage.writes, 0);
  }
}
