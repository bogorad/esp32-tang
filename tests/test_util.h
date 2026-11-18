#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tt {

// Run a shell command with `input` on stdin; returns stdout. `*status` gets the
// exit status. Tests that need jose/clevis call require_tool() first, which
// fails the test run (never skips) when the tool is missing.
std::string run_command(const std::string &cmd, const std::string &input,
                        int *status);
bool have_tool(const char *name);
std::string hex_encode(const uint8_t *data, size_t len);
std::vector<uint8_t> hex_decode(const std::string &hex);
std::string trim(const std::string &s);

}  // namespace tt
