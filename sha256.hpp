/*
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace sha256 {
namespace detail {

static const std::uint32_t round_constant_k[] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

inline std::uint32_t Ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
  return (x & y) ^ (~x & z);
}

inline std::uint32_t Maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

inline std::uint32_t rotate_right(std::uint32_t x, int n) {
  return (x >> n) | (x << (32 - n));
}

inline std::uint32_t upper_sigma_0(std::uint32_t x) {
  return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22);
}

inline std::uint32_t upper_sigma_1(std::uint32_t x) {
  return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25);
}

inline std::uint32_t lower_sigma_0(std::uint32_t x) {
  return rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3);
}

inline std::uint32_t lower_sigma_1(std::uint32_t x) {
  return rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10);
}
} // namespace detail

inline void init(std::uint32_t state[8]) {
  state[0] = 0x6a09e667;
  state[1] = 0xbb67ae85;
  state[2] = 0x3c6ef372;
  state[3] = 0xa54ff53a;
  state[4] = 0x510e527f;
  state[5] = 0x9b05688c;
  state[6] = 0x1f83d9ab;
  state[7] = 0x5be0cd19;
}

inline void block(std::uint32_t state[8], std::uint32_t block[16]) {
  std::uint32_t reg[8];
  std::uint32_t schedule[64];

  /* Initialize registers with the previous intermediate hash value (or IV). */
  for (int i = 0; i < 8; i++) reg[i] = state[i];

  /* Expand message to 64 words (message schedule). */
  for (int i = 0; i < 16; i++) schedule[i] = block[i];
  for (int i = 16; i < 64; i++) {
    schedule[i] = detail::lower_sigma_1(schedule[i -  2]) + schedule[i -  7] +
                  detail::lower_sigma_0(schedule[i - 15]) + schedule[i - 16];
  }

  /* SHA-256 compression function (64 rounds) */
  for (int i = 0; i < 64; i++) {
    auto t1 = reg[7] + detail::upper_sigma_1(reg[4]) + detail::Ch(reg[4], reg[5], reg[6]) + detail::round_constant_k[i] + schedule[i];
    auto t2 = detail::upper_sigma_0(reg[0]) + detail::Maj(reg[0], reg[1], reg[2]);
    reg[7] = reg[6];
    reg[6] = reg[5];
    reg[5] = reg[4];
    reg[4] = reg[3] + t1;
    reg[3] = reg[2];
    reg[2] = reg[1];
    reg[1] = reg[0];
    reg[0] = t1 + t2;
  }

  /* Calculate the intermediate hash value for the next block. */
  for (int i = 0; i < 8; i++) state[i] += reg[i];
}

inline void hash(std::uint8_t const* data, size_t length, std::uint8_t hash[32]) {
  std::uint32_t state[8];
  std::uint32_t block[16];
  std::uint64_t bitlength = length * 8ULL;

  init(state);

  /* Hash complete blocks as long as data is available. */
  while (length >= 64) {
    for (int i = 0; i < 16; i++) {
      block[i] = (data[0] << 24) |
                 (data[1] << 16) |
                 (data[2] <<  8) |
                 (data[3] <<  0);
      length -= 4;
      data += 4;
    }
    sha256::block(state, block);
  }

  int i = 0;

  /* Copy remaining words into the block buffer. */
  while (length >= 4) {
    block[i++] = (data[0] << 24) |
                 (data[1] << 16) |
                 (data[2] <<  8) |
                 (data[3] <<  0);
    length -= 4;
    data += 4;
  }

  /* Copy remaining bytes plus 0x80 terminator into the block. */
  if (length > 0) {
    int shift = 24;
    block[i] = 0;
    while (length > 0) {
      block[i] |= *data++ << shift;
      shift -= 8;
      length--;
    }
    block[i++] |= 0x80 << shift;
  } else {
    block[i++] = 0x80000000;
  }

  /* Does the message length (64-bit) still fit into the current block? If not we will need an extra block. */
  if (i <= 14) {
    for (; i < 14; i++) block[i] = 0;
    block[14] = bitlength >> 32;
    block[15] = bitlength & 0xFFFFFFFF;
    sha256::block(state, block);
  } else {
    for (; i < 16; i++) block[i] = 0;
    sha256::block(state, block);
    for (i = 0; i < 14; i++) block[i] = 0;
    block[14] = bitlength >> 32;
    block[15] = bitlength & 0xFFFFFFFF;
    sha256::block(state, block);
  }

  /* Write final hash to the output buffer in Big-endian mode. */
  for (i = 0; i < 8; i++) {
    hash[i * 4 + 0] = (state[i] >> 24) & 0xFF;
    hash[i * 4 + 1] = (state[i] >> 16) & 0xFF;
    hash[i * 4 + 2] = (state[i] >>  8) & 0xFF;
    hash[i * 4 + 3] = (state[i] >>  0) & 0xFF;
  }
}

} // namespace sha256
