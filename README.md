# hash-sha
A simple implementation of SHA-256 in C++, providing low-level access to the block function.
SHA-1 and SHA-224 implementations will follow.

# Usage

To calculate the SHA-256 of a byte buffer call `sha256::hash` and pass the input byte buffer,
size and output byte buffer.

```cpp
#include <cstring>
#include <string>

#include "sha256.hpp"

int main() {
  std::string input = "Lorem ipsum dolor sit amit.";
  std::uint8_t hash[32];
  sha256::hash((std::uint8_t const*)input.c_str(), input.length(), hash);
  for (int i = 0; i < 32; i++) {
    std::printf("%02X", hash[i]);
  }
  return 0;
}
```

Output: `B18868D4C6FCD8752FF8810C486D0ED4F59298AA3842EB4C120E567E57A48140`

hash-sha also provides two functions `sha256::init` and `sha256::block` which provide
lower-level access to the SHA-256 algorithm.

You will need to provide your own state (std::uint32_t[8] array) and initialize it with `sha256::init`.
You can then use `sha256::block` to stream input data into the hashing algorithm.
After the final `sha256::block` call the state will contain the big-endian encoded hash.

Note, that SHA-256 requires the input message to be padded in a specific way.
The actual data in the final 64-byte block should be followed by an `0x80`  byte.
The final eight bytes of the final block should also contain the bit length of the input message.
If there is not enough space for the final eight byte length, you will need to stream in another block,
that contains the bit length in its final eight bytes. Unused bytes will be padded with zeros.

```cpp
#include <cstdio>

#include "sha256.hpp"

int main() {
  std::uint32_t state[8];
  // Final input block encoded in Big-endian.
  std::uint32_t final_block[16] = {
    0x41424344,  // "ABCD"
    0x45464780,  // "EFG" + 0x80 terminator
    0, 0,        // padding
    0, 0, 0,  0, // padding
    0, 0, 0,  0, // input bit length upper word
    0, 0, 0, 56, // input bit length lower word
  };
  sha256::init(state);
  // Potentially stream in other blocks, while there is more than 64 bytes worth of data...
  sha256::block(state, final_block);
  for (int i = 0; i < 8; i++) {
    std::printf("%02X%02X%02X%02X",
      state[i] >> 24,
     (state[i] >> 16) & 0xFF,
     (state[i] >>  8) & 0xFF,
      state[i] & 0xFF);
  }
  return 0;
}

```

# Resources

SHA-256 implementation is based on the official description of NIST:

https://web.archive.org/web/20150315061807/http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf

# License
hash-sha is public domain software and released under the Unlicense license.
```
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>
```
