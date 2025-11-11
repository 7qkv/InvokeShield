# InvokeShield
InvokeShield is a lightweight C++14+ call obfuscation library that wraps function invocations in encrypted lambdas with compile-time generated keys. It makes static analysis and reverse engineering significantly harder by hiding direct function calls and pointer access.

## What is this
Header-only library providing multiple macro-based protection levels that add pointer scrambling, key mixing and lightweight runtime integrity checks. Not encryption — obfuscation techniques to raise the bar for casual reversing. Designed for common x64 ABIs (GCC, Clang, MSVC) but test on your target platform.

## How to use
```cpp
#include "invokeshield.hpp"

int secret(int x) {
    return x * 2;
}

int main() {
    int a = IVS_CALL(int, secret, 5);
    int b = IVS_ULTIMATE(int, secret, 10);
    (void)a; (void)b;
    return 0;
}
```

## Available macros
- `IVS_CALL` — basic lambda wrapper
- `IVS_PROTECTED` — XOR pointer guard
- `IVS_SECURE` — dual validation + pointer guard
- `IVS_INDIRECT` — indirect call via XOR address flipping
- `IVS_VCALL` — virtual function call (standard vtable layout)
- `IVS_FORTIFIED` — dual pointer guard verification
- `IVS_ARMORED` — multi-layer encrypted call
- `IVS_STEALTH` — loop-based integrity check
- `IVS_LAYERED` — 4-key verification
- `IVS_ULTIMATE` — 5-key system with scrambling and anti-optimization

## How it works
Each macro generates unique compile-time keys using a deterministic mixer. Function pointers are XOR/scrambled and stored in guarded containers. Runtime checks (volatile reads, small loops, multi-enc comparisons) verify integrity before unwrapping and calling the real function. Higher protection levels combine multiple layers to make pattern detection and simple static signatures less effective.

## Building
```bash
g++ -std=c++14 -O2 main.cpp -o invoke_demo
```
```cmd
cl /std:c++14 /O2 main.cpp
```

Requires C++14 or newer.

## Files
- `invokeshield.hpp` - the header you need to include
- `main.cpp` - simple example
- `.gitignore`
- `LICENSE` - MIT
- `README.md` - this file

## Limits
Only tested on x64 with GCC, Clang and MSVC. Won't stop someone who really wants to reverse your program, just makes it harder.

Some macros perform casts between function pointers and integer types which can be implementation-defined behavior.

## License
MIT

---
made by [7qkv](https://github.com/7qkv)
