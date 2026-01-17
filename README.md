# tlsperf

tlsperf is a high-performance TLS benchmarking tool. It utilizes `epoll`, non-blocking sockets, and multi-threading to stress-test TLS handshakes efficiently.

## Requirements

The following packages are required to build the project:
* CMake (3.10 or later)
* OpenSSL development headers (or a compatible fork like BoringSSL/Tongsuo)
* A C compiler (GCC/Clang)
* pthreads

## Build & SSL selection

- Different SSL libraries provide different capabilities:
  - Post-quantum / experimental algorithms: **BoringSSL**
  - GM/TLCP support: **Tongsuo** (formerly BabaSSL)
  - General use: system **OpenSSL**

### A) Build BoringSSL (for linking with tlsperf)
```bash
# Fetch and build BoringSSL (example location: ../boringssl)
git clone https://boringssl.googlesource.com/boringssl ../boringssl
cd ../boringssl
cmake -B build -DCMAKE_POSITION_INDEPENDENT_CODE=ON
make -j"$(nproc)" -C build
```

### B) Build Tongsuo (for linking with tlsperf)
```bash
# Fetch and install to a local prefix (example: ../Tongsuo/build_install)
git clone https://github.com/Tongsuo-Project/Tongsuo ../Tongsuo
cd ../Tongsuo
./config --prefix="$PWD/build_install"
make -j"$(nproc)"
make install
```

### C) Use CMake to build tlsperf with a chosen SSL library

> For system OpenSSL: `cmake -B build && make -j"$(nproc)" -C build`
> For BoringSSL/Tongsuo not installed system-wide, pass include and library paths explicitly.

- Link with **BoringSSL**:
```bash
cd tlsperf
cmake -B build \
  -DOPENSSL_INCLUDE_DIR="$PWD/../boringssl/include" \
  -DOPENSSL_SSL_LIBRARY="$PWD/../boringssl/build/libssl.a" \
  -DOPENSSL_CRYPTO_LIBRARY="$PWD/../boringssl/build/libcrypto.a"
make -j"$(nproc)" -C build
```

- Link with **Tongsuo** (local prefix example: `../Tongsuo/build_install`):
```bash
cd tlsperf
cmake -B build \
  -DOPENSSL_INCLUDE_DIR="$PWD/../Tongsuo/build_install/include" \
  -DOPENSSL_SSL_LIBRARY="$PWD/../Tongsuo/build_install/lib64/libssl.a" \
  -DOPENSSL_CRYPTO_LIBRARY="$PWD/../Tongsuo/build_install/lib64/libcrypto.a"
make -j"$(nproc)" -C build
```

Notes:
- `OPENSSL_INCLUDE_DIR` points to headers; `OPENSSL_SSL_LIBRARY` / `OPENSSL_CRYPTO_LIBRARY` point to libssl/libcrypto (either `.a` or `.so`).

## Usage

```text
Usage: tlsperf <host-or-ip> [options]
TLS handshake perf tester (epoll + non-blocking sockets, multi-threaded)

Positional:
  host-or-ip             : target hostname or IP address (required)

Options:
  -p <port>              : TCP port to connect (default: 443)
  -n <count>             : total number of handshakes to perform (default: 1000)
  -c <concurrency>       : TOTAL concurrency across all threads (default: 100)
  -T <threads>           : number of worker threads (default: number of online CPUs)
  -t <timeout>           : per-handshake timeout in seconds (default: 5)
  -k                     : skip certificate verification (INSECURE)
  -s <servername>        : SNI / server name to send (useful when host is IP)
  -C <ciphers>           : OpenSSL cipher list / TLS1.3 ciphersuites string
  -A auto                : enable CPU affinity auto-binding (thread_id % ncpus)
  -h, --help             : show this help and exit
  --version              : print version and exit
```

Example commands:

```bash
# Benchmark a website with high concurrency
tlsperf example.com -n 10000 -c 200 -T 4 -t 10 -s example.com -A auto

# Test a specific IP with a specific TLS 1.3 cipher suite (insecure/skip verify)
tlsperf 1.2.3.4 -n 100 -c 50 -k -C "TLS_AES_128_GCM_SHA256"
```

## License

The MIT License