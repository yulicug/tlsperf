cmake_minimum_required(VERSION 3.10)
project(tlsperf C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Allow manual override for BoringSSL/Tongsuo builds
set(OPENSSL_ROOT_DIR "" CACHE PATH "Root of OpenSSL/BoringSSL/Tongsuo")
set(OPENSSL_INCLUDE_DIR "" CACHE PATH "OpenSSL/BoringSSL/Tongsuo include dir")
set(OPENSSL_SSL_LIBRARY "" CACHE FILEPATH "Path to libssl.a or shared libssl")
set(OPENSSL_CRYPTO_LIBRARY "" CACHE FILEPATH "Path to libcrypto.a or shared libcrypto")

find_package(OpenSSL REQUIRED)

if(NOT OpenSSL_FOUND)
    # Manual mode (e.g., BoringSSL/Tongsuo not installed system-wide)
    if(NOT OPENSSL_INCLUDE_DIR OR NOT OPENSSL_SSL_LIBRARY OR NOT OPENSSL_CRYPTO_LIBRARY)
        message(FATAL_ERROR "OpenSSL/BoringSSL not found. Provide OPENSSL_INCLUDE_DIR, OPENSSL_SSL_LIBRARY, OPENSSL_CRYPTO_LIBRARY.")
    endif()
    add_library(OpenSSL::SSL UNKNOWN IMPORTED)
    set_target_properties(OpenSSL::SSL PROPERTIES IMPORTED_LOCATION "${OPENSSL_SSL_LIBRARY}")

    add_library(OpenSSL::Crypto UNKNOWN IMPORTED)
    set_target_properties(OpenSSL::Crypto PROPERTIES IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIBRARY}")

    set(OpenSSL_INCLUDE_DIR "${OPENSSL_INCLUDE_DIR}")
endif()

add_executable(tlsperf
    tlsperf.c
    tp_worker.c
    tp_util.c
    tp_tls.c
)

target_include_directories(tlsperf PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OpenSSL_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR}  # covers find_package/manual
)

target_compile_options(tlsperf PRIVATE -Wall -Wextra -O2 -g)

# Detect BoringSSL (heuristic: include or lib path contains "boringssl")
set(BORINGSSL_NEEDS_STDCXX OFF)
if(OPENSSL_INCLUDE_DIR MATCHES "boringssl" OR OPENSSL_SSL_LIBRARY MATCHES "boringssl")
  set(BORINGSSL_NEEDS_STDCXX ON)
endif()

target_link_libraries(tlsperf PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
    ${CMAKE_DL_LIBS}
    $<$<BOOL:${BORINGSSL_NEEDS_STDCXX}>:stdc++>  # BoringSSL is C++
)

add_executable(echcheck
    echcheck.c
)

target_include_directories(echcheck PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OpenSSL_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR}
)

target_compile_options(echcheck PRIVATE -Wall -Wextra -O2 -g)

target_link_libraries(echcheck PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
    ${CMAKE_DL_LIBS}
    $<$<BOOL:${BORINGSSL_NEEDS_STDCXX}>:stdc++>
)

message(STATUS "Using OpenSSL Include: ${OpenSSL_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR}")
message(STATUS "Using OpenSSL SSL lib: ${OPENSSL_SSL_LIBRARY}")
message(STATUS "Using OpenSSL Crypto lib: ${OPENSSL_CRYPTO_LIBRARY}")
message(STATUS "BoringSSL needs libstdc++: ${BORINGSSL_NEEDS_STDCXX}")
