#include "tp_tls.h"
#include <openssl/ssl.h>
#include <stdio.h>

SSL_CTX *create_thread_ctx(const char *cipher_str, int skip_verify)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;

    if (cipher_str && cipher_str[0] != '\0') {
#if !defined(OPENSSL_IS_BORINGSSL) && OPENSSL_VERSION_NUMBER >= 0x10101000L
        if (SSL_CTX_set_ciphersuites(ctx, cipher_str) != 1) {
            fprintf(stderr,
                    "Warning: SSL_CTX_set_ciphersuites didn't match TLS1.3 suites for '%s'\n",
                    cipher_str);
        }
#endif
        if (SSL_CTX_set_cipher_list(ctx, cipher_str) != 1) {
            fprintf(stderr,
                    "Warning: SSL_CTX_set_cipher_list didn't match TLS1.2 suites for '%s'\n",
                    cipher_str);
        }
    }

    if (!skip_verify) {
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            fprintf(stderr, "Warning: could not load system default CA paths\n");
        }
    }

    return ctx;
}