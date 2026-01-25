#ifndef TP_TLS_H
#define TP_TLS_H

#include <openssl/ssl.h>

/* Create and configure SSL_CTX for a worker/thread.
 * cipher_str may be NULL.
 * skip_verify: if non-zero, disable certificate verification.
 * Returns new SSL_CTX* (caller must SSL_CTX_free) or NULL on error.
 */
SSL_CTX *create_thread_ctx(const char *cipher_str, const char *groups_str, int skip_verify);

#endif /* TP_TLS_H */