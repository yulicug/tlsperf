/*
 * echcheck.c - Production-level ECH (Encrypted Client Hello) test tool
 *
 * Uses BoringSSL. Tests all aspects of ECH deployment for a domain.
 *
 * Usage:
 *   echcheck <domain> [port]                 -- verify ECH accepted
 *   echcheck --check-fallback <domain> [port]-- rejection/retry flow
 *   echcheck --check-grease  <domain> [port] -- GREASE ECH tolerance
 *   echcheck --check-config  <domain> [port] -- audit ECHConfig (ciphers, TTL, IDs)
 *   echcheck --check-privacy <domain> [port] -- DNS privacy + public name reachability
 *   echcheck --check-cert    <domain> [port] -- inner cert SAN + TLS1.3 + ALPN
 *   echcheck --all           <domain> [port] -- run all checks
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/base64.h>
#include <openssl/hpke.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* =========================================================================
 * Constants
 * ========================================================================= */

#define ECH_VERSION      0xfe0d   /* RFC 9605 */
#define PASS             "[+]"
#define FAIL             "[-]"
#define INFO             "[*]"
#define WARN             "[!]"

/* HPKE KEM IDs */
#define KEM_P256_SHA256   0x0010
#define KEM_X25519_SHA256 0x0020  /* recommended */

/* HPKE KDF IDs */
#define KDF_HKDF_SHA256   0x0001  /* recommended */
#define KDF_HKDF_SHA384   0x0002
#define KDF_HKDF_SHA512   0x0003

/* HPKE AEAD IDs */
#define AEAD_AES128GCM    0x0001  /* recommended */
#define AEAD_AES256GCM    0x0002
#define AEAD_CHACHA20     0x0003

/* Recommended minimum DNS TTL for ECHConfigs (seconds) */
#define TTL_WARN_LOW   60
#define TTL_WARN_HIGH  86400

/* =========================================================================
 * Parsed representation of one ECHConfig
 * ========================================================================= */

typedef struct {
    uint16_t version;
    uint8_t  config_id;
    uint16_t kem_id;
    uint16_t kdf_id;        /* first cipher suite only for display */
    uint16_t aead_id;
    uint8_t  max_name_len;
    char     public_name[256];
    int      num_cipher_suites;
} EchConfig;

/* =========================================================================
 * Utilities
 * ========================================================================= */

static void print_ssl_errors(void)
{
    unsigned long e;
    while ((e = ERR_get_error())) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        fprintf(stderr, "  SSL: %s\n", buf);
    }
}

static int b64_decode(const char *in, size_t in_len,
                      uint8_t **out, size_t *out_len)
{
    size_t max_len = ((in_len + 3) / 4) * 3 + 4;
    *out = malloc(max_len);
    if (!*out) return 0;
    if (!EVP_DecodeBase64(*out, out_len, max_len,
                          (const uint8_t *)in, in_len)) {
        free(*out); *out = NULL; return 0;
    }
    return 1;
}

static int tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints = {0};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo(%s:%s): %s\n",
                host, port, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *r = res; r; r = r->ai_next) {
        fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, r->ai_addr, r->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
        fprintf(stderr, "connect(%s:%s): %s\n", host, port, strerror(errno));
    return fd;
}

/* =========================================================================
 * DNS helpers
 * ========================================================================= */

/*
 * Fetch ECHConfigList base64 from DNS HTTPS record.
 * Optionally fills *ttl_out.
 * Returns malloc'd base64 string or NULL.
 */
static char *fetch_ech_config_b64(const char *domain, int *ttl_out)
{
    char cmd[512];
    int  ttl = -1;

    /* Get TTL via full answer */
    if (ttl_out) {
        snprintf(cmd, sizeof(cmd),
                 "dig +noall +answer HTTPS %s 2>/dev/null", domain);
        FILE *fp = popen(cmd, "r");
        char line[4096];
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "IN") && strstr(line, "HTTPS")) {
                    /* <name> <ttl> IN HTTPS ... */
                    char tmp[4096];
                    strncpy(tmp, line, sizeof(tmp));
                    char *tok = strtok(tmp, " \t");  /* name */
                    tok = strtok(NULL, " \t");        /* ttl */
                    if (tok) ttl = atoi(tok);
                    break;
                }
            }
            pclose(fp);
        }
        *ttl_out = ttl;
    }

    /* Get RDATA (short form) */
    snprintf(cmd, sizeof(cmd),
             "dig +short HTTPS %s 2>/dev/null", domain);

    FILE *fp = popen(cmd, "r");
    if (!fp) { perror("popen"); return NULL; }

    char line[4096];
    char *result = NULL;

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';
        char *p = strstr(line, " ech=");
        if (!p) p = strstr(line, "\tech=");
        if (!p && strncmp(line, "ech=", 4) == 0) p = line - 1;

        if (p) {
            char *val = strchr(p, '=');
            if (!val) continue;
            val++;
            size_t len = strcspn(val, " \t\r\n");
            if (len == 0) continue;
            result = strndup(val, len);
            break;
        }
    }
    pclose(fp);
    return result;
}

/* =========================================================================
 * ECHConfigList wire-format parser
 * ========================================================================= */

/*
 * Parse all ECHConfigs from a binary ECHConfigList.
 * Returns number of configs parsed (0 on error), fills configs[] array.
 */
static int parse_ech_configs(const uint8_t *buf, size_t len,
                              EchConfig *configs, int max_configs)
{
    if (len < 2) return 0;

    size_t list_len = ((size_t)buf[0] << 8) | buf[1];
    if (list_len + 2 > len) return 0;

    const uint8_t *p   = buf + 2;
    const uint8_t *end = p + list_len;
    int count = 0;

    while (p + 4 <= end && count < max_configs) {
        uint16_t version      = ((uint16_t)p[0] << 8) | p[1];
        uint16_t contents_len = ((uint16_t)p[2] << 8) | p[3];
        p += 4;

        if (p + contents_len > end) break;
        const uint8_t *c     = p;
        const uint8_t *c_end = c + contents_len;
        p += contents_len;

        EchConfig *cfg = &configs[count];
        memset(cfg, 0, sizeof(*cfg));
        cfg->version = version;

        if (version != ECH_VERSION) {
            count++;
            continue;
        }

        /* config_id */
        if (c + 1 > c_end) continue;
        cfg->config_id = c[0]; c++;

        /* kem_id */
        if (c + 2 > c_end) continue;
        cfg->kem_id = ((uint16_t)c[0] << 8) | c[1]; c += 2;

        /* public_key */
        if (c + 2 > c_end) continue;
        uint16_t pk_len = ((uint16_t)c[0] << 8) | c[1]; c += 2;
        if (c + pk_len > c_end) continue;
        c += pk_len;

        /* cipher_suites */
        if (c + 2 > c_end) continue;
        uint16_t cs_len = ((uint16_t)c[0] << 8) | c[1]; c += 2;
        if (c + cs_len > c_end) continue;
        cfg->num_cipher_suites = cs_len / 4;
        /* grab first suite */
        if (cs_len >= 4) {
            cfg->kdf_id  = ((uint16_t)c[0] << 8) | c[1];
            cfg->aead_id = ((uint16_t)c[2] << 8) | c[3];
        }
        c += cs_len;

        /* maximum_name_length */
        if (c + 1 > c_end) continue;
        cfg->max_name_len = c[0]; c++;

        /* public_name */
        if (c + 1 > c_end) continue;
        uint8_t name_len = c[0]; c++;
        if (c + name_len > c_end) continue;
        memcpy(cfg->public_name, c, name_len);
        cfg->public_name[name_len] = '\0';
        c += name_len;

        count++;
    }
    return count;
}

/*
 * Parse just the public_name from the first supported ECHConfig.
 * Returns malloc'd string or NULL.
 */
static char *parse_public_name(const uint8_t *buf, size_t len)
{
    EchConfig cfg;
    if (parse_ech_configs(buf, len, &cfg, 1) < 1)
        return NULL;
    return strdup(cfg.public_name);
}

/* =========================================================================
 * ECHConfigList builders
 * ========================================================================= */

/*
 * Build a fake ECHConfigList with a random HPKE key the server doesn't know.
 * Server will reject ECH and provide retry configs.
 */
static int make_fake_ech_config_list(const char *public_name,
                                     uint8_t **out, size_t *out_len)
{
    EVP_HPKE_KEY *key = EVP_HPKE_KEY_new();
    if (!key) return 0;

    if (!EVP_HPKE_KEY_generate(key, EVP_hpke_x25519_hkdf_sha256())) {
        EVP_HPKE_KEY_free(key); return 0;
    }

    uint8_t *ech_config = NULL;
    size_t   ech_config_len = 0;

    if (!SSL_marshal_ech_config(&ech_config, &ech_config_len,
                                0x42, key, public_name, 64)) {
        EVP_HPKE_KEY_free(key); return 0;
    }
    EVP_HPKE_KEY_free(key);

    *out_len = 2 + ech_config_len;
    *out = malloc(*out_len);
    if (!*out) { OPENSSL_free(ech_config); return 0; }

    (*out)[0] = (uint8_t)((ech_config_len >> 8) & 0xff);
    (*out)[1] = (uint8_t)( ech_config_len       & 0xff);
    memcpy(*out + 2, ech_config, ech_config_len);
    OPENSSL_free(ech_config);
    return 1;
}

/*
 * Build a GREASE ECHConfigList: syntactically valid but with unsupported
 * KEM 0xFFFF. BoringSSL will detect no supported config and send GREASE ECH.
 */
static int make_grease_ech_config_list(const char *public_name,
                                       uint8_t **out, size_t *out_len)
{
    uint8_t fake_pk[32];
    RAND_bytes(fake_pk, sizeof(fake_pk));

    size_t name_len     = strlen(public_name);
    /* ECHConfigContents:
     *  config_id(1) + kem_id(2) + pk_len(2)+pk(32) +
     *  cs_len(2)+cs(4) + max_name_len(1) + name_len(1)+name + ext_len(2) */
    size_t contents_len = 1 + 2 + 2 + 32 + 2 + 4 + 1 + 1 + name_len + 2;
    size_t config_len   = 2 + 2 + contents_len;  /* version + len + contents */
    *out_len = 2 + config_len;                    /* list len + config */

    *out = malloc(*out_len);
    if (!*out) return 0;

    uint8_t *p = *out;

    /* ECHConfigList outer length */
    *p++ = (config_len >> 8) & 0xff;
    *p++ =  config_len       & 0xff;

    /* ECHConfig version = 0xfe0d */
    *p++ = 0xfe; *p++ = 0x0d;

    /* ECHConfigContents length */
    *p++ = (contents_len >> 8) & 0xff;
    *p++ =  contents_len       & 0xff;

    /* config_id */
    *p++ = 0x01;

    /* kem_id = 0xFFFF (unsupported → GREASE) */
    *p++ = 0xFF; *p++ = 0xFF;

    /* public_key (32 random bytes) */
    *p++ = 0x00; *p++ = 32;
    memcpy(p, fake_pk, 32); p += 32;

    /* cipher_suites: HKDF-SHA256 + AES-128-GCM */
    *p++ = 0x00; *p++ = 0x04;
    *p++ = 0x00; *p++ = 0x01;   /* kdf */
    *p++ = 0x00; *p++ = 0x01;   /* aead */

    /* maximum_name_length */
    *p++ = 64;

    /* public_name */
    *p++ = (uint8_t)name_len;
    memcpy(p, public_name, name_len); p += name_len;

    /* extensions: empty */
    *p++ = 0x00; *p++ = 0x00;

    return 1;
}

/* =========================================================================
 * SSL context helpers
 * ========================================================================= */

static SSL_CTX *make_ctx(int verify_peer)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_default_verify_paths(ctx);
    SSL_CTX_set_verify(ctx, verify_peer ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                       NULL);

    /* Offer h2 + http/1.1 ALPN */
    static const uint8_t alpn[] = "\x02h2\x08http/1.1";
    SSL_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn) - 1);

    return ctx;
}

/*
 * Single connect + handshake helper.
 * Always returns SSL* (never NULL if TCP succeeded) so caller can inspect
 * errors. Check SSL_is_init_finished(ssl) to see if handshake completed.
 * Returns NULL only if TCP or SSL object creation fails.
 * Caller owns ssl and fd (*fd_out).
 */
static SSL *do_tls_connect(SSL_CTX *ctx, const char *domain, const char *port,
                           const uint8_t *ech_list, size_t ech_list_len,
                           int *fd_out)
{
    int fd = tcp_connect(domain, port);
    if (fd < 0) { *fd_out = -1; return NULL; }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { close(fd); *fd_out = -1; return NULL; }

    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, domain);

    if (ech_list && ech_list_len) {
        if (!SSL_set1_ech_config_list(ssl, ech_list, ech_list_len)) {
            SSL_free(ssl); close(fd); *fd_out = -1; return NULL;
        }
    }

    SSL_connect(ssl);   /* caller checks SSL_is_init_finished() */
    *fd_out = fd;
    return ssl;
}

/* =========================================================================
 * Cert helpers
 * ========================================================================= */

static void print_cert_names(X509 *cert)
{
    X509_NAME *subj = X509_get_subject_name(cert);
    if (subj) {
        char cn[256] = {0};
        X509_NAME_get_text_by_NID(subj, NID_commonName, cn, sizeof(cn));
        if (cn[0]) printf("    Subject CN   : %s\n", cn);
    }

    GENERAL_NAMES *sans =
        X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (sans) {
        int n = sk_GENERAL_NAME_num(sans);
        for (int i = 0; i < n; i++) {
            GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
            if (gn->type == GEN_DNS) {
                const unsigned char *name =
                    ASN1_STRING_get0_data(gn->d.dNSName);
                printf("    SAN dNSName  : %s\n", name);
            }
        }
        GENERAL_NAMES_free(sans);
    }
}

/* =========================================================================
 * KEM / KDF / AEAD name helpers
 * ========================================================================= */

static const char *kem_name(uint16_t id) {
    switch (id) {
    case KEM_P256_SHA256:   return "DHKEM(P-256, HKDF-SHA256)";
    case KEM_X25519_SHA256: return "DHKEM(X25519, HKDF-SHA256) [recommended]";
    default:                return "Unknown";
    }
}

static const char *kdf_name(uint16_t id) {
    switch (id) {
    case KDF_HKDF_SHA256: return "HKDF-SHA256 [recommended]";
    case KDF_HKDF_SHA384: return "HKDF-SHA384";
    case KDF_HKDF_SHA512: return "HKDF-SHA512";
    default:              return "Unknown";
    }
}

static const char *aead_name(uint16_t id) {
    switch (id) {
    case AEAD_AES128GCM: return "AES-128-GCM [recommended]";
    case AEAD_AES256GCM: return "AES-256-GCM";
    case AEAD_CHACHA20:  return "ChaCha20-Poly1305";
    default:             return "Unknown";
    }
}

/* =========================================================================
 * CHECK: Normal ECH
 * ========================================================================= */

static int check_ech_normal(const char *domain, const char *port)
{
    printf("=== ECH Normal Check: %s ===\n\n", domain);

    printf("%s Querying DNS HTTPS record ...\n", INFO);
    char *ech_b64 = fetch_ech_config_b64(domain, NULL);
    if (!ech_b64) {
        printf("%s No ECHConfigList in DNS — domain does not advertise ECH.\n",
               FAIL);
        return 2;
    }

    uint8_t *ech = NULL; size_t ech_len = 0;
    if (!b64_decode(ech_b64, strlen(ech_b64), &ech, &ech_len)) {
        printf("%s Failed to decode ECHConfigList.\n", FAIL);
        free(ech_b64); return 1;
    }
    free(ech_b64);
    printf("%s ECHConfigList: %zu bytes\n", PASS, ech_len);

    SSL_CTX *ctx = make_ctx(1);
    if (!ctx) { free(ech); return 1; }

    printf("%s Connecting to %s:%s with ECH ...\n", INFO, domain, port);
    int fd = -1;
    SSL *ssl = do_tls_connect(ctx, domain, port, ech, ech_len, &fd);
    free(ech);

    int rc = 1;
    if (!ssl) {
        printf("%s Connection failed.\n", FAIL);
    } else if (!SSL_is_init_finished(ssl)) {
        unsigned long e = ERR_peek_last_error();
        if (ERR_GET_REASON(e) == SSL_R_ECH_REJECTED)
            printf("%s ECH rejected by server.\n", FAIL);
        else
            printf("%s TLS handshake failed.\n", FAIL);
        print_ssl_errors();
    } else {
        int ech_ok = SSL_ech_accepted(ssl);
        printf("\n=== Result ===\n");
        printf("Domain         : %s\n", domain);
        printf("TLS            : %s\n", SSL_get_version(ssl));
        printf("Cipher         : %s\n", SSL_get_cipher(ssl));
        printf("ECH            : %s\n",
               ech_ok ? PASS " ACCEPTED" : FAIL " NOT accepted");
        SSL_shutdown(ssl);
        rc = ech_ok ? 0 : 3;
    }

    if (ssl) SSL_free(ssl);
    if (fd >= 0) close(fd);
    SSL_CTX_free(ctx);
    return rc;
}

/* =========================================================================
 * CHECK: Fallback / Rejection
 * ========================================================================= */

static int check_ech_fallback(const char *domain, const char *port)
{
    printf("=== ECH Fallback / Rejection Check: %s ===\n\n", domain);

    /* --- Fetch real ECHConfigList to get public_name ------------------- */
    printf("%s Fetching real ECHConfigList ...\n", INFO);
    char *ech_b64 = fetch_ech_config_b64(domain, NULL);
    if (!ech_b64) {
        printf("%s No ECHConfigList in DNS.\n", FAIL); return 2;
    }

    uint8_t *real_ech = NULL; size_t real_ech_len = 0;
    if (!b64_decode(ech_b64, strlen(ech_b64), &real_ech, &real_ech_len)) {
        free(ech_b64); return 1;
    }
    free(ech_b64);

    char *public_name = parse_public_name(real_ech, real_ech_len);
    if (!public_name) {
        printf("%s Could not parse public_name.\n", FAIL);
        free(real_ech); return 1;
    }
    printf("%s public_name (outer SNI): %s\n", PASS, public_name);

    /* --- Build fake ECHConfigList (unknown key) ------------------------- */
    uint8_t *fake_ech = NULL; size_t fake_ech_len = 0;
    if (!make_fake_ech_config_list(public_name, &fake_ech, &fake_ech_len)) {
        printf("%s Could not generate fake ECHConfig.\n", FAIL);
        free(public_name); free(real_ech); return 1;
    }
    printf("%s Fake ECHConfig generated (%zu bytes, random unknown key)\n",
           INFO, fake_ech_len);

    /* --- Connect with fake ECH ----------------------------------------- */
    SSL_CTX *ctx = make_ctx(0);   /* no verify — server cert is for outer name */
    if (!ctx) { free(fake_ech); free(public_name); free(real_ech); return 1; }

    printf("%s Connecting with FAKE ECH key (expecting rejection) ...\n", INFO);
    int fd = -1;
    SSL *ssl = do_tls_connect(ctx, domain, port, fake_ech, fake_ech_len, &fd);
    free(fake_ech);

    int rc = 0;

    if (!ssl) {
        printf("%s Connection failed entirely.\n", FAIL);
        SSL_CTX_free(ctx); free(public_name); free(real_ech);
        return 1;
    }

    if (SSL_is_init_finished(ssl)) {
        printf("%s Unexpected: handshake succeeded with fake ECH key.\n", WARN);
        printf("    ECH accepted: %s\n",
               SSL_ech_accepted(ssl) ? "yes" : "no");
        rc = 3;
        goto done;
    }

    {
        if (ERR_GET_REASON(ERR_peek_last_error()) != SSL_R_ECH_REJECTED) {
            printf("%s Expected SSL_R_ECH_REJECTED but got different error:\n",
                   FAIL);
            print_ssl_errors();
            rc = 1;
            goto done;
        }
    }
    ERR_clear_error();
    printf("%s Server correctly returned SSL_R_ECH_REJECTED\n\n", PASS);

    /* --- Check A: outer name ------------------------------------------- */
    printf("--- Check A: Fallback uses outer public_name ---\n");
    {
        const char *ename = NULL; size_t ename_len = 0;
        SSL_get0_ech_name_override(ssl, &ename, &ename_len);
        if (ename_len > 0) {
            printf("%s Outer name in fallback: %.*s\n",
                   PASS, (int)ename_len, ename);
            if (strncmp(ename, public_name, ename_len) == 0
                && public_name[ename_len] == '\0')
                printf("%s Matches ECHConfig public_name\n", PASS);
            else
                printf("%s Outer name differs from public_name '%s'\n",
                       WARN, public_name);
        } else {
            printf("%s No outer name override returned.\n", FAIL);
            rc = 1;
        }
    }

    /* --- Check B: server cert covers outer public_name ----------------- */
    printf("\n--- Check B: Server cert covers outer public_name ---\n");
    {
        X509 *cert = SSL_get_peer_certificate(ssl);
        if (cert) {
            print_cert_names(cert);
            int match = X509_check_host(cert, public_name,
                                        strlen(public_name), 0, NULL);
            if (match == 1)
                printf("%s Cert covers public_name '%s'\n", PASS, public_name);
            else {
                printf("%s Cert does NOT cover public_name '%s'\n",
                       FAIL, public_name);
                rc = 1;
            }
            X509_free(cert);
        } else {
            printf("%s No peer certificate returned.\n", FAIL);
            rc = 1;
        }
    }

    /* --- Check C: retry configs provided ------------------------------- */
    printf("\n--- Check C: Server provides retry ECHConfigs ---\n");
    {
        const uint8_t *retry = NULL; size_t retry_len = 0;
        SSL_get0_ech_retry_configs(ssl, &retry, &retry_len);

        if (retry_len == 0) {
            printf("%s Server provided NO retry ECHConfigs (ECH disabled?)\n",
                   FAIL);
            rc = 1;
            goto done;
        }
        printf("%s Server provided %zu bytes of retry ECHConfigs\n",
               PASS, retry_len);

        /* --- Check D: retry configs match DNS -------------------------- */
        printf("\n--- Check D: Retry configs match DNS ECHConfigs ---\n");
        if (retry_len == real_ech_len &&
            memcmp(retry, real_ech, retry_len) == 0) {
            printf("%s Retry configs are byte-identical to DNS ECHConfigs\n",
                   PASS);
        } else {
            printf("%s Retry configs differ from DNS (key rotation in progress?)\n",
                   WARN);
            printf("    DNS bytes: %zu  Retry bytes: %zu\n",
                   real_ech_len, retry_len);
        }

        /* --- Check E: retry with server configs → ECH accepted --------- */
        printf("\n--- Check E: Retry with server ECHConfigs → ECH accepted ---\n");

        uint8_t *saved = malloc(retry_len);
        size_t   saved_len = retry_len;
        memcpy(saved, retry, retry_len);

        SSL_free(ssl); ssl = NULL;
        close(fd); fd = -1;

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        printf("%s Reconnecting with retry ECHConfigs ...\n", INFO);

        ssl = do_tls_connect(ctx, domain, port, saved, saved_len, &fd);
        free(saved);

        if (!ssl) {
            printf("%s Retry connection failed.\n", FAIL);
            rc = 1;
        } else {
            int ech_ok = SSL_ech_accepted(ssl);
            printf("%s ECH %s on retry\n",
                   ech_ok ? PASS : FAIL,
                   ech_ok ? "ACCEPTED" : "NOT accepted");
            if (ech_ok) SSL_shutdown(ssl);
            else rc = 1;
        }
    }

done:
    printf("\n=== Fallback Summary ===\n");
    printf("Inner domain  : %s\n", domain);
    printf("Outer name    : %s\n", public_name);
    printf("Overall       : %s\n\n", rc == 0 ? "PASS" : "FAIL");

    if (ssl) SSL_free(ssl);
    if (fd >= 0) close(fd);
    SSL_CTX_free(ctx);
    free(public_name);
    free(real_ech);
    return rc;
}

/* =========================================================================
 * CHECK: GREASE ECH
 * =========================================================================
 * Sends an ECH extension with an unsupported KEM (0xFFFF). BoringSSL
 * detects no supported config and sends GREASE ECH. Server must tolerate
 * this — either ignore (non-ECH server → success) or reject gracefully
 * (ECH server → SSL_R_ECH_REJECTED with retry configs).
 */
static int check_ech_grease(const char *domain, const char *port)
{
    printf("=== ECH GREASE Check: %s ===\n\n", domain);
    printf("%s GREASE ECH: unsupported KEM (0xFFFF) sent in ClientHello.\n",
           INFO);
    printf("%s Servers must not hard-fail on unknown ECH extensions.\n\n", INFO);

    /* Use public_name from DNS if available, else use domain itself */
    char *ech_b64 = fetch_ech_config_b64(domain, NULL);
    char *public_name = NULL;

    if (ech_b64) {
        uint8_t *real_ech = NULL; size_t real_ech_len = 0;
        if (b64_decode(ech_b64, strlen(ech_b64), &real_ech, &real_ech_len)) {
            public_name = parse_public_name(real_ech, real_ech_len);
            free(real_ech);
        }
        free(ech_b64);
    }
    if (!public_name) public_name = strdup(domain);

    printf("%s public_name for GREASE config: %s\n\n", INFO, public_name);

    /* Build GREASE ECHConfigList */
    uint8_t *grease = NULL; size_t grease_len = 0;
    if (!make_grease_ech_config_list(public_name, &grease, &grease_len)) {
        printf("%s Failed to build GREASE ECHConfigList.\n", FAIL);
        free(public_name); return 1;
    }

    SSL_CTX *ctx = make_ctx(0);   /* no cert verify, we want to see behavior */
    if (!ctx) { free(grease); free(public_name); return 1; }

    printf("%s Connecting with GREASE ECH ...\n", INFO);
    int fd = -1;
    SSL *ssl = do_tls_connect(ctx, domain, port, grease, grease_len, &fd);
    free(grease);

    int rc = 0;

    if (!ssl) {
        printf("%s Connection failed — server may have rejected GREASE ECH.\n",
               FAIL);
        rc = 1;
        goto done_grease;
    }

    if (SSL_is_init_finished(ssl)) {
        /* Connection succeeded — GREASE was ignored (non-ECH server) or
         * BoringSSL silently dropped the unsupported config */
        int ech_ok = SSL_ech_accepted(ssl);
        if (!ech_ok) {
            printf("%s Server tolerated GREASE ECH, connected normally "
                   "(ECH not negotiated, as expected)\n", PASS);
        } else {
            printf("%s Unexpected: ECH accepted with GREASE config\n", WARN);
        }
        SSL_shutdown(ssl);
    } else {
        unsigned long e = ERR_peek_last_error();
        if (ERR_GET_REASON(e) == SSL_R_ECH_REJECTED) {
            ERR_clear_error();
            /* ECH server: graceful rejection is fine */
            const uint8_t *retry = NULL; size_t retry_len = 0;
            SSL_get0_ech_retry_configs(ssl, &retry, &retry_len);
            printf("%s ECH server: gracefully rejected GREASE ECH\n", PASS);
            printf("%s Server provided %zu bytes of retry ECHConfigs\n",
                   retry_len > 0 ? PASS : WARN, retry_len);
        } else {
            printf("%s TLS hard failure on GREASE ECH (server intolerant):\n",
                   FAIL);
            print_ssl_errors();
            rc = 1;
        }
    }

done_grease:
    printf("\n=== GREASE Summary ===\n");
    printf("Domain   : %s\n", domain);
    printf("Overall  : %s\n\n", rc == 0 ? "PASS" : "FAIL");

    if (ssl) SSL_free(ssl);
    if (fd >= 0) close(fd);
    SSL_CTX_free(ctx);
    free(public_name);
    return rc;
}

/* =========================================================================
 * CHECK: Config Audit
 * =========================================================================
 * Parses the ECHConfigList from DNS and audits:
 *   - ECHConfig version (must be 0xfe0d)
 *   - KEM, KDF, AEAD algorithm choices
 *   - Duplicate config IDs
 *   - Number of configs (rollover readiness)
 *   - DNS TTL
 *   - max_name_length (padding)
 */
static int check_ech_config(const char *domain, const char *port)
{
    (void)port;
    printf("=== ECH Config Audit: %s ===\n\n", domain);

    int ttl = -1;
    char *ech_b64 = fetch_ech_config_b64(domain, &ttl);
    if (!ech_b64) {
        printf("%s No ECHConfigList in DNS HTTPS record.\n", FAIL);
        return 2;
    }

    uint8_t *ech = NULL; size_t ech_len = 0;
    if (!b64_decode(ech_b64, strlen(ech_b64), &ech, &ech_len)) {
        printf("%s Failed to decode ECHConfigList.\n", FAIL);
        free(ech_b64); return 1;
    }
    free(ech_b64);

    printf("%s ECHConfigList raw size: %zu bytes\n", INFO, ech_len);

    /* Parse all configs */
    EchConfig configs[16];
    int n = parse_ech_configs(ech, ech_len, configs, 16);
    free(ech);

    printf("%s ECHConfig entries found: %d\n\n", INFO, n);

    int rc = 0;

    for (int i = 0; i < n; i++) {
        EchConfig *c = &configs[i];
        printf("--- ECHConfig[%d] ---\n", i);
        printf("  config_id       : 0x%02x\n", c->config_id);
        printf("  version         : 0x%04x %s\n",
               c->version,
               c->version == ECH_VERSION ? PASS : FAIL " (not 0xfe0d!)");

        if (c->version != ECH_VERSION) {
            printf("%s Unsupported ECHConfig version 0x%04x\n",
                   FAIL, c->version);
            rc = 1;
            continue;
        }

        printf("  public_name     : %s\n", c->public_name);
        printf("  max_name_length : %u (padding covers names up to %u chars)\n",
               c->max_name_len, c->max_name_len);

        /* KEM */
        printf("  KEM (0x%04x)    : %s\n", c->kem_id, kem_name(c->kem_id));
        if (c->kem_id != KEM_X25519_SHA256) {
            printf("  %s KEM is not the recommended X25519 (0x0020)\n", WARN);
        }

        /* Cipher suites */
        printf("  cipher suites   : %d total\n", c->num_cipher_suites);
        printf("  KDF  (0x%04x)   : %s\n", c->kdf_id, kdf_name(c->kdf_id));
        printf("  AEAD (0x%04x)   : %s\n", c->aead_id, aead_name(c->aead_id));

        if (c->kdf_id != KDF_HKDF_SHA256) {
            printf("  %s KDF is not the recommended HKDF-SHA256\n", WARN);
        }
        if (c->aead_id != AEAD_AES128GCM) {
            printf("  %s AEAD is not the recommended AES-128-GCM\n", WARN);
        }
        printf("\n");
    }

    /* Duplicate config ID check */
    printf("--- Duplicate config_id check ---\n");
    {
        int dup = 0;
        for (int i = 0; i < n; i++)
            for (int j = i + 1; j < n; j++)
                if (configs[i].config_id == configs[j].config_id) {
                    printf("%s Duplicate config_id 0x%02x (configs %d and %d)\n",
                           FAIL, configs[i].config_id, i, j);
                    dup = 1; rc = 1;
                }
        if (!dup)
            printf("%s No duplicate config IDs\n", PASS);
    }

    /* Multiple configs (key rollover readiness) */
    printf("\n--- Key rollover readiness ---\n");
    if (n >= 2) {
        printf("%s Multiple ECHConfigs present (%d) — supports key rollover\n",
               PASS, n);
    } else {
        printf("%s Only one ECHConfig — no overlap for key rotation\n", WARN);
        printf("    Recommendation: serve 2 configs during key rollover periods\n");
    }

    /* DNS TTL */
    printf("\n--- DNS TTL ---\n");
    if (ttl < 0) {
        printf("%s Could not determine TTL\n", WARN);
    } else {
        printf("    TTL: %d seconds\n", ttl);
        if (ttl < TTL_WARN_LOW) {
            printf("%s TTL is very low (%ds) — excessive DNS queries\n",
                   WARN, ttl);
        } else if (ttl > TTL_WARN_HIGH) {
            printf("%s TTL is very high (%ds) — slow key rotation\n",
                   WARN, ttl);
        } else {
            printf("%s TTL is reasonable (%ds)\n", PASS, ttl);
        }
        printf("    After key rotation, old clients may cache stale ECHConfigs\n"
               "    for up to %ds — server must keep old keys for this duration.\n",
               ttl);
    }

    printf("\n=== Config Audit Summary ===\n");
    printf("Domain   : %s\n", domain);
    printf("Configs  : %d\n", n);
    printf("Overall  : %s\n\n", rc == 0 ? "PASS" : "FAIL/WARN");
    return rc;
}

/* =========================================================================
 * CHECK: Privacy
 * =========================================================================
 *   1. Warn about plaintext DNS revealing inner domain
 *   2. Check public_name is independently resolvable and reachable
 *   3. Verify public_name has a valid TLS certificate
 *   4. Check HTTPS record exists for public_name (retry config delivery)
 */
static int check_ech_privacy(const char *domain, const char *port)
{
    (void)port;
    printf("=== ECH Privacy Check: %s ===\n\n", domain);

    int rc = 0;

    /* --- Check 1: Plaintext DNS warning -------------------------------- */
    printf("--- Check 1: DNS privacy ---\n");
    printf("%s ECH hides the inner SNI from network observers — but ONLY if\n",
           WARN);
    printf("    DNS queries are also encrypted (DoH / DoT).\n");
    printf("    A plaintext DNS query for '%s' reveals the inner domain\n",
           domain);
    printf("    to any on-path observer, defeating ECH's privacy goal.\n");
    printf("    Recommendation: use a DoH/DoT resolver (e.g. 1.1.1.1:853).\n\n");

    /* --- Fetch ECHConfig to get public_name ---------------------------- */
    char *ech_b64 = fetch_ech_config_b64(domain, NULL);
    if (!ech_b64) {
        printf("%s No ECHConfigList in DNS — cannot determine public_name.\n",
               FAIL);
        return 2;
    }

    uint8_t *real_ech = NULL; size_t real_ech_len = 0;
    if (!b64_decode(ech_b64, strlen(ech_b64), &real_ech, &real_ech_len)) {
        free(ech_b64); return 1;
    }
    free(ech_b64);

    char *public_name = parse_public_name(real_ech, real_ech_len);
    free(real_ech);
    if (!public_name) {
        printf("%s Could not parse public_name.\n", FAIL); return 1;
    }
    printf("%s ECHConfig public_name: %s\n\n", INFO, public_name);

    /* --- Check 2: public_name is resolvable ---------------------------- */
    printf("--- Check 2: public_name is independently resolvable ---\n");
    {
        struct addrinfo hints = {0};
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        struct addrinfo *res = NULL;
        int grc = getaddrinfo(public_name, "443", &hints, &res);
        if (grc == 0) {
            /* Count addresses */
            int cnt = 0;
            for (struct addrinfo *r = res; r; r = r->ai_next) cnt++;
            printf("%s public_name resolves to %d address(es)\n", PASS, cnt);
            freeaddrinfo(res);
        } else {
            printf("%s public_name '%s' does not resolve: %s\n",
                   FAIL, public_name, gai_strerror(grc));
            printf("    Fallback TLS cert verification will fail on ECH rejection.\n");
            rc = 1;
        }
    }

    /* --- Check 3: public_name has valid TLS cert ----------------------- */
    printf("\n--- Check 3: public_name has valid TLS certificate ---\n");
    {
        SSL_CTX *ctx = make_ctx(1);
        if (ctx) {
            int fd2 = -1;
            SSL *ssl2 = do_tls_connect(ctx, public_name, "443",
                                       NULL, 0, &fd2);
            if (ssl2 && SSL_is_init_finished(ssl2)) {
                printf("%s TLS connection to public_name succeeded\n", PASS);
                X509 *cert = SSL_get_peer_certificate(ssl2);
                if (cert) {
                    print_cert_names(cert);
                    int match = X509_check_host(cert, public_name,
                                                strlen(public_name), 0, NULL);
                    printf("%s Cert %s public_name '%s'\n",
                           match == 1 ? PASS : FAIL,
                           match == 1 ? "covers" : "does NOT cover",
                           public_name);
                    if (match != 1) rc = 1;
                    X509_free(cert);
                }
                SSL_shutdown(ssl2);
            } else {
                printf("%s Could not establish TLS to public_name '%s'\n",
                       FAIL, public_name);
                printf("    Clients cannot verify cert during ECH rejection.\n");
                rc = 1;
            }
            if (ssl2) SSL_free(ssl2);
            if (fd2 >= 0) close(fd2);
            SSL_CTX_free(ctx);
        }
    }

    /* --- Check 4: HTTPS record for public_name ------------------------- */
    printf("\n--- Check 4: HTTPS record on public_name (retry config delivery) ---\n");
    {
        char *pub_ech = fetch_ech_config_b64(public_name, NULL);
        if (pub_ech) {
            printf("%s public_name has an HTTPS record with ECH config\n",
                   PASS);
            printf("    Clients can re-query public_name for fresh retry configs.\n");
            free(pub_ech);
        } else {
            /* Check if HTTPS record exists without ECH */
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                     "dig +short HTTPS %s 2>/dev/null", public_name);
            FILE *fp = popen(cmd, "r");
            char line[256] = {0};
            if (fp) {
                if (fgets(line, sizeof(line), fp) == NULL) line[0] = '\0';
                pclose(fp);
            }

            if (strlen(line) > 2) {
                printf("%s public_name has HTTPS record (no ECH config in it)\n",
                       WARN);
                printf("    Clients cannot get retry configs from public_name DNS.\n");
            } else {
                printf("%s public_name has NO HTTPS record\n", WARN);
                printf("    Retry config delivery via DNS is not supported.\n");
            }
        }
    }

    printf("\n=== Privacy Summary ===\n");
    printf("Inner domain  : %s\n", domain);
    printf("Outer name    : %s\n", public_name);
    printf("Overall       : %s\n\n", rc == 0 ? "PASS" : "FAIL");

    free(public_name);
    return rc;
}

/* =========================================================================
 * CHECK: Certificate & Protocol
 * =========================================================================
 *   1. TLS 1.3 enforced (ECH requires TLS 1.3)
 *   2. Server cert covers inner domain (not just outer)
 *   3. ALPN negotiated correctly
 *   4. ECH accepted
 */
static int check_ech_cert(const char *domain, const char *port)
{
    printf("=== ECH Cert & Protocol Check: %s ===\n\n", domain);

    char *ech_b64 = fetch_ech_config_b64(domain, NULL);
    if (!ech_b64) {
        printf("%s No ECHConfigList in DNS.\n", FAIL); return 2;
    }

    uint8_t *ech = NULL; size_t ech_len = 0;
    if (!b64_decode(ech_b64, strlen(ech_b64), &ech, &ech_len)) {
        free(ech_b64); return 1;
    }
    free(ech_b64);

    SSL_CTX *ctx = make_ctx(1);
    if (!ctx) { free(ech); return 1; }

    printf("%s Connecting with real ECH ...\n", INFO);
    int fd = -1;
    SSL *ssl = do_tls_connect(ctx, domain, port, ech, ech_len, &fd);
    free(ech);

    int rc = 0;

    if (!ssl || !SSL_is_init_finished(ssl)) {
        if (ssl && ERR_GET_REASON(ERR_peek_last_error()) == SSL_R_ECH_REJECTED) {
            printf("%s ECH was rejected — cannot check inner cert.\n", FAIL);
            ERR_clear_error();
        } else {
            printf("%s TLS handshake failed.\n", FAIL);
            print_ssl_errors();
        }
        rc = 1;
        goto done_cert;
    }

    /* --- Check 1: TLS 1.3 --------------------------------------------- */
    printf("\n--- Check 1: TLS version ---\n");
    {
        const char *ver = SSL_get_version(ssl);
        int is_13 = (strcmp(ver, "TLSv1.3") == 0);
        printf("%s TLS version: %s\n",
               is_13 ? PASS : FAIL, ver);
        if (!is_13) {
            printf("    ECH requires TLS 1.3. Connections falling back to "
                   "TLS 1.2 send SNI in plaintext.\n");
            rc = 1;
        }
    }

    /* --- Check 2: ECH accepted ----------------------------------------- */
    printf("\n--- Check 2: ECH accepted ---\n");
    {
        int ech_ok = SSL_ech_accepted(ssl);
        printf("%s ECH %s\n",
               ech_ok ? PASS : FAIL,
               ech_ok ? "ACCEPTED" : "NOT accepted (inner SNI may be exposed)");
        if (!ech_ok) rc = 1;
    }

    /* --- Check 3: Inner domain cert ------------------------------------ */
    printf("\n--- Check 3: Server cert covers inner domain ---\n");
    {
        X509 *cert = SSL_get_peer_certificate(ssl);
        if (cert) {
            printf("    Server presented:\n");
            print_cert_names(cert);
            int match = X509_check_host(cert, domain,
                                        strlen(domain), 0, NULL);
            printf("%s Cert %s inner domain '%s'\n",
                   match == 1 ? PASS : FAIL,
                   match == 1 ? "covers" : "does NOT cover",
                   domain);
            if (match != 1) {
                printf("    The inner ClientHello SNI must match the cert "
                       "presented after ECH decryption.\n");
                rc = 1;
            }
            X509_free(cert);
        } else {
            printf("%s No peer certificate.\n", FAIL);
            rc = 1;
        }
    }

    /* --- Check 4: ALPN ------------------------------------------------- */
    printf("\n--- Check 4: ALPN negotiation ---\n");
    {
        const uint8_t *proto = NULL; unsigned proto_len = 0;
        SSL_get0_alpn_selected(ssl, &proto, &proto_len);
        if (proto_len > 0) {
            printf("%s ALPN negotiated: %.*s\n", PASS, proto_len, proto);
        } else {
            printf("%s No ALPN negotiated\n", WARN);
        }
    }

    SSL_shutdown(ssl);

done_cert:
    printf("\n=== Cert & Protocol Summary ===\n");
    printf("Domain   : %s\n", domain);
    printf("Overall  : %s\n\n", rc == 0 ? "PASS" : "FAIL");

    if (ssl) SSL_free(ssl);
    if (fd >= 0) close(fd);
    SSL_CTX_free(ctx);
    return rc;
}

/* =========================================================================
 * CHECK: All
 * ========================================================================= */

static int check_all(const char *domain, const char *port)
{
    printf("########################################\n");
    printf("# echcheck --all: %s\n", domain);
    printf("########################################\n\n");

    int r1 = check_ech_normal (domain, port);
    int r2 = check_ech_fallback(domain, port);
    int r3 = check_ech_grease  (domain, port);
    int r4 = check_ech_config  (domain, port);
    int r5 = check_ech_privacy (domain, port);
    int r6 = check_ech_cert    (domain, port);

    printf("########################################\n");
    printf("# Overall Results\n");
    printf("########################################\n");
    printf("  Normal ECH    : %s\n", r1 == 0 ? "PASS" : "FAIL");
    printf("  Fallback      : %s\n", r2 == 0 ? "PASS" : "FAIL");
    printf("  GREASE        : %s\n", r3 == 0 ? "PASS" : "FAIL");
    printf("  Config Audit  : %s\n", r4 == 0 ? "PASS" : "WARN/FAIL");
    printf("  Privacy       : %s\n", r5 == 0 ? "PASS" : "FAIL");
    printf("  Cert/Protocol : %s\n", r6 == 0 ? "PASS" : "FAIL");

    int any_fail = (r1 && r1 != 3) || (r2 && r2 != 3) || r3 || r4 || r5 || r6;
    printf("\nFinal: %s\n", any_fail ? "FAIL" : "PASS");
    return any_fail ? 1 : 0;
}

/* =========================================================================
 * main
 * ========================================================================= */

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage:\n"
            "  %s <domain> [port]                  verify ECH accepted\n"
            "  %s --check-fallback <domain> [port]  rejection/retry flow\n"
            "  %s --check-grease  <domain> [port]   GREASE ECH tolerance\n"
            "  %s --check-config  <domain> [port]   audit ECHConfig (ciphers, TTL, IDs)\n"
            "  %s --check-privacy <domain> [port]   DNS privacy + public name reachability\n"
            "  %s --check-cert    <domain> [port]   inner cert SAN + TLS1.3 + ALPN\n"
            "  %s --all           <domain> [port]   run all checks\n"
            "\n  port defaults to 443\n",
            argv[0], argv[0], argv[0], argv[0],
            argv[0], argv[0], argv[0]);
        return 1;
    }

    const char *mode   = NULL;
    int         arg_idx = 1;

    if (argv[1][0] == '-') {
        mode    = argv[1];
        arg_idx = 2;
        if (argc < 3) {
            fprintf(stderr, "Missing domain after %s\n", mode);
            return 1;
        }
    }

    const char *domain = argv[arg_idx];
    const char *port   = (argc > arg_idx + 1) ? argv[arg_idx + 1] : "443";

    if (!mode)                               return check_ech_normal (domain, port);
    if (!strcmp(mode, "--check-fallback"))   return check_ech_fallback(domain, port);
    if (!strcmp(mode, "--check-grease"))     return check_ech_grease  (domain, port);
    if (!strcmp(mode, "--check-config"))     return check_ech_config  (domain, port);
    if (!strcmp(mode, "--check-privacy"))    return check_ech_privacy (domain, port);
    if (!strcmp(mode, "--check-cert"))       return check_ech_cert    (domain, port);
    if (!strcmp(mode, "--all"))              return check_all         (domain, port);

    fprintf(stderr, "Unknown option: %s\n", mode);
    return 1;
}
