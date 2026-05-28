/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief What protects an 802.15.4 frame
 */

#define TE_LGR_USER "TAPI 802154"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "logger_api.h"
#include "te_string.h"

#include "tapi_802154_sec.h"

/* See description in tapi_802154_sec.h */
void
tapi_802154_nonce(uint64_t src_addr, uint32_t counter,
                  tapi_802154_sec_level level, uint8_t *nonce)
{
    unsigned int i;

    /*
     * The address goes in big endian here, which is the opposite of
     * how it travels in the frame header. The standard says so, and
     * getting it the other way round produces a nonce that is
     * perfectly well formed and decrypts nothing.
     */
    for (i = 0; i < 8; i++)
        nonce[i] = (uint8_t)((src_addr >> (8 * (7 - i))) & 0xff);

    nonce[8] = (uint8_t)((counter >> 24) & 0xff);
    nonce[9] = (uint8_t)((counter >> 16) & 0xff);
    nonce[10] = (uint8_t)((counter >> 8) & 0xff);
    nonce[11] = (uint8_t)(counter & 0xff);

    nonce[12] = (uint8_t)(level & 0x07);
}

/** Set up a CCM context for one operation. */
static EVP_CIPHER_CTX *
sec_ccm_begin(const uint8_t *key, const uint8_t *nonce, size_t mic_len,
              bool encrypting, const uint8_t *tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;

    if (ctx == NULL)
        return NULL;

    if (EVP_CipherInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL,
                          encrypting ? 1 : 0) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                            TAPI_802154_NONCE_LEN, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)mic_len,
                            (void *)tag) != 1 ||
        EVP_CipherInit_ex(ctx, NULL, NULL, key, nonce,
                          encrypting ? 1 : 0) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    (void)len;

    return ctx;
}

/* See description in tapi_802154_sec.h */
te_errno
tapi_802154_secure(const uint8_t *key, const uint8_t *nonce,
                   tapi_802154_sec_level level, const uint8_t *header,
                   size_t header_len, uint8_t *payload,
                   size_t *payload_len, size_t max_len)
{
    size_t mic_len = tapi_802154_mic_len(level);
    EVP_CIPHER_CTX *ctx;
    uint8_t *plain = NULL;
    int len = 0;
    te_errno rc = 0;

    if (level == TAPI_802154_SEC_NONE)
        return 0;

    if (*payload_len + mic_len > max_len)
    {
        ERROR("No room for a %zu byte integrity code", mic_len);
        return TE_RC(TE_TAPI, TE_ESMALLBUF);
    }

    ctx = sec_ccm_begin(key, nonce, mic_len, true, NULL);
    if (ctx == NULL)
        return TE_RC(TE_TAPI, TE_EFAIL);

    /*
     * CCM has to be told the total plaintext length before any of it
     * is given, which is what this first call with a NULL output does.
     * Skipping it makes every operation fail with no useful error.
     */
    if (EVP_CipherUpdate(ctx, NULL, &len, NULL,
                         (int)(tapi_802154_encrypts(level) ?
                               *payload_len : 0)) != 1)
    {
        rc = TE_RC(TE_TAPI, TE_EFAIL);
        goto out;
    }

    if (header_len != 0 &&
        EVP_CipherUpdate(ctx, NULL, &len, header, (int)header_len) != 1)
    {
        rc = TE_RC(TE_TAPI, TE_EFAIL);
        goto out;
    }

    if (tapi_802154_encrypts(level) && *payload_len != 0)
    {
        plain = malloc(*payload_len);
        if (plain == NULL)
        {
            rc = TE_RC(TE_TAPI, TE_ENOMEM);
            goto out;
        }

        memcpy(plain, payload, *payload_len);

        if (EVP_CipherUpdate(ctx, payload, &len, plain,
                             (int)*payload_len) != 1)
        {
            rc = TE_RC(TE_TAPI, TE_EFAIL);
            goto out;
        }
    }
    else if (!tapi_802154_encrypts(level) && *payload_len != 0)
    {
        /*
         * A level that signs without encrypting: the payload is part
         * of what is signed rather than part of what is transformed,
         * so it goes in as additional data and comes out unchanged.
         */
        if (EVP_CipherUpdate(ctx, NULL, &len, payload,
                             (int)*payload_len) != 1)
        {
            rc = TE_RC(TE_TAPI, TE_EFAIL);
            goto out;
        }
    }

    if (EVP_CipherFinal_ex(ctx, payload + *payload_len, &len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)mic_len,
                            payload + *payload_len) != 1)
    {
        rc = TE_RC(TE_TAPI, TE_EFAIL);
        goto out;
    }

    *payload_len += mic_len;

out:
    free(plain);
    EVP_CIPHER_CTX_free(ctx);

    return rc;
}

/* See description in tapi_802154_sec.h */
te_errno
tapi_802154_unsecure(const uint8_t *key, const uint8_t *nonce,
                     tapi_802154_sec_level level, const uint8_t *header,
                     size_t header_len, uint8_t *payload,
                     size_t *payload_len)
{
    size_t mic_len = tapi_802154_mic_len(level);
    size_t body;
    EVP_CIPHER_CTX *ctx;
    uint8_t *cipher = NULL;
    int len = 0;
    te_errno rc = 0;

    if (level == TAPI_802154_SEC_NONE)
        return 0;

    if (*payload_len < mic_len)
    {
        ERROR("A frame claiming a %zu byte integrity code has %zu bytes",
              mic_len, *payload_len);
        return TE_RC(TE_TAPI, TE_EBADMSG);
    }

    body = *payload_len - mic_len;

    ctx = sec_ccm_begin(key, nonce, mic_len, false, payload + body);
    if (ctx == NULL)
        return TE_RC(TE_TAPI, TE_EFAIL);

    if (EVP_CipherUpdate(ctx, NULL, &len, NULL,
                         (int)(tapi_802154_encrypts(level) ? body : 0)) != 1)
    {
        rc = TE_RC(TE_TAPI, TE_EFAIL);
        goto out;
    }

    if (header_len != 0 &&
        EVP_CipherUpdate(ctx, NULL, &len, header, (int)header_len) != 1)
    {
        rc = TE_RC(TE_TAPI, TE_EFAIL);
        goto out;
    }

    if (tapi_802154_encrypts(level) && body != 0)
    {
        cipher = malloc(body);
        if (cipher == NULL)
        {
            rc = TE_RC(TE_TAPI, TE_ENOMEM);
            goto out;
        }

        memcpy(cipher, payload, body);

        /*
         * In CCM decryption OpenSSL reports the verdict from this call
         * rather than from a final one - there is no final call - so a
         * failure here is a frame that was tampered with.
         */
        if (EVP_CipherUpdate(ctx, payload, &len, cipher, (int)body) != 1)
        {
            ERROR("The integrity code on this frame does not match");
            rc = TE_RC(TE_TAPI, TE_EBADMSG);
            goto out;
        }
    }
    else if (body != 0)
    {
        if (EVP_CipherUpdate(ctx, NULL, &len, payload, (int)body) != 1)
        {
            ERROR("The integrity code on this frame does not match");
            rc = TE_RC(TE_TAPI, TE_EBADMSG);
            goto out;
        }
    }

    *payload_len = body;

out:
    free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return rc;
}
