/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief What protects an 802.15.4 frame
 *
 * @defgroup tapi_802154_sec Frame security (tapi_802154_sec)
 * @ingroup tapi_802154
 * @{
 *
 * Zigbee and Thread protect a frame the same way, because they both
 * inherit it from 802.15.4: AES-CCM*, keyed with a network key,
 * with a nonce built from who sent it and a counter.
 *
 * @section tapi_802154_sec_nonce The nonce is the whole thing
 *
 *     SourceExtendedAddress | FrameCounter | SecurityLevel
 *              8                   4              1
 *
 * Thirteen bytes, and every part of it matters. The counter is what
 * makes two frames from one device encrypt differently, so a device
 * that restarts its counter encrypts two different frames with the
 * same keystream - and exclusive-oring them removes the key. It is
 * exactly the failure @ref tapi_lorawan_audit looks for in LoRaWAN,
 * for exactly the same reason.
 *
 * @code
 * uint8_t nonce[TAPI_802154_NONCE_LEN];
 *
 * tapi_802154_nonce(0x0011223344556677, 42,
 *                   TAPI_802154_SEC_ENC_MIC32, nonce);
 * CHECK_RC(tapi_802154_secure(key, nonce, TAPI_802154_SEC_ENC_MIC32,
 *                             header, header_len, payload, &len));
 * @endcode
 */

#ifndef __TSF_TAPI_802154_SEC_H__
#define __TSF_TAPI_802154_SEC_H__

#include <stdint.h>

#include "te_defs.h"
#include "te_errno.h"

#include "tapi_802154.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Length of the nonce, in bytes. */
#define TAPI_802154_NONCE_LEN 13

/**
 * Build the nonce for a frame.
 *
 * @param[in]  src_addr     The sender's extended address.
 * @param[in]  counter      Its frame counter.
 * @param[in]  level        The security level.
 * @param[out] nonce        Buffer of @ref TAPI_802154_NONCE_LEN bytes.
 */
extern void tapi_802154_nonce(uint64_t src_addr, uint32_t counter,
                              tapi_802154_sec_level level, uint8_t *nonce);

/**
 * Encrypt a payload and put an integrity code after it.
 *
 * The header is signed and not encrypted, which is what lets a router
 * read where a frame is going without being able to read what is in
 * it.
 *
 * @param[in]     key           The key.
 * @param[in]     nonce         From tapi_802154_nonce().
 * @param[in]     level         How much to protect.
 * @param[in]     header        The bytes to sign but not encrypt.
 * @param[in]     header_len    How many.
 * @param[in,out] payload       The payload; the integrity code is
 *                              appended, so there must be room for it.
 * @param[in,out] payload_len   Its length in, and the protected
 *                              length out.
 * @param[in]     max_len       How much room @p payload has.
 *
 * @return Status code.
 */
extern te_errno tapi_802154_secure(const uint8_t *key,
                                   const uint8_t *nonce,
                                   tapi_802154_sec_level level,
                                   const uint8_t *header,
                                   size_t header_len, uint8_t *payload,
                                   size_t *payload_len, size_t max_len);

/**
 * Check the integrity code and decrypt.
 *
 * @param[in]     key           The key.
 * @param[in]     nonce         From tapi_802154_nonce().
 * @param[in]     level         How much it was protected.
 * @param[in]     header        The bytes that were signed.
 * @param[in]     header_len    How many.
 * @param[in,out] payload       The protected payload; decrypted in
 *                              place.
 * @param[in,out] payload_len   Its length in, and the plaintext
 *                              length out.
 *
 * @return Status code.
 * @retval TE_EBADMSG           The integrity code does not match. The
 *                              payload is not decrypted, because
 *                              nothing in it can be trusted.
 */
extern te_errno tapi_802154_unsecure(const uint8_t *key,
                                     const uint8_t *nonce,
                                     tapi_802154_sec_level level,
                                     const uint8_t *header,
                                     size_t header_len, uint8_t *payload,
                                     size_t *payload_len);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_802154_SEC_H__ */

/**@} <!-- END tapi_802154_sec --> */
