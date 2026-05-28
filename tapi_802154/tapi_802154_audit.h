/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief What a network's frames give away
 *
 * @defgroup tapi_802154_audit 802.15.4 security posture
 * @ingroup tapi_802154
 * @{
 *
 * Reads a sequence of frames a test has collected and reports what is
 * wrong with how they are protected.
 *
 * @code
 * tapi_cybersec_report report;
 *
 * tapi_cybersec_report_init(&report);
 * tapi_802154_audit(frames, n_frames, NULL, &report);
 * tapi_cybersec_report_log(&report);
 * @endcode
 */

#ifndef __TSF_TAPI_802154_AUDIT_H__
#define __TSF_TAPI_802154_AUDIT_H__

#include "te_defs.h"
#include "te_errno.h"

#include "tapi_cybersec.h"
#include "tapi_802154.h"

#ifdef __cplusplus
extern "C" {
#endif

/** What the network is expected to do. */
typedef struct tapi_802154_policy {
    /** The least protection every frame must have. */
    tapi_802154_sec_level min_level;
    /**
     * Keys the network should not be using, in hexadecimal.
     *
     * Zigbee's default trust centre link key is published in the
     * specification, which is the case this exists for. Nothing is
     * built in: a test says what it is looking for.
     */
    const char **forbidden_keys;
    /** Number of @a forbidden_keys. */
    size_t n_forbidden_keys;
    /** A key actually in use, to compare against @a forbidden_keys. */
    const char *key_in_use;
    /** The frame counter may go backwards. */
    bool allow_counter_reset;
} tapi_802154_policy;

/** The default: encrypted and signed with at least four bytes. */
extern const tapi_802154_policy tapi_802154_default_policy;

/**
 * Read a sequence of frames and report what is wrong.
 *
 * @param[in]  frames       The frames, in the order they were seen.
 * @param[in]  n_frames     How many.
 * @param[in]  policy       What is expected, or @c NULL for the
 *                          default.
 * @param[out] report       Report to append findings to.
 */
extern void tapi_802154_audit(const tapi_802154_frame *frames,
                              size_t n_frames,
                              const tapi_802154_policy *policy,
                              tapi_cybersec_report *report);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_802154_AUDIT_H__ */

/**@} <!-- END tapi_802154_audit --> */
