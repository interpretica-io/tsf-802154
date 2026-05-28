/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief What a network's frames give away
 */

#define TE_LGR_USER "TAPI 802154"

#include "te_config.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_string.h"

#include "tapi_802154_audit.h"

const tapi_802154_policy tapi_802154_default_policy = {
    .min_level = TAPI_802154_SEC_ENC_MIC32,
    .forbidden_keys = NULL,
    .n_forbidden_keys = 0,
    .key_in_use = NULL,
    .allow_counter_reset = false,
};

/** Find the last frame from the same sender, or SIZE_MAX. */
static size_t
audit_previous_from(const tapi_802154_frame *frames, size_t upto,
                    uint64_t addr)
{
    size_t i;

    for (i = upto; i > 0; i--)
    {
        if (frames[i - 1].src_addr == addr && frames[i - 1].secured)
            return i - 1;
    }

    return (size_t)-1;
}

/* See description in tapi_802154_audit.h */
void
tapi_802154_audit(const tapi_802154_frame *frames, size_t n_frames,
                  const tapi_802154_policy *policy,
                  tapi_cybersec_report *report)
{
    size_t unsecured = 0;
    size_t weak = 0;
    size_t i;

    if (policy == NULL)
        policy = &tapi_802154_default_policy;

    if (n_frames == 0)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
            "ieee802154.nothing-seen", "network",
            "No frames were collected, so nothing about this network was "
            "established.");
        return;
    }

    for (i = 0; i < n_frames; i++)
    {
        const tapi_802154_frame *frame = &frames[i];
        size_t previous;

        /*
         * Acknowledgements carry nothing and are never secured; the
         * standard does not give them anywhere to put security. Counting
         * them as unprotected frames would report every network alive.
         */
        if (frame->type == TAPI_802154_ACK)
            continue;

        if (!frame->secured)
        {
            unsecured++;
            continue;
        }

        if (frame->sec_level < policy->min_level)
            weak++;

        previous = audit_previous_from(frames, i, frame->src_addr);
        if (previous == (size_t)-1)
            continue;

        if (frame->frame_counter > frames[previous].frame_counter)
            continue;

        if (frame->frame_counter == frames[previous].frame_counter)
        {
            te_string subject = TE_STRING_INIT;

            /*
             * The nonce is the address, the counter and the level, so
             * two frames from one device with one counter were
             * encrypted with the same keystream. Exclusive-oring the
             * two ciphertexts removes the key; no key is needed to
             * read them. The same failure as LoRaWAN's, for the same
             * reason.
             */
            te_string_append(&subject, "%016" PRIX64, frame->src_addr);
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_CRITICAL,
                "ieee802154.counter-reuse", te_string_value(&subject),
                "Two frames from this device carry counter %u. The nonce "
                "is built from it, so both were encrypted with the same "
                "keystream and can be combined without any key at all.",
                frame->frame_counter);
            te_string_free(&subject);
        }
        else if (!policy->allow_counter_reset)
        {
            te_string subject = TE_STRING_INIT;

            te_string_append(&subject, "%016" PRIX64, frame->src_addr);
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                "ieee802154.counter-reset", te_string_value(&subject),
                "The frame counter went from %u back to %u. Every frame "
                "recorded above the new value can be sent again and will "
                "be accepted.", frames[previous].frame_counter,
                frame->frame_counter);
            te_string_free(&subject);
        }
    }

    if (unsecured != 0)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
            "ieee802154.unsecured-frames", "network",
            "%zu of %zu frames carry no security at all: readable by "
            "anyone listening and forgeable by anyone transmitting.",
            unsecured, n_frames);
    }

    if (weak != 0)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
            "ieee802154.weak-security-level", "network",
            "%zu frames are protected below the level this network is "
            "expected to use.", weak);
    }

    for (i = 0; i < policy->n_forbidden_keys &&
                policy->key_in_use != NULL; i++)
    {
        uint8_t wanted[TAPI_802154_KEY_LEN];
        uint8_t in_use[TAPI_802154_KEY_LEN];
        size_t a = 0;
        size_t b = 0;

        if (tapi_802154_unhex(policy->forbidden_keys[i], wanted,
                              sizeof(wanted), &a) != 0 ||
            tapi_802154_unhex(policy->key_in_use, in_use, sizeof(in_use),
                              &b) != 0 ||
            a != TAPI_802154_KEY_LEN || b != TAPI_802154_KEY_LEN)
        {
            continue;
        }

        if (memcmp(wanted, in_use, TAPI_802154_KEY_LEN) == 0)
        {
            /*
             * The key is not in the finding. A report may be passed on,
             * and a verdict has to match the same thing tomorrow; which
             * entry of the list it was is enough to act on.
             */
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_CRITICAL,
                "ieee802154.known-key", "network",
                "The network is using one of the keys this test was told "
                "to look for - entry %zu of the list. Zigbee's default "
                "trust centre link key is printed in the specification.",
                i);
        }
    }
}
