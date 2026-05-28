/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief IEEE 802.15.4 frames
 *
 * @defgroup tapi_802154 IEEE 802.15.4 (tapi_802154)
 * @{
 *
 * The radio layer under Zigbee, Thread and Matter-over-Thread: build a
 * frame, take one apart, and check what protects it.
 *
 * @section tapi_802154_name Why this is named after a standard
 *
 * Because 802.15.4 is what Zigbee, Thread and Matter-over-Thread
 * genuinely share, and naming the module after any one of them would
 * claim the other two are variations of it. They are not: they share a
 * radio and a frame format, and diverge completely above it. Z-Wave
 * and LoRaWAN share neither and are not here - LoRaWAN has
 * @ref tapi_lorawan, which is a different architecture entirely.
 *
 * So this module is the layer they have in common, and anything above
 * it says which of them it means.
 *
 * @section tapi_802154_frame What a frame is
 *
 *     FCF | Seq | DestPAN | DestAddr | SrcPAN | SrcAddr | Payload | FCS
 *      2     1      0/2      0/2/8     0/2      0/2/8       n        2
 *
 * Every field after the sequence number is optional, and which ones are
 * there is decided by two two-bit fields inside the FCF. That is the
 * whole difficulty of parsing one: the length of the header cannot be
 * known without reading it.
 *
 * Everything multi-byte is **little endian**, including the addresses,
 * so an extended address written @c 0011223344556677 appears on the
 * wire as @c 7766554433221100.
 *
 * @code
 * tapi_802154_frame frame = tapi_802154_default_frame;
 * te_string wire = TE_STRING_INIT;
 *
 * frame.dest_panid = 0x1234;
 * frame.dest_addr = 0xABCD;
 * frame.src_addr = 0x1111;
 * CHECK_RC(tapi_802154_build(&frame, (const uint8_t *)"payload", 7,
 *                            &wire));
 * @endcode
 */

#ifndef __TSF_TAPI_802154_H__
#define __TSF_TAPI_802154_H__

#include <stdint.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The largest frame the radio will carry, including the checksum. */
#define TAPI_802154_MAX_FRAME 127

/** Length of the frame check sequence. */
#define TAPI_802154_FCS_LEN 2

/** Length of a key. */
#define TAPI_802154_KEY_LEN 16

/** What kind of frame it is. */
typedef enum tapi_802154_type {
    /** A beacon, announcing a network. */
    TAPI_802154_BEACON = 0,
    /** Data. */
    TAPI_802154_DATA = 1,
    /** An acknowledgement. */
    TAPI_802154_ACK = 2,
    /** A MAC command: association, disassociation, a key request. */
    TAPI_802154_COMMAND = 3,
} tapi_802154_type;

/** How an address is given. */
typedef enum tapi_802154_addr_mode {
    /** Not present at all. */
    TAPI_802154_ADDR_NONE = 0,
    /** Two bytes, assigned when the device joined. */
    TAPI_802154_ADDR_SHORT = 2,
    /** Eight bytes, burned into the device. */
    TAPI_802154_ADDR_EXTENDED = 3,
} tapi_802154_addr_mode;

/**
 * How much a frame is protected.
 *
 * The lower three bits of the security control field. The names are
 * the standard's: @c ENC means the payload is encrypted, the number is
 * how many bytes of integrity code there are.
 */
typedef enum tapi_802154_sec_level {
    /** None at all: readable and unsigned. */
    TAPI_802154_SEC_NONE = 0,
    /** Signed with 4 bytes, not encrypted. */
    TAPI_802154_SEC_MIC32 = 1,
    /** Signed with 8 bytes, not encrypted. */
    TAPI_802154_SEC_MIC64 = 2,
    /** Signed with 16 bytes, not encrypted. */
    TAPI_802154_SEC_MIC128 = 3,
    /** Encrypted, not signed. */
    TAPI_802154_SEC_ENC = 4,
    /** Encrypted and signed with 4 bytes. */
    TAPI_802154_SEC_ENC_MIC32 = 5,
    /** Encrypted and signed with 8 bytes. */
    TAPI_802154_SEC_ENC_MIC64 = 6,
    /** Encrypted and signed with 16 bytes. What Thread uses. */
    TAPI_802154_SEC_ENC_MIC128 = 7,
} tapi_802154_sec_level;

/** One frame, as fields rather than as bytes. */
typedef struct tapi_802154_frame {
    /** What kind it is. */
    tapi_802154_type type;
    /** Sequence number. */
    uint8_t seq;
    /** @c true when the sender wants an acknowledgement. */
    bool ack_request;
    /** @c true when more data is waiting for the recipient. */
    bool frame_pending;
    /**
     * @c true when the source PAN is left out because it is the same
     * as the destination's.
     */
    bool panid_compression;
    /** Frame version, @c 0 for the original format. */
    uint8_t version;

    /** How the destination is addressed. */
    tapi_802154_addr_mode dest_mode;
    /** Destination PAN, when there is one. */
    uint16_t dest_panid;
    /** Destination address, short or extended. */
    uint64_t dest_addr;

    /** How the source is addressed. */
    tapi_802154_addr_mode src_mode;
    /** Source PAN, when there is one. */
    uint16_t src_panid;
    /** Source address, short or extended. */
    uint64_t src_addr;

    /** How much the frame is protected. */
    tapi_802154_sec_level sec_level;
    /** @c true when the security header is present. */
    bool secured;
    /**
     * The counter that stops a frame being replayed.
     *
     * As with every protocol that has one, this going backwards is the
     * finding: a device that restarts its counter can have its old
     * frames sent again.
     */
    uint32_t frame_counter;
    /** Which key was used, as the frame names it. */
    uint8_t key_index;

    /** Payload, decrypted when the keys allowed it. */
    uint8_t payload[TAPI_802154_MAX_FRAME];
    /** Length of @a payload. */
    size_t payload_len;
    /** The checksum, as parsed or as computed. */
    uint16_t fcs;
    /** @c true when the checksum on a parsed frame was right. */
    bool fcs_valid;
} tapi_802154_frame;

/** A data frame, short addressing, no security. */
extern const tapi_802154_frame tapi_802154_default_frame;

/**
 * Build a frame and put a checksum on it.
 *
 * @param[in]  frame        The fields; @a fcs is filled in.
 * @param[in]  payload      The payload, or @c NULL.
 * @param[in]  payload_len  Its length.
 * @param[out] wire         String to append the bytes to, as
 *                          hexadecimal.
 *
 * @return Status code.
 * @retval TE_EINVAL        The frame would be too long for the radio.
 */
extern te_errno tapi_802154_build(tapi_802154_frame *frame,
                                  const uint8_t *payload,
                                  size_t payload_len, te_string *wire);

/**
 * Take a frame apart.
 *
 * The checksum is checked and the answer put in
 * tapi_802154_frame::fcs_valid rather than returned as an error: a
 * frame that failed its checksum is exactly what a test looking at a
 * noisy radio wants to see.
 *
 * @param[in]  wire         The bytes.
 * @param[in]  wire_len     How many.
 * @param[out] frame        The fields.
 *
 * @return Status code.
 * @retval TE_EINVAL        Too short, or the header says more than is
 *                          there.
 */
extern te_errno tapi_802154_parse(const uint8_t *wire, size_t wire_len,
                                  tapi_802154_frame *frame);

/**
 * The checksum of a frame body.
 *
 * CRC-16/X.25 - the reflected CCITT polynomial, starting at zero -
 * which is what the standard specifies and what every implementation
 * of it produces.
 *
 * @param data          The frame without its last two bytes.
 * @param len           How many.
 *
 * @return The checksum, in host order.
 */
extern uint16_t tapi_802154_fcs(const uint8_t *data, size_t len);

/**
 * How many bytes of integrity code a security level carries.
 *
 * @param level         The level.
 *
 * @return @c 0, @c 4, @c 8 or @c 16.
 */
extern size_t tapi_802154_mic_len(tapi_802154_sec_level level);

/**
 * Does this level encrypt the payload?
 *
 * @param level         The level.
 *
 * @return @c true when it does.
 */
extern bool tapi_802154_encrypts(tapi_802154_sec_level level);

/**
 * Write a frame into the log.
 *
 * @param what          A word for the log.
 * @param frame         The frame.
 */
extern void tapi_802154_frame_log(const char *what,
                                  const tapi_802154_frame *frame);

/**
 * Turn hexadecimal into bytes.
 *
 * @param[in]  text     The digits.
 * @param[out] data     Where to put them.
 * @param[in]  max_len  How many will fit.
 * @param[out] len      How many there were.
 *
 * @return Status code.
 */
extern te_errno tapi_802154_unhex(const char *text, uint8_t *data,
                                  size_t max_len, size_t *len);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_802154_H__ */

/**@} <!-- END tapi_802154 --> */
