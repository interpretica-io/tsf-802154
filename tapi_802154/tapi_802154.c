/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief IEEE 802.15.4 frames
 *
 * Bit fields and little-endian integers, and the only two things worth
 * saying about it are that the header has no fixed length - the two
 * addressing-mode fields inside the frame control decide it - and that
 * every multi-byte value goes out backwards.
 */

#define TE_LGR_USER "TAPI 802154"

#include "te_config.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_string.h"

#include "tapi_802154.h"

/** The reflected CCITT polynomial. */
#define TAPI_802154_POLY 0x8408

const tapi_802154_frame tapi_802154_default_frame = {
    .type = TAPI_802154_DATA,
    .dest_mode = TAPI_802154_ADDR_SHORT,
    .src_mode = TAPI_802154_ADDR_SHORT,
    .sec_level = TAPI_802154_SEC_NONE,
};

/* See description in tapi_802154.h */
uint16_t
tapi_802154_fcs(const uint8_t *data, size_t len)
{
    uint16_t crc = 0;
    size_t i;

    for (i = 0; i < len; i++)
    {
        unsigned int bit;

        crc ^= data[i];
        for (bit = 0; bit < 8; bit++)
        {
            crc = (crc & 1) != 0 ? (uint16_t)((crc >> 1) ^ TAPI_802154_POLY)
                                 : (uint16_t)(crc >> 1);
        }
    }

    return crc;
}

/* See description in tapi_802154.h */
size_t
tapi_802154_mic_len(tapi_802154_sec_level level)
{
    switch (level)
    {
        case TAPI_802154_SEC_MIC32:
        case TAPI_802154_SEC_ENC_MIC32:
            return 4;
        case TAPI_802154_SEC_MIC64:
        case TAPI_802154_SEC_ENC_MIC64:
            return 8;
        case TAPI_802154_SEC_MIC128:
        case TAPI_802154_SEC_ENC_MIC128:
            return 16;
        default:
            return 0;
    }
}

/* See description in tapi_802154.h */
bool
tapi_802154_encrypts(tapi_802154_sec_level level)
{
    return level >= TAPI_802154_SEC_ENC;
}

/* See description in tapi_802154.h */
te_errno
tapi_802154_unhex(const char *text, uint8_t *data, size_t max_len,
                  size_t *len)
{
    size_t used = 0;

    while (*text != '\0')
    {
        int high;
        int low;

        while (*text == ' ' || *text == ':' || *text == '-')
            text++;

        if (*text == '\0')
            break;

        if (!isxdigit((unsigned char)text[0]) ||
            !isxdigit((unsigned char)text[1]))
        {
            return TE_RC(TE_TAPI, TE_EINVAL);
        }

        if (used >= max_len)
            return TE_RC(TE_TAPI, TE_ESMALLBUF);

        high = isdigit((unsigned char)text[0]) ? text[0] - '0' :
               toupper((unsigned char)text[0]) - 'A' + 10;
        low = isdigit((unsigned char)text[1]) ? text[1] - '0' :
              toupper((unsigned char)text[1]) - 'A' + 10;

        data[used++] = (uint8_t)((high << 4) | low);
        text += 2;
    }

    if (len != NULL)
        *len = used;

    return 0;
}

/** Write an integer out backwards, which is how it goes on the wire. */
static void
put_le(uint8_t *out, uint64_t value, size_t bytes)
{
    size_t i;

    for (i = 0; i < bytes; i++)
        out[i] = (uint8_t)((value >> (8 * i)) & 0xff);
}

/** Read one back. */
static uint64_t
get_le(const uint8_t *in, size_t bytes)
{
    uint64_t value = 0;
    size_t i;

    for (i = 0; i < bytes; i++)
        value |= (uint64_t)in[i] << (8 * i);

    return value;
}

/** How many bytes an addressing mode takes. */
static size_t
addr_bytes(tapi_802154_addr_mode mode)
{
    switch (mode)
    {
        case TAPI_802154_ADDR_SHORT:
            return 2;
        case TAPI_802154_ADDR_EXTENDED:
            return 8;
        default:
            return 0;
    }
}

/* See description in tapi_802154.h */
te_errno
tapi_802154_build(tapi_802154_frame *frame, const uint8_t *payload,
                  size_t payload_len, te_string *wire)
{
    uint8_t buffer[TAPI_802154_MAX_FRAME];
    uint16_t fcf = 0;
    size_t used = 0;
    size_t i;

    /*
     * The frame control, bit by bit and least significant first. The
     * layout is the standard's and there is no way to make it look
     * friendlier: three bits of type, five of flags, then two
     * two-bit addressing modes with a version between them.
     */
    fcf |= (uint16_t)(frame->type & 0x07);
    if (frame->secured)
        fcf |= 1u << 3;
    if (frame->frame_pending)
        fcf |= 1u << 4;
    if (frame->ack_request)
        fcf |= 1u << 5;
    if (frame->panid_compression)
        fcf |= 1u << 6;
    fcf |= (uint16_t)((frame->dest_mode & 0x03) << 10);
    fcf |= (uint16_t)((frame->version & 0x03) << 12);
    fcf |= (uint16_t)((frame->src_mode & 0x03) << 14);

    put_le(buffer + used, fcf, 2);
    used += 2;

    buffer[used++] = frame->seq;

    if (frame->dest_mode != TAPI_802154_ADDR_NONE)
    {
        put_le(buffer + used, frame->dest_panid, 2);
        used += 2;
        put_le(buffer + used, frame->dest_addr,
               addr_bytes(frame->dest_mode));
        used += addr_bytes(frame->dest_mode);
    }

    if (frame->src_mode != TAPI_802154_ADDR_NONE)
    {
        /*
         * The source PAN is left out when the compression bit says it
         * is the same as the destination's - which is the usual case
         * inside one network, and is why so many frames have only one
         * PAN in them.
         */
        if (!frame->panid_compression)
        {
            put_le(buffer + used, frame->src_panid, 2);
            used += 2;
        }

        put_le(buffer + used, frame->src_addr,
               addr_bytes(frame->src_mode));
        used += addr_bytes(frame->src_mode);
    }

    if (frame->secured)
    {
        buffer[used++] = (uint8_t)(frame->sec_level & 0x07);
        put_le(buffer + used, frame->frame_counter, 4);
        used += 4;
        buffer[used++] = frame->key_index;
    }

    if (used + payload_len + TAPI_802154_FCS_LEN > TAPI_802154_MAX_FRAME)
    {
        ERROR("A frame of %zu bytes will not fit in %d",
              used + payload_len + TAPI_802154_FCS_LEN,
              TAPI_802154_MAX_FRAME);
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    if (payload != NULL && payload_len != 0)
    {
        memcpy(buffer + used, payload, payload_len);
        memcpy(frame->payload, payload, payload_len);
        frame->payload_len = payload_len;
        used += payload_len;
    }

    frame->fcs = tapi_802154_fcs(buffer, used);
    put_le(buffer + used, frame->fcs, 2);
    used += 2;

    for (i = 0; i < used; i++)
        te_string_append(wire, "%02X", buffer[i]);

    return 0;
}

/* See description in tapi_802154.h */
te_errno
tapi_802154_parse(const uint8_t *wire, size_t wire_len,
                  tapi_802154_frame *frame)
{
    uint16_t fcf;
    size_t at = 0;
    size_t body;

    memset(frame, 0, sizeof(*frame));

    /* Frame control, sequence number and checksum: the shortest there is. */
    if (wire_len < 3 + TAPI_802154_FCS_LEN)
    {
        ERROR("%zu bytes is too short to be an 802.15.4 frame", wire_len);
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    fcf = (uint16_t)get_le(wire, 2);
    at = 2;

    frame->type = (tapi_802154_type)(fcf & 0x07);
    frame->secured = (fcf & (1u << 3)) != 0;
    frame->frame_pending = (fcf & (1u << 4)) != 0;
    frame->ack_request = (fcf & (1u << 5)) != 0;
    frame->panid_compression = (fcf & (1u << 6)) != 0;
    frame->dest_mode = (tapi_802154_addr_mode)((fcf >> 10) & 0x03);
    frame->version = (uint8_t)((fcf >> 12) & 0x03);
    frame->src_mode = (tapi_802154_addr_mode)((fcf >> 14) & 0x03);

    frame->seq = wire[at++];

    /*
     * From here the header has no fixed length: what is present is
     * whatever the two addressing modes said. Every step checks there
     * is room, because a frame that claims more than it carries is
     * exactly what a fuzzer produces.
     */
    if (frame->dest_mode != TAPI_802154_ADDR_NONE)
    {
        size_t need = 2 + addr_bytes(frame->dest_mode);

        if (at + need + TAPI_802154_FCS_LEN > wire_len)
            return TE_RC(TE_TAPI, TE_EINVAL);

        frame->dest_panid = (uint16_t)get_le(wire + at, 2);
        at += 2;
        frame->dest_addr = get_le(wire + at, addr_bytes(frame->dest_mode));
        at += addr_bytes(frame->dest_mode);
    }

    if (frame->src_mode != TAPI_802154_ADDR_NONE)
    {
        size_t need = addr_bytes(frame->src_mode) +
                      (frame->panid_compression ? 0 : 2);

        if (at + need + TAPI_802154_FCS_LEN > wire_len)
            return TE_RC(TE_TAPI, TE_EINVAL);

        if (frame->panid_compression)
        {
            frame->src_panid = frame->dest_panid;
        }
        else
        {
            frame->src_panid = (uint16_t)get_le(wire + at, 2);
            at += 2;
        }

        frame->src_addr = get_le(wire + at, addr_bytes(frame->src_mode));
        at += addr_bytes(frame->src_mode);
    }

    if (frame->secured)
    {
        if (at + 6 + TAPI_802154_FCS_LEN > wire_len)
            return TE_RC(TE_TAPI, TE_EINVAL);

        frame->sec_level = (tapi_802154_sec_level)(wire[at] & 0x07);
        at++;
        frame->frame_counter = (uint32_t)get_le(wire + at, 4);
        at += 4;
        frame->key_index = wire[at++];
    }

    body = wire_len - at - TAPI_802154_FCS_LEN;

    if (body > sizeof(frame->payload))
        return TE_RC(TE_TAPI, TE_ESMALLBUF);

    if (body > 0)
    {
        memcpy(frame->payload, wire + at, body);
        frame->payload_len = body;
    }

    frame->fcs = (uint16_t)get_le(wire + wire_len - TAPI_802154_FCS_LEN, 2);

    /*
     * Reported rather than raised. A frame that failed its checksum is
     * what a test watching a noisy radio wants to see, and turning it
     * into an error would throw away the frame that proves the point.
     */
    frame->fcs_valid = tapi_802154_fcs(wire, wire_len -
                                       TAPI_802154_FCS_LEN) == frame->fcs;

    return 0;
}

/* See description in tapi_802154.h */
void
tapi_802154_frame_log(const char *what, const tapi_802154_frame *frame)
{
    static const char *const types[] = {
        "beacon", "data", "ack", "command",
    };

    RING("%s: %s seq %u, %04X/%0*" PRIX64 " -> %04X/%0*" PRIX64,
         what, types[frame->type & 0x03], frame->seq,
         frame->src_panid, frame->src_mode == TAPI_802154_ADDR_EXTENDED ?
             16 : 4, frame->src_addr,
         frame->dest_panid,
         frame->dest_mode == TAPI_802154_ADDR_EXTENDED ? 16 : 4,
         frame->dest_addr);

    if (frame->secured)
    {
        RING("  security level %u, counter %u, key %u",
             frame->sec_level, frame->frame_counter, frame->key_index);
    }
    else
    {
        RING("  no security");
    }

    RING("  %zu bytes of payload, checksum %s", frame->payload_len,
         frame->fcs_valid ? "good" : "BAD");
}
