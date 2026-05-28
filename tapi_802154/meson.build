# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica Unipessoal Lda
#
# External TE library (see TE_EXT_REPO): engine-side IEEE 802.15.4 -
# the radio layer under Zigbee, Thread and Matter-over-Thread. Frames,
# the AES-CCM* that protects them, and what a network's traffic gives
# away. Built as a shared library on the engine platform; see below for
# why there is no static one.

if get_option('engine')
    build_lib_shared = true
endif
# Shared on the engine and nothing on an agent, which is the rule TE
# applies to its own engine-side libraries. The default for an external
# repository is the opposite - lib/meson.build builds one static and
# agent-side, because that is what external libraries used to be - and
# the obvious override, "static as well when there are agents", is the
# rule for a library that lives on both sides. This one does not: it
# calls tapi, which is an engine library with no static variant, so
# asking for a static build of it fails the configure with "Tried to
# get unknown variable dep_lib_static_tapi" before a line is compiled.
build_lib_static = false
install_lib = install_dev

headers += files(
    'tapi_802154.h',
    'tapi_802154_audit.h',
    'tapi_802154_sec.h',
)

sources += files(
    'tapi_802154.c',
    'tapi_802154_audit.c',
    'tapi_802154_sec.c',
)

# libcrypto for AES-CCM, and nothing else of it.
deps += [ dependency('libcrypto') ]

te_libs += [
    'tapi',
    'tapi_cybersec',
]
