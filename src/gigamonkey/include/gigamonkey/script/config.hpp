// Copyright (c) 2017 Amaury SÉCHET
// Copyright (c) 2019 Bitcoin Association
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef BITCOIN_CONFIG_H
#define BITCOIN_CONFIG_H

static_assert (sizeof (void*) >= 8, "32 bit systems are not supported");

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <set>
#include <gigamonkey/types.hpp>
#include <gigamonkey/script/flags.h>

namespace Gigamonkey::Bitcoin {
    // if genesis is not enabled, then these values are fixed.
    // otherwise, they have defaults but can be set by the use
    struct script_config final {
        uint32 Flags;

        uint64 MaxOpsPerScript;
        uint64 MaxPubKeysPerMultiSig;
        uint64 MaxStackMemoryUsage;
        uint64 MaxScriptNumLength;
        uint64 MaxScriptSize;

        // if the flags state that the utxo is before genesis, then
        // consensus doesn't matter.
        script_config (uint32 flags = StandardScriptVerifyFlags (true, true), bool consensus = false);
        script_config (uint32 flags,
            uint64 max_ops_per_script,
            uint64 max_pubkeys_per_multisig,
            uint64 max_stack_memory_usage,
            uint64 max_script_num_length,
            uint64 max_script_size);

        bool utxo_after_genesis () const {
            return Flags & SCRIPT_UTXO_AFTER_GENESIS;
        }

        bool support_P2SH () const {
            return !utxo_after_genesis () && (Flags & SCRIPT_VERIFY_P2SH);
        }

        bool verify_sig_push_only () const {
            return Flags & SCRIPT_VERIFY_SIGPUSHONLY;
        }

        bool verify_minimal_data () const {
            return Flags & SCRIPT_VERIFY_MINIMALDATA;
        }

        bool verify_clean_stack () const {
            return Flags & SCRIPT_VERIFY_CLEANSTACK;
        }

        bool check_locktime () const {
            return Flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY && !utxo_after_genesis ();
        }

        bool check_sequence () const {
            return Flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY && !utxo_after_genesis ();
        }

    };
}

#endif
