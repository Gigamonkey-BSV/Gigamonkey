// Copyright (c) 2017 The Bitcoin developers
// Copyright (c) 2019 Bitcoin Association
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/config.hpp>
#include <sv/consensus/consensus.h>
#include <sv/policy/policy.h>
#include <sv/util.h>

#include <boost/algorithm/string.hpp>
#include <limits>

namespace Gigamonkey::Bitcoin {

    script_config::script_config (uint32 flags, bool consensus): Flags {flags} {
        if (!utxo_after_genesis ()) {
            MaxOpsPerScript = MAX_OPS_PER_SCRIPT_BEFORE_GENESIS;
            MaxPubKeysPerMultiSig = MAX_PUBKEYS_PER_MULTISIG_BEFORE_GENESIS;
            // concept of max stack memory usage is not defined before genesis
            // before Genesis stricter limitations exist, so maxStackMemoryUsage can be infinite
            MaxStackMemoryUsage = INT64_MAX;
            MaxScriptSize = MAX_SCRIPT_SIZE_BEFORE_GENESIS;
            MaxScriptNumLength = MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS;
        } else if (consensus) {
            MaxOpsPerScript = MAX_OPS_PER_SCRIPT_AFTER_GENESIS;
            MaxPubKeysPerMultiSig = MAX_PUBKEYS_PER_MULTISIG_AFTER_GENESIS;
            MaxStackMemoryUsage = DEFAULT_STACK_MEMORY_USAGE_CONSENSUS_AFTER_GENESIS;
            MaxScriptSize = MAX_SCRIPT_SIZE_AFTER_GENESIS;
            MaxScriptNumLength = MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS;
        } else {
            MaxOpsPerScript = DEFAULT_OPS_PER_SCRIPT_POLICY_AFTER_GENESIS;
            MaxPubKeysPerMultiSig = DEFAULT_PUBKEYS_PER_MULTISIG_POLICY_AFTER_GENESIS;
            MaxStackMemoryUsage = DEFAULT_STACK_MEMORY_USAGE_CONSENSUS_AFTER_GENESIS;
            MaxScriptSize = DEFAULT_MAX_SCRIPT_SIZE_POLICY_AFTER_GENESIS;
            MaxScriptNumLength = DEFAULT_SCRIPT_NUM_LENGTH_POLICY_AFTER_GENESIS;
        }
    }

    script_config::script_config (uint32 flags,
        uint64 maxOpsPerScript,
        uint64 maxPubKeysPerMultiSig,
        uint64 maxStackMemoryUsage,
        uint64 maxScriptNumLength,
        uint64 maxScriptSize): Flags {flags},
        MaxOpsPerScript {maxOpsPerScript},
        MaxPubKeysPerMultiSig {maxPubKeysPerMultiSig},
        MaxStackMemoryUsage {maxStackMemoryUsage},
        MaxScriptNumLength {maxScriptNumLength},
        MaxScriptSize {maxScriptSize} {

        if (!utxo_after_genesis () && (MaxOpsPerScript != MAX_OPS_PER_SCRIPT_BEFORE_GENESIS ||
            MaxPubKeysPerMultiSig != MAX_PUBKEYS_PER_MULTISIG_BEFORE_GENESIS ||
            MaxStackMemoryUsage != INT64_MAX ||
            MaxScriptSize != MAX_SCRIPT_SIZE_BEFORE_GENESIS ||
            MaxScriptNumLength != MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS))
            throw std::invalid_argument {"Before genesis, all config values must take on the default values"};

        if (MaxOpsPerScript > MAX_OPS_PER_SCRIPT_AFTER_GENESIS)
            throw std::invalid_argument {"Policy value for MaxOpsPerScript must not exceed consensus limit of " +
                std::to_string (MAX_OPS_PER_SCRIPT_AFTER_GENESIS) + "."};

        if (MaxPubKeysPerMultiSig > MAX_PUBKEYS_PER_MULTISIG_AFTER_GENESIS)
            throw std::invalid_argument {"Policy value for maximum public keys per multisig must not exceed consensus limit of "
                + std::to_string (MAX_PUBKEYS_PER_MULTISIG_AFTER_GENESIS) + "."};

        if (MaxScriptNumLength > MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS)
            throw std::invalid_argument {"Policy value for maximum script number length must not exceed consensus limit of " +
                std::to_string (MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS) + "."};

        if (MaxScriptNumLength < MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS)
            throw std::invalid_argument {"Policy value for maximum script number length must not be less than " +
                std::to_string (MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS) + "."};

        if (MaxScriptSize > MAX_SCRIPT_SIZE_AFTER_GENESIS)
            throw std::invalid_argument {"Policy value for max script size must not exceed consensus limit of " +
                std::to_string (MAX_SCRIPT_SIZE_AFTER_GENESIS) + "."};

    }
}
