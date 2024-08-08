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
    bool LessThan (
        int64_t argValue,
        std::string *err,
        const std::string &errorMessage,
        int64_t minValue) {
        if (argValue < minValue) {
            if (err) *err = errorMessage;
            return true;
        }
        return false;
    }

    bool LessThanZero (
        int64_t argValue,
        std::string *err,
        const std::string &errorMessage) {
        return LessThan ( argValue, err, errorMessage, 0 );
    }

    bool script_config::SetMaxOpsPerScriptPolicy (int64_t maxOpsPerScriptPolicyIn, std::string *error) {
        if (LessThanZero (maxOpsPerScriptPolicyIn, error, "Policy value for MaxOpsPerScript cannot be less than zero."))
            return false;

        uint64_t maxOpsPerScriptPolicyInUnsigned = static_cast<uint64_t> (maxOpsPerScriptPolicyIn);

        if (maxOpsPerScriptPolicyInUnsigned > MAX_OPS_PER_SCRIPT_AFTER_GENESIS)
        {
            if (error) {
                *error = "Policy value for MaxOpsPerScript must not exceed consensus limit of " + std::to_string (MAX_OPS_PER_SCRIPT_AFTER_GENESIS) + ".";
            }
            return false;
        }
        else if (maxOpsPerScriptPolicyInUnsigned == 0) maxOpsPerScriptPolicy = MAX_OPS_PER_SCRIPT_AFTER_GENESIS;
        else maxOpsPerScriptPolicy = maxOpsPerScriptPolicyInUnsigned;

        return true;
    }

    uint64_t script_config::GetMaxOpsPerScript () const {
        if (!utxo_after_genesis ()) return MAX_OPS_PER_SCRIPT_BEFORE_GENESIS; // no changes before genesis

        if (Consensus) return MAX_OPS_PER_SCRIPT_AFTER_GENESIS; // use new limit after genesis

        return maxOpsPerScriptPolicy;
    }

    bool script_config::SetMaxPubKeysPerMultiSigPolicy (int64_t maxPubKeysPerMultiSigIn, std::string *err) {
        if (LessThanZero (maxPubKeysPerMultiSigIn, err, "Policy value for maximum public keys per multisig must not be less than zero"))
            return false;

        uint64_t maxPubKeysPerMultiSigUnsigned = static_cast<uint64_t> (maxPubKeysPerMultiSigIn);
        if (maxPubKeysPerMultiSigUnsigned > MAX_PUBKEYS_PER_MULTISIG_AFTER_GENESIS)
        {
            if (err)
                *err = "Policy value for maximum public keys per multisig must not exceed consensus limit of "
                    + std::to_string (MAX_PUBKEYS_PER_MULTISIG_AFTER_GENESIS) + ".";
            return false;
        }
        else if (maxPubKeysPerMultiSigUnsigned == 0) maxPubKeysPerMultiSig = MAX_PUBKEYS_PER_MULTISIG_AFTER_GENESIS;
        else maxPubKeysPerMultiSig = maxPubKeysPerMultiSigUnsigned;

        return true;
    }

    uint64_t script_config::GetMaxPubKeysPerMultiSig () const {
        if (!utxo_after_genesis ()) return MAX_PUBKEYS_PER_MULTISIG_BEFORE_GENESIS; // no changes before  genesis

        if (Consensus) return MAX_PUBKEYS_PER_MULTISIG_AFTER_GENESIS; // use new limit after genesis

        return maxPubKeysPerMultiSig;
    }

    bool script_config::SetMaxStackMemoryUsage (int64_t maxStackMemoryUsageConsensusIn, int64_t maxStackMemoryUsagePolicyIn, std::string *err) {
        if (maxStackMemoryUsageConsensusIn < 0 || maxStackMemoryUsagePolicyIn < 0) {
            if (err) *err = "Policy and consensus value for max stack memory usage must not be less than 0.";
            return false;
        }

        if (maxStackMemoryUsageConsensusIn == 0) maxStackMemoryUsageConsensus = DEFAULT_STACK_MEMORY_USAGE_CONSENSUS_AFTER_GENESIS;
        else maxStackMemoryUsageConsensus = static_cast<uint64_t> (maxStackMemoryUsageConsensusIn);

        if (maxStackMemoryUsagePolicyIn == 0) maxStackMemoryUsagePolicy = DEFAULT_STACK_MEMORY_USAGE_CONSENSUS_AFTER_GENESIS;
        else maxStackMemoryUsagePolicy = static_cast<uint64_t> (maxStackMemoryUsagePolicyIn);

        if (maxStackMemoryUsagePolicy > maxStackMemoryUsageConsensus) {
            if (err)
                *err = "Policy value of max stack memory usage must not exceed consensus limit of " +
                    std::to_string (maxStackMemoryUsageConsensus);
            return false;
        }

        return true;
    }

    uint64_t script_config::GetMaxStackMemoryUsage () const {
        // concept of max stack memory usage is not defined before genesis
        // before Genesis stricter limitations exist, so maxStackMemoryUsage can be infinite
        if (!utxo_after_genesis ()) return INT64_MAX;

        if (Consensus) return maxStackMemoryUsageConsensus;

        return maxStackMemoryUsagePolicy;
    }

    bool script_config::SetMaxScriptNumLengthPolicy (int64_t maxScriptNumLengthIn, std::string *err) {
        if (LessThanZero (maxScriptNumLengthIn, err, "Policy value for maximum script number length must not be less than 0."))
            return false;

        uint64_t maxScriptNumLengthUnsigned = static_cast<uint64_t> (maxScriptNumLengthIn);
        if (maxScriptNumLengthUnsigned > MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS) {
            if (err)
                *err = "Policy value for maximum script number length must not exceed consensus limit of " +
                    std::to_string (MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS) + ".";
            return false;
        } else if (maxScriptNumLengthUnsigned == 0) maxScriptNumLengthPolicy = MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS;
        else if (maxScriptNumLengthUnsigned < MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS) {
            if (err)
                *err = "Policy value for maximum script number length must not be less than " +
                    std::to_string (MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS) + ".";
            return false;
        } else maxScriptNumLengthPolicy = maxScriptNumLengthUnsigned;

        return true;
    }

    uint64_t script_config::GetMaxScriptNumLength () const {
        if (!utxo_after_genesis ()) return MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS; // no changes before genesis

        if (Consensus) return MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS; // use new limit after genesis

        return maxScriptNumLengthPolicy; // use policy
    }

    bool script_config::SetMaxScriptSizePolicy (int64_t maxScriptSizePolicyIn, std::string *err) {
        if (LessThanZero (maxScriptSizePolicyIn, err, "Policy value for max script size must not be less than 0"))
            return false;

        uint64_t maxScriptSizePolicyInUnsigned = static_cast<uint64_t> (maxScriptSizePolicyIn);
        if (maxScriptSizePolicyInUnsigned > MAX_SCRIPT_SIZE_AFTER_GENESIS) {
            if (err)
                *err = "Policy value for max script size must not exceed consensus limit of " +
                    std::to_string (MAX_SCRIPT_SIZE_AFTER_GENESIS);
            return false;
        } else if (maxScriptSizePolicyInUnsigned == 0)
            maxScriptSizePolicy = MAX_SCRIPT_SIZE_AFTER_GENESIS;
        else maxScriptSizePolicy = maxScriptSizePolicyInUnsigned;
        return true;
    }

    uint64_t script_config::GetMaxScriptSize () const {
        if (!utxo_after_genesis ()) return MAX_SCRIPT_SIZE_BEFORE_GENESIS;
        if (Consensus) return MAX_SCRIPT_SIZE_AFTER_GENESIS;
        return maxScriptSizePolicy;
    }

    script_config::script_config (uint32 flags, bool consensus): Flags {flags}, Consensus {consensus} {

        maxOpsPerScriptPolicy = DEFAULT_OPS_PER_SCRIPT_POLICY_AFTER_GENESIS;
        //maxTxSigOpsCountPolicy = DEFAULT_TX_SIGOPS_COUNT_POLICY_AFTER_GENESIS;
        maxPubKeysPerMultiSig = DEFAULT_PUBKEYS_PER_MULTISIG_POLICY_AFTER_GENESIS;

        maxStackMemoryUsagePolicy = DEFAULT_STACK_MEMORY_USAGE_POLICY_AFTER_GENESIS;
        maxStackMemoryUsageConsensus = DEFAULT_STACK_MEMORY_USAGE_CONSENSUS_AFTER_GENESIS;
        maxScriptSizePolicy = DEFAULT_MAX_SCRIPT_SIZE_POLICY_AFTER_GENESIS;

        maxScriptNumLengthPolicy = DEFAULT_SCRIPT_NUM_LENGTH_POLICY_AFTER_GENESIS;

    }
}
