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

    struct script_config final {
        uint32 Flags;
        bool Consensus;

        bool after_genesis () const {
            return Flags & SCRIPT_UTXO_AFTER_GENESIS;
        }

        script_config (uint32 flags = StandardScriptVerifyFlags (true, true), bool consensus = false);

        bool SetMaxOpsPerScriptPolicy (int64_t maxOpsPerScriptPolicyIn, std::string *error);
        uint64_t GetMaxOpsPerScript () const;

        bool SetMaxPubKeysPerMultiSigPolicy (int64_t maxPubKeysPerMultiSigIn, std::string *error = nullptr);
        uint64_t GetMaxPubKeysPerMultiSig () const;

        bool SetMaxStackMemoryUsage (int64_t maxStackMemoryUsageConsensusIn, int64_t maxStackMemoryUsagePolicyIn, std::string *err = nullptr);
        uint64_t GetMaxStackMemoryUsage () const;

        bool SetMaxScriptSizePolicy (int64_t maxScriptSizePolicyIn, std::string *err = nullptr);
        uint64_t GetMaxScriptSize () const;

        bool SetMaxScriptNumLengthPolicy (int64_t maxScriptNumLengthIn, std::string *err = nullptr);
        uint64_t GetMaxScriptNumLength () const;

    private:
        uint64_t maxOpsPerScriptPolicy;
        uint64_t maxPubKeysPerMultiSig;

        uint64_t maxStackMemoryUsagePolicy;
        uint64_t maxStackMemoryUsageConsensus;

        uint64_t maxScriptNumLengthPolicy;

        uint64_t maxScriptSizePolicy;

    };
}

#endif
