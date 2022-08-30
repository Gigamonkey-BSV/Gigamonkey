// Copyright (c) 2017 Amaury SÉCHET
// Copyright (c) 2019 Bitcoin Association
// Copyright (c) 2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_CONFIG
#define GIGAMONKEY_SCRIPT_CONFIG

static_assert(sizeof(void*) >= 8, "32 bit systems are not supported");

#include <gigamonkey/types.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <set>

namespace Gigamonkey::Bitcoin {

struct script_config {
    uint64 MaxOpsPerScript; 
    uint64 MaxPubKeysPerMultiSig;
    uint64 MaxStackMemoryUsage;
    uint64 MaxScriptNumLength;
    uint64 MaxScriptSize;
};

script_config get_standard_script_config(bool isGenesisEnabled, bool isConsensus);

}

#endif
