// Copyright (c) 2019 Bitcoin Association
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#pragma once

#include <cstdint>

namespace Gigamonkey::Bitcoin::interpreter {
    
    /**
    * Configuration interface that contains limits used when evaluating scripts.
    */
    struct config {
        
        uint64_t MaxOpsPerScript;
        uint64_t MaxScriptNumLength;
        uint64_t MaxScriptSize;
        uint64_t MaxPubKeysPerMultiSig;
        uint64_t MaxStackMemoryUsage;
        
        config(bool genesis, bool consensus);
        
    };
    
}
