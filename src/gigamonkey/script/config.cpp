// Copyright (c) 2017 The Bitcoin developers
// Copyright (c) 2019 Bitcoin Association
// Copyright (c) 2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/config.hpp>
#include <sv/consensus/consensus.h>
#include <sv/policy/policy.h>
#include <sv/util.h>

#include <limits>

namespace Gigamonkey::Bitcoin {
    
    script_config get_standard_script_config(bool isGenesisEnabled, bool isConsensus) {
        return script_config {
            !isGenesisEnabled ? MAX_OPS_PER_SCRIPT_BEFORE_GENESIS : 
            isConsensus ? MAX_OPS_PER_SCRIPT_AFTER_GENESIS : 
                DEFAULT_OPS_PER_SCRIPT_POLICY_AFTER_GENESIS, 
            !isGenesisEnabled ? MAX_PUBKEYS_PER_MULTISIG_BEFORE_GENESIS : 
            isConsensus ? MAX_PUBKEYS_PER_MULTISIG_AFTER_GENESIS: 
                DEFAULT_PUBKEYS_PER_MULTISIG_POLICY_AFTER_GENESIS, 
            // concept of max stack memory usage is not defined before genesis
            // before Genesis stricter limitations exist, so maxStackMemoryUsage can be infinite
            !isGenesisEnabled ? INT64_MAX : 
            isConsensus ? DEFAULT_STACK_MEMORY_USAGE_CONSENSUS_AFTER_GENESIS :
                DEFAULT_STACK_MEMORY_USAGE_POLICY_AFTER_GENESIS, 
            !isGenesisEnabled ? MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS : 
            isConsensus ? MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS : 
                DEFAULT_SCRIPT_NUM_LENGTH_POLICY_AFTER_GENESIS, 
            !isGenesisEnabled ? MAX_SCRIPT_SIZE_BEFORE_GENESIS : 
            isConsensus ? MAX_SCRIPT_SIZE_AFTER_GENESIS : 
                DEFAULT_MAX_SCRIPT_SIZE_POLICY_AFTER_GENESIS
        };
    }
}
