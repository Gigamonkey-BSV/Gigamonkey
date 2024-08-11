// Copyright (c) 2021-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_MACHINE
#define GIGAMONKEY_SCRIPT_MACHINE

#include <gigamonkey/script.hpp>
#include <gigamonkey/script/stack.hpp>
#include <gigamonkey/script/counter.hpp>
#include <gigamonkey/script/config.hpp>

namespace Gigamonkey::Bitcoin {

    // a Bitcoin script interpreter that can be advanced step-by-step.
    struct machine {

        bool Halt;
        result Result;

        script_config Config;

        bool UtxoAfterGenesis;
        uint64 MaxScriptNumLength;
        bool RequireMinimal;
            
        maybe<redemption_document> Document;
            
        ptr<two_stack> Stack;
            
        cross<bool> Exec;
        cross<bool> Else;

        long OpCount;

        bool increment_operation ();
        uint64 max_pubkeys_per_multisig () const;

        result step (const program_counter &Counter);

        machine (maybe<redemption_document> doc = {}, const script_config &conf = {}):
            machine (conf.utxo_after_genesis () ?
                std::static_pointer_cast<two_stack> (std::make_shared<limited_two_stack<true>> (conf.GetMaxStackMemoryUsage ())) :
                std::static_pointer_cast<two_stack> (std::make_shared<limited_two_stack<false>> ()), doc, conf) {}

        machine (ptr<two_stack>, maybe<redemption_document> doc = {}, const script_config & = {});
    };

}


#endif
