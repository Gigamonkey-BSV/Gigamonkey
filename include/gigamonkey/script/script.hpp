// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018 The Bitcoin SV developers
// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_SCRIPT
#define GIGAMONKEY_SCRIPT_SCRIPT

#include <gigamonkey/script/error.h>

#include <gigamonkey/sighash.hpp>
#include <gigamonkey/satoshi.hpp>
#include <sv/policy/policy.h>

class CScriptNum;

namespace Gigamonkey::Bitcoin { 
    
    // Test validity of a script. All signature operations succeed. 
    ScriptError evaluate(const script& unlock, const script& lock, uint32 flags = StandardScriptVerifyFlags(true, true));
    
    struct redemption_document {
        satoshi RedeemedValue;
        
        incomplete::transaction Transaction;
        
        index InputIndex;
        
        sighash::document add_script_code(bytes_view script_code) const {
            return sighash::document{RedeemedValue, script_code, Transaction, InputIndex};
        }
        
        // holdovers from Bitcoin Core. 
        bool check_locktime(const CScriptNum &) const;
        bool check_sequence(const CScriptNum &) const;
    };
    
    // Evaluate script with real signature operations. 
    ScriptError evaluate(
        const script& unlock, const script& lock, 
        const redemption_document &doc, 
        uint32 flags = StandardScriptVerifyFlags(true, true));
    
}

#endif 


