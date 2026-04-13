// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018 The Bitcoin SV developers
// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT
#define GIGAMONKEY_SCRIPT

#include <gigamonkey/script/error.h>
#include <gigamonkey/script/config.hpp>
#include <gigamonkey/sighash.hpp>
#include <gigamonkey/satoshi.hpp>
#include <gigamonkey/signature.hpp>

namespace Gigamonkey::Bitcoin { 
    
    // Test validity of a script. All signature operations succeed. 
    Error evaluate (const script &unlock, const script &lock, const script_config & = {});
    
    struct redemption_document;
    
    // Evaluate script with real signature operations. 
    Error evaluate (
        const script &unlock,
        const script &lock,
        const redemption_document &doc,
        const script_config & = {});
    
    struct redemption_document {
        
        incomplete::transaction &Transaction;
        
        index InputIndex;

        satoshi RedeemedValue;

        redemption_document (incomplete::transaction &tx, index x, satoshi v):
            Transaction {tx}, InputIndex {x}, RedeemedValue {v} {}
        
        // holdovers from Bitcoin Core. 
        bool check_locktime (const uint32_little &) const;
        bool check_sequence (const uint32_little &) const;
    };

    // the signature verification algorithm used by the script interpreter.
    // strict signatures are enabled by default because we don't know another format that is usable.
    Error verify_signature (
        byte_slice sig,
        byte_slice pub,
        const sighash::document &doc,
        flag flags = flag::VERIFY_STRICTENC | flag::VERIFY_DERSIG);

    // depricated script type that is supported for backwards compatibilty.
    bool is_P2SH (byte_slice);

    bool provably_unspendable (byte_slice, bool after_genesis = true);
    
}

#endif 


