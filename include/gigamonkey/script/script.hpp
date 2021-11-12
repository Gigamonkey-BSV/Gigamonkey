// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018 The Bitcoin SV developers
// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_SCRIPT
#define GIGAMONKEY_SCRIPT_SCRIPT

#include <gigamonkey/script/error.h>

#include <gigamonkey/script/instruction.hpp>
#include <gigamonkey/sighash.hpp>
#include <gigamonkey/satoshi.hpp>
#include <sv/script/script_num.h>

namespace Gigamonkey::Bitcoin { 
    
    // the result returned from a script evaluatuon. 
    // There is a success or failure and a possible error. 
    struct result; 
    
    // Test validity of a script. All signature operations succeed. 
    result evaluate(const script& unlock, const script& lock, uint32 flags = StandardScriptVerifyFlags(true, true));
    
    struct redemption_document;
    
    // Evaluate script with real signature operations. 
    result evaluate(const script& unlock, const script& lock, const redemption_document &doc, uint32 flags = StandardScriptVerifyFlags(true, true));
    
    bool operator==(const result &, const result &);
    bool operator!=(const result &, const result &);
    
    struct result {
        ScriptError Error;
        bool Success;
        
        result() : result{false} {}
        result(bool b) : Error{SCRIPT_ERR_OK}, Success{b} {}
        result(ScriptError err) : Error{err}, Success{false} {}
        
        bool valid() const {
            return !Error;
        }
        
        bool verify() const {
            return !Error && Success;
        }
        
        operator bool() const {
            return verify();
        }
    };
    
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
    
    bool inline operator==(const result &a, const result &b) {
        return a.Success == b.Success && a.Error == b.Error;
    }
    
    bool inline operator!=(const result &a, const result &b) {
        return !(a == b);
    }
    
    std::ostream inline &operator<<(std::ostream &o, const result &r) {
        if (r.Error) return o << r.Error;
        return o << (r.Success ? "success" : "failure");
    }
    
}

#endif 


