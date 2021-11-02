// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018 The Bitcoin SV developers
// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_SCRIPT
#define GIGAMONKEY_SCRIPT_SCRIPT

#include <gigamonkey/script/error.h>

#include <gigamonkey/script/instruction.hpp>
#include <gigamonkey/wif.hpp>

namespace Gigamonkey::Bitcoin::interpreter { 
    
    // the result returned from a script evaluatuon. 
    // There is a success or failure and a possible error. 
    struct result; 
    
    // Test validity of a script. All signature operations succeed. 
    result evaluate(const script& unlock, const script& lock);
    
    // Evaluate script with real signature operations. 
    result evaluate(const script& unlock, const signature::document &lock);
    
    bool operator==(const result &, const result &);
    bool operator!=(const result &, const result &);
    
    struct result {
        ScriptError Error;
        bool Return;
        
        result() : Error{SCRIPT_ERR_OK}, Return{false} {}
        result(ScriptError err) : Error{err}, Return{false} {}
        
        bool valid() const {
            return !Error;
        }
        
        bool verify() const {
            return !Error && Return;
        }
        
        operator bool() const {
            return verify();
        }
    };
    
    bool inline operator==(const result &a, const result &b) {
        return a.Return == b.Return && a.Error == b.Error;
    }
    
    bool inline operator!=(const result &a, const result &b) {
        return !(a == b);
    }
    
}

#endif 


