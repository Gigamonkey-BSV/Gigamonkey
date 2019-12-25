// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_PAY
#define GIGAMONKEY_SCRIPT_PAY

#include <gigamonkey/script.hpp>
#include <gigamonkey/address.hpp>
#include "pattern.hpp"

namespace gigamonkey::bitcoin::script {
    
    struct pay_to_pubkey {
        static script::pattern pattern(bytes& pubkey) {
            return script::pattern{push{pubkey}, OP_CHECKSIG};
        }
        
        static bytes script(pubkey);
        
        pubkey Pubkey;
        
        bool valid() const {
            return Pubkey.valid();
        }
        
        bytes script() const {
            return script(Pubkey);
        }
        
        pay_to_pubkey(bytes_view b) : Pubkey{} {
            pattern(Pubkey.Value.Value).match(b);
        }
        
        static bytes redeem(const signature& s) {
            return compile(push_data(s.Data));
        }
    };
    
    struct pay_to_address {
        static script::pattern pattern(bytes& address) {
            return script::pattern{OP_DUP, OP_HASH160, push{address}, OP_EQUALVERIFY, OP_CHECKSIG};
        }
        
        static bytes script(const address&);
        
        address Address;
        
        bool valid() const {
            return Address.valid();
        }
        
        bytes script() const {
            return script(Address);
        }
        
        pay_to_address(bytes_view b);
        
        static bytes redeem(const signature& s, const pubkey& p);
    };
    
}

#endif


