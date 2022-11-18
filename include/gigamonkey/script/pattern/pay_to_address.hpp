// Copyright (c) 2019-2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_PATTERN_PAY_TO_ADDRESS
#define GIGAMONKEY_SCRIPT_PATTERN_PAY_TO_ADDRESS

#include <gigamonkey/script/pattern.hpp>

namespace Gigamonkey {
    
    struct pay_to_address {
        static Gigamonkey::pattern pattern(bytes& address) {
            using namespace Bitcoin;
            return {OP_DUP, OP_HASH160, push_size{20, address}, OP_EQUALVERIFY, OP_CHECKSIG};
        }
        
        static bytes script(const digest160& a) {
            using namespace Bitcoin;
            return compile(program{OP_DUP, OP_HASH160, bytes_view(a), OP_EQUALVERIFY, OP_CHECKSIG});
        }
        
        digest160 Address;
        
        bool valid() const {
            return Address.valid();
        }
        
        bytes script() const {
            return script(Address);
        }
        
        pay_to_address(bytes_view script) : Address{} {
            using namespace Bitcoin;
            bytes addr{20};
            if (!pattern(addr).match(script)) return;
            std::copy(addr.begin(), addr.end(), Address.Value.begin());
        }
        
        static bytes redeem(const Bitcoin::signature& s, const Bitcoin::pubkey& p) {
            using namespace Bitcoin;
            return compile(program{} << push_data(s) << push_data(p));
        }
    };
    
} 

#endif

