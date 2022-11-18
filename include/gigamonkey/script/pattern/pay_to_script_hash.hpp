// Copyright (c) 2019-2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_PATTERN_PAY_TO_SCRIPT_HASH
#define GIGAMONKEY_SCRIPT_PATTERN_PAY_TO_SCRIPT_HASH

#include <gigamonkey/script/pattern.hpp>

namespace Gigamonkey {
    
    // an obsolete pattern that was introduced by Gavin. 
    struct pay_to_script_hash {
        static Gigamonkey::pattern pattern(bytes& hash) {
            return {OP_HASH160, push_size{20, hash}, OP_EQUAL};
        }
        
        static bytes script(const digest160& a) {
            using namespace Bitcoin;
            return compile(program{OP_HASH160, bytes_view(a), OP_EQUAL});
        }
        
        digest160 Hash;
        
        bool valid() const {
            return Hash.valid();
        }
        
        bytes script() const {
            return script(Hash);
        }
        
        pay_to_script_hash(bytes_view script) : Hash{} {
            using namespace Bitcoin;
            bytes hash{20};
            if (!pattern(hash).match(script)) return;
            std::copy(hash.begin(), hash.end(), Hash.Value.begin());
        }
        
        static bytes redeem(const bytes_view s) {
            using namespace Bitcoin;
            return compile(program{} << push_data(s));
        }
    };
} 

#endif
