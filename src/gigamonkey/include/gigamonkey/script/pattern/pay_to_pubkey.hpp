// Copyright (c) 2019-2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_PATTERN_PAY_TO_PUBKEY
#define GIGAMONKEY_SCRIPT_PATTERN_PAY_TO_PUBKEY

#include <gigamonkey/script/pattern.hpp>

namespace Gigamonkey {
    
    struct pay_to_pubkey {
        static Gigamonkey::pattern pattern (bytes &pubkey) {
            return {pubkey_pattern (pubkey), Bitcoin::OP_CHECKSIG};
        }
        
        static bytes script (Bitcoin::pubkey p) {
            using namespace Bitcoin;
            return compile (program {push_data (p), Bitcoin::OP_CHECKSIG});
        }
        
        Bitcoin::pubkey Pubkey;
        
        bool valid () const {
            return Pubkey.valid ();
        }
        
        bytes script () const {
            return script (Pubkey);
        }
        
        pay_to_pubkey (slice<const byte> script) : Pubkey {} {
            using namespace Bitcoin;
            pubkey p;
            if (!pattern (p).match (script)) return;
            Pubkey = p;
        }
        
        static bytes redeem (const Bitcoin::signature &s) {
            using namespace Bitcoin;
            return compile (push_data (s));
        }

        constexpr static uint64 redeem_expected_size () {
            return 1 + Bitcoin::signature::MaxSize;
        }
    };
    
} 

#endif
