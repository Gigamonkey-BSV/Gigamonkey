// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SPV
#define GIGAMONKEY_SPV

#include "timechain.hpp"
#include "merkle.hpp"
#include "txid.hpp"

namespace Gigamonkey::Bitcoin {
    
    constexpr header genesis();
    
    struct headers {
        
        struct header {
            Bitcoin::header Header;
            digest<32> Hash;
            N Height;
            work::difficulty Cumulative;
            
            header(Bitcoin::header h, digest<32> s, work::difficulty d) : Header{h}, Hash{s}, Cumulative{d} {}
            
            bool operator==(const header& h) const {
                return Header == h.Header;
            }
            
            bool operator!=(const header& h) const {
                return !operator==(h);
            }
        };
        
        virtual header latest() = 0;
        
        virtual ptr<header> by_height(const N&) = 0;
        
        struct merkle {
            header Header;
            Merkle::path Path;
        };
        
        virtual ptr<merkle> get_path(const txid&) = 0;
        
    };
    
    struct transactions {
        // the transaction lifecycle
        enum status : byte {
            invalid,         // cannot be broadcasted
            valid,           // could be broadcasted
            broadcasted,     // has been spent
            spendable,       // can be redeemed
            confirmed        // has a merkle path
        };
    };
    
}

#endif
