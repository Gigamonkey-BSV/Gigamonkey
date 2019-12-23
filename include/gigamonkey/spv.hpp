// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SPV
#define GIGAMONKEY_SPV

#include "timechain.hpp"
#include "work.hpp"

namespace gigamonkey::bitcoin {
    
    constexpr header genesis();
    
    struct headers {
        
        struct header {
            bitcoin::header Header;
            txid Txid;
            work::difficulty Cumulative;
        };
        
        struct chain {
            list<header> Chain;
            
            bool valid() const {
                return !data::empty(Chain);
            }
            
            work::difficulty difficulty() const {
                return valid() ? Chain.first().Cumulative : work::difficulty{0};
            }
            
            chain add(const bitcoin::header& h) {
                txid digest = h.hash();
                if (Chain.first().Txid != digest) return {};
                return chain{Chain << header{h, digest, difficulty() + h.difficulty()}};
            }
            
            bool operator>(const chain& h) {
                return difficulty() > h.difficulty();
            }
            
            bool operator<(const chain& h) {
                return difficulty() < h.difficulty();
            }
            
            bool operator>=(const chain& h) {
                return difficulty() >= h.difficulty();
            }
            
            bool operator<=(const chain& h) {
                return difficulty() <= h.difficulty();
            }
        private:
            chain(list<header> c) : Chain{c} {}
            chain() : Chain{} {}
            friend struct headers;
        };
        
        ordered_list<chain> Chains;
        map<txid&, list<header>> Headers;
        
        headers() : Chains{ordered_list<chain>{} << chain{list<header>{} << header{genesis(), genesis().hash(), genesis().difficulty()}}} {}
        
        headers attach(const bitcoin::header& h);
        
    };
    
}

#endif
