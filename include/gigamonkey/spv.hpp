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
            digest<32> Hash;
            work::difficulty Cumulative;
            
            bool operator==(const header& h) const {
                return Header == h.Header;
            }
            
            bool operator!=(const header& h) const {
                return !operator==(h);
            }
        };
        
        struct chain {
            list<header> Chain;
            
            bool valid() const {
                return !data::empty(Chain);
            }
            
            work::difficulty difficulty() const {
                return valid() ? Chain.first().Cumulative : work::difficulty{0};
            }
            
            chain add(const bitcoin::header& h) const {
                digest<32> digest = h.hash();
                if (Chain.first().Hash != digest) return {};
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
        map<digest<32>, list<header>> Headers;
        
        headers() : Chains{ordered_list<chain>{} << chain{list<header>{} << header{genesis(), genesis().hash(), genesis().difficulty()}}} {}
        
        headers attach(const bitcoin::header& h) const;
        
    private:
        headers(ordered_list<chain> ch, map<digest<32>, list<header>> h) : Chains{ch}, Headers{h} {}
    };
    
}

#endif
