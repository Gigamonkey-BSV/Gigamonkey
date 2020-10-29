// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/merkle.hpp>

namespace Gigamonkey::Merkle {
    
    leaves round(leaves l) {
        leaves r{};
        while(l.size() >= 2) {
            r = r << hash_concatinated(l.first(), l.rest().first());
            l = l.rest().rest();
        }
        if (l.size() == 1) r = r << hash_concatinated(l.first(), l.first());
        return r;
    }
    
    digest256 root(list<digest256> l) {
        if (l.size() == 0) return digest256();
        while (l.size() > 1) l = round(l); 
        return l.first();
    }
    
    tree::tree(leaves l) : Size{l.size()} {
        size_t r = Size;
        size_t num_hashes = r;
        while (r > 1) {
            r = (r + 1) / 2;
            num_hashes += r;
        } 
        Hashes.resize(num_hashes);
        
        leaves v = l;
        size_t i = 0;
        
        while (true) {
            leaves x = v;
            while (!x.empty()) {
                Hashes[i] = x.first();
                x = x.rest();
                i++;
            }
            if (i == num_hashes) return;
            v = round(v);
        } 
        
    }
        
    Merkle::branch tree::branch(uint32 index) const {
        if (index >= Size) return {};
        
        list<digest256> p;
        uint32 i = index;
        uint32 cumulative = 0;
        size_t size = Size;
        
        while (size > 1) {
            p = p << Hashes[cumulative + i + (i & 1 ? - 1 : i == size - 1 ? 0 : 1)];
            cumulative += size;
            size = (size + 1) / 2;
            i >>= 1;
        }
        
        return Merkle::branch{Hashes[index], path{index, p}, root()};
    }
    
}
