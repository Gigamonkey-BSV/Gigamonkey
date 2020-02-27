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
        
    path::operator bytes() {
        bytes b(4 + 32 * Hashes.size());
        auto w = bytes_writer(b.begin(), b.end()) << uint32_little{Index};
        list<digest256> h = Hashes;
        while(!h.empty()) {
            w << h.first();
            h = h.rest();
        }
        return b;
    }
    
    tree::incomplete tree::incomplete::pairwise_concatinate() const {
        incomplete Next;
        uint32 in = 0;
        uint32 out = 0;
        incomplete This = *this;
        while (!This.Trees.empty()) {
            digest_tree left_in = This.Trees.first();
            bool keep_left = This.Leaves.empty() || This.Leaves.first() != in;
            digest_tree left_out = keep_left ? left_in : digest_tree{};
            
            if (keep_left) This.Leaves = This.Leaves.rest();
            This.Trees = This.Trees.rest();
            in++;
            
            digest_tree right_in;
            digest_tree right_out;
            bool keep_right;
            
            if (This.Trees.size() == 1) {
                right_in = left_in;
                right_out = left_out;
                keep_right = keep_left;
            } else {
                right_in = This.Trees.first();
                keep_right = This.Leaves.empty() || This.Leaves.first() != in;
                right_out = keep_right ? right_in : digest_tree{};
                in++;
            }
            
            Next.Trees << digest_tree{hash_concatinated(left_in.root(), right_in.root()), left_out, right_out};
            if (keep_left || keep_right) Next.Leaves << out;
            out ++;
        }
        return Next;
    }
    
}
