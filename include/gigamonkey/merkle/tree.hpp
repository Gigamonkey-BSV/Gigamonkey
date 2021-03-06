// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MERKLE_TREE
#define GIGAMONKEY_MERKLE_TREE

#include <gigamonkey/merkle/proof.hpp>

namespace Gigamonkey::Merkle {
    
    struct dual;
    class server;
    
    struct tree final : data::tree<digest> {
        uint32 Width;
        uint32 Height;
        
        static tree make(leaf_digests);
        
        tree();
        explicit tree(const digest& root);
        explicit tree(leaf_digests h) : tree{make(h)} {}
        
        bool valid() const;
        
        const list<proof> proofs() const;
        
        proof operator[](uint32 i) const;
        
        operator dual() const;
        
    private:
        tree(data::tree<digest> t, uint32 w, uint32 h) : data::tree<digest>{t}, Width{w}, Height{h} {}
        friend class server;
    };
    
    inline digest root(const tree t) {
        return t.root();
    }
    
    
    inline bool operator==(const tree& a, const tree& b) {
        return a.Width == b.Width && a.Height == b.Height && static_cast<data::tree<digest>>(a) == static_cast<data::tree<digest>>(b);
    }
    
    inline bool operator!=(const tree& a, const tree& b) {
        return !(a == b);
    }
    
    inline tree::tree() : data::tree<digest>{}, Width{0}, Height{0} {}
    
    inline tree::tree(const digest& root) : data::tree<digest>{root}, Width{1}, Height{1} {}
    
}

#endif

