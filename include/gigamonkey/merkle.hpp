// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MERKLE
#define GIGAMONKEY_MERKLE

#include "hash.hpp"

namespace gigamonkey::merkle {
    
    using digest = digest<32>;
        
    inline digest concatinated(const digest& a, const digest& b) {
        return bitcoin::hash256(write(64, a, b));
    }
    
    class tree;
    
    class path {
        friend class tree;
        path(uint32 i, list<digest> h) : Index{i}, Hashes{h} {}
    public:
        
        uint32 Index;
        list<digest> Hashes;
        
        path() : Index{0}, Hashes{} {}
        
        static digest next(uint32 i, const digest& d, const digest& last) {
            return (i & 1) == 1 ? concatinated(last, d) : concatinated(d, last);
        }
        
        bool verify(const digest& root, const digest& leaf) {
            if (Hashes.empty()) return leaf == root;
            return path{Index >> 1, Hashes.rest()}.verify(root, next(Index, leaf, Hashes.first()));
        }
    };
    
    class tree {
        using digest_tree = gigamonkey::tree<digest>;
        static queue<digest_tree> pairwise_concatinate(queue<digest_tree> l);
        
        static digest_tree build(queue<digest_tree> l) {
            if (data::size(l) == 0) return {};
            if (data::size(l) == 1) return l.first();
            return build(pairwise_concatinate(l));
        }
        
        static digest_tree build(queue<digest> l) {
            return build(data::for_each([](const digest& d)->digest_tree{return {d};}, l));
        }
        
    public:
        uint32 Leaves;
        digest_tree Tree;
        
        tree(queue<digest> l) : Leaves{data::size(l)}, Tree{build(l)} {}
        
        merkle::path path(uint32 index);
    };
    
}

#endif
