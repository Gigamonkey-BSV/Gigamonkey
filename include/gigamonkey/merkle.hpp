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
        queue<digest> Hashes;
        
        path() : Index{0}, Hashes{} {}
        path(uint32 i, queue<digest> q) : Index{i}, Hashes{q} {}
        
        static digest next(uint32 i, const digest& d, const digest& last) {
            return (i & 1) == 1 ? concatinated(last, d) : concatinated(d, last);
        }
        
        bool verify(const digest& root, const digest& leaf) {
            if (Hashes.empty()) return leaf == root;
            return path{Index >> 1, Hashes.rest()}.verify(root, next(Index, leaf, Hashes.first()));
        }
        
        explicit operator bytes();
        
        explicit path(bytes_view b);
    };
    
    class tree {
        using digest_tree = gigamonkey::tree<digest>;
        
        static digest_tree deserialize(bytes_view);
        static bytes serialize(digest_tree);
        
        struct incomplete {
            queue<digest_tree> Trees;
            ordered_list<uint32> Leaves;
            
            incomplete pairwise_concatinate() const;
        };
        
        static map<digest&, path> paths(digest_tree);
        
        static digest_tree build(queue<digest> q, ordered_list<uint32> leaves);
        
        tree(digest_tree t, map<digest&, path> p) : Tree{t}, Paths{p} {}
        tree(digest_tree t) : Tree{t}, Paths{paths(t)} {}
        tree() : Tree{}, Paths{} {}
        
    public:
        digest_tree Tree;
        map<digest&, path> Paths;
        
        tree(queue<digest> q,              // All txs in a block in order.
             ordered_list<uint32> leaves   // all indicies of txs that we want to remember. 
        ) : tree{build(q, leaves)} {}
        
        tree add(path) const;
        
        tree remove(queue<digest>) const;
        
        tree remove(const digest& d) const {
            return remove(queue<digest>{} << d);
        }
        
        digest root() const {
            if (Tree.empty()) return {};
            return Tree.root();
        }
    };
    
}

#endif
