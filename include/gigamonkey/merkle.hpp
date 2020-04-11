// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MERKLE
#define GIGAMONKEY_MERKLE

#include "hash.hpp"

namespace Gigamonkey::Merkle {
        
    inline digest256 hash_concatinated(const digest256& a, const digest256& b) {
        return Bitcoin::hash256(write(64, a, b));
    }
    
    using leaves = list<digest256>;
    
    leaves round(leaves l);
    
    digest256 root(list<digest256> l);
    
    struct path {
        list<digest256> Hashes;
        uint32 Index;
        
        path();
        path(list<digest256> p, uint32 i);
        
        digest256 derive_root(digest256 leaf) const;
    
        bool check(digest256 merkle_root, digest256 leaf) const;
        
        bool operator==(const path& p) const;
        
        bool operator!=(const path& p) const;
        
        // serialize and deserialize. 
        explicit operator bytes();
        
        explicit path(bytes_view b);
    };
    
    class tree {
        using digest_tree = Gigamonkey::tree<digest256>;
        
        static digest_tree deserialize(bytes_view);
        static bytes serialize(digest_tree);
        
        struct incomplete {
            list<digest_tree> Trees;
            ordered_list<uint32> Leaves;
            
            incomplete pairwise_concatinate() const;
        };
        
        static data::map<digest256&, path> paths(digest_tree);
        
        static digest_tree build(list<digest256> q, ordered_list<uint32> leaves);
        
        tree(digest_tree t, data::map<digest256&, path> p) : Tree{t}, Paths{p} {}
        tree(digest_tree t) : Tree{t}, Paths{paths(t)} {}
        tree() : Tree{}, Paths{} {}
        
    public:
        digest_tree Tree;
        data::map<digest256&, path> Paths;
        
        tree(list<digest256> q,              // All txs in a block in order.
             ordered_list<uint32> leaves   // all indicies of txs that we want to remember. 
        ) : tree{build(q, leaves)} {}
        
        tree add(path) const;
        
        tree remove(list<digest256>) const;
        
        tree remove(const digest256& d) const {
            return remove(list<digest256>{} << d);
        }
        
        digest256 root() const {
            if (Tree.empty()) return {};
            return Tree.root();
        }
    };
    
}

inline std::ostream& operator<<(std::ostream& o, const Gigamonkey::Merkle::path& p) {
    return o << "path{Index: " << p.Index << ", Hashes: " << p.Hashes << "}";
}

namespace Gigamonkey::Merkle {
    
    inline path::path() : Hashes{}, Index{} {}
    inline path::path(list<digest256> p, uint32 i) : Hashes{p}, Index{i} {};
    
    inline digest256 path::derive_root(digest256 leaf) const {
        return Hashes.size() == 0 ? leaf : 
            path{Hashes.rest(),  Index / 2}.derive_root(
                Index & 1 ? hash_concatinated(Hashes.first(), leaf) : hash_concatinated(leaf, Hashes.first()));
    }
    
    inline bool path::check(digest256 merkle_root, digest256 leaf) const {
        return merkle_root == derive_root(leaf);
    }
    
    inline bool path::operator==(const path& p) const {
        return Hashes == p.Hashes && Index == p.Index;
    }
    
    inline bool path::operator!=(const path& p) const {
        return !operator==(p);
    }
}

#endif
