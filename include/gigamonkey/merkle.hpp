// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MERKLE
#define GIGAMONKEY_MERKLE

#include "hash.hpp"

namespace Gigamonkey::Merkle {
        
    inline digest256 hash_concatinated(const digest256& a, const digest256& b) {
        return Bitcoin::hash256(write(64, a, b));
    }
    
    // all hashes for the leaves of a given tree in order starting from zero.
    using leaf_digests = list<digest256>;
    
    digest256 root(leaf_digests l);
    
    using entry = data::entry<uint32, stack<digest256>>;
    
    using digests = stack<digest256>;
    
    struct path {
        uint32 Index;
        digests Digests;
        
        path();
        path(uint32 i, digests p);
        
        bool valid() const;
        
        digest256 derive_root(const digest256& leaf) const;
        
        operator entry() const {
            return entry{Index, Digests};
        }
    };
    
    struct leaf {
        digest256 Digest;
        uint32 Index;
        
        leaf();
        leaf(digest256 d, uint32 i);
        explicit leaf(digest256 d) : leaf(d, 0) {}
        
        bool valid() const;
    };
    
    struct branch {
        leaf Leaf;
        digests Digests;
        
        branch();
        branch(leaf);
        branch(leaf, digests);
        branch(const digest256& d, path p) : branch{leaf{d, p.Index}, p.Digests} {}
        
        bool valid() const;
        
        bool empty() const;
        
        leaf first() const;
        
        operator leaf() const;
        
        operator path() const {
            return path{Leaf.Index, Digests << Leaf.Digest};
        }
        
        branch rest() const;
        
        digest256 root() const;
    };
    
    inline digest256 path::derive_root(const digest256& leaf) const {
        return branch{leaf, *this}.root();
    }
    
    struct proof {
        branch Branch;
        digest256 Root;
    
        proof();
        explicit proof(const digest256& root);
        proof(branch p, const digest256& root);
        
        bool valid() const;
    };
    
    inline digest256 root(const proof& p) {
        return p.Root;
    }
    
    struct dual;
    class server;
    
    struct tree : data::tree<digest256> {
        uint32 Width;
        uint32 Height;
        
        static tree make(leaf_digests);
        
        tree();
        explicit tree(const digest256& root);
        explicit tree(leaf_digests h) : tree{make(h)} {}
        
        bool valid() const;
        
        list<proof> proofs() const;
        
        proof operator[](uint32 i) const;
        
        operator dual() const;
        
    private:
        tree(data::tree<digest256> t, uint32 w, uint32 h) : data::tree<digest256>{t}, Width{w}, Height{h} {}
        friend class server;
    };
    
    inline digest256 root(const tree t) {
        return t.root();
    }
    
    using map = data::map<uint32, digests>;
    
    // dual to the Merkle tree. Prunable. 
    // would be good in a wallet. 
    // TODO there is a bug in this class that needs to be 
    // fixed before it can be used. 
    /*struct dual {
        map Paths;
        digest256 Root;
        
        dual() : Paths{}, Root{} {}
        dual(map m, digest256 root) : Paths{m}, Root{root} {}
        explicit dual(digest256 root) : dual{{}, root} {}
        
        dual(const proof& p) : Paths{entry(path(p.Branch))}, Root{p.Root} {}
        
        dual(const tree& t);
        
        bool valid() const;
        
        bool contains(uint32) const;
        
        proof operator[](uint32 b) const {
            auto e = Paths[b];
            if (!e.valid() || e.size() == 0) return proof{};
            return proof{branch{leaf{e.first(), b}, e.rest()}, Root};
        }
        
        list<leaf> leaves() const {
            return data::for_each([](const proof& p) -> leaf {
                return p.Branch.Leaf;
            }, proofs());
        }
        
        
        list<proof> proofs() const;
        
        dual operator+(const dual& d) const;
    };
    
    inline dual operator+(const proof& a, const proof& b) {
        return dual{a} + b;
    }*/
    
    // for serving branches. Would be on a miner's computer. 
    class server {
        cross<digest256> Digests;
        
        server() : Digests{}, Width{0}, Height{0} {}
        
    public:
        uint32 Width;
        uint32 Height;
        
        server(leaf_digests);
        server(const tree&);
        
        operator tree() const;
        
        digest256 root() const;
        
        proof operator[](uint32 index) const;
        
        bool operator==(const server& s) const;
    };
    
    inline std::ostream& operator<<(std::ostream& o, const path& p) {
        return o << "path{" << p.Index << ", " << p.Digests << "}";
    }
    
    inline std::ostream& operator<<(std::ostream& o, const leaf& p) {
        return o << "leaf{" << p.Index << ", " << p.Digest << "}";
    }
    
    inline std::ostream& operator<<(std::ostream& o, const branch& b) {
        return o << "branch{" << b.Leaf << ", " << b.Digests << "}";
    }
    
    inline std::ostream& operator<<(std::ostream& o, const proof& p) {
        return o << "proof{" << p.Branch << ", " << p.Root << "}";
    }
    
    inline bool operator==(const path& a, const path& b) {
        return a.Index == b.Index && a.Digests == b.Digests;
    }
    
    inline bool operator==(const leaf& a, const leaf& b) {
        return a.Digest == b.Digest && a.Index == b.Index;
    }
    
    inline bool operator!=(const leaf& a, const leaf& b) {
        return a.Digest != b.Digest || a.Index != b.Index;
    }
    
    inline bool operator<(const leaf& a, const leaf& b) {
        if (a.Digest == b.Digest) return a.Index < b.Index;
        return a.Digest < b.Digest;
    }
    
    inline bool operator>(const leaf& a, const leaf& b) {
        if (a.Digest == b.Digest) return a.Index > b.Index;
        return a.Digest > b.Digest;
    }
    
    inline bool operator==(const branch& a, const branch& b) {
        return a.Leaf == b.Leaf && a.Digests == b.Digests;
    }
    
    inline bool operator==(const proof& a, const proof& b) {
        return a.Root == b.Root && a.Branch == b.Branch;
    }
    
    inline bool operator!=(const proof& a, const proof& b) {
        return a.Root != b.Root || a.Branch != b.Branch;
    }
    
    inline bool operator==(const tree& a, const tree& b) {
        return a.Width == b.Width && a.Height == b.Height && static_cast<data::tree<digest256>>(a) == static_cast<data::tree<digest256>>(b);
    }
    
    inline path::path() : Index{0}, Digests{} {}
    
    inline path::path(uint32 i, stack<digest256> p) : Index{i}, Digests{} {}
        
    inline bool path::valid() const {
        return Digests.valid();
    }
        
    inline leaf::leaf() : Digest{}, Index{0} {}
    
    inline leaf::leaf(digest256 d, uint32 i) : Digest{d}, Index{i} {}
    
    inline bool leaf::valid() const {
        return Digest.valid();
    }
    
    inline branch::branch(): Leaf{}, Digests{} {}
    
    inline branch::branch(leaf l, digests p) : Leaf{l}, Digests{p} {}
    
    inline branch::branch(leaf l) : Leaf{l}, Digests{} {}
        
    inline bool branch::valid() const {
        return Leaf.valid() && Digests.valid();
    }
        
    inline bool branch::empty() const {
        return Digests.empty();
    }
        
    inline leaf branch::first() const {
        return Leaf;
    }
    
    inline branch::operator leaf() const {
        return Leaf;
    }
    
    inline proof::proof() : Branch{}, Root{} {}
    
    inline proof::proof(branch p, const digest256& root) : Branch{p}, Root{root} {}
    
    inline proof::proof(const digest256& root) : Branch{leaf{root, 0}}, Root{root} {}
    
    inline bool proof::valid() const {
        return Root.valid() && Branch.valid() && Root == Branch.root();
    }
    
    inline tree::tree() : data::tree<digest256>{}, Width{0}, Height{0} {}
    
    inline tree::tree(const digest256& root) : data::tree<digest256>{root}, Width{1}, Height{1} {}
    
    inline digest256 server::root() const {
        return Digests[Digests.size() - 1];
    }
        
    inline bool server::operator==(const server& s) const {
        return Width == s.Width && Height == s.Height && Digests == s.Digests;
    }
}

#endif
