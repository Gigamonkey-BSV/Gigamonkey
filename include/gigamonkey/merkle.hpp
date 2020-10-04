// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MERKLE
#define GIGAMONKEY_MERKLE

#include "hash.hpp"

namespace Gigamonkey::Merkle {
    
    using digest = digest256;
        
    inline digest hash_concatinated(const digest& a, const digest& b) {
        return Bitcoin::hash256(write(64, a, b));
    }
    
    // all hashes for the leaves of a given tree in order starting from zero.
    using leaf_digests = list<digest>;
    
    digest root(leaf_digests l);
    
    using digests = stack<digest>;
    
    struct path {
        uint32 Index;
        digests Digests;
        
        path();
        path(uint32 i, const digests p);
        
        bool valid() const;
        
        digest derive_root(const digest& leaf) const;
    };
    
    struct leaf {
        digest Digest;
        uint32 Index;
        
        leaf();
        leaf(digest d, uint32 i);
        explicit leaf(digest d) : leaf(d, 0) {}
        
        bool valid() const;
    };
    
    using entry = data::entry<digest, path>;
    
    struct branch {
        leaf Leaf;
        digests Digests;
        
        branch();
        branch(leaf);
        branch(leaf, digests);
        branch(const digest& d, path p) : branch{leaf{d, p.Index}, p.Digests} {}
        explicit branch(const entry& e) : Leaf{e.Key, e.Value.Index}, Digests{e.Value.Digests} {}
        
        bool valid() const;
        
        bool empty() const;
        
        leaf first() const;
        
        operator leaf() const;
        
        branch rest() const;
        
        digest root() const;
        
        explicit operator path() const;
        
        explicit operator entry() const;
    };
    
    inline digest path::derive_root(const digest& leaf) const {
        return branch{leaf, *this}.root();
    }
    
    struct proof {
        branch Branch;
        digest Root;
    
        proof();
        explicit proof(const digest& root);
        proof(branch p, const digest& root);
        
        bool valid() const;
    };
    
    inline digest root(const proof& p) {
        return p.Root;
    }
    
    struct dual;
    class server;
    
    struct tree : data::tree<digest> {
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
    
    using map = data::map<digest, path>;
    
    // dual to the Merkle tree. Prunable. 
    // would be good in a wallet. 
    struct dual {
        map Paths;
        digest Root;
        
        dual() : Paths{}, Root{} {}
        dual(map m, digest root) : Paths{m}, Root{root} {}
        explicit dual(digest root) : dual{{}, root} {}
        
        dual(const proof& p) : Paths{entry(p.Branch)}, Root{p.Root} {}
        
        dual(const tree& t);
        
        bool valid() const;
        
        bool contains(const digest&) const;
        
        proof operator[](const digest& b) const {
            auto e = Paths[b];
            if (!e.valid()) return proof{};
            return proof{branch{b, e}, Root};
        }
        
        list<leaf> leaves() const {
            return data::for_each([](const proof& p) -> leaf {
                return p.Branch.Leaf;
            }, proofs());
        }
        
        const ordered_list<proof> proofs() const;
        
        dual operator+(const dual& d) const;
    };
    
    inline dual operator+(const proof& a, const proof& b) {
        return dual{a} + b;
    }
    
    // for serving branches. Would be on a miner's computer. 
    class server {
        cross<digest> Digests;
        data::map<digest, uint32> Indices;
        
        server() : Digests{}, Indices{}, Width{0}, Height{0} {}
        
    public:
        uint32 Width;
        uint32 Height;
        
        server(leaf_digests);
        server(const tree&);
        
        operator tree() const;
        
        digest root() const;
        
        list<proof> proofs() const;
        
        proof operator[](const digest& d) const;
        
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
    
    inline std::ostream& operator<<(std::ostream& o, const dual& d) {
        return o << "dual{" << d.Paths << ", " << d.Root << "}";
    }
    
    inline bool operator==(const path& a, const path& b) {
        return a.Index == b.Index && a.Digests == b.Digests;
    }
    
    inline bool operator!=(const path& a, const path& b) {
        return a.Index != b.Index || a.Digests == b.Digests;
    }
    
    inline bool operator==(const leaf& a, const leaf& b) {
        return a.Digest == b.Digest && a.Index == b.Index;
    }
    
    inline bool operator!=(const leaf& a, const leaf& b) {
        return a.Digest != b.Digest || a.Index != b.Index;
    }
    
    inline bool operator<=(const leaf& a, const leaf& b) {
        if (a.Index == b.Index) return a.Digest <= b.Digest;
        return a.Index <= b.Index;
    }
    
    inline bool operator>=(const leaf& a, const leaf& b) {
        if (a.Index == b.Index) return a.Digest >= b.Digest;
        return a.Index >= b.Index;
    }
    
    inline bool operator<(const leaf& a, const leaf& b) {
        if (a.Index == b.Index) return a.Digest < b.Digest;
        return a.Index < b.Index;
    }
    
    inline bool operator>(const leaf& a, const leaf& b) {
        if (a.Index == b.Index) return a.Digest > b.Digest;
        return a.Index > b.Index;
    }
    
    inline bool operator==(const branch& a, const branch& b) {
        return a.Leaf == b.Leaf && a.Digests == b.Digests;
    }
    
    inline bool operator!=(const branch& a, const branch& b) {
        return a.Leaf != b.Leaf || a.Digests != b.Digests;
    }
    
    inline bool operator<=(const branch& a, const branch& b) {
        return a.Leaf <= b.Leaf;
    }
    
    inline bool operator>=(const branch& a, const branch& b) {
        return a.Leaf >= b.Leaf;
    }
    
    inline bool operator<(const branch& a, const branch& b) {
        return a.Leaf < b.Leaf;
    }
    
    inline bool operator>(const branch& a, const branch& b) {
        return a.Leaf > b.Leaf;
    }
    
    inline bool operator==(const proof& a, const proof& b) {
        return a.Root == b.Root && a.Branch == b.Branch;
    }
    
    inline bool operator!=(const proof& a, const proof& b) {
        return a.Root != b.Root || a.Branch != b.Branch;
    }
    
    inline bool operator<=(const proof& a, const proof& b) {
        if (a.Branch == b.Branch) return a.Root <= b.Root;
        return a.Branch <= b.Branch;
    }
    
    inline bool operator>=(const proof& a, const proof& b) {
        if (a.Branch == b.Branch) return a.Root >= b.Root;
        return a.Branch >= b.Branch;
    }
    
    inline bool operator<(const proof& a, const proof& b) {
        if (a.Branch == b.Branch) return a.Root < b.Root;
        return a.Branch < b.Branch;
    }
    
    inline bool operator>(const proof& a, const proof& b) {
        if (a.Branch == b.Branch) return a.Root > b.Root;
        return a.Branch > b.Branch;
    }
    
    inline bool operator==(const tree& a, const tree& b) {
        return a.Width == b.Width && a.Height == b.Height && static_cast<data::tree<digest>>(a) == static_cast<data::tree<digest>>(b);
    }
    
    inline bool operator!=(const tree& a, const tree& b) {
        return !(a == b);
    }
    
    inline bool operator==(const dual& a, const dual& b) {
        return a.Root == b.Root && a.Paths == b.Paths;
    }
    
    inline bool operator!=(const dual& a, const dual& b) {
        return !(a == b);
    }
    
    inline path::path() : Index{0}, Digests{} {}
    
    inline path::path(uint32 i, const digests p) : Index{i}, Digests{p} {}
        
    inline bool path::valid() const {
        return Digests.valid();
    }
        
    inline leaf::leaf() : Digest{}, Index{0} {}
    
    inline leaf::leaf(digest d, uint32 i) : Digest{d}, Index{i} {}
    
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
        
    inline branch::operator path() const {
        return path{Leaf.Index, Digests};
    }
        
    inline branch::operator entry() const {
        return entry{Leaf.Digest, operator path()};
    }
    
    inline proof::proof() : Branch{}, Root{} {}
    
    inline proof::proof(branch p, const digest& root) : Branch{p}, Root{root} {}
    
    inline proof::proof(const digest& root) : Branch{leaf{root, 0}}, Root{root} {}
    
    inline bool proof::valid() const {
        return Root.valid() && Branch.valid() && Root == Branch.root();
    }
    
    inline tree::tree() : data::tree<digest>{}, Width{0}, Height{0} {}
    
    inline tree::tree(const digest& root) : data::tree<digest>{root}, Width{1}, Height{1} {}
    
    inline digest server::root() const {
        return Digests[-1];
    }
        
    inline bool server::operator==(const server& s) const {
        return Width == s.Width && Height == s.Height && Digests == s.Digests;
    }
}

#endif
