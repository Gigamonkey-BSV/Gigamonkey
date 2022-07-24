// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/merkle/tree.hpp>
#include <gigamonkey/merkle/dual.hpp>
#include <gigamonkey/merkle/server.hpp>
#include <algorithm>

namespace Gigamonkey::Merkle {
    
    namespace {
    
        leaf_digests round(leaf_digests l) {
            leaf_digests r{};
            while(l.size() >= 2) {
                r = r << hash_concatinated(l.first(), l.rest().first());
                l = l.rest().rest();
            }
            if (l.size() == 1) r = r << hash_concatinated(l.first(), l.first());
            return r;
        }
    
        bool check_proofs(ordered_list<proof> x) {
            if (x.size() == 0) return true;
            set<leaf> g;
            for (proof p : x) {
                digest256 root = p.Root;
                branch b = p.Branch;
                while (true) {
                    if (g.contains(b.Leaf)) break;
                    g = g.insert(b.Leaf);
                    if (b.empty()) {
                        if (b.Leaf.Digest != root) return false;
                        else break;
                    }
                    b = b.rest();
                }
            }
            return true;
        }
    
        void append_proofs(list<proof>& p, uint32 index, digests l, data::tree<digest256> t, const digest256& r, uint32 height) {
            if (height == 1) {
                p = p << proof{branch{leaf{t.root(), index}, l}, r};
                return;
            }
            
            if (!t.right().empty()) {
                append_proofs(p, (index << 1), l << t.right().root(), t.left(), r, height - 1);
                append_proofs(p, (index << 1) + 1, l << t.left().root(), t.right(), r, height - 1);
            } else append_proofs(p, index << 1, l << t.left().root(), t.left(), r, height - 1);
        }
    
        template <typename it>
        void write_at_height(it& i, const data::tree<digest256>& t, uint32 height) {
            if (height == 0) {
                *i = t.root();
                ++i;
                return;
            }
            
            write_at_height(i, t.left(), height - 1);
            if (!t.right().empty()) write_at_height(i, t.right(), height - 1);
        }
    
        uint32 height(data::tree<digest256> t) {
            if (t.empty()) return 0;
            uint32 right_height = height(t.right());
            uint32 left_height = height(t.left());
            if (right_height != left_height) return 0;
            return right_height + 1;
        }
        
        bool check_tree(const data::tree<digest256>& t, uint32 expected_width, uint32 expected_height) {
            if (expected_height == 0) return false;
            if (expected_height == 1) return expected_width == 1 && !t.empty() && t.left().empty() && t.right().empty() && t.root().valid();
            
            if (t.left().empty()) return false;
            
            uint32 expected_left_width;
            digest256 expected_value;
            
            if (t.right().empty()) {
                expected_left_width = expected_width;
                expected_value = hash_concatinated(t.left().root(), t.left().root());
            } else {
                expected_left_width = 1 << (expected_height - 2);
                expected_value = hash_concatinated(t.left().root(), t.right().root());
                if (!check_tree(t.right(), expected_width - expected_left_width, expected_height - 1)) return false;
            }
            
            if (!check_tree(t.left(), expected_left_width, expected_height - 1)) return false;
            
            return t.root() == expected_value;
        }
    
    }
    
    tree tree::make(leaf_digests h) {
        
        if (h.size() == 0) tree{};
        if (h.size() == 1) return tree{h.first()};
        
        uint32 width = h.size();
        uint32 height = 2;
        
        leaf_digests next_round = round(h);
        
        using trees = list<data::tree<digest256>>;
        trees Trees{};
        
        leaf_digests last = h;
        leaf_digests next = next_round;
        while (!next.empty()) {
            if (last.size() >= 2) {
                Trees = Trees << data::tree<digest256>{next.first(), 
                    data::tree<digest256>{last.first()}, 
                    data::tree<digest256>{last.rest().first()}};
                last = last.rest().rest();
            } else {
                Trees = Trees << data::tree<digest256>{next.first(), 
                    data::tree<digest256>{last.first()}, 
                    data::tree<digest256>{}};
                last = last.rest();
            }
            next = next.rest();
        }
        
        while(next_round.size() > 1) {
            trees last_trees = Trees;
            Trees = trees{};
            next_round = round(next_round);
            next = next_round;
            height++;
            
            while(!next.empty()) {
                if (last_trees.size() >= 2) {
                    Trees = Trees << data::tree<digest256>{next.first(), 
                        data::tree<digest256>{last_trees.first()}, 
                        data::tree<digest256>{last_trees.rest().first()}};
                    last_trees = last_trees.rest().rest();
                } else {
                    Trees = Trees << data::tree<digest256>{next.first(), 
                        data::tree<digest256>{last_trees.first()}, 
                        data::tree<digest256>{}};
                    last_trees = last_trees.rest();
                }
                next = next.rest();
            }
        }
        
        // trees should have size 1 by this point. 
        return tree{Trees.first(), width, height};
    }
    
    digest root(list<digest> l) {
        if (l.size() == 0) return {};
        while (l.size() > 1) l = round(l); 
        return l.first();
    }
    
    digest root(leaf l, digests d) {
        while (d.size() > 0) {
            l = leaf{l.Index & 1 ? hash_concatinated(d.first(), l.Digest) : hash_concatinated(l.Digest, d.first()), l.Index >> 1};
            d = d.rest();
        }
        return l.Digest;
    }
    
    const list<proof> tree::proofs() const {
        
        if (Height == 0 || Width == 0) return {};
        if (Height == 1) return {proof{data::tree<digest256>::root()}};
        
        list<proof> p;
        
        append_proofs(p, 0, {data::tree<digest256>::right().root()}, data::tree<digest256>::left(), data::tree<digest256>::root(), Height - 1);
        append_proofs(p, 1, {data::tree<digest256>::left().root()}, data::tree<digest256>::right(), data::tree<digest256>::root(), Height - 1);
        
        return p;
    }
    
    bool tree::valid() const {
        if (Height == 0 || Width == 0) return false;
        return check_tree(*this, Width, Height);
    }
    
    proof tree::operator[](uint32 i) const {
        if (i >= Width) return {};
        
        uint32 max_index = Width - 1;
        data::tree<digest256> t = *this;
        uint32 next_height = Height - 1;
        stack<digest256> digests;
        
        while (next_height > 0) {
            digests = digests << t.root();
            
            if ((i >> next_height) & 0 || i == max_index) {
                t = t.right();
            } else {
                t = t.left();
            }
            
            next_height--;
        }
        
        return proof{branch{leaf{t.root(), i}, digests}, data::tree<digest256>::root()};
    }
    
    namespace {
        
        class dual_by_index {
            std::map<uint32, digests> Branches;
            digest Root;
            
            bool add_nearest(uint32 index, digests d, uint32 nearest) {
                uint32 height = d.size() - 1;
                
                while(index >> height == nearest >> height && height > 0) height--;
                height += 1;
                
                digests z{};
                digests x = Branches[nearest];
                digests b = d;
            
                for (int i = 0; i <= height; i++) {
                    x = x.rest();
                    z = z << b.first();
                    b = b.rest();
                }
            
                while(!z.empty()) {
                    x = x << z.first();
                    z = z.rest();
                }
                
                Branches.insert_or_assign(index, x);
                return true;
            }
            
            bool add(const branch& p) {
                
                uint32 index = p.Leaf.Index;
                digests d = p.Digests << p.Leaf.Digest;
                
                auto it = Branches.find(index);
                if (it != Branches.end()) {
                    if (it->second != d) return false;
                    return true;
                }
                
                uint32 height = d.size();
                
                cross<uint32> leaves;
                leaves.resize(Branches.size());
                {
                    int i = 0;
                    for (const auto& b : Branches) {
                        leaves[i] = b.first;
                        i++;
                    }
                }
                
                uint32 min = 0;
                uint32 max = leaves.size() - 1;
                
                if (index < leaves[min]) {
                    if (leaves[min] >> (height - 2) == index >> (height - 2)) return add_nearest(index, d, leaves[min]);
                    Branches.insert_or_assign(index, d);
                    return true;
                }
                
                if (index > leaves[max]) {
                    if (leaves[max] >> (height - 2) == index >> (height - 2)) return add_nearest(index, d, leaves[max]);
                    Branches.insert_or_assign(index, d);
                    return true;
                }
                
                while (max - min > 1) {
                    uint32 mid = (max - min) / 2 + min;
                    if (index > leaves[mid]) min = mid;
                    else max = mid;
                }
                
                if (leaves[min] >> (height - 2) == index >> (height - 2)) return add_nearest(index, d, leaves[min]);
                return add_nearest(index, d, leaves[max]);
            
            }
            
        public:
            dual_by_index(const dual& d) {
                Root = d.Root;
                for (const entry& e : d.Paths) Branches.insert_or_assign(e.Value.Index, e.Value.Digests << e.Key);
            }
            
            operator dual() const {
                map m;
                for (const auto& b : Branches) m = m.insert(b.second.first(), path{b.first, b.second.rest()});
                return dual{m, Root};
            }
            
            bool add_all(ordered_list<proof> p) {
                for (const proof& x : p) if (!add(x.Branch)) return false;
                return true;
            }
            
        };
        
    }
    
    dual dual::operator+(const dual& d) const {
        if (!valid()) return d;
        if (Root != d.Root) return {};
        dual_by_index x(*this);
        if (!x.add_all(d.proofs())) return {};
        return dual(x);
    }
    
    dual::dual(const tree& t) : dual{} {
        if (t.Width == 0) return;
        Root = t.root();
        list<proof> p = t.proofs();
        for (const proof& x : p) Paths = Paths.insert(entry(x.Branch));
    }
    
    const ordered_list<proof> dual::proofs() const {
        ordered_list<proof> p{};
        for (const auto& e : Paths) p = p << proof{branch(e), Root};
        return p;
    }
    
    bool dual::valid() const {
        return Root.valid() && Paths.valid() && Paths.size() > 0 && check_proofs(proofs());
    }
    
    server::server(const tree& t) : server {} {
        if (t.Width == 0 || t.Height == 0) return;
        
        Width = t.Width;
        Height = t.Height;
        
        uint32 width = Width;
        uint32 total = width;
        
        while (width > 1) {
            width = (width + 1) / 2;
            total += width;
        } 
        
        Digests.resize(total);
        
        uint32 height = Height;
        auto b = Digests.begin();
        do {
            height--;
            write_at_height(b, t, height);
        } while (height > 0);
    }
    
    server::operator tree() const {
        if (Width == 0 || Height == 0) return tree{};
            
        list<data::tree<digest256>> trees{};
        
        auto b = Digests.begin();
        for (int i = 0; i < Width; i++) {
            trees = trees << *b;
            b++;
        }
        
        while (trees.size() > 1) {
            list<data::tree<digest256>> new_trees{};
            
            while (trees.size() > 1) {
                new_trees = new_trees << data::tree<digest256>{*b, trees.first(), trees.rest().first()};
                trees = trees.rest().rest();
                b++;
            }
            
            if (trees.size() == 1) {
                new_trees = new_trees << data::tree<digest256>{*b, trees.first(), data::tree<digest256>{}};
                trees = trees.rest();
                b++;
            }
            
            trees = new_trees;
        }
        
        return tree{trees.first(), Width, Height};
    }
    
    server::server(leaf_digests l) : server{} {
        if (l.size() == 0) return;
        
        Width = l.size();
        Height = 1;
        
        uint32 width = Width;
        uint32 total = width;
        while (width > 1) {
            width = (width + 1) / 2;
            total += width;
            Height++;
        } 
        Digests.resize(total);
        
        leaf_digests v = l;
        uint32 i = 0;
        
        while (true) {
            leaf_digests x = v;
            while (!x.empty()) {
                Digests[i] = x.first();
                x = x.rest();
                i++;
            }
            if (i == total) break;
            v = round(v);
        } 
        
        auto a = Digests[total - 1];
        auto b = Digests[-1];
        
        for (uint32 x = 0; x < Width; x++) Indices = Indices.insert(Digests[x], x + 1);
        
    }
    
    namespace {
        proof get_server_proof(const cross<digest>& x, uint32 width, uint32 index) {
            digests p;
            uint32 i = index;
            uint32 cumulative = 0;
            
            while (width > 1) {
                p = p << x[cumulative + i + (i & 1 ? - 1 : i == width - 1 ? 0 : 1)];
                cumulative += width;
                width = (width + 1) / 2;
                i >>= 1;
            }
            
            return proof{branch{leaf{x[index], index}, data::reverse(p)}, x[-1]};
        }
    }
    
    proof server::operator[](const digest& d) const {
        uint32 index = Indices[d];
        if (index == 0) return {};
        
        return get_server_proof(Digests, Width, index - 1);
    }
        
    list<proof> server::proofs() const {
        list<proof> p;
        for (uint32 i = 0; i < Width; i++) p = p << get_server_proof(Digests, Width, i);
        return p;
    }
    
}
