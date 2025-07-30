// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/merkle/tree.hpp>
#include <gigamonkey/merkle/dual.hpp>
#include <gigamonkey/merkle/server.hpp>
#include <algorithm>

namespace Gigamonkey::Merkle {

    template <typename X> using dt = data::tree<X>;
    
    namespace {
    
        leaf_digests round (leaf_digests l) {
            leaf_digests r {};
            while (l.size () >= 2) {
                r <<= hash_concatinated (first (l), first (rest (l)));
                l = rest (rest (l));
            }
            if (l.size () == 1) r <<= hash_concatinated (first (l), first (l));
            return r;
        }
    
        void append_proofs (list<proof> &p, uint32 index, digests l, dt<digest256> t, const digest256 &r, uint32 height) {
            if (height == 1) {
                p = p << proof {branch {leaf {root (t), index}, l}, r};
                return;
            }
            
            if (!empty (right (t))) {
                append_proofs (p, (index << 1), l >> root (right (t)), left (t), r, height - 1);
                append_proofs (p, (index << 1) + 1, l >> root (left (t)), right (t), r, height - 1);
            } else append_proofs (p, index << 1, l >> root (left (t)), left (t), r, height - 1);
        }
    
        template <typename it>
        void write_at_height (it &i, const dt<digest256> &t, uint32 height) {
            if (height == 0) {
                *i = root (t);
                ++i;
                return;
            }
            
            write_at_height (i, t.left(), height - 1);
            if (!empty (right (t))) write_at_height (i, t.right (), height - 1);
        }
    
        uint32 height (dt<digest256> t) {
            if (empty (t)) return 0;
            uint32 right_height = height (right (t));
            uint32 left_height = height (left (t));
            if (right_height != left_height) return 0;
            return right_height + 1;
        }
        
        bool check_tree (const dt<digest256> &t, uint32 expected_width, uint32 expected_height) {
            if (expected_height == 0) return false;
            if (expected_height == 1)
                return expected_width == 1 && !empty (t) && empty (left (t)) && empty (t.right ()) && root (t).valid ();
            
            if (empty (left (t))) return false;
            
            uint32 expected_left_width;
            digest256 expected_value;
            
            if (empty (right (t))) {
                expected_left_width = expected_width;
                expected_value = hash_concatinated (root (left (t)), root (left (t)));
            } else {
                expected_left_width = 1 << (expected_height - 2);
                expected_value = hash_concatinated (root (left (t)), root (right (t)));
                if (!check_tree (right (t), expected_width - expected_left_width, expected_height - 1)) return false;
            }
            
            if (!check_tree (left (t), expected_left_width, expected_height - 1)) return false;
            
            return root (t) == expected_value;
        }
    
    }
    
    tree tree::make (leaf_digests h) {
        
        if (h.size () == 0) tree {};
        if (h.size () == 1) return tree {first (h)};
        
        uint32 width = h.size ();
        uint32 height = 2;
        
        leaf_digests next_round = round (h);
        
        using trees = list<dt<digest256>>;
        trees Trees {};
        
        leaf_digests last = h;
        leaf_digests next = next_round;

        while (!next.empty ()) {
            if (data::size (last) >= 2) {
                Trees = Trees << dt<digest256> {first (next),
                    dt<digest256> {first (last)},
                    dt<digest256> {first (rest (last))}};
                last = rest (rest (last));
            } else {
                Trees = Trees << dt<digest256> {first (next),
                    dt<digest256> {first (last)},
                    dt<digest256> {}};
                last = rest (last);
            }
            next = rest (next);
        }
        
        while (next_round.size () > 1) {
            trees last_trees = Trees;
            Trees = trees {};
            next_round = round (next_round);
            next = next_round;
            height++;
            
            while (!next.empty ()) {
                if (last_trees.size () >= 2) {
                    Trees = Trees << dt<digest256> {first (next),
                        dt<digest256> {first (last_trees)},
                        dt<digest256> {first (rest (last_trees))}};
                    last_trees = rest (rest (last_trees));
                } else {
                    Trees = Trees << dt<digest256> {first (next),
                        dt<digest256> {first (last_trees)},
                        dt<digest256> {}};
                    last_trees = rest (last_trees);
                }

                next = rest (next);
            }
        }
        
        // trees should have size 1 by this point. 
        return tree {first (Trees), width, height};
    }
    
    digest root (list<digest> l) {
        if (l.size () == 0) return {};
        while (l.size () > 1) l = round (l);
        return first (l);
    }
    
    digest root (leaf l, digests d) {
        while (d.size () > 0) {
            l = l.next (bool (first (d)) ? *first (d) : l.Digest);
            d = rest (d);
        }
        return l.Digest;
    }
    
    const list<proof> tree::proofs () const {
        
        if (Height == 0 || Width == 0) return {};
        if (Height == 1) return list<proof> {}.append (proof {dt<digest256>::root ()});
        
        list<proof> p;
        
        append_proofs (p, 0,
            {dt<digest256>::right ().root ()}, dt<digest256>::left (), dt<digest256>::root (), Height - 1);

        append_proofs (p, 1,
            {dt<digest256>::left ().root ()}, dt<digest256>::right (), dt<digest256>::root (), Height - 1);
        
        return p;
    }
    
    bool tree::valid () const {
        if (Height == 0 || Width == 0) return false;
        return check_tree (*this, Width, Height);
    }
    
    proof tree::operator [] (uint32 i) const {
        if (i >= Width) return {};
        
        uint32 max_index = Width - 1;
        dt<digest256> t = *this;
        uint32 next_height = Height - 1;
        stack<maybe<digest256>> digests;
        
        while (next_height > 0) {
            digests = digests >> data::root (t);
            
            if ((i >> next_height) & 0 || i == max_index) {
                t = data::right (t);
            } else {
                t = data::left (t);
            }
            
            next_height--;
        }
        
        return proof {branch {leaf {t.root (), i}, digests}, dt<digest256>::root ()};
    }
    
    namespace {
        
        class dual_by_index {
            std::map<uint32, digests> Branches;
            digest Root;
            
            bool add_nearest (uint32 index, digests d, uint32 nearest) {
                uint32 height = d.size () - 1;
                
                while (index >> height == nearest >> height && height > 0) height--;
                height += 1;
                
                digests z {};
                digests x = Branches[nearest];
                digests b = d;
            
                for (int i = 0; i <= height; i++) {
                    x = rest (x);
                    z >>= first (b);
                    b = rest (b);
                }
            
                while (!empty (z)) {
                    x >>= first (z);
                    z = rest (z);
                }
                
                Branches.insert_or_assign (index, x);
                return true;
            }
            
            bool add (const branch &p) {
                
                uint32 index = p.Leaf.Index;
                digests d = p.Digests >> p.Leaf.Digest;
                
                auto it = Branches.find (index);
                if (it != Branches.end ()) {
                    if (it->second != d) return false;
                    return true;
                }
                
                uint32 height = d.size ();
                
                cross<uint32> leaves;
                leaves.resize (Branches.size ());
                {
                    int i = 0;
                    for (const auto& b : Branches) {
                        leaves[i] = b.first;
                        i++;
                    }
                }
                
                uint32 min = 0;
                uint32 max = leaves.size () - 1;
                
                if (index < leaves[min]) {
                    if (leaves[min] >> (height - 2) == index >> (height - 2))
                        return add_nearest (index, d, leaves[min]);

                    Branches.insert_or_assign (index, d);
                    return true;
                }
                
                if (index > leaves[max]) {
                    if (leaves[max] >> (height - 2) == index >> (height - 2))
                        return add_nearest (index, d, leaves[max]);

                    Branches.insert_or_assign (index, d);
                    return true;
                }
                
                while (max - min > 1) {
                    uint32 mid = (max - min) / 2 + min;
                    if (index > leaves[mid]) min = mid;
                    else max = mid;
                }
                
                if (leaves[min] >> (height - 2) == index >> (height - 2))
                    return add_nearest (index, d, leaves[min]);

                return add_nearest (index, d, leaves[max]);
            
            }
            
        public:
            dual_by_index (const dual &d) {
                Root = d.Root;
                for (const entry &e : d.Paths)
                    Branches.insert_or_assign (e.Value.Index, e.Value.Digests >> e.Key);
            }
            
            operator dual () const {
                map m;
                for (const auto &[k, v] : Branches) m = m.insert (*first (v), path {k, rest (v)});
                return dual {m, Root};
            }
            
            bool add_all (ordst<proof> p) {
                for (const proof &x : p) if (!add (x.Branch)) return false;
                return true;
            }
            
        };
        
    }
    
    dual dual::operator + (const dual &d) const {
        if (!valid ()) return d;
        if (Root != d.Root) return {};
        dual_by_index x (*this);
        if (!x.add_all (d.proofs ())) return {};
        return dual (x);
    }
    
    dual::dual (const tree &t) : dual {} {
        if (t.Width == 0) return;
        Root = t.root ();
        list<proof> p = t.proofs ();
        for (const proof& x : p) Paths = Paths.insert (entry (x.Branch));
    }
    
    const ordst<proof> dual::proofs () const {
        ordst<proof> p {};
        for (const auto &e : Paths) p >>= proof {branch (e), Root};
        return p;
    }
    
    server::server (const tree &t) : server {} {
        if (t.Width == 0 || t.Height == 0) return;
        
        Width = t.Width;
        Height = t.Height;
        
        uint32 width = Width;
        uint32 total = width;
        
        while (width > 1) {
            width = (width + 1) / 2;
            total += width;
        } 
        
        Digests.resize (total);
        
        uint32 height = Height;
        auto b = Digests.begin ();
        do {
            height--;
            write_at_height (b, t, height);
        } while (height > 0);
    }
    
    server::operator tree () const {
        if (Width == 0 || Height == 0) return tree {};
            
        list<dt<digest256>> trees {};
        
        auto b = Digests.begin ();
        for (int i = 0; i < Width; i++) {
            trees = trees << *b;
            b++;
        }
        
        while (trees.size () > 1) {
            list<dt<digest256>> new_trees {};
            
            while (trees.size () > 1) {
                new_trees = new_trees << dt<digest256> {*b, data::first (trees), data::first (data::rest (trees))};
                trees = data::rest (data::rest (trees));
                b++;
            }
            
            if (trees.size () == 1) {
                new_trees = new_trees << dt<digest256> {*b, data::first (trees), dt<digest256> {}};
                trees = data::rest (trees);
                b++;
            }
            
            trees = new_trees;
        }
        
        return tree {first (trees), Width, Height};
    }
    
    server::server (leaf_digests l) : server{} {
        if (size (l) == 0) return;
        
        Width = size (l);
        Height = 1;
        
        uint32 width = Width;
        uint32 total = width;
        while (width > 1) {
            width = (width + 1) / 2;
            total += width;
            Height++;
        } 
        Digests.resize (total);
        
        leaf_digests v = l;
        uint32 i = 0;
        
        while (true) {
            leaf_digests x = v;
            while (!empty (x)) {
                Digests[i] = first (x);
                x = rest (x);
                i++;
            }
            if (i == total) break;
            v = round (v);
        } 
        
        auto a = Digests[total - 1];
        auto b = Digests[-1];
        
        for (uint32 x = 0; x < Width; x++) Indices = Indices.insert (Digests[x], x + 1);
        
    }
    
    namespace {
        proof get_server_proof (const cross<digest> &x, uint32 width, uint32 index) {
            digests p;
            uint32 i = index;
            uint32 cumulative = 0;
            
            while (width > 1) {
                p >>= x[cumulative + i + (i & 1 ? - 1 : i == width - 1 ? 0 : 1)];
                cumulative += width;
                width = (width + 1) / 2;
                i >>= 1;
            }
            
            return proof {branch{leaf{x[index], index}, reverse (p)}, x[-1]};
        }
    }
    
    proof server::operator [] (const digest &d) const {
        uint32 index = Indices[d];
        if (index == 0) return {};
        
        return get_server_proof (Digests, Width, index - 1);
    }
        
    list<proof> server::proofs () const {
        list<proof> p;
        for (uint32 i = 0; i < Width; i++) p <<= get_server_proof (Digests, Width, i);
        return p;
    }
    
}
