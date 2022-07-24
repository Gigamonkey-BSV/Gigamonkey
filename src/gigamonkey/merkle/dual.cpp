// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/merkle/dual.hpp>

#include <nlohmann/json.hpp>

// This file contains a method of serializing and deserializing dual merkle trees. 
namespace Gigamonkey::Merkle {
    
    namespace {
        using index = data::math::nonnegative<int32>;
        
        struct tree_node {
            
            uint32 Digest;
            index Left;
            index Right;
            
            tree_node() : Digest{}, Left{}, Right{} {}
            tree_node(const uint32& d, index l, index r) : Digest{d}, Left{l}, Right{r} {}
            explicit tree_node(const uint32& d) : Digest{d}, Left{}, Right{} {}
            
            bool operator==(const tree_node& t) const {
                return Digest == t.Digest && Left == t.Left && Right == t.Right;
            }
            
            bool operator!=(const tree_node& t) const {
                return !(*this == t);
            }
            
        };
    
        struct inverted_from {
            
            // map of digests to digest index.
            data::map<digest, index> Digests;
            
            // map of node index to node. 
            std::map<uint32, tree_node> Nodes;
            
            // map of digests to branches. 
            data::map<uint32, index> Branches;
            
            index Index;
            
            explicit operator json() const;
            
            bool valid() const {
                return Nodes.size() != 0;
            }
            
            explicit inverted_from(const dual& d) : Digests{}, Nodes{}, Branches{}, Index{0} {
                insert_or_find(d.Root);
                
                uint32 n = Nodes.size();
                Nodes[n] = tree_node{0};
                
                for (const data::entry<digest, path>& x : d.Paths) {
                    uint32 i = insert_or_find(x.Key);
                    
                    if (i == 0) return;
                    uint32 n = Nodes.size();
                    Nodes[n] = tree_node{i};
                    
                    insert_path(x.Value, n);
                    
                }
                
            }
            
            void insert_path(const path& d, uint32 p) {
                
                uint32 i;
                uint32 n;
                
                if (d.Digests.size() == 0) {
                    i = 0;
                    n = 0;
                } else {
                    i = insert_or_find(d.Digests.first());
                    if (!Branches.contains(i)) {
                        uint32 n = Nodes.size();
                        Nodes[n] = tree_node{i};
                        Branches = Branches.insert(i, index{static_cast<int>(n)});
                        insert_path(d.Digests.rest(), d.Index, n);
                    }
                }
                
                if (d.Index & 1) Nodes[n].Left = index{static_cast<int>(p)};
                else Nodes[n].Right = index{static_cast<int>(p)};
                
            }
            
            void insert_path(const digests& d, uint32 x, uint32 p) {
                
                uint32 i;
                uint32 n;
                
                if (d.size() == 0) {
                    i = 0;
                    n = 0;
                } else {
                    i = insert_or_find(d.first());
                    if (!Branches.contains(i)) {
                        uint32 n = Nodes.size();
                        Nodes[n] = tree_node{i};
                        Branches = Branches.insert(i, index{static_cast<int>(n)});
                        insert_path(d.rest(), x >> 1, n);
                    } else n = Branches[i];
                }
                
                if (x & 1) Nodes[n].Right = index{static_cast<int>(p)};
                else Nodes[n].Left = index{static_cast<int>(p)};
                
            }
            
            uint32 insert_or_find(const digest& x) {
                auto find = Digests.contains(x);
                if (find) return *find;
                Digests = Digests.insert(x, Index);
                return Index++;
            }
            
        };
        
        struct inverted_to {
            std::vector<digest> Digests;
            std::vector<tree_node> Nodes;
            
            explicit inverted_to(const json& j);
            
            explicit operator dual() const;
            
            // add all paths at index i to map p.
            map paths(digests d, index i, uint32 b, map p) const;
            
            bool valid() const {
                if (Digests.size() == 0 || Nodes.size() == 0) return false;
                return true;
            }
        };
        
        json write(const data::map<digest, index> d) {
            json x = json::array();
            for (const data::entry<digest, index>& e : d) x[e.Value] = data::encoding::hex::write(e.Key);
            return x;
        }
        
        json write(const std::map<uint32, tree_node> v) {
            json x = json::array();
            for (const std::pair<uint32, tree_node> n : v) 
                x.push_back(json::array({n.second.Digest, int32(n.second.Left), int32(n.second.Right)}));
            return x;
        }
        
        inverted_from::operator json() const {
            return json::array({write(Digests), write(Nodes)});
        } 
        
        bool read_digest(const json& j, digest& d) {
            if (!j.is_string()) return false;
            string hex_digest = j;
            ptr<bytes> v = data::encoding::hex::read(hex_digest);
            if (v == nullptr || hex_digest.size() != 64) return false;
            std::copy(v->begin(), v->end(), d.begin());
            return true;
        }
        
        std::vector<digest> read_digests(const json& j) {
            if (!j.is_array() || j.size() == 0) return {};
            
            std::vector<digest> digests{};
            digests.resize(j.size());
            
            for (int i = 0; i < j.size(); i++) if (!read_digest(j[i], digests[i])) return {};
            
            return digests;
        }
        
        bool read_tree_node(const json& j, tree_node& n) {
            
            if (!j.is_array() || 
                j.size() != 3 || 
                !j[0].is_number_unsigned() || 
                !j[1].is_number_integer() || 
                !j[2].is_number_integer()) return false;
            
            n.Digest = uint32(j[0]);
            
            n.Left = index(j[1]);
            n.Right = index(j[2]);
            
            return true;
        } 
        
        std::vector<tree_node> read_nodes(const json& j) {
            if (!j.is_array() || j.size() == 0) return {};
            
            std::vector<tree_node> nodes{};
            nodes.resize(j.size());
            
            for (int i = 0; i < j.size(); i++) if (!read_tree_node(j[i], nodes[i])) return {};
            
            return nodes;
        }
        
        inverted_to::inverted_to(const json& j) {
            
            if (!j.is_array() || j.size() != 2) return;
            
            Digests = read_digests(j[0]);
            if (Digests.size() == 0) return;
            
            Nodes = read_nodes(j[1]);
            if(Nodes.size() == 0) return;
            
        }
    
        map inverted_to::paths(digests d, index i, uint32 b, map p) const {
            if (i < 0) return p;
            const tree_node& t = Nodes[i];
            
            if (t.Left == -1 && t.Right == -1) return p.insert(Digests[t.Digest], path{b >> 1, d});
            
            d = d << Digests[t.Digest];
            
            // not sure if this part is right... 
            return paths(d, t.Right, (b << 1) + 1, paths(d, t.Left, b << 1, p));
            
        }
        
        inverted_to::operator dual() const {
            if (!valid()) return {};
            
            dual d{};
            d.Root = Digests[0];
            
            if (Nodes[0].Left == -1 && Nodes[0].Right == -1) {
                d.Paths = d.Paths.insert(d.Root, path{0, {}});
                return d;
            }
            
            d.Paths = paths({}, Nodes[0].Right, 1, paths({}, Nodes[0].Left, 0, d.Paths));
            
            return d;
            
        }
        
    }
    
    json dual::serialize() const {
        return json(inverted_from{*this});
    }
    
    dual dual::deserialize(const json& j) {
        return dual(inverted_to{j});
    }
    
}
