// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/merkle.hpp>

namespace gigamonkey::merkle {
    
    branch::branch(branch* l, branch* r) : Left{l}, Right{r}, Node{l->Node.Digest, r->Node.Digest} {
        Left->Node.Direction = left;
        Right->Node.Direction = right;
        Left->Node.Parent = this;
        Right->Node.Parent = this;
    }
    
    list<step> tree::path(const digest& d) {
        list<step> steps{};
        digest Digest = d;
        branch* Branch = Leaves[Digest];
        while(Branch != nullptr) {
            steps = steps << step{Digest == Branch->Node.Left ? left : right, Branch->Node};
            Branch = Branch->Node.Parent;
        }
        return steps;
    }
    
    tree::tree(list<digest> e) : Tree{nullptr}, Leaves{}, Elements{e} {
        if (Elements.size() == 0) return;
        
        list<branch*> next{};
        
        list<digest> elem = Elements;
        
        while(elem.size() > 0) {
            if (elem.size() == 1) { 
                next = next << new branch{node{elem.first()}};
                Leaves.insert(elem.first(), next.first());
                elem = elem.rest();
            } else {
                next = next << new branch{node{elem.first(), elem.rest().first()}};
                Leaves.insert(elem.first(), next.first());
                Leaves.insert(elem.rest().first(), next.first());
                elem = elem.rest().rest();
            }
        }
        
        while(next.size() > 1) {
            list<branch*> last = next;
            next = list<branch*>{};
            
            while(last.size() > 0) {
                if (last.size() == 1) {
                    next = next << new branch{last.first()};
                    last = last.rest();
                } else {
                    next = next << new branch{last.first(), last.rest().first()};
                    last = last.rest().rest();
                }
            }
        }
        
        Tree = next.first();
        
    }
}
