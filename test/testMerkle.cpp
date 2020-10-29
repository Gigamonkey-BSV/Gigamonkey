// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/merkle.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Bitcoin {
    
    TEST(MerkleTest, TestMerkle) {
        
        list<string> transactions("a", "b", "c", "d", "e", "f", "g", "h");
        
        list<digest256> leaves = for_each([](const string x) -> digest256 {
            return hash256(x);
        }, transactions);
        
        digest256 fail = hash256("Z");
        
        for (int i = 1; i <= leaves.size(); i++) {
            list<digest256> l = take(leaves, i);
            
            Merkle::tree t{l};
            EXPECT_EQ(t.root(), Merkle::root(l));
            
            for (uint32 j = 0; j < i; j++) {
                Merkle::branch p = t.branch(j);
        
                EXPECT_TRUE(p.valid());
                p.Root = fail;
                EXPECT_FALSE(p.valid());
            }
        }
    }
}
