// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/merkle.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Merkle {
    
    TEST(MerkleTest, TestMerkle) {
        EXPECT_FALSE(leaf{}.valid());
        EXPECT_FALSE(proof{}.valid());
        EXPECT_FALSE(tree{}.valid());
        EXPECT_FALSE(dual{}.valid());
        
        list<string> transactions("a", "b", "c", "d", "e", "f", "g", "h");
        
        list<digest256> leaves = take(for_each([](const string x) -> digest256 {
            return Bitcoin::hash256(x);
        }, transactions), 8);
        
        digest256 fail = Bitcoin::hash256("Z");
        
        for (int i = 1; i <= leaves.size(); i++) {
            
            leaf_digests l = take(leaves, i);
            
            tree Tree{l};
            
            EXPECT_TRUE(Tree.valid());
            
            // check that the root function will calculate the same value as the tree root. 
            EXPECT_EQ(Tree.root(), root(l));
            
            list<proof> tree_proofs = Tree.proofs();
            
            EXPECT_TRUE(tree_proofs.valid());
            
            // construct the dual tree from the tree. 
            dual Dual{Tree};
            
            EXPECT_EQ(Dual.proofs(), tree_proofs);
            
            EXPECT_TRUE(Dual.valid());
            
            server Server{l};
            
            EXPECT_EQ(Server.root(), Tree.root());
            
            EXPECT_EQ(tree_proofs, Server.proofs());
            
            EXPECT_EQ(Tree, tree(Server));
            
            EXPECT_EQ(server(Tree), Server);
            
            //dual ReconstructedLeft{};
            
            for (const leaf& j : Dual.leaves()) {
                proof p = Dual[j.Digest];
                
                EXPECT_TRUE(p.valid());
                
                proof q = Server[j.Digest];
                /*
                EXPECT_FALSE(ReconstructedLeft[j.Digest].valid());
                
                ReconstructedLeft = ReconstructedLeft + p;
                
                EXPECT_TRUE(ReconstructedLeft[j.Digest].valid());*/
                
                EXPECT_TRUE(q.valid());
                EXPECT_EQ(p, q);
                q.Root = fail;
                EXPECT_FALSE(q.valid());
            }
            /*
            EXPECT_EQ(Dual, ReconstructedLeft);
            
            dual ReconstructedRight{};
            
            uint32 j = i;
            while (j > 0) {
                j--;
                
                proof p = Dual[j];
                
                EXPECT_FALSE(ReconstructedRight[j].valid());
                
                ReconstructedRight = ReconstructedRight + p;
                
                EXPECT_TRUE(ReconstructedRight[j].valid());
            }
            
            EXPECT_EQ(Dual, ReconstructedRight);*/
            
            Dual.Root = fail;
            EXPECT_FALSE(Dual.valid());
        }
    }
}
