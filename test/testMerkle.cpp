// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/merkle.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Merkle {
    
    list<proof> get_server_proofs(const server& x) {
        list<proof> p;
        for(uint32 i = 0; i < x.Width; i++) p = p << x[i];
        return p;
    }
    
    TEST(MerkleTest, TestMerkle) {
        EXPECT_FALSE(leaf{}.valid());
        EXPECT_FALSE(proof{}.valid());
        EXPECT_FALSE(tree{}.valid());
        //EXPECT_FALSE(dual{}.valid());
        
        list<string> transactions("a", "b", "c", "d", "e", "f", "g", "h");
        
        list<digest256> leaves = for_each([](const string x) -> digest256 {
            return Bitcoin::hash256(x);
        }, transactions);
        
        digest256 fail = Bitcoin::hash256("Z");
        
        for (int i = 1; i <= leaves.size(); i++) {
            leaf_digests l = take(leaves, i);
            
            tree Tree{l};
            
            EXPECT_TRUE(Tree.valid());
            
            // check that the root function will calculate the same value as the tree root. 
            EXPECT_EQ(Tree.root(), root(l));
            
            list<proof> tree_proofs = Tree.proofs();
            
            EXPECT_TRUE(tree_proofs.valid());
            /*
            // construct the dual tree from the tree. 
            dual Dual{Tree};
            
            list<proof> dual_proofs = Dual.proofs();
            
            EXPECT_EQ(tree_proofs, dual_proofs);
            
            EXPECT_TRUE(Dual.valid());*/
            
            server Server{l};
            
            list<proof> server_proofs = get_server_proofs(Server);
            
            EXPECT_EQ(tree_proofs, server_proofs);
            
            EXPECT_EQ(Tree, tree(Server));
            
            EXPECT_EQ(server(Tree), Server);
            
            //dual ReconstructedLeft{};
            
            for (uint32 j = 0; j < i; j++) {
                //proof p = Dual[j];
                
                //EXPECT_TRUE(p.valid());
                
                proof q = Server[j];
                /*
                EXPECT_FALSE(ReconstructedLeft[j].valid());
                
                ReconstructedLeft = ReconstructedLeft + p;
                
                EXPECT_TRUE(ReconstructedLeft[j].valid());*/
                
                EXPECT_TRUE(q.valid());
                //EXPECT_EQ(p, q);
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
            
            EXPECT_EQ(Dual, ReconstructedRight);
            
            Dual.Root = fail;
            EXPECT_FALSE(Dual.valid());*/
        }
    }
}
