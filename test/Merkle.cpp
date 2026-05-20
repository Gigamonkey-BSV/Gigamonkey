// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/merkle/tree.hpp>
#include <gigamonkey/merkle/dual.hpp>
#include <gigamonkey/merkle/server.hpp>
#include <gigamonkey/merkle/serialize.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Merkle {
    
    TEST (Merkle, Merkle) {
        EXPECT_FALSE (leaf {}.valid ());
        EXPECT_FALSE (proof {}.valid ());
        EXPECT_FALSE (tree {}.valid ());
        EXPECT_FALSE (dual {}.valid ());
        
        list<std::string> transactions {"a", "b", "c", "d", "e", "f", "g", "h"};
        
        list<digest256> leaves = take (lift ([] (const std::string x) -> digest256 {
            return Bitcoin::Hash256 (x);
        }, transactions), 8);
        
        digest256 fail = Bitcoin::Hash256 ("Z");
        
        for (int i = 1; i <= leaves.size (); i++) {
            leaf_digests l = take (leaves, i);
            
            tree Tree {l};
            
            EXPECT_TRUE (Tree.valid ());
            
            // check that the root function will calculate the same value as the tree root. 
            EXPECT_EQ (Tree.root (), root (l));
            
            list<proof> tree_proofs = Tree.proofs ();
            
            EXPECT_TRUE (tree_proofs.valid ());
            
            // construct the dual tree from the tree. 
            dual Dual {Tree};
            
            EXPECT_TRUE (Dual.valid ());
            
            EXPECT_EQ (Dual.proofs (), tree_proofs);
            
            server Server {l};
            
            EXPECT_EQ (Server.root (), Tree.root ());
            
            EXPECT_EQ (tree_proofs, Server.proofs ());
            
            EXPECT_EQ (Tree, tree (Server));
            
            EXPECT_EQ (server (Tree), Server);
            
            dual ReconstructedLeft {};
            
            for (const leaf &j : Dual.leaves ()) {
                proof p = Dual[j.Digest];
                
                EXPECT_TRUE (p.valid ());
                
                proof q = Server[j.Digest];
                
                EXPECT_FALSE (ReconstructedLeft[j.Digest].valid ());
                
                ReconstructedLeft = ReconstructedLeft + p;
                
                EXPECT_TRUE (ReconstructedLeft[j.Digest].valid ());
                
                EXPECT_TRUE (q.valid ());
                EXPECT_EQ (p, q);
                q.Root = fail;
                EXPECT_FALSE (q.valid ());
                
            }
            
            EXPECT_EQ (Dual, ReconstructedLeft);
            
            dual ReconstructedRight {};
            
            for (const leaf& j : reverse (Dual.leaves ())) {
                proof p = Dual[j.Digest];
                
                EXPECT_FALSE (ReconstructedRight[j.Digest].valid ());
                
                ReconstructedRight = ReconstructedRight + p;
                
                EXPECT_TRUE (ReconstructedRight[j.Digest].valid ());
            }
            
            EXPECT_EQ (Dual, ReconstructedRight);
            
            Dual.Root = fail;
            EXPECT_FALSE (Dual.valid ());
        }
    }
    
    // This test comes from 
    // https://tsc.bitcoinassociation.net/standards/merkle-proof-standardised-format/
    // and is not very good but it's better than nothing. 
    TEST (Merkle, Serilization) {
        bytes binary_format = *encoding::hex::read (
            "000cef65a4611570303539143dabd6aa64dbd0f41ed89074406dc0e7cd251cf1efff69f17b44cfe9c2a23285168fe05084e125"
            "4daa5305311ed8cd95b19ea6b0ed7505008e66d81026ddb2dae0bd88082632790fc6921b299ca798088bef5325a607efb9004d"
            "104f378654a25e35dbd6a539505a1e3ddbba7f92420414387bb5b12fc1c10f00472581a20a043cee55edee1c65dd6677e09903"
            "f22992062d8fd4b8d55de7b060006fcc978b3f999a3dbb85a6ae55edc06dd9a30855a030b450206c3646dadbd8c000423ab027"
            "3c2572880cdc0030034c72ec300ec9dd7bbc7d3f948a9d41b3621e39");
        
        std::stringstream JSON_message {R"JSON({
            "index": 12,
            "txOrId": "ffeff11c25cde7c06d407490d81ef4d0db64aad6ab3d14393530701561a465ef",
            "target": "75edb0a69eb195cdd81e310553aa4d25e18450e08f168532a2c2e9cf447bf169",
            "nodes": [
                "b9ef07a62553ef8b0898a79c291b92c60f7932260888bde0dab2dd2610d8668e",
                "0fc1c12fb1b57b38140442927fbadb3d1e5a5039a5d6db355ea25486374f104d",
                "60b0e75dd5b8d48f2d069229f20399e07766dd651ceeed55ee3c040aa2812547",
                "c0d8dbda46366c2050b430a05508a3d96dc0ed55aea685bb3d9a993f8b97cc6f",
                "391e62b3419d8a943f7dbc7bddc90e30ec724c033000dc0c8872253c27b03a42"
            ]
        })JSON"};
        
        JSON JSON_format;
        JSON_message >> JSON_format;

        auto read_binary = proofs_serialization_standard::read_binary (binary_format);
        auto read_JSON = proofs_serialization_standard::read_JSON (JSON_format);
        
        auto write_binary_from_binary = bytes (read_binary);
        auto write_binary_from_JSON = bytes (read_JSON);

        EXPECT_EQ (write_binary_from_binary, binary_format);
        EXPECT_EQ (JSON (read_JSON), JSON_format);
        EXPECT_EQ (JSON (read_binary), JSON_format);
        EXPECT_EQ (write_binary_from_JSON, binary_format);
        
    }
}
