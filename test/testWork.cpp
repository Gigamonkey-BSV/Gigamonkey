// Copyright (c) 2019 Katrina Swales
// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work/proof.hpp>
#include "dot_cross.hpp"
#include "gtest/gtest.h"
#include <iostream>

namespace Gigamonkey::work {
    
    template <typename X, typename f, typename Y, typename Z>
    list<X> outer(f fun, list<Y> y, list<Z> z) {
        list<X> x{};
        while (!y.empty()) {
            list<Z> zz = z;
            while (!zz.empty()) {
                x = x << fun(y.first(), zz.first());
                zz = zz.rest();
            }
            y = y.rest();
        }
        return x;
    }
    
    TEST(WorkTest, TestWork) {
        
        std::string message1{"Capitalists can spend more energy than socialists."};
        std::string message2{"If you can't transform energy, why should anyone listen to you?"};
        
        auto messages = list<std::string>{} << message1 << message2;
        
        const compact target_32{32, 0x080000};
        const compact target_64{32, 0x040000};
        const compact target_128{32, 0x020000};
        const compact target_256{32, 0x010000};
        const compact target_512{32, 0x008000};
        
        auto targets = list<compact>{} <<   
            target_64 << 
            target_128 << 
            target_256 << 
            target_512; 
        
        // puzzle format from before ASICBoost was developed. 
        auto puzzles = outer<puzzle>([](std::string m, compact t) -> puzzle {
            digest256 message_hash = sha256(m);
            return puzzle(1, message_hash, t, 
                Merkle::path{}, bytes{}, bytes(m));
        }, messages, targets);
        
        // use standard mask for general purpose version bits that are used with ASICBoost. 
        auto mask = ASICBoost::Mask;
        
        // puzzle format from after ASICBoost. 
        auto puzzles_with_mask = outer<puzzle>([mask](std::string m, compact t) -> puzzle {
            digest256 message_hash = sha256(m);
            return puzzle(1, message_hash, t, 
                Merkle::path{}, bytes{}, bytes(m), mask);
        }, messages, targets);
        
        uint64_big extra_nonce = 90983;
        
        auto proofs = data::for_each([&extra_nonce](puzzle p) -> proof {
            return cpu_solve(p, solution(Bitcoin::timestamp(1), 0, extra_nonce++, 353));
        }, puzzles); 
        
        // we add a non-trivial version mask. 
        auto proofs_with_mask = data::for_each([&extra_nonce](puzzle p) -> proof {
            // add a non-trivial version bits field. 
            return cpu_solve(p, solution(share{Bitcoin::timestamp(1), 0, extra_nonce++, 0xffffff}, 353));
        }, puzzles_with_mask); 
        
        EXPECT_TRUE(dot_cross([](puzzle p, solution x) -> bool {
            return proof{p, x}.valid();
        }, data::for_each([](proof p) -> puzzle {
            return p.Puzzle;
        }, proofs), data::for_each([](proof p) -> solution {
            return p.Solution;
        }, proofs)));
        
        EXPECT_TRUE(dot_cross([](puzzle p, solution x) -> bool {
            return proof{p, x}.valid();
        }, data::for_each([](proof p) -> puzzle {
            return p.Puzzle;
        }, proofs_with_mask), data::for_each([](proof p) -> solution {
            return p.Solution;
        }, proofs_with_mask)));
        
        // apply mask and the result should still be valid;
        // we have just converted back to the old format. 
        EXPECT_TRUE(dot_cross([](puzzle p, solution x) -> bool {
            return proof{p, x}.valid();
        }, data::for_each([](proof p) -> puzzle {
            auto p_fixed = p.Puzzle;
            p_fixed.Candidate.Category = (p_fixed.Candidate.Category & ~p_fixed.VersionMask) | (p.Solution.Share.version(p_fixed.VersionMask));
            return p.Puzzle;
        }, proofs_with_mask), data::for_each([](proof p) -> solution {
            auto x_fixed = p.Solution;
            x_fixed.Share.VersionBits = {};
            return p.Solution;
        }, proofs_with_mask)));
        
    }

}
