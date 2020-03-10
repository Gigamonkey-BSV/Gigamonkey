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
        
        const target target_2 = SuccessHalf;
        const target target_4 = SuccessQuarter;
        const target target_8 = SuccessEighth;
        const target target_16 = SuccessSixteenth;
        const target target_32{32, 0x080000};
        const target target_64{32, 0x040000};
        const target target_128{32, 0x020000};
        const target target_256{32, 0x010000};
        
        auto targets = list<target>{} << 
            target_16 << 
            target_32 << 
            target_64 << 
            target_128 << 
            target_256; 
        
        auto puzzles = outer<puzzle>([](std::string m, target t) -> puzzle {
            digest256 message_hash = sha256(m);
            return puzzle(1, message_hash, t, 
                Merkle::path{}, bytes{}, bytes(m));
        }, messages, targets);
        
        byte extra_nonce = 0;
        
        auto proofs = data::for_each([&extra_nonce](puzzle p) -> proof {
            return cpu_solve(p, solution(timestamp(1), 0, bytes{0xab, 0xcd, 0xef, extra_nonce++}));
        }, puzzles); 
        
        EXPECT_TRUE(dot_cross([](puzzle p, solution x) -> bool {
            bool success = proof{p, x}.valid();
            return success;
        }, data::for_each([](proof p) -> puzzle {
            return p.Puzzle;
        }, proofs), data::for_each([](proof p) -> solution {
            return p.Solution;
        }, proofs)));
        
    }

}
