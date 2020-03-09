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
        
        std::cout << "begin work test." << std::endl;
        
        std::string message1{"Capitalists can spend more energy than socialists."};
        std::string message2{"If you can't transform energy, why should anyone listen to you?"};
        
        auto messages = list<std::string>{} << message1 << message2;
        
        const target target_half = SuccessHalf;
        const target target_quarter = SuccessQuarter;
        const target target_eighth = SuccessEighth;
        const target target_sixteenth = SuccessSixteenth;
        const target target_thirty_second{31, 0xffffff};
        
        auto targets = list<target>{} << 
            target_half << 
            target_quarter << 
            target_eighth << 
            target_sixteenth << 
            target_thirty_second; 
        
        auto puzzles = outer<puzzle>([](std::string m, target t) -> puzzle {
            digest256 message_hash = sha256(m);
            std::cout << "Work test: calculated hash as " << message_hash << std::endl;
            return puzzle(1, message_hash, t, 
                Merkle::path{}, bytes{}, bytes(m));
        }, messages, targets);
        
        solution initial(timestamp(1), 0, 4843);
        
        auto proofs = data::for_each([initial](puzzle p) -> proof {
            return cpu_solve(p, initial);
        }, puzzles); 
        
        EXPECT_TRUE(dot_cross([](puzzle p, solution x) -> bool {
            return proof(p, x).valid();
        }, data::for_each([](proof p) -> puzzle {
            return p.Puzzle;
        }, proofs), data::for_each([](proof p) -> solution {
            return p.Solution;
        }, proofs)));
        
    }

}
