// Copyright (c) 2019 Katrina Swales
// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work/proof.hpp>
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
    
    template <typename X, typename f, typename Y>
    list<X> for_each(f fun, list<Y> y) {
        list<X> x{};
        while (!y.empty()) {
            x = x << fun(y.first());
            y = y.rest();
        }
        return x;
    }
    
    template <typename f, typename X, typename Y>
    bool dot_cross(f foo, list<X> x, list<Y> y) {
        if (x.size() != y.size()) return false;
        if (x.size() == 0) return true;
        list<X> input = x;
        list<Y> expected = y;
        while (!input.empty()) {
            list<Y> expected_rest = expected;
            X in = input.first();
            Y ex = expected_rest.first();
            
            if(!foo(in, ex)) return false;
            
            expected_rest = expected_rest.rest();
            
            while(!expected.empty()) {
                in = input.first();
                ex = expected_rest.first();
                
                if(foo(in, ex)) return false;
                expected_rest = expected_rest.rest();
            }
            
            expected = expected.rest();
            input = input.rest();
        }
        
        return true;
    }

    TEST(WorkTest, TestWork) {
        
        std::cout << "begin work test." << std::endl;
        /*
        const target minimum_target{31, 0xffffff};
        
        std::string message1{"Capitalists can spend more energy than socialists."};
        std::string message2{"If you can't transform energy, why should anyone listen to you?"};
        
        auto messages = list<std::string>{} << message1 << message2;
        
        const target target_half = SuccessHalf;
        const target target_quarter = SuccessQuarter;
        const target target_eighth = SuccessEighth;
        const target target_sixteenth = SuccessSixteenth;
        const target target_thirty_second = minimum_target;
        
        auto targets = list<target>{} << 
            target_half << 
            target_quarter << 
            target_eighth << 
            target_sixteenth << 
            target_thirty_second; 
            
        auto to_puzzle = [](std::string m, target t) -> puzzle {
            return puzzle(1, Bitcoin::hash256(m), t, 
                Merkle::path{}, bytes{}, bytes(m));
        };
        
        auto puzzles = outer<puzzle>(to_puzzle, messages, targets);
                
        solution initial;
        
        auto solve_puzzle = [initial](puzzle p) -> solution {
            return puzzle::cpu_solve(p, initial);
        };
        
        auto solutions = for_each<solution>(solve_puzzle, puzzles); 
        
        auto expect_solution_valid = [](puzzle p, solution x) -> bool {
            return proof(p, x).valid();
        };
        
        EXPECT_TRUE(dot_cross(expect_solution_valid, puzzles, solutions));*/
        
    }

}
