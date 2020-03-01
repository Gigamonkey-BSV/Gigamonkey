// Copyright (c) 2019 Katrina Swales
// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work/proof.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::work {
    
    template <typename X, typename f, typename Y, typename Z>
    list<list<X>> outer(f fun, list<X> y, list<Z> z);
    
    template <typename X, typename f, typename Y>
    list<list<X>> for_each(f fun, list<list<Y>> y);
    
    template <typename f, typename X, typename Y>
    bool test_valid(f fun, X x, Y y); 

    TEST(WorkTest, TestWork) {
        
        const target minimum_target{31, 0xffffff};
        
        std::string message1{"Capitalists can spend more energy than socialists."};
        std::string message2{"If you can't transform energy, why should anyone listen to you?"};
        
        const list<std::string> messages{message1, message2};
        
        const target target_half = SuccessHalf;
        const target target_quarter = SuccessQuarter;
        const target target_eighth = SuccessEighth;
        const target target_sixteenth = SuccessSixteenth;
        const target target_thirty_second = minimum_target;
        
        const list<target> targets{
            target_half,
            target_quarter,
            target_eighth,
            target_sixteenth,
            target_thirty_second}; 
            
        auto to_puzzle = [](std::string m, target t) -> puzzle {
            return puzzle(1, Bitcoin::hash256(m), t, 
                Merkle::path{}, bytes{}, bytestring(m));
        };
        
        const list<list<puzzle> puzzles = outer<puzzle>(to_puzzle, messages, targets);
                
        solution initial;
        
        auto solve_puzzle = [initial](puzzle p) -> solution {
            return puzzle::cpu_solve(p, initial);
        };
        
        const tensor<solution, 2> solutions = for_each<solution>(solve_puzzle, puzzles); 
        
        auto check_solution = [](puzzle p, solution x) -> bool {
            return proof(p, x).valid();
        }
        
        EXPECT_TRUE(test_valid(check_solution, puzzles, solutions));
        
    }

}
