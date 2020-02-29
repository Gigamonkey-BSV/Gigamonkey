// Copyright (c) 2019 Katrina Swales
// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::work {
    
    template <typename X, typename f, typename Y, typename Z>
    tensor<X, 2> outer(f fun, Y y, Z z) {
        tensor<X, 2> x{{y.size(), z.size()}};
        for (int i = 0; i < y.size(); i++) 
            for (int j = 0; j < z.size();j++) x[i][j] = f(y[i], z[i]);
    }
    
    template <typename X, typename f, typename Y>
    tensor<X, 2> for_each(f fun, Y y) {
        tensor<X, 2> x{y.dimension<0>(), y.dimension<1>()};
        for (int i = 0; i < y.dimension<0>(); i++) 
            for (int j = 0; j < y.dimension<1>();j++) x[i][j] = f(y[i][i]);
    }
    
    template <typename f, typename X, typename Y>
    bool test_valid(f fun, X x, Y y) {
        if (x.dimension<0>() != y.dimension<0>() || x.dimension<1>() != y.dimension<1>()) return false;
        for (int i = 0; i < x.dimension<0>(); i++) 
            for (int j = 0; j < x.dimension<1>(); j++) 
                for (int k = 0; k < y.dimension<0>(); k++) 
                    for (int l = 0; l < y.dimension<1>(); l++) {
                        bool result = f(x[i][j], y[k][l]);
                        if ((i == k && j == l && !result) || 
                            ((i != k || j != l) && result)) return false;
                    }

        return true;
    }

    // can result in stack smashing
    TEST(WorkTest, TestWork) {
        
        const target minimum_target{31, 0xffffff};
        
        std::string message1{"Capitalists can spend more energy than socialists."};
        std::string message2{"If you can't transform energy, why should anyone listen to you?"};
        
        const cross<std::string> messages{message1, message2};
        
        const target target_half = SuccessHalf;
        const target target_quarter = SuccessQuarter;
        const target target_eighth = SuccessEighth;
        const target target_sixteenth = SuccessSixteenth;
        const target target_thirty_second = minimum_target;
        
        const cross<target> targets{
            target_half,
            target_quarter,
            target_eighth,
            target_sixteenth,
            target_thirty_second}; 
            
        auto to_puzzle = [](std::string m, target t) -> puzzle {
            return puzzle(1, Bitcoin::hash256(m), t, 
                Merkle::path{}, bytes{}, bytestring(m));
        };
        
        const tensor<puzzle, 2> puzzles = outer<puzzle>(to_puzzle, messages, targets);
                
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
