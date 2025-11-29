// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work/target.hpp>
#include <gigamonkey/stratum/difficulty.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::work {

    TEST (Difficulty, Difficulty) {

        EXPECT_TRUE (difficulty::minimum ().valid ());
        EXPECT_TRUE (difficulty (1).valid ());
        EXPECT_TRUE (difficulty (2).valid ());
        
        EXPECT_EQ (uint256 (difficulty (1)), difficulty::unit ());

        EXPECT_LT (SuccessHalf.difficulty (), SuccessQuarter.difficulty ());
        EXPECT_GT (SuccessQuarter.difficulty (), SuccessHalf.difficulty ());
        
        EXPECT_LT (SuccessHalf.difficulty (), SuccessEighth.difficulty ());
        EXPECT_GT (SuccessEighth.difficulty (), SuccessHalf.difficulty ());
        
        EXPECT_LT (SuccessHalf.difficulty (), SuccessSixteenth.difficulty ());
        EXPECT_GT (SuccessSixteenth.difficulty (), SuccessHalf.difficulty ());
        
        EXPECT_GT (SuccessHalf.difficulty (), difficulty::minimum ());
        EXPECT_LT (difficulty::minimum (), SuccessHalf.difficulty ());
        
        EXPECT_LT (SuccessQuarter.difficulty (), SuccessEighth.difficulty ());
        EXPECT_GT (SuccessEighth.difficulty (), SuccessQuarter.difficulty ());
        
        EXPECT_LT (SuccessQuarter.difficulty (), SuccessSixteenth.difficulty ());
        EXPECT_GT (SuccessSixteenth.difficulty (), SuccessQuarter.difficulty ());
        
        EXPECT_GT (SuccessQuarter.difficulty (), difficulty::minimum ());
        EXPECT_LT (difficulty::minimum (), SuccessQuarter.difficulty ());
        
        EXPECT_LT (SuccessEighth.difficulty (), SuccessSixteenth.difficulty ());
        EXPECT_GT (SuccessSixteenth.difficulty (), SuccessEighth.difficulty ());
        
        EXPECT_GT (SuccessEighth.difficulty (), difficulty::minimum ());
        EXPECT_LT (difficulty::minimum (), SuccessEighth.difficulty ());
        
        EXPECT_GT (SuccessSixteenth.difficulty (), difficulty::minimum ());
        EXPECT_LT (difficulty::minimum (), SuccessSixteenth.difficulty ());

        EXPECT_GT (difficulty (1), difficulty::minimum ());
        
        EXPECT_LT (difficulty (1), difficulty (2));
        EXPECT_GT (difficulty (2), difficulty (1));
        
        EXPECT_LT (1, difficulty (3) / difficulty (2));
        EXPECT_GT (difficulty (3) / difficulty (2), 1);
        
        EXPECT_LT (difficulty (3) / difficulty (2), 2);
        EXPECT_GT (2, difficulty (3) / difficulty (2));
        
        work::difficulty ten_thousanth {float64 (.0001)};
        work::difficulty one_thousand {float64 (1000.)};
        work::difficulty one {float64 (1.)};
        work::difficulty some_big_number {float64 (120000.)};

        EXPECT_EQ (compact {compact {ten_thousanth}.difficulty ()}, compact {ten_thousanth});
        EXPECT_EQ (compact {compact {one_thousand}.difficulty ()}, compact {one_thousand});
        EXPECT_EQ (compact {compact {one}.difficulty ()}, compact {one});
        EXPECT_EQ (compact {compact {some_big_number}.difficulty ()}, compact {some_big_number});

        EXPECT_EQ (compact {uint256 (one)}.expand (), compact {one}.expand ());
        EXPECT_EQ (compact {uint256 (ten_thousanth)}.expand (), compact {ten_thousanth}.expand ());
        EXPECT_EQ (compact {uint256 (one_thousand)}.expand (), compact {one_thousand}.expand ());
        EXPECT_EQ (compact {uint256 (some_big_number)}.expand (), compact {some_big_number}.expand ());

        EXPECT_EQ (compact {uint256 (0)}.expand (), compact{0}.expand ());
        
    }

}



