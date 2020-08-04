// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work/target.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::work {

    TEST(DifficultyTest, TestDifficulty) {
        EXPECT_TRUE(difficulty::minimum().valid());
        EXPECT_TRUE(difficulty(1).valid());
        EXPECT_TRUE(difficulty(2).valid());
        //EXPECT_TRUE((difficulty(3) / difficulty(2)).valid());
        
        EXPECT_LT(SuccessHalf.difficulty(), SuccessQuarter.difficulty());
        EXPECT_GT(SuccessQuarter.difficulty(), SuccessHalf.difficulty());
        
        EXPECT_LT(SuccessHalf.difficulty(), SuccessEighth.difficulty());
        EXPECT_GT(SuccessEighth.difficulty(), SuccessHalf.difficulty());
        
        EXPECT_LT(SuccessHalf.difficulty(), SuccessSixteenth.difficulty());
        EXPECT_GT(SuccessSixteenth.difficulty(), SuccessHalf.difficulty());
        
        EXPECT_LT(SuccessHalf.difficulty(), difficulty::minimum());
        EXPECT_GT(difficulty::minimum(), SuccessHalf.difficulty());
        
        EXPECT_LT(SuccessQuarter.difficulty(), SuccessEighth.difficulty());
        EXPECT_GT(SuccessEighth.difficulty(), SuccessQuarter.difficulty());
        
        EXPECT_LT(SuccessQuarter.difficulty(), SuccessSixteenth.difficulty());
        EXPECT_GT(SuccessSixteenth.difficulty(), SuccessQuarter.difficulty());
        
        EXPECT_LT(SuccessQuarter.difficulty(), difficulty::minimum());
        EXPECT_GT(difficulty::minimum(), SuccessQuarter.difficulty());
        
        EXPECT_LT(SuccessEighth.difficulty(), SuccessSixteenth.difficulty());
        EXPECT_GT(SuccessSixteenth.difficulty(), SuccessEighth.difficulty());
        
        EXPECT_LT(SuccessEighth.difficulty(), difficulty::minimum());
        EXPECT_GT(difficulty::minimum(), SuccessEighth.difficulty());
        
        EXPECT_LT(SuccessSixteenth.difficulty(), difficulty::minimum());
        EXPECT_GT(difficulty::minimum(), SuccessSixteenth.difficulty());
        
        EXPECT_EQ(difficulty(1), difficulty::minimum());
        
        EXPECT_LT(difficulty(1), difficulty(2));
        EXPECT_GT(difficulty(2), difficulty(1));
        /*
        EXPECT_LT(difficulty(1), difficulty(3) / difficulty(2));
        EXPECT_GT(difficulty(3) / difficulty(2), difficulty(1));
        
        EXPECT_LT(difficulty(3) / difficulty(2), difficulty(2));
        EXPECT_GT(difficulty(2), difficulty(3) / difficulty(2));*/
        
    }

}

