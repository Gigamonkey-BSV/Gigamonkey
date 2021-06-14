// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work/target.hpp>
#include <gigamonkey/stratum/difficulty.hpp>
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
        
        compact ten_thousanth{work::difficulty{double(.0001)}}; 
        compact one_thousand{work::difficulty{double(1000.)}}; 
        compact one{work::difficulty{double(1.)}}; 
        compact some_big_number{work::difficulty{double(1.)}}; 
        
        EXPECT_EQ(compact{ten_thousanth.difficulty()}, ten_thousanth);
        EXPECT_EQ(compact{one_thousand.difficulty()}, one_thousand);
        EXPECT_EQ(compact{one.difficulty()}, one);
        EXPECT_EQ(compact{some_big_number.difficulty()}, some_big_number);
        
    }

}

//taken from btc pool

namespace Gigamonkey::Stratum {
    TEST(DifficultyTest, DiffTargetDiff) {
        for (uint32_t i = 0; i < 64; i++) {
            difficulty diff{1 << i};
            ASSERT_EQ(diff, difficulty(uint256(diff)));
        }
    }

    TEST(DifficultyTest, BitsToTarget) {
        ASSERT_EQ(
            work::compact{0x1b0404cb}.expand(),
            uint256(
                "0x00000000000404CB000000000000000000000000000000000000000000000000"));
    }

    TEST(DifficultyTest, TargetToDiff) {

        // 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF /
        // 0x00000000000404CB000000000000000000000000000000000000000000000000
        // = 16307.669773817162 (pdiff)

        ASSERT_EQ(
            difficulty(
                uint256{"0x00000000000404CB000000000000000000000000000000000000000000000000"}),
            difficulty{16307ULL});
    }

    static void TestDiffToTarget(uint64_t diff, string target) {
        ASSERT_EQ((uint256)(difficulty{diff}), uint256(target));
    }

    TEST(DifficultyTest, DiffToTargetBitcoin) {
    TestDiffToTarget(
        1ull, "0x00000000ffff0000000000000000000000000000000000000000000000000000");
    TestDiffToTarget(
        2ull, "0x000000007fff8000000000000000000000000000000000000000000000000000");
    TestDiffToTarget(
        3ull, "0x0000000055550000000000000000000000000000000000000000000000000000");
    TestDiffToTarget(
        4ull, "0x000000003fffc000000000000000000000000000000000000000000000000000");
    TestDiffToTarget(
        1073741831ull,
        "0x0000000000000003fffbff9000700c3ff3bea901572583da77e5941ae2e3cd0f");
    TestDiffToTarget(
        1ull << 10,
        "0x00000000003fffc0000000000000000000000000000000000000000000000000");
    TestDiffToTarget(
        1ull << 20,
        "0x0000000000000ffff00000000000000000000000000000000000000000000000");
    TestDiffToTarget(
        1ull << 30,
        "0x0000000000000003fffc00000000000000000000000000000000000000000000");
    TestDiffToTarget(
        1ull << 63,
        "0x000000000000000000000001fffe000000000000000000000000000000000000");
    }
}



