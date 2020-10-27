// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work/target.hpp>
#include <gigamonkey/stratum/difficulty.hpp>
#include <btcpool/difficulty.hpp>
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
            BitcoinDifficulty::TargetToDiff(
                uint256{"0x00000000000404CB000000000000000000000000000000000000000000000000"}),
            difficulty{16307ULL});
    }
}

using string = std::string;

static void TestDiffToTarget(uint64_t diff, string target) {
    uint256 targetWithoutTable, targetWithTable;
    BitcoinDifficulty::DiffToTarget(difficulty{diff}, targetWithoutTable, false);
    BitcoinDifficulty::DiffToTarget(difficulty{diff}, targetWithTable, true);
    ASSERT_EQ(targetWithoutTable.ToString(), target);
    ASSERT_EQ(targetWithTable.ToString(), target);
}

TEST(DifficultyTest, DiffToTargetBitcoin) {
  TestDiffToTarget(
      1ull, "00000000ffff0000000000000000000000000000000000000000000000000000");
  TestDiffToTarget(
      2ull, "000000007fff8000000000000000000000000000000000000000000000000000");
  TestDiffToTarget(
      3ull, "0000000055550000000000000000000000000000000000000000000000000000");
  TestDiffToTarget(
      4ull, "000000003fffc000000000000000000000000000000000000000000000000000");
  TestDiffToTarget(
      1073741831ull,
      "0000000000000003fffbff9000700c3ff3bea901572583da77e5941ae2e3cd0f");
  TestDiffToTarget(
      1ull << 10,
      "00000000003fffc0000000000000000000000000000000000000000000000000");
  TestDiffToTarget(
      1ull << 20,
      "0000000000000ffff00000000000000000000000000000000000000000000000");
  TestDiffToTarget(
      1ull << 30,
      "0000000000000003fffc00000000000000000000000000000000000000000000");
  TestDiffToTarget(
      1ull << 63,
      "000000000000000000000001fffe000000000000000000000000000000000000");
}

TEST(DifficultyTest, DiffToTargetTable) {
    uint256 t1, t2;

    for (uint64_t i = 0; i < 10240; i++) {
        BitcoinDifficulty::DiffToTarget(difficulty{i}, t1, false);
        BitcoinDifficulty::DiffToTarget(difficulty{i}, t2, true);
        ASSERT_EQ(t1, t2);
    }

    for (uint32_t i = 0; i < 64; i++) {
        difficulty diff{1 << i};
        BitcoinDifficulty::DiffToTarget(diff, t1, false);
        BitcoinDifficulty::DiffToTarget(diff, t2, true);
        ASSERT_EQ(t1, t2);
    }
}

TEST(DifficultyTest, uint256) {
    uint256 u1, u2;

    u1 = uint256S(
        "00000000000000000392381eb1be66cd8ef9e2143a0e13488875b3e1649a3dc9");
    u2 = uint256S(
        "00000000000000000392381eb1be66cd8ef9e2143a0e13488875b3e1649a3dc9");
    ASSERT_EQ(UintToArith256(u1) == UintToArith256(u2), true);
    ASSERT_EQ(UintToArith256(u1) >= UintToArith256(u2), true);
    ASSERT_EQ(UintToArith256(u1) < UintToArith256(u2), false);

    u1 = uint256S(
        "00000000000000000392381eb1be66cd8ef9e2143a0e13488875b3e1649a3dc9");
    u2 = uint256S(
        "000000000000000000cc35a4f0ebd7b5c8165b28d73e6369f49098c1a632d1a9");
    ASSERT_EQ(UintToArith256(u1) > UintToArith256(u2), true);
}

TEST(DifficultyTest, BitsToDifficulty) {
    uint64_t diff = 163074209ull;

    // 0x1b0404cb: https://en.bitcoin.it/wiki/Difficulty
    double d;
    BitcoinDifficulty::BitsToDifficulty(0x1b0404cbu, &d); // diff = 16307.420939
    ASSERT_EQ((uint64_t)(d * 10000.0), diff);
}


