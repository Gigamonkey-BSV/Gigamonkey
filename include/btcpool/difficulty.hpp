/*
 The MIT License (MIT)

 Copyright (c) [2019] [BTC.COM]
               [2020] [Daniel Krawisz]

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 */

#ifndef BTCPOOL_DIFFICULTY
#define BTCPOOL_DIFFICULTY

#include "arith_uint256.h"
#include "uint256.h"

#include <array>
#include <cmath>
#include <cstdint>
#include <string>

#include <gigamonkey/work/target.hpp>

using target = Gigamonkey::Bitcoin::target;

using difficulty = Gigamonkey::Stratum::difficulty;

template <uint32_t DiffOneBits, size_t TableSize = 64>
struct Difficulty {
    static const uint64_t GetDiffOneBits() { return DiffOneBits; }

    static const arith_uint256 &GetDiffOneTarget() {
        static const auto DiffOneTarget = arith_uint256{}.SetCompact(DiffOneBits);
        return DiffOneTarget;
    }

    static const std::array<uint256, TableSize> &GetDiffToTargetTable() {
        static const auto DiffToTargetTable = GenerateDiffToTargetTable();
        return DiffToTargetTable;
    }

    static std::array<uint256, TableSize> GenerateDiffToTargetTable() {
        std::array<uint256, TableSize> table;
        uint32_t shifts = 0;
        for (auto &target : table) {
        target = ArithToUint256(GetDiffOneTarget() >> (shifts++));
        }
        return table;
    }

    static difficulty TargetToDiff(const Gigamonkey::uint256 &targ) {
        uint256 target;
        std::copy(targ.begin(), targ.end(), target.begin());
        arith_uint256 t = UintToArith256(target);
        return difficulty{(GetDiffOneTarget() / t).GetLow64()};
    }

    static void DiffToTarget(difficulty diff, uint256 &target, bool useTable = true) {
        static const auto MaxTarget = uint256S(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        if (diff == 0) {
            target = MaxTarget;
            return;
        }

        if (useTable) {
            // try to find by table
            static const auto &DiffToTargetTable = GetDiffToTargetTable();
            auto p = static_cast<uint64_t>(log2(diff.Value));
            if (p < TableSize && diff == (1ull << p)) {
                target = DiffToTargetTable[p];
                return;
            }
        }

        // If it is not found in the table, it will be calculated.
        target = ArithToUint256(GetDiffOneTarget() / diff.Value);
    }

    static void BitsToDifficulty(uint32_t bits, double *difficulty) {
        arith_uint256 target;
        target.SetCompact(bits);
        *difficulty = GetDiffOneTarget().getdouble() / target.getdouble();
    }

    static void BitsToDifficulty(uint32_t bits, uint64_t *difficulty) {
        arith_uint256 target;
        target.SetCompact(bits);
        *difficulty = (GetDiffOneTarget() / target).GetLow64();
    }
};

using BitcoinDifficulty = Difficulty<0x1d00ffff>;

#endif
