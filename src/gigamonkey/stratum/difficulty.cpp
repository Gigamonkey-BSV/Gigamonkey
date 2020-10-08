
#include <cmath>
#include <gigamonkey/stratum/difficulty.hpp>

namespace Gigamonkey::Stratum {
    
    // taken from BTCPool

    template <uint32_t DiffOneBits, size_t TableSize = 64>
    struct Difficulty {
        static const uint64_t GetDiffOneBits() { return DiffOneBits; }

        static const std::array<uint256, TableSize> &GetDiffToTargetTable() {
            static const auto DiffToTargetTable = GenerateDiffToTargetTable();
            return DiffToTargetTable;
        }

        static std::array<uint256, TableSize> GenerateDiffToTargetTable() {
            std::array<uint256, TableSize> table;
            uint32_t shifts = 0;
            for (auto &target : table) {
                target = ArithToUint256(work::difficulty::unit() >> (shifts++));
            }
            return table;
        }

        static difficulty TargetToDiff(const uint256 &target) {
            return difficulty{(work::difficulty::unit() / target).GetLow64()};
        }

        static void
        DiffToTarget(difficulty diff, uint256 &target, bool useTable = true) {
            static const auto MaxTarget = uint256(
                "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            if (diff.Value == 0) {
            target = MaxTarget;
            return;
            }

            if (useTable) {
            // try to find by table
            static const auto &DiffToTargetTable = GetDiffToTargetTable();
            auto p = static_cast<uint64_t>(std::log2(diff.Value));
            if (p < TableSize && diff.Value == (1ull << p)) {
                target = DiffToTargetTable[p];
                return;
            }
            }

            // If it is not found in the table, it will be calculated.
            target = ArithToUint256(work::difficulty::unit() / diff.Value);
        }

        static void BitsToDifficulty(uint32_t bits, double *difficulty) {
            arith_uint256 target;
            target.SetCompact(bits);
            *difficulty = double(work::difficulty::unit()) / target.getdouble();
        }

        static void BitsToDifficulty(uint32_t bits, uint64_t *difficulty) {
            arith_uint256 target;
            target.SetCompact(bits);
            *difficulty = (work::difficulty::unit() / target).GetLow64();
        }
    };
    
    using BitcoinDifficulty = Difficulty<0x1d00ffff>;

    difficulty::difficulty(const work::compact& t) {
        uint256 targ;
        *this = BitcoinDifficulty::TargetToDiff(t.expand());
    }

}
