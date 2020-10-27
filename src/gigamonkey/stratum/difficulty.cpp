
#include <gigamonkey/stratum/difficulty.hpp>

namespace Gigamonkey::Stratum {

    template <uint32_t DiffOneBits, size_t TableSize = 64>
    struct Difficulty {
        static const uint64_t GetDiffOneBits() { return DiffOneBits; }

        static const uint256 &GetDiffOneTarget() {
            static const auto DiffOneTarget = work::compact(DiffOneBits).expand();
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
                target = (GetDiffOneTarget() >> (shifts++));
            }
            return table;
        }

        static difficulty TargetToDiff(const uint256 &target) {
            return difficulty{(GetDiffOneTarget() / target).GetLow64()};
        }

        static void DiffToTarget(difficulty diff, Gigamonkey::uint256 &target) {
            static const auto MaxTarget = Gigamonkey::uint256(
                "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            if (diff == 0) {
                target = MaxTarget;
                return;
            }

            // try to find by table
            static const auto &DiffToTargetTable = GetDiffToTargetTable();
            auto p = static_cast<uint64_t>(log2(diff.Value));
            if (p < TableSize && diff == (1ull << p)) {
                target = DiffToTargetTable[p];
                return;
            }

            // If it is not found in the table, it will be calculated.
            target = GetDiffOneTarget() / uint64(diff);
        }
    };

    using BitcoinDifficulty = Difficulty<0x1d00ffff>;
    
    difficulty::difficulty(const uint256& d) {
        *this = BitcoinDifficulty::TargetToDiff(d);
    }
        
    difficulty::operator uint256() const {
        uint256 t;
        BitcoinDifficulty::DiffToTarget(*this, t);
        return t;
    }

}
