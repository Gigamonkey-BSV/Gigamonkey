
#include <gigamonkey/stratum/difficulty.hpp>
#include <btcpool/difficulty.hpp>

namespace Gigamonkey::Stratum {
    difficulty::difficulty(const work::compact& t) {
        ::uint256 targ;
        auto d = t.expand();
        std::copy(d.begin(), d.end(), targ.begin());
        *this = BitcoinDifficulty::TargetToDiff(targ);
    }

}
