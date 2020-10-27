
#include <gigamonkey/stratum/difficulty.hpp>
#include <btcpool/difficulty.hpp>

namespace Gigamonkey::Stratum {
    
    difficulty::difficulty(const uint256& d) {
        *this = BitcoinDifficulty::TargetToDiff(d);
    }
        
    difficulty::operator uint256() const {
        uint256 t;
        ::uint256 x;
        BitcoinDifficulty::DiffToTarget(*this, x);
        std::copy(x.begin(), x.end(), t.begin());
        return t;
    }

}
