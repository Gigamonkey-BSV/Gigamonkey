// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/timestamp.hpp>

namespace Gigamonkey::Bitcoin {

    timestamp::operator std::tm () const {
        time_t t = static_cast<time_t> (uint32 (*this));
        std::tm tm = *gmtime (&t);
        return tm;
    }
    
    std::ostream &operator << (std::ostream &o, const timestamp &s) {
        auto t = std::tm (s);
        char buff[20];
        std::strftime (buff, 20, "%Y-%m-%d %H:%M:%S", &t);
        return o << "{" << uint32 (s) << ", \"" << buff << "\"}";
    }
    
}
