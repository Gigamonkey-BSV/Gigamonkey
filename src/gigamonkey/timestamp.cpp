// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/timestamp.hpp>

namespace Gigamonkey::Bitcoin {

    timestamp::operator ptr<std::tm> () const {
        time_t t = static_cast<time_t> (uint32 (*this));
        return ptr<std::tm> {std::gmtime (&t)};
    }
    
    std::ostream &operator << (std::ostream &o, const timestamp &s) {
        auto t = ptr<std::tm> (s);
        char buff[20];
        std::strftime (buff, 20, "%Y-%m-%d %H:%M:%S", t.get ());
        return o << "{" << uint32 (s) << ", \"" << buff << "\"}";
    }
    
}
