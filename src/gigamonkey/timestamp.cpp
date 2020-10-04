// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/timestamp.hpp>

namespace Gigamonkey::Bitcoin {
    
    std::ostream& operator<<(std::ostream& o, const timestamp& s) {
        time_t t = static_cast<time_t>(uint32_t(s));
        std::stringstream ss;
        ss << ctime(&t);
        string str = ss.str();
        return o << "\"" << str.substr(0, str.size() - 2) << "\"";
    }
}
