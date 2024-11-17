// Copyright (c) 2022 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef GIGAMONKEY_P2P_COMMAND
#define GIGAMONKEY_P2P_COMMAND

#include <string_view>
#include <array>

namespace Gigamonkey::Bitcoin::p2p {

    struct command : public std::array<char, 12> {
        constexpr command (const char *x): std::array<char, 12> {0} {
            int i = 0;
            while (*x != '\0') {
                (*this) [i] = *x;
                x++;
                i++;
            }
        }
    };
}

#endif //GIGAMONKEY_INCLUDE_GIGAMONKEY_P2P_COMMAND
