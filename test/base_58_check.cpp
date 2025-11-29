// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/p2p/checksum.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::base58 {

    TEST (Base58, Base58Check) {
        
        std::string hex {"010203fdfeff"};
        std::string encoded_0 {"14HV44ipwoaqfg"};
        std::string encoded_3 {"kCr8KebD6cWdVj"};

        bytes decoded_hex = *encoding::hex::read (hex);

        check check_0 {0, decoded_hex};
        check check_3 {3, decoded_hex};
        EXPECT_EQ (check_0, check {encoded_0});
        EXPECT_EQ (check_3, check {encoded_3});
        
    }

}
