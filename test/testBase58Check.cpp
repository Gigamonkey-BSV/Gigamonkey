// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/address.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::base58 {

    TEST(Base58Test, TestBase58Check) {
        
        std::string hex{"010203fdfeff"};
        std::string encoded_0{"14HV44ipwoaqfg"};
        std::string encoded_3{"kCr8KebD6cWdVj"};
        
        EXPECT_EQ(check(0, *encoding::hex::read(hex)), check(encoded_0));
        
        EXPECT_EQ(check(3, *encoding::hex::read(hex)), check(encoded_3));
        
    }

}
