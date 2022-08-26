// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/hash.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey {
    
    TEST(DigestTest, TestDigest) {
        std::string reversed{"0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff"};
        
        digest256 digest{reversed};
        
        EXPECT_EQ(string(digest), reversed);
        
        EXPECT_EQ(digest[0], 0xff);
        EXPECT_EQ(0x00, digest[31]);
    }
    
}
