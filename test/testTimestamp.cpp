// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/timestamp.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Bitcoin {

    TEST (TimestampTest, TestTimestamp) {
        time_t t = 1601529910;
        timestamp tb {t};
        uint32 ut = uint32 (tb);
        EXPECT_EQ (tb, timestamp {ut});
        EXPECT_EQ (t, static_cast<time_t> (ut));
    }

}

