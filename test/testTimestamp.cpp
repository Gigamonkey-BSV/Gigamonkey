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
        std::tm tm (tb);
        EXPECT_EQ (tm.tm_year + 1900, 2020);
        string expected_time {"2020-10-01 05:25:10"};
        string exported_time = string (tb);
        EXPECT_EQ (exported_time, expected_time);
        EXPECT_EQ (tb, timestamp (exported_time));
    }

}

