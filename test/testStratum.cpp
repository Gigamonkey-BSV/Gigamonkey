// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/session_id.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Stratum {

    TEST(StratumTest, TestStratumSessionID) {
        uint32 a = 303829;
        uint32 b = 773822929;
        session_id id_a(a);
        session_id id_b(b);
        EXPECT_NE(id_a, id_b);
        encoding::hex::fixed<4> hex_a = encoding::hex::fixed<4>(id_a);
        encoding::hex::fixed<4> hex_b = encoding::hex::fixed<4>(id_b);
        EXPECT_NE(hex_a, hex_b);
        EXPECT_EQ(id_a, session_id{hex_a});
        EXPECT_EQ(id_b, session_id{hex_b});
        json j_a;
        json j_b;
        session_id j_id_a;
        session_id j_id_b;
        to_json(j_a, id_a);
        to_json(j_b, id_b);
        EXPECT_NE(j_a, j_b);
        from_json(j_a, j_id_a);
        from_json(j_b, j_id_b);
        EXPECT_NE(j_id_a, j_id_b);
        EXPECT_EQ(id_a, j_id_a);
        EXPECT_EQ(id_b, j_id_b);
    }

}

