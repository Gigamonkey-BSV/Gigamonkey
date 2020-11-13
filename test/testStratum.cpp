// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/session_id.hpp>
#include <gigamonkey/stratum/mining_authorize.hpp>
#include <gigamonkey/stratum/mining_subscribe.hpp>
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

namespace Gigamonkey::Stratum::mining { 
    TEST(StratumTest, TestMiningAuthorize) {
        authorize_request with_password(64, "dk", "meep");
        authorize_request without_password(94, "dk");
        
        authorize_response true_response{64, true};
        authorize_response false_response{94, false};
        
        EXPECT_TRUE(data::valid(with_password));
        EXPECT_TRUE(data::valid(without_password));
        
        EXPECT_TRUE(data::valid(true_response));
        EXPECT_TRUE(data::valid(false_response));
        
        EXPECT_NE(with_password, without_password);
        EXPECT_NE(true_response, false_response);
        
        json with_password_json;
        json without_password_json;
        
        json true_response_json;
        json false_response_json;
        
        to_json(with_password_json, with_password);
        to_json(without_password_json, without_password);
        to_json(true_response_json, true_response);
        to_json(false_response_json, false_response);
        
        EXPECT_NE(with_password_json, without_password_json);
        EXPECT_NE(true_response_json, false_response_json);
        
        authorize_request with_password_read;
        authorize_request without_password_read;
        
        authorize_response true_response_read;
        authorize_response false_response_read;
        
        EXPECT_FALSE(data::valid(with_password_read));
        EXPECT_FALSE(data::valid(without_password_read));
        
        EXPECT_FALSE(data::valid(true_response_read));
        EXPECT_FALSE(data::valid(false_response_read));
        
        from_json(with_password_json, with_password_read);
        from_json(without_password_json, without_password_read);
        from_json(true_response_json, true_response_read);
        from_json(false_response_json, false_response_read);
        
    }
    
    TEST(StratumTest, TestMiningSubscribe) {
        subscribe_request with_user_id(23, "dk", 2);
        subscribe_request without_user_id(45, "dk");
        
        subscribe_response response_1{23, {subscription{mining_set_difficulty, 1}, subscription{mining_notify, 2}}, 7, 8};
        subscribe_response response_2{45, {subscription{mining_notify, 3}}, 30, 8};
        
        EXPECT_TRUE(data::valid(with_user_id));
        EXPECT_TRUE(data::valid(without_user_id));
        
        EXPECT_TRUE(data::valid(response_1));
        EXPECT_TRUE(data::valid(response_2));
        
        EXPECT_NE(with_user_id, without_user_id);
        EXPECT_NE(response_1, response_2);
        
        json with_user_id_json;
        json without_user_id_json;
        
        json response_1_json;
        json response_2_json;
        
        to_json(with_user_id_json, with_user_id);
        to_json(without_user_id_json, without_user_id);
        to_json(response_1_json, response_1);
        to_json(response_2_json, response_2);
        
        EXPECT_NE(with_user_id_json, without_user_id_json);
        EXPECT_NE(response_1_json, response_2_json);
        
        subscribe_request with_user_id_read;
        subscribe_request without_user_id_read;
        
        subscribe_response response_1_read;
        subscribe_response response_2_read;
        
        EXPECT_FALSE(data::valid(with_user_id_read));
        EXPECT_FALSE(data::valid(without_user_id_read));
        
        EXPECT_FALSE(data::valid(response_1_read));
        EXPECT_FALSE(data::valid(response_2_read));
        
        from_json(with_user_id_json, with_user_id_read);
        from_json(without_user_id_json, without_user_id_read);
        from_json(response_1_json, response_1_read);
        from_json(response_2_json, response_2_read);
    }
    
    TEST(StratumTest, TestNotifySubmit) {
        // TODO need to test merkle branches here. 
    }

}

