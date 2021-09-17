// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/session_id.hpp>
#include <gigamonkey/stratum/mining_authorize.hpp>
#include <gigamonkey/stratum/mining_subscribe.hpp>
#include <gigamonkey/stratum/job.hpp>
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
        EXPECT_TRUE(from_json(j_a, j_id_a));
        EXPECT_TRUE(from_json(j_b, j_id_b));
        EXPECT_NE(j_id_a, j_id_b);
        EXPECT_EQ(id_a, j_id_a);
        EXPECT_EQ(id_b, j_id_b);
    }
    
}

namespace Gigamonkey::Stratum::mining { 
    TEST(StratumTest, TestBooleanResponse) {
        struct response_test_case {
            message_id ID;
            bool Result;
            
            operator boolean_response() const {
                return boolean_response{ID, Result};
            }
        };
        
        std::vector<response_test_case> test_cases{{64, true}, {94, false}};
        
        for (const auto& i : test_cases) for (const auto& j : test_cases) {
            auto response_i = boolean_response(i);
            auto response_j = boolean_response(j);
            EXPECT_EQ(i.Result, response_i.result());
            if (i.ID == j.ID) {
                EXPECT_EQ(i.ID, response_j.id());
                EXPECT_EQ(response_i, response_j);
            } else {
                EXPECT_NE(i.ID, response_j.id());
                EXPECT_NE(response_i, response_j);
            }
        }
        
    }

    TEST(StratumTest, TestMiningAuthorize) {
        struct request_test_case {
            message_id ID;
            authorize_request::parameters Params;
            
            operator authorize_request() const {
                if (Params.Password) return authorize_request{ID, Params.Username, *Params.Password};
                return authorize_request{ID, Params.Username};
            }
        };
        
        std::vector<request_test_case> test_cases{
            {64, authorize_request::parameters{"dk", "meep"}}, 
            {94, authorize_request::parameters{"dk"}}};
        
        for (const auto& i : test_cases) for (const auto& j : test_cases) {
            auto request_i = authorize_request(i);
            auto request_j = authorize_request(j);
            auto deserialized_i = authorize_request::deserialize(static_cast<request>(request_i).params());
            auto deserialized_j = authorize_request::deserialize(static_cast<request>(request_j).params());
            EXPECT_EQ(request_i.valid(), deserialized_i.valid());
            if (i.ID == j.ID) {
                EXPECT_EQ(i.ID, request_j.id());
                EXPECT_EQ(request_i, request_j);
                EXPECT_EQ(deserialized_i, deserialized_j);
                EXPECT_EQ(i.Params, deserialized_j);
            } else {
                EXPECT_NE(i.ID, request_j.id());
                EXPECT_NE(request_i, request_j);
                EXPECT_NE(deserialized_i, deserialized_j);
                EXPECT_NE(i.Params, deserialized_j);
            }
        }
        
    }
    
    TEST(StratumTest, TestMiningSubscribe) {
        struct request_test_case {
            message_id ID;
            subscribe_request::parameters Params;
            
            operator subscribe_request() const {
                if (Params.ExtraNonce1) return subscribe_request{ID, Params.UserAgent, *Params.ExtraNonce1};
                return subscribe_request{ID, Params.UserAgent};
            }
        };
        
        struct response_test_case {
            message_id ID;
            subscribe_response::parameters Result;
            
            operator subscribe_response() const {
                return subscribe_response{ID, Result.Subscriptions, Result.ExtraNonce1, Result.ExtraNonce2Size};
            }
        };
        
        std::vector<request_test_case> request_test_cases{{23, {"dk", 2}}, {45, {"dk"}}};
        
        std::vector<response_test_case> response_test_cases {
            {23, {{subscription{mining_set_difficulty, 1}, subscription{mining_notify, 2}}, 7, 8}}, 
            {45, {{subscription{mining_notify, 3}}, 30, 8}}};
        
        for (const auto& i : request_test_cases) for (const auto& j : request_test_cases) {
            auto request_i = subscribe_request(i);
            auto request_j = subscribe_request(j);
            auto deserialized_i = subscribe_request::deserialize(request_i.params());
            auto deserialized_j = subscribe_request::deserialize(request_j.params());
            EXPECT_EQ(request_i.valid(), deserialized_i.valid());
            if (i.ID == j.ID) {
                EXPECT_EQ(i.ID, request_j.id());
                EXPECT_EQ(request_i, request_j);
                EXPECT_EQ(deserialized_i, deserialized_j);
                EXPECT_EQ(i.Params, deserialized_j);
            } else {
                EXPECT_NE(i.ID, request_j.id());
                EXPECT_NE(request_i, request_j);
                EXPECT_NE(deserialized_i, deserialized_j);
                EXPECT_NE(i.Params, deserialized_j);
            }
        }
        
        for (const auto& i : response_test_cases) for (const auto& j : response_test_cases) {
            auto response_i = subscribe_response(i);
            auto response_j = subscribe_response(j);
            auto deserialized_i = subscribe_response::deserialize(static_cast<response>(response_i).result());
            auto deserialized_j = subscribe_response::deserialize(static_cast<response>(response_j).result());
            EXPECT_EQ(response_i.valid(), deserialized_i.valid());
            if (i.ID == j.ID) {
                EXPECT_EQ(i.ID, response_j.id());
                EXPECT_EQ(response_i, response_j);
                EXPECT_EQ(deserialized_i, deserialized_j);
                EXPECT_EQ(i.Result, deserialized_j);
            } else {
                EXPECT_NE(i.ID, response_j.id());
                EXPECT_NE(response_i, response_j);
                EXPECT_NE(deserialized_i, deserialized_j);
                EXPECT_NE(i.Result, deserialized_j);
            }
        }
        
    }
    
    TEST(StratumTest, TestMiningSubmit) {
        struct notification_test_case {
            message_id ID;
            notify::parameters Params;
            
            operator notify() const {
                return notify{Params};
            }
        };
        
        std::vector<notification_test_case> notify_test_cases{};
        
        for (const auto& i : notify_test_cases) for (const auto& j : notify_test_cases) {
            auto notify_i = notify(i);
            auto notify_j = notify(j);
            auto deserialized_i = notify::deserialize(static_cast<notification>(notify_i).params());
            auto deserialized_j = notify::deserialize(static_cast<notification>(notify_j).params());
            EXPECT_EQ(notify_i.valid(), deserialized_i.valid());
            if (i.ID == j.ID) {
                EXPECT_EQ(notify_i, notify_j);
                EXPECT_EQ(deserialized_i, deserialized_j);
                EXPECT_EQ(i.Params, deserialized_j);
            } else {
                EXPECT_NE(notify_i, notify_j);
                EXPECT_NE(deserialized_i, deserialized_j);
                EXPECT_NE(i.Params, deserialized_j);
            }
        }
    }
    
    TEST(StratumTest, TestMiningNotify) {
        struct request_test_case {
            message_id ID;
            share Params;
            
            operator submit_request() const {
                return submit_request{ID, Params};
            }
        };
        
        std::vector<request_test_case> request_test_cases{};
        
        for (const auto& i : request_test_cases) for (const auto& j : request_test_cases) {
            auto request_i = submit_request(i);
            auto request_j = submit_request(j);
            auto deserialized_i = submit_request::deserialize(static_cast<request>(request_i).params());
            auto deserialized_j = submit_request::deserialize(static_cast<request>(request_j).params());
            EXPECT_EQ(request_i.valid(), deserialized_i.valid());
            if (i.ID == j.ID) {
                EXPECT_EQ(i.ID, request_j.id());
                EXPECT_EQ(request_i, request_j);
                EXPECT_EQ(deserialized_i, deserialized_j);
                EXPECT_EQ(i.Params, submit_request::deserialize(static_cast<request>(request_j).params()));
            } else {
                EXPECT_NE(i.ID, request_j.id());
                EXPECT_NE(request_i, request_j);
                EXPECT_NE(deserialized_i, deserialized_j);
                EXPECT_NE(i.Params, submit_request::deserialize(static_cast<request>(request_j).params()));
            }
        }
    }

}

