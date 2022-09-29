// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/session_id.hpp>
#include <gigamonkey/stratum/mining_authorize.hpp>
#include <gigamonkey/stratum/mining_subscribe.hpp>
#include <gigamonkey/stratum/job.hpp>
#include <gigamonkey/stratum/server_session.hpp>
#include <gigamonkey/stratum/miner.hpp>
#include <gigamonkey/work/ASICBoost.hpp>
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
        json j_a = session_id::serialize(id_a);
        json j_b = session_id::serialize(id_b);
        EXPECT_NE(j_a, j_b);
        optional<session_id> j_id_a = session_id::deserialize(j_a);
        optional<session_id> j_id_b = session_id::deserialize(j_b);
        EXPECT_TRUE(j_id_a);
        EXPECT_TRUE(j_id_b);
        EXPECT_NE(*j_id_a, *j_id_b);
        EXPECT_EQ(id_a, *j_id_a);
        EXPECT_EQ(id_b, *j_id_b);
    }
    
    // taken from https://braiins.com/stratum-v1/docs
    TEST(StratumTest, TestStratumPuzzle) {
        
        mining::subscribe_response subscribe_response{json::parse(
            R"({"id": 1, "result": [ [ ["mining.set_difficulty", "b4b6693b72a50c7116db18d6497cac52"], ["mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f"]], "08000002", 4], "error": null})")};
        
        mining::subscribe_response::parameters srparams = subscribe_response.result();
        
        EXPECT_TRUE(subscribe_response.valid());
        
        mining::notify notify{json::parse(
            R"({"params": 
                ["bf", "4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000",
                    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008",
                    "072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000", 
                    [], "00000002", "1c2ac4af", "504e86b9", false], 
                "id": null, "method": "mining.notify"})")};
        
        EXPECT_TRUE(notify.valid());
        
        mining::submit_request submit_request{json::parse(
            R"({"params": ["slush.miner1", "bf", "00000001", "504e86ed", "b2957c02"], 
                "id": 4, "method": "mining.submit"})")};
        
        EXPECT_TRUE(submit_request.valid());
        
        digest256 expected_block_hash{"32abdc31d947623a2482144f92dbc092a84fd8ee6e2b5ae60f87762000000000"};
        digest256 expected_prev_hash{"f8b6164d19e2f65a2aae448f787fe66d61e57a48c0c6771b1e920b4400000000"};
        
        proof p{worker{"Daniel", subscribe_response.result().ExtraNonce}, notify.params(), submit_request.params()};
        
        EXPECT_TRUE(p.valid());
        
        auto work_proof = work::proof(p);
        work::string z = work_proof.string();
        auto block_hash = z.hash();
        EXPECT_EQ(expected_block_hash, block_hash);
        EXPECT_EQ(z.Digest, expected_prev_hash);
        /*
        std::cout << "meta: " << work_proof.meta() << std::endl;
        std::cout << "meta hash: " << Bitcoin::Hash256(work_proof.meta()) << std::endl;
        std::cout << "string: " << z.write() << std::endl;
        std::cout << "expected prev hash: " << expected_prev_hash << std::endl;
        std::cout << "         prev hash:        " << z.Digest << std::endl;
        std::cout << "expected block hash: " << expected_block_hash << std::endl;
        std::cout << "         block hash:        " << block_hash << std::endl;
        */
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
        
        boolean_response null_no_error{json::parse(R"({"id":55, "result": null, "error": null})")};
        boolean_response null_with_error{json::parse(R"({"id":55, "result": null, "error": [4, "hi"]})")};
        boolean_response false_with_error{json::parse(R"({"id":55, "result": false, "error": [4, "hi"]})")};
        boolean_response false_no_error{json::parse(R"({"id":55, "result": false, "error": null})")};
        boolean_response true_no_error{json::parse(R"({"id":55, "result": true, "error": null})")};
        boolean_response true_with_error{json::parse(R"({"id":55, "result": true, "error": [4, "hi"]})")};
        
        EXPECT_FALSE(null_no_error.valid());
        
        EXPECT_TRUE(null_with_error.valid());
        EXPECT_FALSE(null_with_error.result());
        
        EXPECT_TRUE(false_with_error.valid());
        EXPECT_FALSE(false_with_error.result());
        
        EXPECT_TRUE(false_no_error.valid());
        EXPECT_FALSE(false_no_error.result());
        
        EXPECT_TRUE(true_no_error.valid());
        EXPECT_TRUE(true_no_error.result());
        
        EXPECT_TRUE(true_with_error.valid());
        EXPECT_FALSE(true_with_error.result());
        
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
                return subscribe_response{ID, Result.Subscriptions, Result.ExtraNonce};
            }
        };
        
        std::vector<request_test_case> request_test_cases{{23, {"dk", 2}}, {45, {"dk"}}};
        
        std::vector<response_test_case> response_test_cases {
            {23, {{subscription{mining_set_difficulty, "1"}, subscription{mining_notify, "2"}}, {7, 8}}}, 
            {45, {{subscription{mining_notify, "3"}}, {30, 8}}}};
        
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
    
    TEST(StratumTest, TestStratumDifficulty) {
        difficulty d1{work::difficulty{.0001}};
        difficulty d2{555};
        EXPECT_TRUE(d1.valid());
        EXPECT_TRUE(d2.valid());
        work::compact t1{work::difficulty(d1)};
        work::compact t2{work::difficulty(d2)};
        EXPECT_EQ(t1, work::compact{work::difficulty(difficulty{t1})});
        EXPECT_EQ(t2, work::compact{work::difficulty(difficulty{t2})});
    }
    
    TEST(StratumTest, TestStratumProof) {
        job_id jid = "2333";
        extranonce en{1, 8};
        int32_little version = 2;
        Bitcoin::timestamp timestamp{3};
        
        work::compact d{work::difficulty(.0001)};
        digest256 prevHash{"0x0000000000000000000000000000000000000000000000000000000000000001"};
        bytes gentx1 = bytes::from_hex("abcdef");
        bytes gentx2 = bytes::from_hex("010203");
        
        bytes extra_nonce_2 = bytes::from_hex("abcdef0123456789");
        
        int32_little gpr = 0xffffffff;
        int32_little version_mask = work::ASICBoost::Mask;
        
        string name{"Daniel"};
        
        mining::notify::parameters notify{jid, prevHash, gentx1, gentx2, {}, version, d, timestamp, true};
        
        auto worker_v1 = worker{name, en};
        auto worker_v2 = worker{name, en, version_mask};
        
        EXPECT_FALSE(worker_v1.Mask);
        EXPECT_TRUE(worker_v2.Mask);
        
        auto puzzle_v1 = work::puzzle{version, prevHash, d, {}, gentx1, gentx2};
        auto puzzle_v2 = work::puzzle{version, prevHash, d, {}, gentx1, gentx2, version_mask};
        
        auto initial_share_v1 = work::share{timestamp, 65067, extra_nonce_2};
        auto initial_share_v2 = work::share{timestamp, 449600, extra_nonce_2, gpr};
        
        EXPECT_FALSE(initial_share_v1.Bits);
        EXPECT_TRUE(initial_share_v2.Bits);
        
        auto work_proof_v1 = work::proof{puzzle_v1, {initial_share_v1, en.ExtraNonce1}};
        auto work_proof_v2 = work::proof{puzzle_v2, {initial_share_v2, en.ExtraNonce1}};
        
        EXPECT_TRUE(work_proof_v1.valid());
        EXPECT_TRUE(work_proof_v2.valid());
        
        auto share_v1 = share{name, jid, work_proof_v1.Solution.Share};
        auto share_v2 = share{name, jid, work_proof_v2.Solution.Share};
        
        auto nonce_v1 = share_v1.Share.Nonce;
        auto nonce_v2 = share_v2.Share.Nonce;
        
        auto proof_v1 = proof{worker_v1, notify, share_v1};
        auto proof_v2 = proof{worker_v2, notify, share_v2};
        
        EXPECT_EQ(work_proof_v1, work::proof(proof_v1));
        EXPECT_EQ(work_proof_v2, work::proof(proof_v2));
        
        EXPECT_NE(work_proof_v1, work::proof(proof_v2));
        EXPECT_NE(work_proof_v2, work::proof(proof_v1));
        
        EXPECT_TRUE(proof_v1.valid());
        EXPECT_TRUE(proof_v2.valid());
        
    }
    
    TEST(StratumTest, TestMiningConfigure) {
        //extensions::requests{ };
    }

}

