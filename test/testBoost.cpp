#include <gigamonkey/boost/boost.hpp>
#include <gigamonkey/script/machine.hpp>
#include <gigamonkey/address.hpp>
#include <gigamonkey/wif.hpp>
#include <gigamonkey/stratum/job.hpp>

#include "gtest/gtest.h"

#include <iostream>

struct scripts {
    data::bytes input_script;
    data::bytes output_script;
};
    
std::ostream& operator<<(std::ostream& o, scripts x) {
    return o << "{InputScript: " << x.input_script << ", OutputScript: " << x.output_script << "}";
}

namespace Gigamonkey::Boost {

    template <typename f, typename X, typename Y>
    bool dot_cross(f foo, list<X> x, list<Y> y) {
        if (x.size() != y.size()) return false;
        if (x.size() == 0) return true;
        list<X> input = x;
        list<Y> expected = y;
        while (!input.empty()) {
            list<Y> uuu = expected;
            X in = input.first();
            Y ex = uuu.first();
            
            if(!foo(in, ex)) return false;
            
            uuu = uuu.rest();
            
            while(!uuu.empty()) {
                ex = uuu.first();
                
                if(foo(in, ex)) return false;
                uuu = uuu.rest();
            }
            
            expected = expected.rest();
            input = input.rest();
        }
        
        return true;
    }
    
    template <typename X>
    static bool test_orthogonal(list<X> a, list<X> b) {
        return dot_cross([](X a, X b) -> bool {
            return a == b;
        }, a, b);
    }
    
    template <typename X>
    static bool test_equal(list<X> a, list<X> b) {
        if (a.size() != b.size()) return false;
        while(!a.empty()) {
            if (a.first() != b.first()) return false;
            a = a.rest();
            b = b.rest();
        }
        return true;
    }
    
    template <typename X, typename f, typename Y>
    static list<X> for_each(f fun, list<Y> y) {
        list<X> x;
        while(!y.empty()) {
            x = x << fun(y.first());
            y = y.rest();
        }
        return x;
    }
    
    template <typename X, typename f, typename Y, typename Z>
    static list<X> map_thread(f fun, list<Y> y, list<Z> z) {
        list<X> x;
        if (y.size() != z.size()) return x;
        while(!y.empty()) {
            x = x << fun(y.first(), z.first());
            y = y.rest();
            z = z.rest();
        }
        return x;
    }
    
    class test_case {
        test_case(
            puzzle j, 
            const output_script& x, 
            const Stratum::job& sj, 
            Stratum::session_id n1, 
            const bytes& n2, 
            Bitcoin::secret key) : 
            Puzzle{j}, Script{x}, Job{sj}, ExtraNonce1{n1}, ExtraNonce2{n2}, Key{key}, Bits{} {}
            
        test_case(
            puzzle j, 
            const output_script& x, 
            const Stratum::job& sj, 
            Stratum::session_id n1, 
            const bytes& n2, 
            Bitcoin::secret key, 
            int32_little bits) : 
            Puzzle{j}, Script{x}, Job{sj}, ExtraNonce1{n1}, ExtraNonce2{n2}, Key{key}, Bits{bits} {}
        
        static test_case build(
            const output_script& o, 
            Stratum::job_id jobID, 
            Bitcoin::timestamp start, 
            const Stratum::worker& worker, 
            uint64_big n2, uint64 key) {
            Bitcoin::secret s(Bitcoin::secret::main, secp256k1::secret(uint256(key)));
            puzzle Puzzle{o, s};
            
            bytes extra_nonce_2(8);
            std::copy(n2.begin(), n2.end(), extra_nonce_2.begin());
            
            return test_case{Puzzle, o, 
                Stratum::job{worker, Stratum::mining::notify::parameters{jobID, work::puzzle(Puzzle), start, true}}, 
                worker.ExtraNonce.ExtraNonce1, extra_nonce_2, s};
        }
        
        static test_case build(Boost::type type, 
            const uint256& content, 
            work::compact target, 
            const bytes& tag, 
            uint32_little user_nonce, 
            const bytes& data, 
            const Stratum::job_id jobID, 
            Bitcoin::timestamp start, 
            const Stratum::worker& worker, 
            uint64_big n2, 
            uint64 key) { 
            Bitcoin::secret s(Bitcoin::secret::main, secp256k1::secret(uint256(key)));
            digest160 address = s.address().Digest;
            puzzle Puzzle{type, 1, content, target, tag, user_nonce, data, s, false};
            
            output_script o = type == contract ? 
                output_script::contract(1, content, target, tag, user_nonce, data, address, false) : 
                output_script::bounty(1, content, target, tag, user_nonce, data, false);
                
            bytes extra_nonce_2(8);
            std::copy(n2.begin(), n2.end(), extra_nonce_2.begin());
            
            return test_case(Puzzle, o, 
                Stratum::job{worker, Stratum::mining::notify::parameters{jobID, work::puzzle(Puzzle), start, true}}, 
                worker.ExtraNonce.ExtraNonce1, extra_nonce_2, s);
        }
        
        static test_case build(Boost::type type, 
            const uint256& content, 
            work::compact target, 
            const bytes& tag, 
            uint32_little user_nonce, 
            const bytes& data, 
            int32_little bits, 
            const Stratum::job_id jobID, 
            Bitcoin::timestamp start, 
            const Stratum::worker& worker, 
            uint64_big n2, 
            uint64 key) { 
            Bitcoin::secret s(Bitcoin::secret::main, secp256k1::secret(uint256(key)));
            digest160 address = s.address().Digest;
            puzzle Puzzle{type, 1, content, target, tag, user_nonce, data, s, true};
            
            output_script o = type == contract ? 
                output_script::contract(1, content, target, tag, user_nonce, data, address, true) : 
                output_script::bounty(1, content, target, tag, user_nonce, data, true);
                
            bytes extra_nonce_2(8);
            std::copy(n2.begin(), n2.end(), extra_nonce_2.begin());
            
            return test_case(Puzzle, o, 
                Stratum::job{worker, Stratum::mining::notify::parameters{jobID, work::puzzle(Puzzle), start, true}}, 
                worker.ExtraNonce.ExtraNonce1, extra_nonce_2, s, bits);
        }
        
    public:
        puzzle Puzzle;
        output_script Script;
        Stratum::job Job;
        Stratum::session_id ExtraNonce1;
        bytes ExtraNonce2;
        Bitcoin::secret Key;
        std::optional<int32_little> Bits;
        
        test_case(
            output_script o, 
            Stratum::job_id jobID, 
            Bitcoin::timestamp start, 
            const Stratum::worker& worker, 
            uint64_big n2, 
            uint64 key) : 
            test_case(build(o, jobID, start, worker, n2, key)) {}
        
        test_case(Boost::type type, 
            uint256 content, 
            work::compact target, 
            bytes tag, 
            uint32_little user_nonce, 
            bytes data, 
            Stratum::job_id jobID, 
            Bitcoin::timestamp start,
            const Stratum::worker& worker,
            uint64_big n2, uint64 key) : 
            test_case(build(type, content, target, tag, user_nonce, data, jobID, start, worker, n2, key)) {}
        
        test_case(Boost::type type, 
            uint256 content, 
            work::compact target, 
            bytes tag, 
            uint32_little user_nonce, 
            bytes data, 
            int32_little bits, 
            Stratum::job_id jobID, 
            Bitcoin::timestamp start,
            const Stratum::worker& worker,
            uint64_big n2, uint64 key) : 
            test_case(build(type, content, target, tag, user_nonce, data, bits, jobID, start, worker, n2, key)) {}
        
        work::solution initial_solution() const {
            return work::solution(
                Bits ? work::share(Job.timestamp(), 0, ExtraNonce2, *Bits) : 
                work::share(Job.timestamp(), 0, ExtraNonce2), ExtraNonce1);
        }
        
        work::proof solve() const {
            return work::cpu_solve(work::puzzle(Puzzle), initial_solution());
        }
    };

    TEST(BoostTest, TestBoost) {
        
        const digest256 ContentsA = SHA2_256(std::string{} + 
            "Capitalists will always be able to expend more energy that socialists.");
        
        const digest256 ContentsB = SHA2_256(std::string{} + 
            "It's very difficult to censor a message that has lots of proof-of-work because everyone wants to see it."); 
        
        EXPECT_NE(ContentsA, ContentsB) << "ContentA and ContentB are equal. Contents must be different for negative tests.";
        
        const work::compact Target{32, 0x0080ff};
            
        EXPECT_TRUE(Target.valid()) << "Target is not valid. ";
        
        const uint32_little UserNonce{77777777}; 
        
        const Stratum::job_id JobID{0}; 
        
        const Stratum::worker_name WorkerName{"Lubzuguv"}; 
        
        const Bitcoin::timestamp Start{1111};
        
        const uint32_little InitialNonce{0};
        
        const uint64 InitialKey{13034};
        
        const digest160 Tag = Bitcoin::Hash160(std::string{"kangaroos"});
        
        const bytes AdditionalData = bytes::from_string("contextual information aka metadata");
        
        Bitcoin::signature Signature{}; // Don't need a real signature. 
        
        // Here are the test cases. 
        const list<test_case> test_cases = list<test_case>{} << 
            // This is an invalid case. The rest are valid. 
            test_case{
                output_script{}, 
                JobID, Start, 
                Stratum::worker{WorkerName, {97979}}, 
                302203233,
                InitialKey} << 
            // We vary test cases over bounty/contract, contents, and version bits.
            test_case{ // bounty v1 
                Boost::bounty, 
                ContentsA, 
                Target, 
                bytes_view(Tag), 
                UserNonce, 
                AdditionalData, 
                JobID, Start, 
                Stratum::worker{WorkerName, {97980}}, 
                302203234,
                InitialKey + 1} << 
            test_case{ // contract v1
                Boost::contract, 
                ContentsA, 
                Target, bytes_view(Tag), 
                UserNonce + 1, 
                AdditionalData, 
                JobID, Start, 
                Stratum::worker{WorkerName, {97981}}, 
                302203235,
                InitialKey + 2} << 
            test_case{ // bounty v1
                Boost::bounty, 
                ContentsB, 
                Target, bytes_view(Tag), 
                UserNonce + 2, 
                AdditionalData,
                JobID, Start, 
                Stratum::worker{WorkerName, {97982}}, 
                302203236,
                InitialKey + 3} << 
            test_case{ // contract v1
                Boost::contract, 
                ContentsB, 
                Target, bytes_view(Tag), 
                UserNonce + 3, 
                AdditionalData,
                JobID, Start, 
                Stratum::worker{WorkerName, {97983}}, 
                302203237,
                InitialKey + 4} << 
            test_case{ // bounty v2
                Boost::bounty, 
                ContentsA, 
                Target, 
                bytes_view(Tag), 
                UserNonce, 
                AdditionalData, 
                0xabcd,
                JobID, Start, 
                Stratum::worker{WorkerName, {97980}, work::ASICBoost::Mask}, 
                302203234,
                InitialKey + 5} << 
            test_case{ // contract v2
                Boost::contract, 
                ContentsA, 
                Target, bytes_view(Tag), 
                UserNonce + 1, 
                AdditionalData, 
                0xabcd,
                JobID, Start, 
                Stratum::worker{WorkerName, {97981}, work::ASICBoost::Mask}, 
                302203235,
                InitialKey + 6} << 
            test_case{ // bounty v2
                Boost::bounty, 
                ContentsB, 
                Target, bytes_view(Tag), 
                UserNonce + 2, 
                AdditionalData,
                0xabcd,
                JobID, Start, 
                Stratum::worker{WorkerName, {97982}, work::ASICBoost::Mask}, 
                302203236,
                InitialKey + 7} << 
            test_case{ // contract v2
                Boost::contract, 
                ContentsB, 
                Target, bytes_view(Tag), 
                UserNonce + 3, 
                AdditionalData,
                0xabcd,
                JobID, Start, 
                Stratum::worker{WorkerName, {97983}, work::ASICBoost::Mask}, 
                302203237,
                InitialKey + 8};
                
        // Phase 1: Test whether all the different representations of puzzles have the same values of valid/invalid. 
        
        // here is the list of jobs. 
        const list<puzzle> puzzles = data::for_each([](const test_case t) -> puzzle {
            return t.Puzzle;
        }, test_cases);
        
        // The list of validity values. 
        auto puzzle_validity = data::for_each([](const puzzle j) -> bool {
            return j.valid();
        }, puzzles);
                
        // Here is the list of output scripts. 
        const list<output_script> output_scripts = data::for_each([](const test_case t) -> output_script {
            return t.Script;
        }, test_cases);
        
        auto output_script_validity = data::for_each([](const output_script p) -> bool {
            return p.valid();
        }, output_scripts);
        
        EXPECT_TRUE(test_equal(puzzle_validity, output_script_validity)) << "puzzles and output scripts do not have equal validity.";
        
        // Here are the stratum jobs. 
        auto Stratum_jobs = data::for_each([](const test_case& t) -> Stratum::job {
            return t.Job;
        }, test_cases);
        
        auto stratum_job_validity = data::for_each([](const Stratum::job j) -> bool {
            return j.valid();
        }, Stratum_jobs);
        
        EXPECT_TRUE(test_equal(puzzle_validity, stratum_job_validity)) << "puzzles and Stratum jobs do not have equal validity.";
        
        // Phase 2: output scripts should be equal to those reconstructed from puzzles. 
        
        auto output_scripts_from_puzzles = data::for_each([](const puzzle j) -> output_script {
            return j.output_script();
        }, puzzles);
        
        EXPECT_TRUE(test_orthogonal(output_scripts, output_scripts_from_puzzles)) << "could not reconstruct output scripts from puzzles";
        
        // Phase 3: puzzles should be equal to those reconstructed from Stratum jobs. 
        
        auto boost_puzzle_to_work_puzzle = data::for_each([](puzzle p) -> work::puzzle {
            return static_cast<work::puzzle>(p);
        }, puzzles);
        
        auto stratum_job_to_work_puzzle = data::for_each([](Stratum::job j) -> work::puzzle {
            return work::job(j).Puzzle;
        }, Stratum_jobs);
        
        EXPECT_TRUE(test_equal(boost_puzzle_to_work_puzzle, stratum_job_to_work_puzzle)) << "could not reconstruct puzzles from jobs.";
        
        // Phase 4: generate solutions and check validity. 
        
        auto proofs = data::for_each([](const test_case t) -> work::proof {
            return t.solve();
        }, test_cases);
        
        auto proof_validity = data::for_each([](work::proof p) -> bool {
            return p.valid();
        }, proofs);
        
        EXPECT_TRUE(test_equal(puzzle_validity, proof_validity)) << "proofs are not valid.";
        
        // Phase 5: proofs from Boost inputs and outputs. 
        
        // here are the input scripts. 
        auto input_scripts = map_thread<input_script>([Signature](const test_case t, work::proof i) -> input_script {
            return input_script{Signature, t.Key.to_public(), i.Solution, t.Puzzle.Type, bool(i.Solution.Share.Bits)};
        }, test_cases, proofs);
        
        auto proofs_from_scripts = map_thread<work::proof>([](output_script o, input_script i) -> work::proof {
            return static_cast<work::proof>(proof{o, i});
        }, output_scripts, input_scripts);
        
        EXPECT_TRUE(test_orthogonal(proofs, proofs_from_scripts)) << "could not reconstruct proofs from scripts.";
        
        // Phase 6: check scripts valid. 
        
        // serialized forms of the output and input scripts. 
        list<script> serialized_output_scripts = data::for_each([](const output_script o) -> script {
            auto script = o.write();
            EXPECT_EQ(script.size(), o.serialized_size());
            return script;
        }, output_scripts);
        
        auto unserialized_output_scripts = data::for_each([](const script o) -> output_script {
            return output_script(o);
        }, serialized_output_scripts);
        
        EXPECT_TRUE(test_orthogonal(output_scripts, unserialized_output_scripts)) << "could not serialize and deserialize output scripts.";
        
        list<script> serialized_input_scripts = data::for_each([](const input_script i) -> script {
            auto script = i.write();
            EXPECT_EQ(script.size(), i.serialized_size());
            return script;
        }, input_scripts);
        
        auto unserialized_input_scripts = data::for_each([](const script o) -> input_script {
            return input_script(o);
        }, serialized_input_scripts);
        
        EXPECT_TRUE(test_orthogonal(input_scripts, unserialized_input_scripts)) << "could not serialize and deserialize input scripts.";
        
        list<scripts> list_of_scripts = map_thread<scripts>([](const bytes in, const bytes out) -> scripts {
            return scripts{in, out};
        }, serialized_input_scripts, serialized_output_scripts);
        
        bool check_scripts = dot_cross([](bytes_view in, bytes_view out) {
            return Bitcoin::evaluate(in, out);
        }, serialized_input_scripts.rest(), serialized_output_scripts.rest());
        
        EXPECT_TRUE(check_scripts) << "Boost scripts are not valid.";
        
        /*{
            auto in = serialized_input_scripts.rest();
            auto out = serialized_output_scripts.rest();
            
            while (!data::empty(in)) {
                Bitcoin::interpreter::machine m{in.first(), out.first()};
                step_through(m);
                in = in.rest();
                out = out.rest();
            }
        }*/
    
        // Phase 7: proofs from Stratum jobs and shares. 
        
        // The Stratum shares. 
        auto Stratum_shares = data::for_each([WorkerName, JobID](work::proof x) -> Stratum::share {
            return Stratum::share{WorkerName, JobID, x.Solution.Share};
        }, proofs);
        
        auto proofs_from_stratum = map_thread<work::proof>([](Stratum::job j, Stratum::share sh) -> work::proof {
            return Stratum::solved{j, sh}.proof();
        }, Stratum_jobs, Stratum_shares);
        
        EXPECT_TRUE(test_orthogonal(proofs, proofs_from_stratum)) << "could not reconstruct proofs from Stratum.";
        
    }
    
    TEST(BoostTest, DoExtraPoW1) {
        
        Bitcoin::transaction tx = Bitcoin::transaction{*data::encoding::hex::read(encoding::hex::string{
            "010000000174d9f6dc235207fbbcdff7bdc412dcb375eb634da698ed164cc1e9aa1b88729a040000006b4830450221008596410738406e0e85892"
            "92a0e7a4d960e739025ab1859a3df6c77b4cf8c59ac0220733024f199162bc7b9ccd648aae56f0a0e307558a9827a26d35b1016de1865c54121025a77fe27d1db166"
            "b660205ff08b97f7dd87c7c68edaa2931895c2c8577f1a351ffffffff027d20000000000000e108626f6f7374706f777504000000002035b8fcb6882f93bddb928c9"
            "872198bcdf057ab93ed615ad938f24a63abde588104ffff001d140000000000000000000000000000000000000000040000000020000000000000000000000000000"
            "00000000000000000000000000000000000007e7c557a766b7e52796b557a8254887e557a8258887e7c7eaa7c6b7e7e7c8254887e6c7e7c8254887eaa01007e816c8"
            "25488537f7681530121a5696b768100a0691d00000000000000000000000000000000000000000000000000000000007e6c539458959901007e819f6976a96c88acb"
            "461590e000000001976a914ba6e459a2b505dc78e44e8c5874776c00890e16088ac00000000"})};
        
        list<Boost::output> boost_outputs; 
        
        for(const Bitcoin::output& o : tx.Outputs) {
            auto x = Boost::output_script::read(o.Script);
            
            Boost::output b{o};
            if (b.valid()) boost_outputs = boost_outputs << b;
        }
        
        EXPECT_EQ(boost_outputs.size(), 1);
        
        Boost::output_script boost_script{boost_outputs.first().Script};
        
        encoding::hex::string signature_hex{"00"};
        encoding::hex::string minerPubKey_hex{"00"};
        encoding::hex::string extraNonce1_hex{"0a00000a"};
        encoding::hex::string extraNonce2_hex{"bf07000000000000"};
        encoding::hex::string time_hex{"5e6dc081"};
        encoding::hex::string minerPubKeyHash_hex{"9fb8cb68b8850a13c7438e26e1d277b748be657a"};
        
        bytes signature(1); 
        bytes pubkey(1);  
        uint32_little nonce{2089482288};
        uint32_little timestamp{};
        Stratum::session_id extra_nonce_1{}; 
        digest160 miner_address{};
        
        bytes signature_bytes = bytes(signature_hex);
        bytes minerPubKey_bytes = bytes(minerPubKey_hex);
        bytes extraNonce1_bytes = bytes(extraNonce1_hex);
        bytes extra_nonce_2 = bytes(extraNonce2_hex);
        bytes time_bytes = bytes(time_hex);
        bytes minerPubKeyHash_bytes = bytes(minerPubKeyHash_hex);
        
        std::copy(signature_bytes.begin(), signature_bytes.end(), signature.begin());
        std::copy(minerPubKey_bytes.begin(), minerPubKey_bytes.end(), pubkey.begin());
        std::copy(extraNonce1_bytes.begin(), extraNonce1_bytes.end(), extra_nonce_1.begin());
        
        std::copy(time_bytes.begin(), time_bytes.end(), timestamp.begin());
        
        std::copy(minerPubKeyHash_bytes.begin(), minerPubKeyHash_bytes.end(), miner_address.begin());
        
        work::puzzle puzzle{work::candidate{boost_script.Category, boost_script.Content, boost_script.Target, Merkle::path{}}, 
            Boost::puzzle::header(boost_script.Tag, miner_address), 
            Boost::puzzle::body(boost_script.UserNonce, boost_script.AdditionalData)};
            
        work::proof pr = work::cpu_solve(puzzle, work::solution{Bitcoin::timestamp{timestamp}, nonce, extra_nonce_2, extra_nonce_1});
        
        EXPECT_EQ(pr.Solution.Share.Nonce, nonce);
        
    }

    TEST(BoostTest, DoExtraPoW2) {
        
        Bitcoin::transaction tx = Bitcoin::transaction{*data::encoding::hex::read(encoding::hex::string{
            "01000000018ff2fe10e8629051853507b4189bf3981569a0d358e0506033a11618f2e3b10c010000006b483045022100f82288631d8c8b6b6fba"
            "9094a6d56af6ab572347b7365dcf7e6d68905cb8fd000220390cde292cc50a92bd60e680bfcbddf17443d904c7372880b6ec312a06952fb3412102be82a62c8c3d8"
            "e949c9b54a60b4cadf0efacec08164b3eca3b6e793f52bf8d8affffffff0220090000000000001976a914cdb2b66b5fa33fa3f55fb9296f31d445892d990988ace2"
            "18000000000000e108626f6f7374706f7775047800000020325593000000000000000000000000000000000000000000000000000000000004ffff001d142312000"
            "00000000000000000000000000000000004886600002094000000000000000000000000000000000000000000000000000000000000007e7c557a766b7e52796b55"
            "7a8254887e557a8258887e7c7eaa7c6b7e7e7c8254887e6c7e7c8254887eaa01007e816c825488537f7681530121a5696b768100a0691d000000000000000000000"
            "00000000000000000000000000000000000007e6c539458959901007e819f6976a96c88ac00000000"})};
        
        list<Boost::output> boost_outputs; 
        
        for(const Bitcoin::output& o : tx.Outputs) {
            Boost::output b{o};
            if (b.valid()) boost_outputs = boost_outputs << b;
        }
        
        EXPECT_EQ(boost_outputs.size(), 1);
        
        Boost::output_script boost_script{boost_outputs.first().Script};
        
        encoding::hex::string signature_hex{"00"};
        encoding::hex::string minerPubKey_hex{"02f96821f6d9a6150e0ea06b00c8c77597e863330041be70438ff6fb211d7efe66"};
        encoding::hex::string extraNonce2_hex{"0000000000000000"};
        encoding::hex::string time_hex{"5e802ed9"};
        encoding::hex::string minerPubKeyHash_hex{"92e4d5ab4bb067f872d28f44d3e5433e56fca190"};
        
        bytes signature(1); 
        bytes pubkey(minerPubKey_hex.size() / 2);  
        uint32_little nonce{0x10AC9844};
        uint32_little timestamp{};
        Stratum::session_id extra_nonce_1{1174405125}; 
        digest160 miner_address{};
        
        bytes signature_bytes = bytes(signature_hex);
        bytes minerPubKey_bytes = bytes(minerPubKey_hex);
        bytes extra_nonce_2 = bytes(extraNonce2_hex);
        bytes time_bytes = bytes(time_hex);
        bytes minerPubKeyHash_bytes = bytes(minerPubKeyHash_hex);
            
        std::copy(signature_bytes.begin(), signature_bytes.end(), signature.begin());
        std::copy(minerPubKey_bytes.begin(), minerPubKey_bytes.end(), pubkey.begin());
        
        std::copy(time_bytes.begin(), time_bytes.end(), timestamp.begin());
        
        std::copy(minerPubKeyHash_bytes.begin(), minerPubKeyHash_bytes.end(), miner_address.begin());
        
        work::puzzle puzzle{work::candidate{boost_script.Category, 
            boost_script.Content, boost_script.Target, Merkle::path{}}, 
            Boost::puzzle::header(boost_script.Tag, miner_address), 
            Boost::puzzle::body(boost_script.UserNonce, boost_script.AdditionalData)};
        
        uint64_big n2;
        std::copy(extra_nonce_2.begin(), extra_nonce_2.end(), n2.begin());
        n2 += 5;
        std::copy(n2.begin(), n2.end(), extra_nonce_2.begin());
        
        work::proof pr = work::cpu_solve(puzzle, work::solution{Bitcoin::timestamp{timestamp}, nonce, extra_nonce_2, extra_nonce_1});
        
        EXPECT_EQ(pr.Solution.Share.Nonce, nonce);
        
    }
    
    // this is used to test against the boostpow-js library. 
    TEST(BoostTest, TestAgainstBoostPoWJS) {
        bytes content_string = bytes::from_string("hello animal");
        bytes tag_string = bytes::from_string("this is a tag");
        bytes data_string = bytes::from_string("this is more additionalData");
        
        digest256 content{};
        std::copy(content_string.begin(), content_string.end(), content.begin());
        
        // the inputs for the boost output (locking) script.  
        encoding::hex::string given_category{"d2040000"};
        encoding::hex::string given_user_nonce{"c8010000"};
        encoding::hex::string given_tag = encoding::hex::write(tag_string);
        encoding::hex::string given_additional_data = encoding::hex::write(data_string);
        work::difficulty given_diff{0.0001};
        
        // the inputs for the boost input (unlocking) script. 
        encoding::hex::string given_signature{"300602010a02010b41"};
        encoding::hex::string given_miner_pubkey{"020000000000000000000000000000000000000000000000000000000000000007"};
        encoding::hex::string given_nonce_v1{"f8fc1600"};
        encoding::hex::string given_nonce_v2{"04670400"};
        encoding::hex::string given_extra_nonce_1{"02000000"};
        encoding::hex::string given_extra_nonce_2{"0000000300000003"};
        encoding::hex::string given_time{"12300009"};
        
        // getMinerPubkeyHashHex() => "1A7340DA6FB3F728439A4BECFCA9CBEDDAF8795F"
        // getMinerPubkeyHashString() => "13Qrdvv3cXys9aryjZho6vHxDW3PRgX5pm"
        Bitcoin::pubkey miner_pubkey{given_miner_pubkey};
        Bitcoin::address miner_address = miner_pubkey.address(Bitcoin::address::main);
        
        // for version 2, we use general purpose bits. 
        encoding::hex::string general_purpose_bits{"ffffffff"};
        
        // expected values that are returned from the scripts. 
        
        // getCategoryNumber() => 1234
        int32_little expected_category_number_v1;
        int32_little general_purpose_bits_number;
        int32_little expected_category_number_v2;
        
        boost::algorithm::unhex(given_category.begin(), given_category.end(), expected_category_number_v1.begin());
        boost::algorithm::unhex(general_purpose_bits.begin(), general_purpose_bits.end(), general_purpose_bits_number.begin());
        expected_category_number_v2 = (work::ASICBoost::Mask & expected_category_number_v1) | 
            (work::ASICBoost::Bits & general_purpose_bits_number);
        
        // should be 0x1e270fd8 in little endian, ie d80f271e
        //  1e is the exponent, 
        //  0x270fd8 are the digits. 
        work::compact compact(given_diff);
        
        // getUserNonceNumber() => 456
        uint32_little expected_user_nonce_number;
        boost::algorithm::unhex(given_user_nonce.begin(), given_user_nonce.end(), expected_user_nonce_number.begin());
        
        Bitcoin::signature signature{bytes(given_signature)};
        
        // getNonceNumber() => 1175034
        uint32_little expected_nonce_number_v1;
        uint32_little expected_nonce_number_v2;
        boost::algorithm::unhex(given_nonce_v1.begin(), given_nonce_v1.end(), expected_nonce_number_v1.begin());
        boost::algorithm::unhex(given_nonce_v2.begin(), given_nonce_v2.end(), expected_nonce_number_v2.begin());
        
        // getTimeNumber() => 151007250
        uint32_little expected_time_number;
        boost::algorithm::unhex(given_time.begin(), given_time.end(), expected_time_number.begin());
        
        // getExtraNonce1Number() => 33554432
        uint32_big expected_extra_nonce_1_number;
        boost::algorithm::unhex(given_extra_nonce_1.begin(), given_extra_nonce_1.end(), expected_extra_nonce_1_number.begin());
        
        // getExtraNonce2Number() => 12884901891
        uint64_big expected_extra_nonce_2_number;
        bytes expected_extra_nonce_2(8);
        boost::algorithm::unhex(given_extra_nonce_2.begin(), given_extra_nonce_2.end(), expected_extra_nonce_2_number.begin());
        std::copy(expected_extra_nonce_2_number.begin(), expected_extra_nonce_2_number.end(), expected_extra_nonce_2.begin());
        
        output_script locking_script_bounty_v1 = output_script::bounty(
            expected_category_number_v1, 
            content, 
            compact, 
            bytes(given_tag), 
            expected_user_nonce_number, 
            bytes(given_additional_data), false);
        
        output_script locking_script_bounty_v2 = output_script::bounty(
            expected_category_number_v1, 
            content, 
            compact, 
            bytes(given_tag), 
            expected_user_nonce_number, 
            bytes(given_additional_data), true);
        
        output_script locking_script_contract_v1 = output_script::contract(
            expected_category_number_v1, 
            content, 
            compact, 
            bytes(given_tag), 
            expected_user_nonce_number, 
            bytes(given_additional_data), 
            miner_address.Digest, false);
        
        output_script locking_script_contract_v2 = output_script::contract(
            expected_category_number_v1, 
            content, 
            compact, 
            bytes(given_tag), 
            expected_user_nonce_number, 
            bytes(given_additional_data), 
            miner_address.Digest, true);
        
        EXPECT_TRUE(locking_script_bounty_v1.valid());
        EXPECT_TRUE(locking_script_bounty_v2.valid());
        
        EXPECT_TRUE(locking_script_contract_v1.valid());
        EXPECT_TRUE(locking_script_contract_v2.valid());
        
        // test that category and user nonce are correct. This is actually trivial here but it is something
        // that needs to be done properly in the javascript lib. 
        EXPECT_EQ(locking_script_bounty_v1.Category, expected_category_number_v1);
        EXPECT_EQ(locking_script_bounty_v1.UserNonce, expected_user_nonce_number);
        EXPECT_EQ(locking_script_bounty_v2.UserNonce, expected_user_nonce_number);
        
        EXPECT_EQ(locking_script_contract_v1.Category, expected_category_number_v1);
        EXPECT_EQ(locking_script_contract_v1.UserNonce, expected_user_nonce_number);
        EXPECT_EQ(locking_script_contract_v2.UserNonce, expected_user_nonce_number);
        
        Stratum::session_id extra_nonce_1{expected_extra_nonce_1_number};
        Bitcoin::timestamp timestamp{expected_time_number};
        
        input_script unlocking_script_bounty_v1 = input_script::bounty(
            Bitcoin::signature(bytes(given_signature)), 
            miner_pubkey, 
            expected_nonce_number_v1, 
            timestamp, 
            expected_extra_nonce_2, 
            extra_nonce_1, 
            miner_address.Digest);
        
        input_script unlocking_script_bounty_v2 = input_script::bounty(
            Bitcoin::signature(bytes(given_signature)), 
            miner_pubkey, 
            expected_nonce_number_v2, 
            timestamp, 
            expected_extra_nonce_2, 
            extra_nonce_1, 
            general_purpose_bits_number, 
            miner_address.Digest);
        
        input_script unlocking_script_contract_v1 = input_script::contract(
            Bitcoin::signature(bytes(given_signature)), 
            miner_pubkey, 
            expected_nonce_number_v1, 
            timestamp, 
            expected_extra_nonce_2, 
            extra_nonce_1);
        
        input_script unlocking_script_contract_v2 = input_script::contract(
            Bitcoin::signature(bytes(given_signature)), 
            miner_pubkey, 
            expected_nonce_number_v2, 
            timestamp, 
            expected_extra_nonce_2, 
            extra_nonce_1, 
            general_purpose_bits_number);
        
        EXPECT_TRUE(unlocking_script_bounty_v1.valid());
        EXPECT_TRUE(unlocking_script_bounty_v2.valid());
        
        EXPECT_TRUE(unlocking_script_contract_v1.valid());
        EXPECT_TRUE(unlocking_script_contract_v2.valid());
        
        bytes out_bounty_v1 = locking_script_bounty_v1.write();
        bytes in_bounty_v1 = unlocking_script_bounty_v1.write();
        bytes out_bounty_v2 = locking_script_bounty_v2.write();
        bytes in_bounty_v2 = unlocking_script_bounty_v2.write();
        
        bytes out_contract_v1 = locking_script_contract_v1.write();
        bytes in_contract_v1 = unlocking_script_contract_v1.write();
        bytes out_contract_v2 = locking_script_contract_v2.write();
        bytes in_contract_v2 = unlocking_script_contract_v2.write();
        
        // expected scripts in ASM. 
        
        string expected_locking_script_ASM_bounty_v1{"626F6F7374706F77 OP_DROP D2040000 "
            "68656C6C6F20616E696D616C0000000000000000000000000000000000000000 "
            "D80F271E 74686973206973206120746167 C8010000 74686973206973206D6F7265206164646974696F6E616C44617461 " 
            "OP_CAT OP_SWAP OP_5 OP_ROLL OP_DUP OP_TOALTSTACK OP_CAT OP_2 OP_PICK OP_TOALTSTACK OP_5 OP_ROLL OP_SIZE OP_4 OP_EQUALVERIFY "
            "OP_CAT OP_5 OP_ROLL OP_SIZE OP_8 OP_EQUALVERIFY OP_CAT OP_SWAP OP_CAT OP_HASH256 OP_SWAP OP_TOALTSTACK OP_CAT OP_CAT OP_SWAP "
            "OP_SIZE OP_4 OP_EQUALVERIFY OP_CAT OP_FROMALTSTACK OP_CAT OP_SWAP OP_SIZE OP_4 OP_EQUALVERIFY OP_CAT OP_HASH256 00 OP_CAT "
            "OP_BIN2NUM OP_FROMALTSTACK OP_SIZE OP_4 OP_EQUALVERIFY OP_3 OP_SPLIT OP_DUP OP_BIN2NUM OP_3 21 OP_WITHIN OP_VERIFY "
            "OP_TOALTSTACK OP_DUP OP_BIN2NUM 0 OP_GREATERTHAN OP_VERIFY 0000000000000000000000000000000000000000000000000000000000 "
            "OP_CAT OP_FROMALTSTACK OP_3 OP_SUB OP_8 OP_MUL OP_RSHIFT 00 OP_CAT OP_BIN2NUM OP_LESSTHAN OP_VERIFY OP_DUP OP_HASH160 "
            "OP_FROMALTSTACK OP_EQUALVERIFY OP_CHECKSIG"};
        
        string expected_unlocking_script_ASM_bounty_v1{"300602010A02010B41 "
            "020000000000000000000000000000000000000000000000000000000000000007 F8FC1600 12300009 0000000300000003 02000000 "
            "1A7340DA6FB3F728439A4BECFCA9CBEDDAF8795F"};
        
        string expected_locking_script_ASM_bounty_v2{"626F6F7374706F77 OP_DROP D2040000 "
            "68656C6C6F20616E696D616C0000000000000000000000000000000000000000 "
            "D80F271E 74686973206973206120746167 C8010000 74686973206973206D6F7265206164646974696F6E616C44617461 "
            "OP_CAT OP_SWAP OP_5 OP_ROLL OP_DUP OP_TOALTSTACK OP_CAT OP_2 OP_PICK OP_TOALTSTACK OP_6 OP_ROLL OP_SIZE OP_4 OP_EQUALVERIFY "
            "OP_CAT OP_6 OP_ROLL OP_SIZE 20 OP_LESSTHANOREQUAL OP_VERIFY OP_CAT OP_SWAP OP_CAT OP_HASH256 OP_SWAP OP_TOALTSTACK OP_CAT "
            "OP_TOALTSTACK FF1F00E0 OP_DUP OP_INVERT OP_TOALTSTACK OP_AND OP_SWAP OP_FROMALTSTACK OP_AND OP_OR OP_FROMALTSTACK OP_CAT " 
            "OP_SWAP OP_SIZE OP_4 OP_EQUALVERIFY OP_CAT OP_FROMALTSTACK OP_CAT OP_SWAP OP_SIZE OP_4 OP_EQUALVERIFY OP_CAT OP_HASH256 " 
            "00 OP_CAT OP_BIN2NUM OP_FROMALTSTACK OP_SIZE OP_4 OP_EQUALVERIFY OP_3 OP_SPLIT OP_DUP OP_BIN2NUM OP_3 21 OP_WITHIN OP_VERIFY "
            "OP_TOALTSTACK OP_DUP OP_BIN2NUM 0 OP_GREATERTHAN OP_VERIFY 0000000000000000000000000000000000000000000000000000000000 "
            "OP_CAT OP_FROMALTSTACK OP_3 OP_SUB OP_8 OP_MUL OP_RSHIFT 00 OP_CAT OP_BIN2NUM OP_LESSTHAN OP_VERIFY OP_DUP OP_HASH160 "
            "OP_FROMALTSTACK OP_EQUALVERIFY OP_CHECKSIG"};
        
        string expected_unlocking_script_ASM_bounty_v2{"300602010A02010B41 "
            "020000000000000000000000000000000000000000000000000000000000000007 04670400 12300009 0000000300000003 02000000 FFFFFFFF "
            "1A7340DA6FB3F728439A4BECFCA9CBEDDAF8795F"};
        
        string expected_locking_script_ASM_contract_v1{"626F6F7374706F77 OP_DROP 1A7340DA6FB3F728439A4BECFCA9CBEDDAF8795F D2040000 "
            "68656C6C6F20616E696D616C0000000000000000000000000000000000000000 "
            "D80F271E 74686973206973206120746167 C8010000 74686973206973206D6F7265206164646974696F6E616C44617461 "
            "OP_CAT OP_SWAP OP_5 OP_ROLL OP_DUP OP_TOALTSTACK OP_CAT OP_2 OP_PICK OP_TOALTSTACK OP_5 OP_ROLL OP_SIZE OP_4 OP_EQUALVERIFY "
            "OP_CAT OP_5 OP_ROLL OP_SIZE OP_8 OP_EQUALVERIFY OP_CAT OP_SWAP OP_CAT OP_HASH256 OP_SWAP OP_TOALTSTACK OP_CAT OP_CAT OP_SWAP "
            "OP_SIZE OP_4 OP_EQUALVERIFY OP_CAT OP_FROMALTSTACK OP_CAT OP_SWAP OP_SIZE OP_4 OP_EQUALVERIFY OP_CAT OP_HASH256 00 OP_CAT "
            "OP_BIN2NUM OP_FROMALTSTACK OP_SIZE OP_4 OP_EQUALVERIFY OP_3 OP_SPLIT OP_DUP OP_BIN2NUM OP_3 21 OP_WITHIN OP_VERIFY "
            "OP_TOALTSTACK OP_DUP OP_BIN2NUM 0 OP_GREATERTHAN OP_VERIFY 0000000000000000000000000000000000000000000000000000000000 "
            "OP_CAT OP_FROMALTSTACK OP_3 OP_SUB OP_8 OP_MUL OP_RSHIFT 00 OP_CAT OP_BIN2NUM OP_LESSTHAN OP_VERIFY OP_DUP OP_HASH160 "
            "OP_FROMALTSTACK OP_EQUALVERIFY OP_CHECKSIG"};
        
        string expected_unlocking_script_ASM_contract_v1{"300602010A02010B41 "
            "020000000000000000000000000000000000000000000000000000000000000007 F8FC1600 12300009 0000000300000003 02000000"};
        
        string expected_locking_script_ASM_contract_v2{"626F6F7374706F77 OP_DROP 1A7340DA6FB3F728439A4BECFCA9CBEDDAF8795F D2040000 "
            "68656C6C6F20616E696D616C0000000000000000000000000000000000000000 "
            "D80F271E 74686973206973206120746167 C8010000 74686973206973206D6F7265206164646974696F6E616C44617461 "
            "OP_CAT OP_SWAP OP_5 OP_ROLL OP_DUP OP_TOALTSTACK OP_CAT OP_2 OP_PICK OP_TOALTSTACK OP_6 OP_ROLL OP_SIZE OP_4 OP_EQUALVERIFY "
            "OP_CAT OP_6 OP_ROLL OP_SIZE 20 OP_LESSTHANOREQUAL OP_VERIFY OP_CAT OP_SWAP OP_CAT OP_HASH256 OP_SWAP OP_TOALTSTACK OP_CAT " 
            "OP_TOALTSTACK FF1F00E0 OP_DUP OP_INVERT OP_TOALTSTACK OP_AND OP_SWAP OP_FROMALTSTACK OP_AND OP_OR OP_FROMALTSTACK OP_CAT " 
            "OP_SWAP OP_SIZE OP_4 OP_EQUALVERIFY OP_CAT OP_FROMALTSTACK OP_CAT OP_SWAP OP_SIZE OP_4 OP_EQUALVERIFY OP_CAT OP_HASH256 " 
            "00 OP_CAT OP_BIN2NUM OP_FROMALTSTACK OP_SIZE OP_4 OP_EQUALVERIFY OP_3 OP_SPLIT OP_DUP OP_BIN2NUM OP_3 21 OP_WITHIN OP_VERIFY "
            "OP_TOALTSTACK OP_DUP OP_BIN2NUM 0 OP_GREATERTHAN OP_VERIFY 0000000000000000000000000000000000000000000000000000000000 " 
            "OP_CAT OP_FROMALTSTACK OP_3 OP_SUB OP_8 OP_MUL OP_RSHIFT 00 OP_CAT OP_BIN2NUM OP_LESSTHAN OP_VERIFY OP_DUP OP_HASH160 " 
            "OP_FROMALTSTACK OP_EQUALVERIFY OP_CHECKSIG"};
        
        string expected_unlocking_script_ASM_contract_v2{"300602010A02010B41 "
            "020000000000000000000000000000000000000000000000000000000000000007 04670400 12300009 0000000300000003 02000000 FFFFFFFF"};
        
        // test that the scripts are correct
        EXPECT_EQ(
            boost::to_upper_copy(Bitcoin::ASM(out_bounty_v1)), 
            expected_locking_script_ASM_bounty_v1);
        
        EXPECT_EQ(
            boost::to_upper_copy(Bitcoin::ASM(in_bounty_v1)), 
            expected_unlocking_script_ASM_bounty_v1);
        
        EXPECT_EQ(
            boost::to_upper_copy(Bitcoin::ASM(out_bounty_v2)), 
            expected_locking_script_ASM_bounty_v2);
        
        EXPECT_EQ(
            boost::to_upper_copy(Bitcoin::ASM(in_bounty_v2)), 
            expected_unlocking_script_ASM_bounty_v2);
        
        EXPECT_EQ(
            boost::to_upper_copy(Bitcoin::ASM(out_contract_v1)), 
            expected_locking_script_ASM_contract_v1);
        
        EXPECT_EQ(
            boost::to_upper_copy(Bitcoin::ASM(in_contract_v1)), 
            expected_unlocking_script_ASM_contract_v1);
        
        EXPECT_EQ(
            boost::to_upper_copy(Bitcoin::ASM(out_contract_v2)), 
            expected_locking_script_ASM_contract_v2);
        
        EXPECT_EQ(
            boost::to_upper_copy(Bitcoin::ASM(in_contract_v2)), 
            expected_unlocking_script_ASM_contract_v2);
        
        proof p_bounty_v1{locking_script_bounty_v1, unlocking_script_bounty_v1};
        EXPECT_TRUE(p_bounty_v1.valid());
        
        proof p_bounty_v2{locking_script_bounty_v2, unlocking_script_bounty_v2};
        EXPECT_TRUE(p_bounty_v2.valid());
        
        proof p_contract_v1{locking_script_contract_v1, unlocking_script_contract_v1};
        EXPECT_TRUE(p_contract_v1.valid());
        
        proof p_contract_v2{locking_script_contract_v2, unlocking_script_contract_v2};
        EXPECT_TRUE(p_contract_v2.valid());
        
        bool script_valid_bounty_v1 = Bitcoin::evaluate(in_bounty_v1, out_bounty_v1).verify();
        EXPECT_TRUE(script_valid_bounty_v1);
        
        bool script_valid_bounty_v2 = Bitcoin::evaluate(in_bounty_v2, out_bounty_v2).verify();
        EXPECT_TRUE(script_valid_bounty_v2);
        
        bool script_valid_contract_v1 = Bitcoin::evaluate(in_contract_v1, out_contract_v1).verify();
        EXPECT_TRUE(script_valid_contract_v1);
        
        bool script_valid_contract_v2 = Bitcoin::evaluate(in_contract_v2, out_contract_v2).verify();
        EXPECT_TRUE(script_valid_contract_v2);
        
        auto proof_contract_v1 = proof{locking_script_contract_v1, unlocking_script_contract_v1};
        auto proof_bounty_v1 = proof{locking_script_bounty_v1, unlocking_script_bounty_v1};
        auto proof_contract_v2 = proof{locking_script_contract_v2, unlocking_script_contract_v2};
        auto proof_bounty_v2 = proof{locking_script_bounty_v2, unlocking_script_bounty_v2};
        
        EXPECT_TRUE(proof_contract_v1.valid());
        EXPECT_TRUE(proof_bounty_v1.valid());
        EXPECT_TRUE(proof_contract_v2.valid());
        EXPECT_TRUE(proof_bounty_v2.valid());
        
    }
    
    // this is used to test against the boostpow-js library. 
    TEST(BoostTest, TestAgainstBoostPoWJSRedeem) {
        
        Bitcoin::secret from_key{Bitcoin::secret::main,
            secp256k1::secret{uint256{"0x0000000000000000000000000000000000000000000000000000000000000003"}}};
        
        bytes content_string = bytes::from_string("hello animal");
        bytes tag_string = bytes::from_string("this is a tag");
        bytes data_string = bytes::from_string("this is more additionalData");
        
        digest256 content{};
        std::copy(content_string.begin(), content_string.end(), content.begin());
        
        // the inputs for the boost output (locking) script.  
        encoding::hex::string given_category{"d2040000"};
        encoding::hex::string given_user_nonce{"c8010000"};
        encoding::hex::string given_tag = encoding::hex::write(tag_string);
        encoding::hex::string given_additional_data = encoding::hex::write(data_string);
        work::difficulty given_diff{0.0001};
        
        // the inputs for the boost input (unlocking) script. 
        encoding::hex::string given_nonce_v1{"f8fc1600"};
        encoding::hex::string given_nonce_v2{"04670400"};
        encoding::hex::string given_extra_nonce_1{"02000000"};
        encoding::hex::string given_extra_nonce_2_v1{"0000000300000003"};
        encoding::hex::string given_extra_nonce_2_v2{"0000000000000000000000000000000000000000000000000000000300000003"};
        
        Bitcoin::pubkey miner_pubkey = from_key.to_public();
        Bitcoin::address miner_address = miner_pubkey.address(Bitcoin::address::main);
        
        // for version 2, we use general purpose bits. 
        encoding::hex::string general_purpose_bits{"ffffffff"};
        
        // expected values that are returned from the scripts. 
        
        // getCategoryNumber() => 1234
        int32_little expected_category_number_v1;
        int32_little general_purpose_bits_number;
        int32_little expected_category_number_v2;
        
        boost::algorithm::unhex(given_category.begin(), given_category.end(), expected_category_number_v1.begin());
        boost::algorithm::unhex(general_purpose_bits.begin(), general_purpose_bits.end(), general_purpose_bits_number.begin());
        expected_category_number_v2 = (work::ASICBoost::Mask & expected_category_number_v1) | 
            (work::ASICBoost::Bits & general_purpose_bits_number);
        
        // should be 0x1e270fd8 in little endian, ie d80f271e
        //  1e is the exponent, 
        //  0x270fd8 are the digits. 
        work::compact compact(given_diff);
        
        // getUserNonceNumber() => 456
        uint32_little expected_user_nonce_number;
        boost::algorithm::unhex(given_user_nonce.begin(), given_user_nonce.end(), expected_user_nonce_number.begin());
        
        // getTimeNumber() => 151007250
        uint32_little expected_time_number{151007250};
        
        // getExtraNonce1Number() => 33554432
        Stratum::session_id expected_extra_nonce_1_number;
        boost::algorithm::unhex(given_extra_nonce_1.begin(), given_extra_nonce_1.end(), expected_extra_nonce_1_number.begin());
        
        bytes expected_extra_nonce_2_v1(8);
        bytes expected_extra_nonce_2_v2(32);
        boost::algorithm::unhex(given_extra_nonce_2_v1.begin(), given_extra_nonce_2_v1.end(), expected_extra_nonce_2_v1.begin());
        boost::algorithm::unhex(given_extra_nonce_2_v2.begin(), given_extra_nonce_2_v2.end(), expected_extra_nonce_2_v2.begin());
        
        puzzle puzzle_bounty_v1{output_script::bounty(
            expected_category_number_v1, 
            content, 
            compact, 
            bytes(given_tag), 
            expected_user_nonce_number, 
            bytes(given_additional_data), false), from_key};
        
        puzzle puzzle_bounty_v2{output_script::bounty(
            expected_category_number_v1, 
            content, 
            compact, 
            bytes(given_tag), 
            expected_user_nonce_number, 
            bytes(given_additional_data), true), from_key};
        
        puzzle puzzle_contract_v1{output_script::contract(
            expected_category_number_v1, 
            content, 
            compact, 
            bytes(given_tag), 
            expected_user_nonce_number, 
            bytes(given_additional_data), 
            miner_address.Digest, false), from_key};
        
        puzzle puzzle_contract_v2{output_script::contract(
            expected_category_number_v1, 
            content, 
            compact, 
            bytes(given_tag), 
            expected_user_nonce_number, 
            bytes(given_additional_data), 
            miner_address.Digest, true), from_key};
        
        Stratum::session_id extra_nonce_1{expected_extra_nonce_1_number};
        Bitcoin::timestamp timestamp{expected_time_number};
        
        uint32_little nonceV1{151906};
        uint32_little nonceV2{2768683};
            
        work::solution initial_v1{
            work::share{timestamp, nonceV1, expected_extra_nonce_2_v1}, 
            expected_extra_nonce_1_number};
            
        work::solution initial_v2{
            work::share{timestamp, nonceV2, expected_extra_nonce_2_v2, general_purpose_bits_number}, 
            expected_extra_nonce_1_number};
        
        work::proof final_v1 = work::cpu_solve(work::puzzle(puzzle_bounty_v1), initial_v1);
        
        work::proof final_v2 = work::cpu_solve(work::puzzle(puzzle_bounty_v2), initial_v2);
        
        work::proof proof_bounty_v1{work::puzzle(puzzle_bounty_v1), final_v1.Solution};
        work::proof proof_contract_v1{work::puzzle(puzzle_contract_v1), final_v1.Solution};
        work::proof proof_bounty_v2{work::puzzle(puzzle_bounty_v2), final_v2.Solution};
        work::proof proof_contract_v2{work::puzzle(puzzle_contract_v2), final_v2.Solution};
        
        EXPECT_TRUE(proof_bounty_v1.valid());
        EXPECT_TRUE(proof_contract_v1.valid());
        EXPECT_TRUE(proof_bounty_v2.valid());
        EXPECT_TRUE(proof_contract_v2.valid());
        
    }

}
