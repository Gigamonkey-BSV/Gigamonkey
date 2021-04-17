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
            uint64_big n2, 
            Bitcoin::secret key) : 
            Puzzle{j}, Script{x}, Job{sj}, ExtraNonce1{n1}, ExtraNonce2{n2}, Key{key}, Bits{} {}
            
        test_case(
            puzzle j, 
            const output_script& x, 
            const Stratum::job& sj, 
            Stratum::session_id n1, 
            uint64_big n2, 
            Bitcoin::secret key, 
            int32_little bits) : 
            Puzzle{j}, Script{x}, Job{sj}, ExtraNonce1{n1}, ExtraNonce2{n2}, Key{key}, Bits{bits} {}
        
        static test_case build(
            const output_script& o, 
            Stratum::job_id jobID, 
            Bitcoin::timestamp start, 
            const Stratum::worker& worker, 
            uint64_big n2, uint64 key) {
            Bitcoin::secret s(Bitcoin::secret::main, secp256k1::secret(secp256k1::coordinate(key)));
            puzzle Puzzle{o, s};
            return test_case{Puzzle, o, 
                Stratum::job{worker, Stratum::mining::notify::parameters{jobID, work::puzzle(Puzzle), start, true}}, 
                worker.ExtraNonce1, n2, s};
        }
        
        static test_case build(Boost::type type, 
            const uint256& content, 
            work::compact target, 
            bytes tag, 
            uint32_little user_nonce, 
            bytes data, 
            const Stratum::job_id jobID, 
            Bitcoin::timestamp start, 
            const Stratum::worker& worker, 
            uint64_big n2, 
            uint64 key) { 
            Bitcoin::secret s(Bitcoin::secret::main, secp256k1::secret(secp256k1::coordinate(key)));
            digest160 address = s.address().Digest;
            puzzle Puzzle{type, 1, content, target, tag, user_nonce, data, s, false};
            
            output_script o = type == contract ? 
                output_script::contract(1, content, target, tag, user_nonce, data, address, false) : 
                output_script::bounty(1, content, target, tag, user_nonce, data, false);
            
            return test_case(Puzzle, o, 
                Stratum::job{worker, Stratum::mining::notify::parameters{jobID, work::puzzle(Puzzle), start, true}}, 
                worker.ExtraNonce1, n2, s);
        }
        
        static test_case build(Boost::type type, 
            const uint256& content, 
            work::compact target, 
            bytes tag, 
            uint32_little user_nonce, 
            bytes data, 
            int32_little bits, 
            const Stratum::job_id jobID, 
            Bitcoin::timestamp start, 
            const Stratum::worker& worker, 
            uint64_big n2, 
            uint64 key) { 
            Bitcoin::secret s(Bitcoin::secret::main, secp256k1::secret(secp256k1::coordinate(key)));
            digest160 address = s.address().Digest;
            puzzle Puzzle{type, 1, content, target, tag, user_nonce, data, s, true};
            
            output_script o = type == contract ? 
                output_script::contract(1, content, target, tag, user_nonce, data, address, true) : 
                output_script::bounty(1, content, target, tag, user_nonce, data, true);
            
            return test_case(Puzzle, o, 
                Stratum::job{worker, Stratum::mining::notify::parameters{jobID, work::puzzle(Puzzle), start, true}}, 
                worker.ExtraNonce1, n2, s, bits);
        }
        
    public:
        puzzle Puzzle;
        output_script Script;
        Stratum::job Job;
        Stratum::session_id ExtraNonce1;
        uint64_big ExtraNonce2;
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
        
        const digest256 ContentsA = sha256(std::string{} + 
            "Capitalists will always be able to expend more energy that socialists.");
        
        const digest256 ContentsB = sha256(std::string{} + 
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
        
        const digest160 Tag = Bitcoin::hash160(std::string{"kangaroos"});
        
        const bytes AdditionalData{std::string{"contextual information aka metadata"}};
        
        Bitcoin::signature Signature{}; // Don't need a real signature. 
        
        // Here are the test cases. 
        const list<test_case> test_cases = list<test_case>{} << 
            // This is an invalid case. The rest are valid. 
            test_case{
                output_script{}, 
                JobID, Start, 
                Stratum::worker{WorkerName, 97979}, 
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
                Stratum::worker{WorkerName, 97980}, 
                302203234,
                InitialKey + 1} << 
            test_case{ // contract v1
                Boost::contract, 
                ContentsA, 
                Target, bytes_view(Tag), 
                UserNonce + 1, 
                AdditionalData, 
                JobID, Start, 
                Stratum::worker{WorkerName, 97981}, 
                302203235,
                InitialKey + 2} << 
            test_case{ // bounty v1
                Boost::bounty, 
                ContentsB, 
                Target, bytes_view(Tag), 
                UserNonce + 2, 
                AdditionalData,
                JobID, Start, 
                Stratum::worker{WorkerName, 97982}, 
                302203236,
                InitialKey + 3} << 
            test_case{ // contract v1
                Boost::contract, 
                ContentsB, 
                Target, bytes_view(Tag), 
                UserNonce + 3, 
                AdditionalData,
                JobID, Start, 
                Stratum::worker{WorkerName, 97983}, 
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
                Stratum::worker{WorkerName, 97980, work::ASICBoost::Mask}, 
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
                Stratum::worker{WorkerName, 97981, work::ASICBoost::Mask}, 
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
                Stratum::worker{WorkerName, 97982, work::ASICBoost::Mask}, 
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
                Stratum::worker{WorkerName, 97983, work::ASICBoost::Mask}, 
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
            return o.write();
        }, output_scripts);
        
        auto unserialized_output_scripts = data::for_each([](const script o) -> output_script {
            return output_script(o);
        }, serialized_output_scripts);
        
        EXPECT_TRUE(test_orthogonal(output_scripts, unserialized_output_scripts)) << "could not serialize and deserialize output scripts.";
        
        list<script> serialized_input_scripts = data::for_each([](const input_script i) -> script {
            return i.write();
        }, input_scripts);
        
        auto unserialized_input_scripts = data::for_each([](const script o) -> input_script {
            return input_script(o);
        }, serialized_input_scripts);
        
        EXPECT_TRUE(test_orthogonal(input_scripts, unserialized_input_scripts)) << "could not serialize and deserialize input scripts.";
        
        list<scripts> list_of_scripts = map_thread<scripts>([](const bytes in, const bytes out) -> scripts {
            return scripts{in, out};
        }, serialized_input_scripts, serialized_output_scripts);
        
        bool check_scripts = dot_cross([](bytes_view in, bytes_view out) {
            return Bitcoin::evaluate_script(in, out).valid();
        }, serialized_input_scripts.rest(), serialized_output_scripts.rest());
        
        EXPECT_TRUE(check_scripts) << "Boost scripts are not valid.";
    
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
        
        string raw_tx_hex{ "010000000174d9f6dc235207fbbcdff7bdc412dcb375eb634da698ed164cc1e9aa1b88729a040000006b4830450221008596410738406e0e8589292a0e7a4d960e739025ab1859a3df6c77b4cf8c59ac0220733024f199162bc7b9ccd648aae56f0a0e307558a9827a26d35b1016de1865c54121025a77fe27d1db166b660205ff08b97f7dd87c7c68edaa2931895c2c8577f1a351ffffffff027d20000000000000e108626f6f7374706f777504000000002035b8fcb6882f93bddb928c9872198bcdf057ab93ed615ad938f24a63abde588104ffff001d14000000000000000000000000000000000000000004000000002000000000000000000000000000000000000000000000000000000000000000007e7c557a766b7e52796b557a8254887e557a8258887e7c7eaa7c6b7e7e7c8254887e6c7e7c8254887eaa01007e816c825488537f7681530121a5696b768100a0691d00000000000000000000000000000000000000000000000000000000007e6c539458959901007e819f6976a96c88acb461590e000000001976a914ba6e459a2b505dc78e44e8c5874776c00890e16088ac00000000"};
        
        bytes raw_tx = *data::encoding::hex::read(raw_tx_hex); 
        Bitcoin::transaction tx = Bitcoin::transaction::read(raw_tx);
        
        list<Boost::output> boost_outputs; 
        
        for(const Bitcoin::output& o : tx.Outputs) {
            Boost::output b{o};
            if (b.valid()) boost_outputs = boost_outputs << b;
        }
        
        EXPECT_EQ(boost_outputs.size(), 1);
        
        Boost::output_script boost_script{boost_outputs.first()};
        
        string signature_hex{"00"};
        string minerPubKey_hex{"00"};
        string extraNonce1_hex{"0a00000a"};
        string extraNonce2_hex{"bf07000000000000"};
        string time_hex{"5e6dc081"};
        string minerPubKeyHash_hex{"9fb8cb68b8850a13c7438e26e1d277b748be657a"};
        
        bytes signature(1); 
        bytes pubkey(1);  
        uint32_little nonce{2089482288};
        uint32_little timestamp{};
        uint64_big extra_nonce_2{};
        Stratum::session_id extra_nonce_1{}; 
        digest160 miner_address{};
        
        bytes signature_bytes = *encoding::hex::read(signature_hex);
        bytes minerPubKey_bytes = *encoding::hex::read(minerPubKey_hex);
        bytes extraNonce1_bytes = *encoding::hex::read(extraNonce1_hex);
        bytes extraNonce2_bytes = *encoding::hex::read(extraNonce2_hex);
        bytes time_bytes = *encoding::hex::read(time_hex);
        bytes minerPubKeyHash_bytes = *encoding::hex::read(minerPubKeyHash_hex);
        
        std::copy(signature_bytes.begin(), signature_bytes.end(), signature.begin());
        std::copy(minerPubKey_bytes.begin(), minerPubKey_bytes.end(), pubkey.begin());
        std::copy(extraNonce1_bytes.begin(), extraNonce1_bytes.end(), extra_nonce_1.begin());
        
        std::copy(extraNonce2_bytes.begin(), extraNonce2_bytes.end(), extra_nonce_2.begin());
        std::copy(time_bytes.begin(), time_bytes.end(), timestamp.begin());
        
        std::copy(minerPubKeyHash_bytes.begin(), minerPubKeyHash_bytes.end(), miner_address.begin());
        
        work::puzzle puzzle{work::candidate{boost_script.Category, boost_script.Content, boost_script.Target, Merkle::path{}}, 
            Boost::puzzle::header(boost_script.Tag, miner_address), 
            Boost::puzzle::body(boost_script.UserNonce, boost_script.AdditionalData)};
            
        work::proof pr = work::cpu_solve(puzzle, work::solution{Bitcoin::timestamp{timestamp}, nonce, extra_nonce_2, extra_nonce_1});
        
        EXPECT_EQ(pr.Solution.Share.Nonce, nonce);
        
    }

    TEST(BoostTest, DoExtraPoW2) {
        
        string raw_tx_hex{ "01000000018ff2fe10e8629051853507b4189bf3981569a0d358e0506033a11618f2e3b10c010000006b483045022100f82288631d8c8b6b6fba9094a6d56af6ab572347b7365dcf7e6d68905cb8fd000220390cde292cc50a92bd60e680bfcbddf17443d904c7372880b6ec312a06952fb3412102be82a62c8c3d8e949c9b54a60b4cadf0efacec08164b3eca3b6e793f52bf8d8affffffff0220090000000000001976a914cdb2b66b5fa33fa3f55fb9296f31d445892d990988ace218000000000000e108626f6f7374706f7775047800000020325593000000000000000000000000000000000000000000000000000000000004ffff001d14231200000000000000000000000000000000000004886600002094000000000000000000000000000000000000000000000000000000000000007e7c557a766b7e52796b557a8254887e557a8258887e7c7eaa7c6b7e7e7c8254887e6c7e7c8254887eaa01007e816c825488537f7681530121a5696b768100a0691d00000000000000000000000000000000000000000000000000000000007e6c539458959901007e819f6976a96c88ac00000000"};
        
        bytes raw_tx = *data::encoding::hex::read(raw_tx_hex); 
        Bitcoin::transaction tx = Bitcoin::transaction::read(raw_tx);
        
        list<Boost::output> boost_outputs; 
        
        for(const Bitcoin::output& o : tx.Outputs) {
            Boost::output b{o};
            if (b.valid()) boost_outputs = boost_outputs << b;
        }
        
        EXPECT_EQ(boost_outputs.size(), 1);
        
        Boost::output_script boost_script{boost_outputs.first()};
        
        string signature_hex{"00"};
        string minerPubKey_hex{"02f96821f6d9a6150e0ea06b00c8c77597e863330041be70438ff6fb211d7efe66"};
        string extraNonce2_hex{"0000000000000000"};
        string time_hex{"5e802ed9"};
        string minerPubKeyHash_hex{"92e4d5ab4bb067f872d28f44d3e5433e56fca190"};
        
        bytes signature(1); 
        bytes pubkey(minerPubKey_hex.size() / 2);  
        uint32_little nonce{0x10AC9844};
        uint32_little timestamp{};
        uint64_big extra_nonce_2{};
        Stratum::session_id extra_nonce_1{1174405125}; 
        digest160 miner_address{};
        
        bytes signature_bytes = *data::encoding::hex::read(signature_hex);
        bytes minerPubKey_bytes = *data::encoding::hex::read(minerPubKey_hex);
        bytes extraNonce2_bytes = *data::encoding::hex::read(extraNonce2_hex);
        bytes time_bytes = *data::encoding::hex::read(time_hex);
        bytes minerPubKeyHash_bytes = *data::encoding::hex::read(minerPubKeyHash_hex);
            
        std::copy(signature_bytes.begin(), signature_bytes.end(), signature.begin());
        std::copy(minerPubKey_bytes.begin(), minerPubKey_bytes.end(), pubkey.begin());
        
        std::copy(extraNonce2_bytes.begin(), extraNonce2_bytes.end(), extra_nonce_2.begin());
        std::copy(time_bytes.begin(), time_bytes.end(), timestamp.begin());
        
        std::copy(minerPubKeyHash_bytes.begin(), minerPubKeyHash_bytes.end(), miner_address.begin());
        
        work::puzzle puzzle{work::candidate{boost_script.Category, boost_script.Content, boost_script.Target, Merkle::path{}}, 
            Boost::puzzle::header(boost_script.Tag, miner_address), 
            Boost::puzzle::body(boost_script.UserNonce, boost_script.AdditionalData)};
        
        extra_nonce_2 += 5;
        
        std::cout << "about to mine; extra nonce 2 = " << extra_nonce_2 << std::endl;
        
        work::proof pr = work::cpu_solve(puzzle, work::solution{Bitcoin::timestamp{timestamp}, nonce, extra_nonce_2, extra_nonce_1});
        
        EXPECT_EQ(pr.Solution.Share.Nonce, nonce);
        
        std::cout << "done mining; nonce = " << encoding::hex::write(pr.Solution.Share.Nonce) << "; extra_nonce_2 = " << encoding::hex::write(pr.Solution.Share.ExtraNonce2) << std::endl;
        
    }

}
