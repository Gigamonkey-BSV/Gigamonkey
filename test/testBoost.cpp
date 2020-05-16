#include <gigamonkey/boost/boost.hpp>
#include <gigamonkey/script.hpp>
#include <gigamonkey/address.hpp>
#include <gigamonkey/wif.hpp>
#include <gigamonkey/stratum/stratum.hpp>

#include "gtest/gtest.h"

#include <iostream>

// Boost unit tests - some details left still! 
// I don't know where this file should go just yet. 

struct scripts {
    data::bytes input_script;
    data::bytes output_script;
};
    
std::ostream& operator<<(std::ostream& o, scripts x) {
    return o << "{InputScript: " << x.input_script << ", OutputScript: " << x.output_script << "}";
}

namespace Gigamonkey::Boost {
    
    class tests {
    
        template <typename f, typename X, typename Y>
        static bool dot_cross(f foo, list<X> x, list<Y> y) {
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
            test_case(puzzle j, const output_script& x, const Stratum::job& sj, uint64_little n2, Bitcoin::secret key) : 
                Puzzle{j}, Script{x}, Job{sj}, ExtraNonce2{n2}, Key{key} {}
            
            static test_case build(
                const output_script& o, 
                Stratum::job_id jobID, 
                timestamp start, 
                const Stratum::worker& worker, 
                uint64_little n2, uint64 key) {
                Bitcoin::secret s(Bitcoin::secret::main, secp256k1::secret(secp256k1::coordinate(key)));
                puzzle Puzzle{o, s.address().Digest, worker.ExtraNonce1};
                return test_case{Puzzle, o, Stratum::job{jobID, Puzzle, worker, start, true}, n2, s};
            }
            
            static test_case build(Boost::type type, 
                const uint256& content, 
                work::target target, 
                bytes tag, 
                uint32_little user_nonce, 
                bytes data, 
                const Stratum::job_id jobID, 
                timestamp start, 
                const Stratum::worker& worker, 
                uint64_little n2, 
                uint64 key) { 
                Bitcoin::secret s(Bitcoin::secret::main, secp256k1::secret(secp256k1::coordinate(key)));
                digest160 address = s.address().Digest;
                puzzle Puzzle{type, 1, content, target, tag, user_nonce, data, address, worker.ExtraNonce1};
                
                return test_case(Puzzle, 
                    output_script{type, 1, content, target, tag, user_nonce, data, address}, 
                    Stratum::job{jobID, Puzzle, worker, start, true}, 
                    n2, s);
            }
            
        public:
            puzzle Puzzle;
            output_script Script;
            Stratum::job Job;
            uint64_little ExtraNonce2;
            Bitcoin::secret Key;
            
            test_case(
                output_script o, 
                Stratum::job_id jobID, 
                timestamp start, 
                const Stratum::worker& worker, 
                uint64_little n2, 
                uint64 key) : 
                test_case(build(o, jobID, start, worker, n2, key)) {}
            
            test_case(Boost::type type, 
                uint256 content, 
                work::target target, 
                bytes tag, 
                uint32_little user_nonce, 
                bytes data, 
                Stratum::job_id jobID, 
                timestamp start,
                const Stratum::worker& worker,
                uint64_little n2, 
                uint64 key) : 
                test_case(build(type, content, target, tag, user_nonce, data, jobID, start, worker, n2, key)) {}
        };
        
    public:
        struct response {
            bool Success;
            string Reason;
            
            response() : Success{true}, Reason{} {}
            response(string reason) : Success{false}, Reason{reason} {}
        };
        
        static response test_scripts(list<output_script> output_scripts, list<input_script> input_scripts) {
            
            // serialized forms of the output and input scripts. 
            list<script> serialized_output_scripts = data::for_each([](const output_script o) -> script {
                return o.write();
            }, output_scripts);
            
            list<script> serialized_input_scripts = data::for_each([](const input_script i) -> script {
                return i.write();
            }, input_scripts);
            
            list<scripts> list_of_scripts = map_thread<scripts>([](const bytes in, const bytes out) -> scripts {
                return scripts{in, out};
            }, serialized_input_scripts, serialized_output_scripts);
            
            if (!test_orthogonal(output_scripts, 
                data::for_each([](const script o) -> output_script {
                    return output_script(o);
                }, serialized_output_scripts))) 
                return {"could not serialize and deserialize output scripts."};
            
            if (!test_orthogonal(input_scripts, 
                data::for_each([](const script o) -> input_script {
                    return input_script(o);
                }, serialized_input_scripts))) 
                return {"could not serialize and deserialize input scripts."};
            
            if (!dot_cross([](bytes_view in, bytes_view out) {
                    return Bitcoin::evaluate_script(in, out).valid();
                }, serialized_input_scripts.rest(), serialized_output_scripts.rest())) 
                return {"Boost scripts are not valid."};
            
            return {};
        }

        response operator()(
            const digest256 ContentsA,
            const digest256 ContentsB, 
            const work::target Target, 
            const uint32_little UserNonce, 
            const Stratum::job_id JobID, 
            const Stratum::worker_name WorkerName, 
            const timestamp Start, 
            const uint32_little InitialNonce,
            const uint64 InitialKey) {
            
            if (ContentsA == ContentsB) 
                return {"ContentA and ContentB are equal. Contents must be different for negative tests."};
            
            if (!Target.valid())
                return {"Target is not valid. "};
            
            if (Target.difficulty() > work::difficulty::minimum())
                return {"Target must be under minimum difficulty for testing purposes."};
            
            if (!Start.valid())
                return {"initial timestamp is not valid. "};
            
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
                // We vary test cases over bounty/contract and over contents.
                test_case{
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
                test_case{
                    Boost::contract, 
                    ContentsA, 
                    Target, bytes_view(Tag), 
                    UserNonce, 
                    AdditionalData, 
                    JobID, Start, 
                    Stratum::worker{WorkerName, 97981}, 
                    302203235,
                    InitialKey + 2} << 
                test_case{
                    Boost::bounty, 
                    ContentsB, 
                    Target, bytes_view(Tag), 
                    UserNonce, 
                    AdditionalData,
                    JobID, Start, 
                    Stratum::worker{WorkerName, 97982}, 
                    302203236,
                    InitialKey + 3} << 
                test_case{
                    Boost::contract, 
                    ContentsB, 
                    Target, bytes_view(Tag), 
                    UserNonce, 
                    AdditionalData,
                    JobID, Start, 
                    Stratum::worker{WorkerName, 97983}, 
                    302203237,
                    InitialKey + 4};
            
            // here is the list of jobs. 
            const list<puzzle> puzzles = data::for_each([](const test_case t) -> puzzle {
                return t.Puzzle;
            }, test_cases);
                    
            // Here is the list of output scripts. 
            const list<output_script> output_scripts = data::for_each([](const test_case t) -> output_script {
                return t.Script;
            }, test_cases);
            
            // Here are the stratum jobs. 
            auto Stratum_jobs = data::for_each([](const test_case& t) -> Stratum::job {
                return t.Job;
            }, test_cases);
            
            // finally we generate solutions. 
            auto proofs = data::for_each([](const test_case t) -> work::proof {
                return work::cpu_solve(t.Puzzle, work::solution(t.Job.Notify.Now, 0, t.ExtraNonce2));
            }, test_cases);
            
            // here are the input scripts. 
            auto input_scripts = map_thread<input_script>([Signature](const test_case t, work::proof i) -> input_script {
                return input_script{Signature, t.Key.to_public(), t.Puzzle.ExtraNonce, i.Solution, t.Puzzle.Type};
            }, test_cases, proofs);
            
            // The Stratum shares. 
            auto Stratum_shares = data::for_each([WorkerName, JobID](work::proof x) -> Stratum::share {
                return Stratum::share{1, WorkerName, JobID, 
                    x.Solution.ExtraNonce, 
                    x.Solution.Timestamp, 
                    x.Solution.Nonce};
            }, proofs);
            
            // Test 1: whether jobs, output scripts, Stratum jobs, and proofs have the same value of valid/invalid. 
            
            // The list of validity values for jobs. 
            auto job_validity = data::for_each([](const puzzle j) -> bool {
                return j.valid();
            }, puzzles);
            
            if (!test_equal(job_validity,  
                data::for_each([](const output_script p) -> bool {
                    return p.valid();
                }, output_scripts)))
                return {"jobs and output scripts do not have equal validity."};
            
            if (!test_equal(job_validity, 
                data::for_each([](const Stratum::job j) -> bool {
                    return j.valid();
                }, Stratum_jobs)))
                return {"jobs and Stratum jobs do not have equal validity."};
            
            if (!test_equal(job_validity, 
                data::for_each([](work::proof p) -> bool {
                    return p.valid();
                }, proofs))) 
                return {"proofs are not valid."};
            
            // Test 2: output scripts should be equal to those reconstructed from jobs. 
            if (!test_orthogonal(output_scripts, 
                data::for_each([](const puzzle j) -> output_script {
                    return j.output_script();
                }, puzzles))) 
                return {"could not reconstruct output scripts from jobs"};
            
            // Test 3: puzzles should be equal to those reconstructed from Stratum jobs. 
            if (!test_equal(data::for_each([](puzzle p) -> work::puzzle {
                    return static_cast<work::puzzle>(p);
                }, puzzles), 
                data::for_each([](Stratum::job j) -> work::puzzle {
                    return j.puzzle();
                }, Stratum_jobs))) 
                return {"could not reconstruct puzzles from jobs."};
            
            // Test 4: proofs from Boost inputs and outputs. 
            if (!test_orthogonal(proofs, map_thread<work::proof>([](output_script o, input_script i) -> work::proof {
                return static_cast<work::proof>(proof{o, i});
            }, output_scripts, input_scripts))) 
                return {"could not reconstruct proofs from scripts."};
            
            // Test 5: proofs from Stratum jobs and shares. 
            if (!test_orthogonal(proofs, map_thread<work::proof>([](Stratum::job j, Stratum::share sh) -> work::proof {
                return Stratum::solved{j, sh}.proof();
            }, Stratum_jobs, Stratum_shares))) 
                return {"could not reconstruct proofs from Stratum."};
            /*
            // Test 6: Stratum jobs and shares to json and back. 
            if (!test_orthogonal(Stratum_jobs, 
                data::for_each([](const Stratum::job j) -> Stratum::job {
                    json serialized;
                    Stratum::job unserialized = j;
                    Stratum::to_json(serialized, unserialized.Notify);
                    Stratum::from_json(serialized, unserialized.Notify);
                    return unserialized;
                }, Stratum_jobs)))
                return {"could not convert Stratum job to json and back"};
            
            if (!test_orthogonal(Stratum_shares, 
                data::for_each([](const Stratum::share j) -> Stratum::share {
                    json serialized;
                    Stratum::share unserialized{};
                    Stratum::to_json(serialized, j);
                    Stratum::from_json(serialized, unserialized);
                    return unserialized;
                }, Stratum_shares)))
                return {"could not convert Stratum shares to json and back"};*/
            
            // Test 7: whether we can serialize and deserialize output and input scripts
            // and whether the scripts are valid. 
            return test_scripts(output_scripts, input_scripts);
        }
    
    };

}

namespace Gigamonkey {

    TEST(BoostTest, TestBoost) {

        const digest256 ContentsA = sha256(std::string{} + 
            "Capitalists will always be able to expend more energy that socialists.");
        const digest256 ContentsB = sha256(std::string{} + 
            "It's very difficult to censor a message that has lots of proof-of-work because everyone wants to see it."); 
        const uint32_little UserNonce{77777777}; 
        const Stratum::job_id JobID{0}; 
        const Stratum::worker_name WorkerName{0}; 
        const timestamp Start{1};
        
        Boost::tests::response r;
        
        EXPECT_NO_THROW(r = Boost::tests{}(
            ContentsA, ContentsB, work::target{32, 0x0080ff}, UserNonce, JobID, WorkerName, Start, 0, 13034));
        EXPECT_TRUE(r.Success) << "Tests failed because: " << r.Reason << std::endl;
        
        EXPECT_TRUE(r.Success);
    }

}
