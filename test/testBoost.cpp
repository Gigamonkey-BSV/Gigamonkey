#include <gigamonkey/boost/boost.hpp>
#include <gigamonkey/script.hpp>
#include <gigamonkey/address.hpp>
#include <gigamonkey/wif.hpp>

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
        /*
        struct test_input {
            Boost::type Type; 
            uint256 Content; 
            work::target Target;
            bytes Tag;
            uint64_little UserNonce;
            bytes Data;
            Bitcoin::secret Key;
            uint32_little ExtraNonce;
        };
        
        static output_script get_output_script(test_input);
        
        static job get_job(test_input);*/
        
        class test_case {
            test_case(job j, output_script x, Bitcoin::secret key, uint32_little n1, uint64_little n2) : 
                Job{j}, Script{x}, Key{key}, ExtraNonce1{n1}, ExtraNonce2{n2} {}
            
            static test_case build(output_script o, uint64 key, uint32_little n1, uint64_little n2) {
                Bitcoin::secret s(Bitcoin::secret::main, secp256k1::secret(secp256k1::coordinate(key)));
                return test_case{job{o, s.address().Digest}, o, s, n1, n2};
            }
            
            static test_case build(Boost::type type, 
                uint256 content, 
                work::target target, 
                bytes tag, 
                uint32_little user_nonce, 
                bytes data, 
                uint64 key, 
                uint32_little n1, 
                uint64_little n2) { 
                Bitcoin::secret s(Bitcoin::secret::main, secp256k1::secret(secp256k1::coordinate(key)));
                uint160 address = s.address().Digest;
                
                return test_case(
                    job(type, 1, content, target, tag, user_nonce, data, address), 
                    output_script(type, 1, content, target, tag, user_nonce, data, address), 
                    s, n1, n2);
            }
            
        public:
            job Job;
            output_script Script;
            Bitcoin::secret Key;
            uint32_little ExtraNonce1;
            uint64_little ExtraNonce2;
            
            test_case(output_script o, uint64 key, uint32_little n1, uint64_little n2) : 
                test_case(build(o, key, n1, n2)) {}
            
            test_case(Boost::type type, 
                uint256 content, 
                work::target target, 
                bytes tag, 
                uint32_little user_nonce, 
                bytes data, 
                uint64 key, 
                uint32_little n1, 
                uint64_little n2) : 
                test_case(build(type, content, target, tag, user_nonce, data, key, n1, n2)) {}
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
                }, serialized_input_scripts, serialized_output_scripts)) 
                return {"Boost scripts are not valid."};
            
            return {};
        }

        response operator()(
            const digest256 ContentsA,
            const digest256 ContentsB, 
            const work::target Target, 
            const uint32_little UserNonce, 
            const Stratum::id JobID, 
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
            
            Bitcoin::signature Signature{bytes(65)}; // Don't need a real signature. 
             
            Stratum::worker Worker{WorkerName, 303};
            
            // Here are the test cases. 
            const list<test_case> test_cases = list<test_case>{} << 
                // This is an invalid case. The rest are valid. 
                test_case{
                    output_script{}, 
                    InitialKey, 
                    97979, 302203233} << 
                // We vary test cases over bounty/contract and over contents.
                test_case{
                    Boost::bounty, 
                    ContentsA, 
                    Target, 
                    bytes_view(Tag), 
                    UserNonce, 
                    AdditionalData,
                    InitialKey + 1, 
                    97980, 302203234} << 
                test_case{
                    Boost::contract, 
                    ContentsA, 
                    Target, bytes_view(Tag), 
                    UserNonce, 
                    AdditionalData, 
                    InitialKey + 2, 
                    97981, 302203235} << 
                test_case{
                    Boost::bounty, 
                    ContentsB, 
                    Target, bytes_view(Tag), 
                    UserNonce, 
                    AdditionalData,
                    InitialKey + 3, 
                    97982, 302203236} << 
                test_case{
                    Boost::contract, 
                    ContentsB, 
                    Target, bytes_view(Tag), 
                    UserNonce, 
                    AdditionalData,
                    InitialKey + 4, 
                    97983, 302203237};
            
            // here is the list of jobs. 
            const list<job> jobs = data::for_each([](const test_case t) -> job {
                return t.Job;
            }, test_cases);
                    
            // Here is the list of output scripts. 
            const list<output_script> output_scripts = data::for_each([](const test_case t) -> output_script {
                return t.Script;
            }, test_cases);
                    
            // Here is the list of output puzzles. 
            const list<work::puzzle> puzzles = data::for_each([](const test_case t) -> work::puzzle {
                return t.Job.Puzzle;
            }, test_cases);
            
            /*
            // Here are the stratum jobs. 
            auto Stratum_jobs = data::for_each([JobID, WorkerName, Start](job j) -> Stratum::job {
                output_script o = j.output_script();
                return Stratum::job(JobID, o.Category, 
                    Stratum::worker(WorkerName, o.UserNonce), 
                    Stratum::notify(o.Content, write(o.Tag.size() + 20, o.Tag, j.miner_address()), 
                        o.AdditionalData, list<digest256>{}, o.Target, Start, true));
            }, jobs);*/
            
            // finally we generate solutions. 
            auto proofs = data::for_each([Start](const test_case t) -> work::proof {
                return work::cpu_solve(t.Job.Puzzle, work::solution(Start, 0, write(12, t.ExtraNonce1, t.ExtraNonce2)));
            }, test_cases);
            
            // here are the input scripts. 
            auto input_scripts = map_thread<input_script>([Signature](const test_case t, work::proof i) -> input_script {
                return input_script{Signature, t.Key.to_public(), i.Solution, t.Job.Type};
            }, test_cases, proofs);
            
            // The Stratum shares. 
            auto shares = data::for_each([WorkerName, JobID](work::proof x) -> Stratum::share {
                return Stratum::share{WorkerName, JobID, 
                    x.Solution.ExtraNonce, 
                    x.Solution.Timestamp, 
                    x.Solution.Nonce};
            }, proofs);
            
            // Test 1: whether jobs, output scripts, Stratum jobs, and proofs have the same value of valid/invalid. 
            
            // The list of validity values for jobs. 
            auto job_validity = data::for_each([](const job j) -> bool {
                return j.valid();
            }, jobs);
            
            if (!test_equal(job_validity,  
                data::for_each([](const output_script p) -> bool {
                    return p.valid();
                }, output_scripts)))
                return {"jobs and output scripts do not have equal validity."};
            /*
            if (!test_equal(job_validity, 
                data::for_each([](const Stratum::job j) -> bool {
                    return j.valid();
                }, Stratum_jobs)))
                return {"jobs and Stratum jobs do not have equal validity."};*/
            
            if (!test_equal(job_validity, 
                data::for_each([](work::proof p) -> bool {
                    return p.valid();
                }, proofs))) 
                return {"proofs are not valid."};
            
            // Test 2: output scripts should be equal to those reconstructed from jobs. 
            if (!test_orthogonal(output_scripts, 
                data::for_each([](const job j) -> output_script {
                    return j.output_script();
                }, jobs))) 
                return {"could not reconstruct output scripts from jobs"};
            
            /*
            // Test 3: puzzles should be equal to those reconstructed from Stratum jobs. 
            if (!test_orthogonal(puzzles, 
                data::for_each([](Stratum::job j) -> work::puzzle {
                    return Stratum::work_puzzle(j);
                }, Stratum_jobs))) 
                return {"could not reconstruct puzzles from jobs."};*/
            
            // Test 4: proofs from Boost inputs and outputs. 
            /*
            if (!test_orthogonal(proofs, map_thread<work::proof>(Boost::work_proof, output_scripts, input_scripts))) 
                return {"could not reconstruct proofs from scripts."};*/
            
            // Test 5: proofs from Stratum jobs and shares. 
            /*if (!test_orthogonal(proofs, map_thread<work::proof>(Stratum::work_proof, Stratum_jobs, shares))) 
                return {"could not reconstruct proofs from Stratum."};
            
            // Test 6: Stratum job to json and back. 
            if (!test_orthogonal(Stratum_jobs, 
                data::for_each([](const Stratum::job j) -> Stratum::job {
                    json serialized;
                    Stratum::job unserialized = j;
                    Stratum::to_json(serialized, j.Notify);
                    Stratum::from_json(serialized, unserialized.Notify);
                    return unserialized;
                }, Stratum_jobs)))
                return {"could not convert Stratum job to json and back"};*/
            
            // Test 7: whether we can serialize and deserialize output and input scripts and whether the scripts are valid. 
            return test_scripts(output_scripts, input_scripts);
        }
    
    };

}

namespace Gigamonkey {

    TEST(BoostTest, TestBoost) {
        
        std::cout << "Boost Test setup" << std::endl;

        const digest256 ContentsA = sha256(std::string{} + 
            "Capitalists will always be able to expend more energy that socialists.");
        const digest256 ContentsB = sha256(std::string{} + 
            "It's very difficult to censor a message that has lots of proof-of-work because everyone wants to see it."); 
        const uint32_little UserNonce{77777777}; 
        const Stratum::id JobID{0}; 
        const Stratum::worker_name WorkerName{0}; 
        const timestamp Start{1};
        
        Boost::tests::response r;
        
        EXPECT_NO_THROW(r = Boost::tests{}(
            ContentsA, ContentsB, work::target{32, 0x0080ff}, UserNonce, JobID, WorkerName, Start, 0, 13034));
        EXPECT_TRUE(r.Success) << "Tests failed because: " << r.Reason << std::endl;
        
        EXPECT_TRUE(r.Success);
    }

}
