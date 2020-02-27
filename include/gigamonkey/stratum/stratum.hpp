#ifndef GIGAMONKEY_STRATUM_STRATUM
#define GIGAMONKEY_STRATUM_STRATUM

#include <gigamonkey/work/proof.hpp>
#include <nlohmann/json.hpp>

namespace Gigamonkey {
    // Best documentation for Stratum here: https://docs.google.com/document/d/1ocEC8OdFYrvglyXbag1yi8WoskaZoYuR5HGhwf0hWAY/edit
    
    using json = nlohmann::json;
    
    namespace Stratum {
        using id = uint64_t;
        using uint256 = Gigamonkey::uint256;
        
        // TODO I'm not sure what worker_name is really supposed to be. 
        using worker_name = uint64_t;
        
        // Representation of a Stratum notify message. 
        struct notify { 
            // would be hash of prev block for Bitcoin, contents for Boost. 
            uint256 Digest; 
            
            // Stratum separates the coinbase into two parts. Between these two parts
            // the nonces contributed from both parties (miner and mining pool) are inserted.
            bytes GenerationTx1;
            bytes GenerationTx2;
            
            // The path is always index zero, so we don't need to store an index. 
            list<digest256> Path;
            
            work::target Target;
            timestamp Now;
            
            bool Clean;
            
            notify() : Digest{}, GenerationTx1{}, GenerationTx2{}, Path{}, Target{}, Now{}, Clean{} {}
            notify(uint256 d, bytes tx1, bytes tx2, list<digest256> p, work::target t, timestamp n, bool c) : 
                Digest{d}, GenerationTx1{tx1}, GenerationTx2{tx2}, Path{p}, Target{t}, Now{n}, Clean{c} {};
            
            bool valid() const {
                return Now.valid() && Target.valid();
            }
            
            bool operator==(const notify& n) const {
                return Digest == n.Digest && GenerationTx1 == n.GenerationTx1 && GenerationTx2 == n.GenerationTx2 && Path == n.Path && Target == n.Target && Now == n.Now && Clean == n.Clean;
            }
            
            bool operator!=(const notify& n) const {
                return !operator==(n);
            }
        };
        
        // A Stratum share; also a representation of the 'submit' method.
        struct share {
            worker_name Name;
            id JobID;
            bytes ExtraNonce2;
            timestamp nTime;
            nonce nOnce;
        };
        
        void to_json(json& j, const notify& p); 

        void from_json(const json& j, notify& p); 
        
        void to_json(json& j, const share& p); 

        void from_json(const json& j, share& p); 
        
        struct worker {
            worker_name Name;
            bytes ExtraNonce1;
            uint32_t ExtraNonce2_size;
            
            worker() : Name{}, ExtraNonce1{}, ExtraNonce2_size{} {}
            worker(worker_name n, bytes n1, uint32 n2_size) : 
                Name{n}, ExtraNonce1{n1}, ExtraNonce2_size{n2_size} {};
            
            // for Boost
            worker(worker_name n, uint64_little n1) : Name{n}, ExtraNonce1(8), ExtraNonce2_size(4) {
                std::copy(n1.data(), n1.data() + 8, ExtraNonce1.begin());
            }
            
            bool operator==(const worker& w) const {
                return Name == w.Name && ExtraNonce1 == w.ExtraNonce1 && ExtraNonce2_size == w.ExtraNonce2_size;
            }
            
            bool operator!=(const worker& w) const {
                return !operator==(w);
            }
        };
        
        struct job {  
            id JobID;
            
            int32_little Version;
            
            worker Worker;
            
            notify Notify;
            
            job() : JobID{}, Version{}, Worker{}, Notify{} {}
            job(id i, int32_little v, worker w, notify n) : 
                JobID{i}, Version{v}, Worker{w}, Notify{n} {};
            
            bool valid() const {
                return Notify.valid();
            }
            
            bool operator==(const job& j) const {
                return JobID == j.JobID && Version == j.Version && Worker == j.Worker && Notify == j.Notify;
            }
            
            bool operator!=(const job& j) const {
                return !operator==(j);
            }
        };
        
        inline work::puzzle work_puzzle(job j) {
            return work::puzzle{
                j.Version, 
                j.Notify.Digest, 
                j.Notify.Target, 
                Merkle::path{j.Notify.Path, 0}, 
                j.Notify.GenerationTx1, 
                j.Notify.GenerationTx2};
        }
        
        inline work::proof work_proof(job j, share sh) {
            return work::proof{
                work_puzzle(j), 
                work::solution{
                    sh.nTime, 
                    sh.nOnce, 
                    write(j.Worker.ExtraNonce1.size() + sh.ExtraNonce2.size(), 
                        j.Worker.ExtraNonce1, 
                        sh.ExtraNonce2)}};
        }
        
        inline bool check(job j, share sh) {
            return j.Worker.Name == sh.Name && 
                j.Worker.ExtraNonce2_size == sh.ExtraNonce2.size() && 
                work_proof(j, sh).valid();
        }
    }
    
}

#endif 

