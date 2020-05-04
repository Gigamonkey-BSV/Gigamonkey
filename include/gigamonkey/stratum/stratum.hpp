#ifndef GIGAMONKEY_STRATUM_STRATUM
#define GIGAMONKEY_STRATUM_STRATUM

#include <gigamonkey/work/proof.hpp>

namespace Gigamonkey::Stratum {
    using id = uint32;
    using uint256 = Gigamonkey::uint256;
    
    using worker_name = std::string;
    
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
            return Digest == n.Digest && 
                GenerationTx1 == n.GenerationTx1 && 
                GenerationTx2 == n.GenerationTx2 && 
                Path == n.Path && Target == n.Target && 
                Now == n.Now && Clean == n.Clean;
        }
        
        bool operator!=(const notify& n) const {
            return !operator==(n);
        }
    };
    
    // A Stratum share; also a representation of the 'submit' method.
    struct share {
        worker_name Name;
        id JobID;
        uint64_little ExtraNonce2;
        timestamp nTime;
        nonce nOnce;
        
        bool valid() const {
            return Name != std::string{};
        }
    };
    
    void to_json(json& j, const notify& p); 
    void from_json(const json& j, notify& p); 
    
    void to_json(json& j, const share& p); 
    void from_json(const json& j, share& p); 
    
    struct worker {
        worker_name Name;
        uint32_little ExtraNonce1;
        constexpr static uint32_t ExtraNonce2_size{8};
        
        worker() : Name{}, ExtraNonce1{} {}
        
        // for Boost
        worker(worker_name n, uint32_little n1) : Name{n}, ExtraNonce1{n1} {}
        
        bool operator==(const worker& w) const {
            return Name == w.Name && ExtraNonce1 == w.ExtraNonce1;
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
        job(id i, int32_little v, const worker& w, notify n) : 
            JobID{i}, Version{v}, Worker{w}, Notify{n} {}
        job(id i, const work::puzzle& puzzle, const worker& w, timestamp now, bool clean) : 
            JobID{i}, Version{puzzle.Category}, Worker{w}, 
            Notify{puzzle.Digest, puzzle.Header, puzzle.Body, puzzle.Path.Hashes, puzzle.Target, now, clean} {}
        
        bool valid() const {
            return Notify.valid();
        }
        
        bool operator==(const job& j) const {
            return JobID == j.JobID && Version == j.Version && Worker == j.Worker && Notify == j.Notify;
        }
        
        bool operator!=(const job& j) const {
            return !operator==(j);
        }
        
        work::puzzle puzzle() const {
            if (!valid()) return work::puzzle{};
            return work::puzzle{
                Version, 
                Notify.Digest, 
                Notify.Target, 
                Merkle::path{Notify.Path, 0}, 
                Notify.GenerationTx1, 
                Worker.ExtraNonce1,
                Notify.GenerationTx2};
        }
    };
    
    struct solved {
        job Job;
        share Share;
        
        solved(const job& j, const share&sh) : Job{j}, Share{sh} {}
        
        solved(id i, const worker_name& name, const work::proof& p, bool clean) : 
            Job{i, p.Puzzle, worker{name, p.Puzzle.ExtraNonce}, p.Solution.Timestamp, clean}, Share{} {}
        
        work::proof proof() const {
            return work::proof{
                Job.puzzle(), 
                work::solution{
                    Share.nTime, 
                    Share.nOnce, 
                    Share.ExtraNonce2}};
        }
        
        bool valid() const {
            return proof().valid();
        }
    
    };
    
}

#endif 

