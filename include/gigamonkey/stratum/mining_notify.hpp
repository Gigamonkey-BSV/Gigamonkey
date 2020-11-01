// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MINING_NOTIFY
#define GIGAMONKEY_STRATUM_MINING_NOTIFY

#include <gigamonkey/stratum/stratum.hpp>
#include <gigamonkey/stratum/session_id.hpp>

namespace Gigamonkey::Stratum::mining {
    
    // Representation of a Stratum notify message. 
    struct notify;
    
    // A Stratum share; also a representation of the 'submit' method.
    struct submit;
    
    void to_json(json& j, const notify& p); 
    void from_json(const json& j, notify& p); 
    
    void to_json(json& j, const submit& p); 
    void from_json(const json& j, submit& p); 
}

namespace Gigamonkey::Stratum {
    
    using job_id = uint32;
    
    using worker_name = std::string;
    
    using share = mining::submit;
    
    struct worker {
        worker_name Name;
        session_id ExtraNonce1;
        constexpr static uint32_t ExtraNonce2_size{8};
        
        worker() : Name{}, ExtraNonce1{} {}
        
        // for Boost
        worker(worker_name n, session_id n1) : Name{n}, ExtraNonce1{n1} {}
        
        bool operator==(const worker& w) const {
            return Name == w.Name && ExtraNonce1 == w.ExtraNonce1;
        }
        
        bool operator!=(const worker& w) const {
            return !operator==(w);
        }
        
        uint32_little extra_nonce_1() const {
            return ExtraNonce1.Value;
        }
    };
    
}

namespace Gigamonkey::Stratum::mining {
    
    // Representation of a Stratum notify message. 
    struct notify { 
        job_id ID; 
        // would be hash of prev block for Bitcoin, contents for Boost. 
        uint256 Digest; 
        
        // Stratum separates the coinbase into two parts. Between these two parts
        // the nonces contributed from both parties (miner and mining pool) are inserted.
        bytes GenerationTx1;
        bytes GenerationTx2;
        
        // The path is always index zero, so we don't need to store an index. 
        Merkle::digests Path;
        
        work::compact Target;
        Bitcoin::timestamp Now;
        
        bool Clean;
        
        notify() : ID{}, Digest{}, GenerationTx1{}, GenerationTx2{}, Path{}, Target{}, Now{}, Clean{} {}
        notify(job_id id, uint256 d, bytes tx1, bytes tx2, Merkle::digests p, work::compact t, Bitcoin::timestamp n, bool c) : 
            ID{id}, Digest{d}, GenerationTx1{tx1}, GenerationTx2{tx2}, Path{p}, Target{t}, Now{n}, Clean{c} {};
        
        explicit notify(const notification&);
            
        bool valid() const {
            return Target.valid();
        }
        
        bool operator==(const notify& n) const {
            return ID == n.ID && Digest == n.Digest && 
                GenerationTx1 == n.GenerationTx1 && 
                GenerationTx2 == n.GenerationTx2 && 
                Path == n.Path && Target == n.Target && 
                Now == n.Now && Clean == n.Clean;
        }
        
        bool operator!=(const notify& n) const {
            return !operator==(n);
        }
        
        explicit operator notification() const;
    };
    
    // A Stratum share; also a representation of the 'submit' method.
    struct submit {
        request_id ID;
        worker_name Name;
        job_id JobID;
        uint64_little ExtraNonce2;
        Bitcoin::timestamp nTime;
        nonce nOnce;
        
        submit() : ID{}, Name{}, JobID{}, ExtraNonce2{}, nTime{}, nOnce{} {}
        submit(request_id id, worker_name name, job_id jid, uint64_little n2, Bitcoin::timestamp time, nonce n)
            : ID{id}, Name{name}, JobID{jid}, ExtraNonce2{n2}, nTime{time}, nOnce{n} {}
        
        explicit submit(const request& n);
        
        bool valid() const {
            return Name != std::string{};
        }
        
        bool operator==(const submit& n) const {
            return ID == n.ID && Name == n.Name && 
                JobID == n.JobID && 
                ExtraNonce2 == n.ExtraNonce2 && 
                nTime == n.nTime && nOnce == n.nOnce;
        }
        
        bool operator!=(const submit& n) const {
            return !operator==(n);
        }
        
        explicit operator request() const;
    };
    
}

namespace Gigamonkey::Stratum {
    
    struct job {  
        
        int32_little Version;
        
        worker Worker;
        
        mining::notify Notify;
        
        job() : Version{}, Worker{}, Notify{} {}
        job(int32_little v, const worker& w, mining::notify n) : 
            Version{v}, Worker{w}, Notify{n} {}
        job(job_id i, const work::puzzle& puzzle, const worker& w, Bitcoin::timestamp now, bool clean) : 
            Version{puzzle.Category}, Worker{w}, 
            Notify{i, puzzle.Digest, puzzle.Header, puzzle.Body, puzzle.Path.Digests, puzzle.Target, now, clean} {}
        
        bool valid() const {
            return Notify.valid();
        }
        
        bool operator==(const job& j) const {
            return Version == j.Version && Worker == j.Worker && Notify == j.Notify;
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
                Merkle::path{0, Notify.Path}, 
                Notify.GenerationTx1, 
                Worker.ExtraNonce1.Value,
                Notify.GenerationTx2};
        }
        
        Bitcoin::timestamp timestamp() const {
            return Bitcoin::timestamp(Notify.Now);
        }
    };
    
    struct solved {
        job Job;
        share Share;
        
        solved(const job& j, const share&sh) : Job{j}, Share{sh} {}
        
        solved(job_id i, const worker_name& name, const work::proof& p, bool clean) : 
            Job{i, p.Puzzle, worker{name, session_id{p.Puzzle.ExtraNonce}}, p.Solution.Timestamp, clean}, Share{} {}
        
        work::proof proof() const {
            return work::proof{
                Job.puzzle(), 
                work::solution{
                    Bitcoin::timestamp{Share.nTime}, 
                    Share.nOnce, 
                    Share.ExtraNonce2}};
        }
        
        bool valid() const {
            return proof().valid();
        }
    
    };
    
}

#endif
