// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MINING
#define GIGAMONKEY_STRATUM_MINING

#include <gigamonkey/stratum/session_id.hpp>
#include <gigamonkey/work/proof.hpp>

namespace Gigamonkey::Stratum {
    
    using job_id = uint32;
    
    using worker_name = std::string;
    
    struct worker;
    struct share;
    
    bool operator==(const worker& a, const worker& b);
    bool operator!=(const worker& a, const worker& b);
    
    bool operator==(const share& a, const share& b);
    bool operator!=(const share& a, const share& b);
    
    struct worker {
        worker_name Name;
        session_id ExtraNonce1;
        constexpr static uint32 ExtraNonce2_size{8};
        
        worker();
        
        // for Boost
        worker(worker_name n, session_id n1);
    };
    
    // A Stratum share; also a representation of the 'submit' method.
    struct share {
        worker_name Name;
        job_id JobID;
        work::solution Solution; 
        
        share();
        share(worker_name name, job_id jid, const work::solution& x);
        share(worker_name name, job_id jid, uint64_big en2, Bitcoin::timestamp t, nonce n);
        
        bool valid() const;
    };
    
    inline bool operator==(const worker& a, const worker& b) {
        return a.Name == b.Name && a.ExtraNonce1 == b.ExtraNonce1;
    }
        
    inline bool operator!=(const worker& a, const worker& b) {
        return !(a == b);
    }
    
    inline worker::worker() : Name{}, ExtraNonce1{} {}
        
    inline worker::worker(worker_name n, session_id n1) : Name{n}, ExtraNonce1{n1} {}
    
    inline bool operator==(const share& a, const share& b) {
        return a.Name == b.Name && 
            a.JobID == b.JobID && a.Solution == b.Solution;
    }
    
    inline bool operator!=(const share& a, const share& b) {
        return !(a == b);
    }
    
    inline share::share() : Name{}, JobID{}, Solution{} {}
    
    inline share::share(worker_name name, job_id jid, const work::solution& x) : 
        Name{name}, JobID{jid}, Solution{x} {}
    
    inline share::share(worker_name name, job_id jid, uint64_big en2, Bitcoin::timestamp t, nonce n) : 
        Name{name}, JobID{jid}, Solution{t, n, en2} {}
    
    inline bool share::valid() const {
        return Name != std::string{};
    }
   
}

#endif
