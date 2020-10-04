// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_JOB
#define GIGAMONKEY_STRATUM_JOB

#include <gigamonkey/address.hpp>
#include <gigamonkey/boost/boost.hpp>
#include <gigamonkey/stratum/difficulty.hpp>

#include <gigamonkey/stratum/mining_submit.hpp>
#include <gigamonkey/stratum/mining_notify.hpp>

namespace Gigamonkey::Stratum {
    
    struct job;
    struct solved;
    
    bool operator==(const job& a, const job& b);
    bool operator!=(const job& a, const job& b);
    
    bool operator==(const solved& a, const solved& b);
    bool operator!=(const solved& a, const solved& b);
    
    struct job {
        
        worker Worker;
        
        mining::notify::parameters Notify;
        
        job();
        job(const worker&, const mining::notify::parameters&);
        job(job_id, const worker_name&, const work::puzzle&, Bitcoin::timestamp, bool clean);
        
        bool valid() const;
        
        work::puzzle puzzle() const;
        Bitcoin::timestamp timestamp() const;
        
    };
    
    struct solved {
        job Job;
        share Share;
        
        solved(const job& j, const share& sh);
        solved(job_id i, const worker_name& name, const work::proof& p, bool clean);
        
        work::proof proof() const;
        
        bool valid() const;
    
    };
    
    inline bool operator==(const job& a, const job& b) {
        return a.Worker == b.Worker && a.Notify == b.Notify;
    }
        
    inline bool operator!=(const job& a, const job& b) {
        return !(a == b);
    }
    
    inline bool operator==(const solved& a, const solved& b) {
        return a.Job == b.Job && a.Share == b.Share;
    }
        
    inline bool operator!=(const solved& a, const solved& b) {
        return !(a == b);
    }
        
    inline job::job() : Worker{}, Notify{} {}
    
    inline job::job(const worker& w, const mining::notify::parameters& n) : Worker{w}, Notify{n} {}
    
    inline job::job(job_id i, const worker_name& name, const work::puzzle& puzzle, Bitcoin::timestamp now, bool clean) : 
        Worker{name, puzzle.ExtraNonce1}, 
        Notify{i, puzzle.Digest, puzzle.Header, puzzle.Body, puzzle.Path.Digests, puzzle.Category, puzzle.Target, now, clean} {}
    
    inline bool job::valid() const {
        return data::valid(Worker) && data::valid(Notify);
    }
    
    inline work::puzzle job::puzzle() const {
        if (!valid()) return work::puzzle{};
        return work::puzzle{
            Notify.Version, 
            Notify.Digest, 
            Notify.Target, 
            Merkle::path{0, Notify.Path}, 
            Notify.GenerationTx1, 
            Worker.ExtraNonce1,
            Notify.GenerationTx2};
    }
    
    inline Bitcoin::timestamp job::timestamp() const {
        return Notify.Now;
    }
    
    inline solved::solved(const job& j, const share&sh) : Job{j}, Share{sh} {}
    
    inline solved::solved(job_id i, const worker_name& name, const work::proof& p, bool clean) : 
        Job{i, name, p.Puzzle, p.Solution.Timestamp, clean}, 
        Share{name, i, p.Solution} {}
    
    inline work::proof solved::proof() const {
        return work::proof{Job.puzzle(), Share.Solution};
    }
    
    inline bool solved::valid() const {
        return proof().valid();
    }
    
}

#endif
