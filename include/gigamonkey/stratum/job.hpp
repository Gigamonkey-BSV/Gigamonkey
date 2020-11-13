// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_JOB
#define GIGAMONKEY_STRATUM_JOB

#include <gigamonkey/work/proof.hpp>
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
        
        mining::notify Notify;
        
        job();
        job(const worker& w, mining::notify n);
        job(job_id i, const work::puzzle& puzzle, const worker& w, Bitcoin::timestamp now, bool clean);
        
        bool valid() const {
            return data::valid(Worker) && data::valid(Notify);
        }
        
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
    
    inline job::job(const worker& w, mining::notify n) : Worker{w}, Notify{n} {}
    
    inline job::job(job_id i, const work::puzzle& puzzle, const worker& w, Bitcoin::timestamp now, bool clean) : 
        Worker{w}, Notify{i, puzzle.Digest, puzzle.Header, puzzle.Body, puzzle.Path.Digests, puzzle.Category, puzzle.Target, now, clean} {}
    
    inline work::puzzle job::puzzle() const {
        if (!valid()) return work::puzzle{};
        return work::puzzle{
            Notify.Version, 
            Notify.Digest, 
            Notify.Target, 
            Merkle::path{0, Notify.Path}, 
            Notify.GenerationTx1, 
            Worker.ExtraNonce1.Value,
            Notify.GenerationTx2};
    }
    
    inline Bitcoin::timestamp job::timestamp() const {
        return Notify.Now;
    }
    
    inline solved::solved(const job& j, const share&sh) : Job{j}, Share{sh} {}
    
    inline solved::solved(job_id i, const worker_name& name, const work::proof& p, bool clean) : 
        Job{i, p.Puzzle, worker{name, session_id{p.Puzzle.ExtraNonce}}, p.Solution.Timestamp, clean}, 
        Share{name, i, p.Solution} {}
    
    inline work::proof solved::proof() const {
        return work::proof{Job.puzzle(), Share.Solution};
    }
    
    inline bool solved::valid() const {
        return proof().valid();
    }
    
}

#endif
