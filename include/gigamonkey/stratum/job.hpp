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
        
        bool valid() const;
        
        explicit operator work::job() const;
        Bitcoin::timestamp timestamp() const;
        
    };
    
    struct solved {
        job Job;
        share Share;
        
        solved(const job& j, const share& sh);
        
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
    
    //inline job::job(job_id i, const worker_name& name, const work::job& j, Bitcoin::timestamp now, bool clean) : 
    //    Worker{name, j.ExtraNonce1}, Notify{i, j.Puzzle, now, clean} {}
    
    inline bool job::valid() const {
        return data::valid(Worker) && data::valid(Notify);
    }
    
    inline job::operator work::job() const {
        if (!valid()) return work::job{};
        return work::job{work::puzzle{
                Notify.Version, 
                Notify.Digest, 
                Notify.Target, 
                Merkle::path{0, Notify.Path}, 
                Notify.GenerationTx1,
                Notify.GenerationTx2, 
            Worker.Mask ? *Worker.Mask : int32_little{-1}}, 
            Worker.ExtraNonce1};
    }
    
    inline Bitcoin::timestamp job::timestamp() const {
        return Notify.Now;
    }
    
    inline solved::solved(const job& j, const share&sh) : Job{j}, Share{sh} {}
    
    inline work::proof solved::proof() const {
        return work::proof{work::job(Job), Share.Share};
    }
    
    inline bool solved::valid() const {
        return proof().valid();
    }
    
}

#endif
