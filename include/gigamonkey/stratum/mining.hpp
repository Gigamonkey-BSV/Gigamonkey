// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MINING
#define GIGAMONKEY_STRATUM_MINING

#include <gigamonkey/stratum/stratum.hpp>
#include <gigamonkey/stratum/extensions.hpp>
#include <gigamonkey/stratum/session_id.hpp>
#include <gigamonkey/work/proof.hpp>

namespace Gigamonkey::Stratum {
    
    using job_id = string;
    
    using worker_name = string;
    
    struct worker;
    struct share;
    
    bool operator == (const worker &a, const worker &b);
    bool operator != (const worker &a, const worker &b);
    
    bool operator == (const share &a, const share &b);
    bool operator != (const share &a, const share &b);
    
    struct extranonce {
        constexpr static uint32 BitcoinExtraNonce2Size {8};
        
        session_id ExtraNonce1;
        size_t ExtraNonce2Size;
        
        extranonce () : ExtraNonce1 {0}, ExtraNonce2Size {0} {}
        extranonce (session_id id) : ExtraNonce1 {id}, ExtraNonce2Size {BitcoinExtraNonce2Size} {}
        extranonce (session_id id, size_t size) : ExtraNonce1 {id}, ExtraNonce2Size {size} {}
        
        bool operator == (const extranonce &p) const {
            return ExtraNonce1 == p.ExtraNonce1 && ExtraNonce2Size == p.ExtraNonce2Size;
        }
        
        bool operator != (const extranonce &p) const {
            return !(operator == (p));
        }
        
        bool valid () const {
            return ExtraNonce2Size > 0;
        }
    };
    
    struct worker {
        worker_name Name;
        extranonce ExtraNonce;
        maybe<extensions::version_mask> Mask;
        
        worker ();
        
        worker (worker_name n, extranonce ex);
        worker (worker_name n, extranonce ex, int32_little mask);
    };
    
    // A Stratum share; also a representation of the 'submit' method.
    struct share {
        worker_name Name;
        job_id JobID;
        work::share Share; 
        
        share ();
        share (worker_name name, job_id jid, const work::share &x);
        share (worker_name name, job_id jid, bytes en2, Bitcoin::timestamp t, nonce n);
        
        bool valid () const;
    };
    
    inline bool operator == (const worker &a, const worker &b) {
        return a.Name == b.Name && a.ExtraNonce == b.ExtraNonce && a.Mask == b.Mask;
    }
        
    inline bool operator != (const worker &a, const worker &b) {
        return !(a == b);
    }
    
    inline worker::worker () : Name {}, ExtraNonce {} {}
        
    inline worker::worker (worker_name n, extranonce n1) : Name {n}, ExtraNonce {n1}, Mask {} {}
        
    inline worker::worker (worker_name n, extranonce n1, int32_little mask) : Name {n}, ExtraNonce {n1}, Mask {mask} {}
    
    inline bool operator == (const share &a, const share &b) {
        return a.Name == b.Name && 
            a.JobID == b.JobID && a.Share == b.Share;
    }
    
    inline bool operator != (const share &a, const share &b) {
        return !(a == b);
    }
    
    inline share::share () : Name {}, JobID {}, Share {} {}
    
    inline share::share (worker_name name, job_id jid, const work::share &x) :
        Name {name}, JobID {jid}, Share {x} {}
    
    inline share::share (worker_name name, job_id jid, bytes en2, Bitcoin::timestamp t, nonce n) :
        Name {name}, JobID {jid}, Share {t, n, en2} {}
    
    inline bool share::valid () const {
        return Name != std::string {};
    }
    
    std::ostream inline &operator << (std::ostream &o, const extranonce &p) {
        return o << "{ExtraNonce1: " << p.ExtraNonce1 << ", ExtraNonce2Size: " << p.ExtraNonce2Size << "}";
    }
   
}

#endif
