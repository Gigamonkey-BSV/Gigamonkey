// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MINING_NOTIFY
#define GIGAMONKEY_STRATUM_MINING_NOTIFY

#include <gigamonkey/merkle.hpp>

#include <gigamonkey/stratum/difficulty.hpp>
#include <gigamonkey/stratum/session_id.hpp>

#include <gigamonkey/stratum/stratum.hpp>

namespace Gigamonkey::Stratum::mining {
    
    // Representation of a Stratum notify message. 
    struct notify;
    
    bool operator==(const notify&, const notify&);
    bool operator!=(const notify&, const notify&);
    
    void to_json(json& j, const notify& p); 
    void from_json(const json& j, notify& p); 
    
    std::ostream& operator<<(std::ostream&, const notify&);
    
}

namespace Gigamonkey::Stratum {
    
    struct worker {
        worker_name Name;
        session_id ExtraNonce1;
        constexpr static uint32_t ExtraNonce2_size{8};
        
        worker();
        
        // for Boost
        worker(worker_name n, session_id n1);
        
        uint32_little extra_nonce_1() const;
    };
    
    bool operator==(const worker& a, const worker& b);
    bool operator!=(const worker& a, const worker& b);
    
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
        
        int32_little Version;
        
        work::compact Target;
        
        Bitcoin::timestamp Now;
        
        bool Clean;
        
        bool valid() const {
            return data::valid(Digest) && data::valid(Path) && data::valid(Target) && data::valid(Now);
        }
        
        notify();
        notify(job_id, uint256, bytes, bytes, Merkle::digests, int32_little, work::compact, Bitcoin::timestamp, bool);
        
        explicit notify(const notification&);
        explicit operator notification() const;
        
    };
    
}

namespace Gigamonkey::Stratum {
    
    inline bool operator==(const worker& a, const worker& b) {
        return a.Name == b.Name && a.ExtraNonce1 == b.ExtraNonce1;
    }
        
    inline bool operator!=(const worker& a, const worker& b) {
        return !(a == b);
    }
    
    inline worker::worker() : Name{}, ExtraNonce1{} {}
        
    inline worker::worker(worker_name n, session_id n1) : Name{n}, ExtraNonce1{n1} {}
        
    inline uint32_little worker::extra_nonce_1() const {
        return ExtraNonce1.Value;
    }
    
}

namespace Gigamonkey::Stratum::mining {
    
    inline bool operator==(const notify& a, const notify& b) {
        return a.ID == b.ID && a.Digest == b.Digest && 
            a.GenerationTx1 == b.GenerationTx1 && 
            a.GenerationTx2 == b.GenerationTx2 && 
            a.Path == b.Path && a.Version == b.Version && a.Target == b.Target && 
            a.Now == b.Now && a.Clean == b.Clean;
    }
    
    inline bool operator!=(const notify& a, const notify& b) {
        return !(a == b);
    }
    
    inline std::ostream& operator<<(std::ostream& o, const notify& r) {
        json j;
        to_json(j, r);
        return o << j;
    }
    
    inline notify::notify() : ID{}, Digest{}, GenerationTx1{}, GenerationTx2{}, Path{}, Target{}, Now{}, Clean{} {}
    
    inline notify::notify(job_id id, uint256 d, bytes tx1, bytes tx2, Merkle::digests p, 
        int32_little v, work::compact t, Bitcoin::timestamp n, bool c) : 
        ID{id}, Digest{d}, GenerationTx1{tx1}, GenerationTx2{tx2}, Path{p}, Version{v}, Target{t}, Now{n}, Clean{c} {};
    
}

#endif
