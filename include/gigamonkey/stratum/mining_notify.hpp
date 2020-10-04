// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MINING_NOTIFY
#define GIGAMONKEY_STRATUM_MINING_NOTIFY

#include <gigamonkey/stratum/difficulty.hpp>

#include <gigamonkey/stratum/stratum.hpp>
#include <gigamonkey/stratum/mining.hpp>

namespace Gigamonkey::Stratum::mining {
    
    // Representation of a Stratum notify message. 
    struct notify : notification { 
        struct parameters {
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
                return Digest != 0 && Path.valid() && Target.valid() && Now.valid();
            } 
            
            parameters();
            parameters(job_id id, const uint256& u, const bytes& t1, const bytes& t2, 
                Merkle::digests p, int32_little v, work::compact c, Bitcoin::timestamp t, bool b);
    
            bool operator==(const parameters& b) const;
            bool operator!=(const parameters& b) const;
            
        };
        
        static Stratum::parameters serialize(const parameters&);
        static parameters deserialize(const Stratum::parameters&);
        
        using notification::notification;
        notify(const parameters& p) : notification{mining_notify, serialize(p)} {}
        notify(
            job_id id, const uint256& u, const bytes& t1, const bytes& t2, 
            Merkle::digests p, int32_little v, work::compact c, Bitcoin::timestamp t, bool b) :
            notify{parameters{id, u, t1, t2, p, v, c, t, b}} {}
    };
    
    inline notify::parameters::parameters() : 
        ID{}, Digest{}, GenerationTx1{}, GenerationTx2{}, Path{}, Version{}, Target{}, Now{}, Clean{} {}
    
    inline notify::parameters::parameters(
        job_id id, const uint256& u, const bytes& t1, const bytes& t2, 
        Merkle::digests p, int32_little v, work::compact c, Bitcoin::timestamp t, bool b) : 
        ID{id}, Digest{u}, GenerationTx1{t1}, GenerationTx2{t2}, Path{p}, Version{v}, Target{c}, Now{t}, Clean{b} {};

    bool inline notify::parameters::operator==(const parameters& b) const {
        return ID == b.ID && Digest == b.Digest && 
            GenerationTx1 == b.GenerationTx1 && GenerationTx2 == b.GenerationTx2 && 
            Path == b.Path && Version == b.Version && Target == b.Target && 
            Now == b.Now && Clean == b.Clean;
    }
    
    bool inline notify::parameters::operator!=(const parameters& b) const {
        return !(*this == b);
    }
    
}

#endif
