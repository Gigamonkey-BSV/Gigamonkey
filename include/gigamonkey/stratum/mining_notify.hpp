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
            job_id JobID;
            
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
            parameters(job_id id, const work::puzzle& p, Bitcoin::timestamp t, bool b) : 
                parameters{id, p.Candidate.Digest, p.Header, p.Body, p.Candidate.Path.Digests, p.Candidate.Category, p.Candidate.Target, t, b} {}
    
            bool operator==(const parameters& b) const;
            bool operator!=(const parameters& b) const;
            
            explicit operator work::puzzle() const {
                return work::puzzle{Version, Digest, Target, Merkle::path{0, Path}, GenerationTx1, GenerationTx2};
            }
            
        };
        
        static Stratum::parameters serialize(const parameters&);
        static parameters deserialize(const Stratum::parameters&);
        
        parameters params() const {
            return deserialize(notification::params());
        }
        
        using notification::notification;
        notify(const parameters& p) : notification{mining_notify, serialize(p)} {}
        notify(
            job_id id, const uint256& u, const bytes& t1, const bytes& t2, 
            Merkle::digests p, int32_little v, work::compact c, Bitcoin::timestamp t, bool b) :
            notify{parameters{id, u, t1, t2, p, v, c, t, b}} {}
        notify(
            job_id id, const work::puzzle& p, Bitcoin::timestamp t, bool b) :
            notify{parameters{id, p, t, b}} {}
            
        static bool valid(const notification& n) {
            return n.valid() && n.method() == mining_notify && deserialize(n.params()).valid();
        }
        
        bool valid() const {
            return valid(*this);
        }
        
        friend std::ostream& operator<<(std::ostream&, const parameters &);
    };
}

namespace Gigamonkey::Stratum {
    
    struct proof {
        worker Worker;
        mining::notify::parameters Notify;
        share Share;
        
        explicit operator work::proof() const {
            return work::proof{ bool(Worker.Mask) ? 
                work::puzzle{Notify.Version, Notify.Digest, Notify.Target, 
                    Merkle::path{0, Notify.Path}, Notify.GenerationTx1, Notify.GenerationTx2, *Worker.Mask} : 
                work::puzzle{Notify.Version, Notify.Digest, Notify.Target, 
                    Merkle::path{0, Notify.Path}, Notify.GenerationTx1, Notify.GenerationTx2}, 
                work::solution{Share.Share, Worker.ExtraNonce.ExtraNonce1}};
        }
        
        bool valid() const {
            return valid(Notify.Target);
        }
        
        bool valid(const work::compact &t) const {
            return (Share.JobID == Notify.JobID) && 
                (bool(Worker.Mask) == bool(Share.Share.Bits)) && 
                (work::proof(*this).string().hash() < t.expand());
        }
    };
}

namespace Gigamonkey::Stratum::mining {
    
    inline notify::parameters::parameters() : 
        JobID{}, Digest{}, GenerationTx1{}, GenerationTx2{}, Path{}, Version{}, Target{}, Now{}, Clean{} {}
    
    inline notify::parameters::parameters(
        job_id id, const uint256& u, const bytes& t1, const bytes& t2, 
        Merkle::digests p, int32_little v, work::compact c, Bitcoin::timestamp t, bool b) : 
        JobID{id}, Digest{u}, GenerationTx1{t1}, GenerationTx2{t2}, Path{p}, Version{v}, Target{c}, Now{t}, Clean{b} {};

    bool inline notify::parameters::operator==(const parameters& b) const {
        return JobID == b.JobID && Digest == b.Digest && 
            GenerationTx1 == b.GenerationTx1 && GenerationTx2 == b.GenerationTx2 && 
            Path == b.Path && Version == b.Version && Target == b.Target && 
            Now == b.Now && Clean == b.Clean;
    }
    
    bool inline notify::parameters::operator!=(const parameters& b) const {
        return !(*this == b);
    }
    
    std::ostream inline &operator<<(std::ostream &o, const notify::parameters &p) {
        return o << "{ID: " << p.JobID << ", Digest: " << p.Digest << ", GenerationTx1 " << p.GenerationTx1 
            << ", GenerationTx2: " << p.GenerationTx2 << ", Path: " << p.Path << ", Version: " << p.Version 
            << ", Difficulty: " << work::difficulty(p.Target) << ", Now: " << p.Now << ", Clean: " << (p.Clean ? "true" : "false") << "}";
    }
    
}

#endif
