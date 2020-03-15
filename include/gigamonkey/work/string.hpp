// Copyright (c) 2019-2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WORK_STRING
#define GIGAMONKEY_WORK_STRING

#include <gigamonkey/timechain.hpp>

namespace Gigamonkey::work {
    
    struct string {
        int32_little Version;
        uint256 Digest;
        uint256 MerkleRoot;
        timestamp Timestamp;
        target Target;
        nonce Nonce;
        
        string() : Version(0), Digest(0), MerkleRoot(0), Timestamp(), Target(0), Nonce(0) {}
        string(int32_little v, uint256 d, uint256 mp, timestamp ts, target tg, nonce n) : 
            Version{v}, Digest{d}, MerkleRoot{mp}, Timestamp{ts}, Target{tg}, Nonce{n} {}
        
        static string read(slice<80> x) {
            return string{
                Gigamonkey::header::version(x), 
                uint<32>{Gigamonkey::header::previous(x)}, 
                uint<32>{Gigamonkey::header::merkle_root(x)}, 
                timestamp{Gigamonkey::header::timestamp(x)}, 
                work::target{Gigamonkey::header::target(x)}, 
                Gigamonkey::header::nonce(x)};
        }
        
        explicit string(slice<80> x) : string(read(x)) {}
        
        uint<80> write() const;
        
        uint256 hash() const {
            return Bitcoin::hash256(write());
        }
        
        static bool valid(const slice<80> x) {
            return Bitcoin::hash256(x).Value < header::target(x).expand();
        }
        
        bool valid() const;
        
        explicit string(const Bitcoin::header& h) : 
            Version(h.Version), Digest(h.Previous), MerkleRoot(h.MerkleRoot), Timestamp(h.Timestamp), Target(h.Target), Nonce(h.Nonce) {}
        
        work::difficulty difficulty() const {
            return Target.difficulty();
        }
        
        explicit operator CBlockHeader() const;
        
        bool operator==(const string& x) const {
            return Version == x.Version && 
                Digest == x.Digest && 
                MerkleRoot == x.MerkleRoot && 
                Timestamp == x.Timestamp && 
                Target == x.Target && 
                Nonce == x.Nonce;
        }
        
        bool operator!=(const string& x) const {
            return !operator==(x);
        }
    };
    
}

inline std::ostream& operator<<(std::ostream& o, const Gigamonkey::work::string& work_string) {
    return o << "work_string{" << data::encoding::hex::write(work_string.write()) << "}";
}

namespace Gigamonkey::work {
    inline bool string::valid() const {
        return hash() < Target.expand();
    }
}

#endif


