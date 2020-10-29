// Copyright (c) 2019-2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WORK_STRING
#define GIGAMONKEY_WORK_STRING

#include <gigamonkey/timechain.hpp>

namespace Gigamonkey::work {
    
    struct string {
        int32_little Category;
        uint256 Digest;
        uint256 MerkleRoot;
        Bitcoin::timestamp Timestamp;
        compact Target;
        nonce Nonce;
        
        string() : Category(0), Digest(0), MerkleRoot(0), Timestamp(), Target(0), Nonce(0) {}
        string(int32_little v, uint256 d, uint256 mp, Bitcoin::timestamp ts, compact tg, nonce n) : 
            Category{v}, Digest{d}, MerkleRoot{mp}, Timestamp{ts}, Target{tg}, Nonce{n} {}
        
        static string read(const slice<80> x) {
            return string{
                Bitcoin::header::version(x), 
                uint<32>{Bitcoin::header::previous(x)}, 
                uint<32>{Bitcoin::header::merkle_root(x)}, 
                Bitcoin::timestamp{Bitcoin::header::timestamp(x)}, 
                compact{Bitcoin::header::target(x)}, 
                Bitcoin::header::nonce(x)};
        }
        
        explicit string(const slice<80>& x) : string(read(x)) {}
        explicit string(const bsv::CBlockHeader&);
        
        uint<80> write() const {
            return operator Bitcoin::header().write();
        }
        
        uint256 hash() const {
            return Bitcoin::hash256(write());
        }
        
        static bool valid(const slice<80> x) {
            return Bitcoin::hash256(x).Value < Bitcoin::header::target(x).expand();
        }
        
        bool valid() const;
        
        explicit string(const Bitcoin::header& h) : 
            Category(h.Version), Digest(h.Previous), MerkleRoot(h.MerkleRoot), Timestamp(h.Timestamp), Target(h.Target), Nonce(h.Nonce) {}
        
        work::difficulty difficulty() const {
            return Target.difficulty();
        }
        
        explicit operator bsv::CBlockHeader() const;
        
        explicit operator Bitcoin::header() const {
            return {Category, digest256{Digest}, digest256{MerkleRoot}, Timestamp, Target, Nonce};
        }
    };
        
    bool inline operator==(const string& x, const string& y) {
        return y.Category == x.Category && 
            y.Digest == x.Digest && 
            y.MerkleRoot == x.MerkleRoot && 
            y.Timestamp == x.Timestamp && 
            y.Target == x.Target && 
            y.Nonce == x.Nonce;
    }
    
    bool inline operator!=(const string& x, const string& y) {
        return !(x == y);
    }
    
    inline std::ostream& operator<<(std::ostream& o, const string& work_string) {
        return o << "work_string{" << data::encoding::hex::write(work_string.write()) << "}";
    }

    bool inline string::valid() const {
        return hash() < Target.expand();
    }
}

#endif


