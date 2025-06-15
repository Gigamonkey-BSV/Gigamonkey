// Copyright (c) 2019-2025 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WORK_STRING
#define GIGAMONKEY_WORK_STRING

#include <gigamonkey/timechain.hpp>
#include <gigamonkey/work/ASICBoost.hpp>

namespace Gigamonkey::work {

    struct string;

    bool operator == (const string &x, const string &y);

    std::ostream &operator << (std::ostream &o, const string &work_string);
    
    struct string {
        int32_little Category;
        uint256 Digest;
        uint256 MerkleRoot;
        Bitcoin::timestamp Timestamp;
        compact Target;
        Bitcoin::nonce Nonce;
        
        string ();
        string (int32_little v, uint256 d, uint256 mp, Bitcoin::timestamp ts, compact tg, Bitcoin::nonce n);
        string (uint16_little m, uint16_little b, uint256 d, uint256 mp, Bitcoin::timestamp ts, compact tg, Bitcoin::nonce n);
        
        static string read (slice<const byte, 80> x);
        
        explicit string (slice<const byte, 80> x);
        
        byte_array<80> write () const;
        
        uint256 hash () const;
        
        static bool valid (slice<const byte, 80> x);
        
        bool valid () const;
        
        explicit string (const Bitcoin::header &h);
        
        work::difficulty difficulty () const;
        
        explicit operator Bitcoin::header () const;
        
        int32_little version () const;
        
        uint16_little magic_number () const;
        
        uint16_little general_purpose_bits () const;
    };
        
    bool inline operator == (const string &x, const string &y) {
        return y.Category == x.Category && 
            y.Digest == x.Digest && 
            y.MerkleRoot == x.MerkleRoot && 
            y.Timestamp == x.Timestamp && 
            y.Target == x.Target && 
            y.Nonce == x.Nonce;
    }
    
    bool inline operator != (const string &x, const string &y) {
        return !(x == y);
    }
    
    std::ostream inline &operator << (std::ostream &o, const string &work_string) {
        return o << "work_string{" << encoding::hex::write (work_string.write ()) << "}";
    }

    inline string::string () : Category (0), Digest (0), MerkleRoot (0), Timestamp (), Target (0), Nonce (0) {}
    inline string::string (int32_little v, uint256 d, uint256 mp, Bitcoin::timestamp ts, compact tg, Bitcoin::nonce n) :
        Category {v}, Digest {d}, MerkleRoot {mp}, Timestamp {ts}, Target {tg}, Nonce {n} {}
    inline string::string (uint16_little m, uint16_little b, uint256 d, uint256 mp, Bitcoin::timestamp ts, compact tg, Bitcoin::nonce n) :
        Category {ASICBoost::category (m, b)}, Digest {d}, MerkleRoot {mp}, Timestamp {ts}, Target {tg}, Nonce {n} {}

    inline string string::read (slice<const byte, 80> x) {
        return string {
            Bitcoin::header::version (x),
            uint_little<32> {Bitcoin::header::previous (x)},
            uint_little<32> {Bitcoin::header::merkle_root (x)},
            Bitcoin::timestamp {Bitcoin::header::timestamp (x)},
            compact {Bitcoin::header::target (x)},
            Bitcoin::header::nonce (x)};
    }

    inline string::string (slice<const byte, 80> x) : string (read (x)) {}

    byte_array<80> inline string::write () const {
        return operator Bitcoin::header ().write ();
    }

    uint256 inline string::hash () const {
        return Bitcoin::Hash256 (write ());
    }

    bool inline string::valid (slice<const byte, 80> x) {
        return Bitcoin::Hash256 (x) < Bitcoin::header::target (x).expand ();
    }

    bool inline string::valid () const {
        return hash () < Target.expand ();
    }

    inline string::string (const Bitcoin::header &h) :
        Category (h.Version), Digest (h.Previous), MerkleRoot (h.MerkleRoot),
        Timestamp (h.Timestamp), Target (h.Target), Nonce (h.Nonce) {}

    work::difficulty inline string::difficulty () const {
        return Target.difficulty ();
    }

    inline string::operator Bitcoin::header () const {
        return {Category, digest256 {Digest}, digest256 {MerkleRoot}, Timestamp, Target, Nonce};
    }

    int32_little inline string::version () const {
        return ASICBoost::version (Category);
    }

    uint16_little inline string::magic_number () const {
        return ASICBoost::magic_number (Category);
    }

    uint16_little inline string::general_purpose_bits () const {
        return ASICBoost::bits(Category);
    }
}

#endif


