// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TIMECHAIN
#define GIGAMONKEY_TIMECHAIN

#include <gigamonkey/hash.hpp>
#include <gigamonkey/p2p/var_int.hpp>
#include <gigamonkey/p2p/command.hpp>
#include <gigamonkey/satoshi.hpp>
#include <gigamonkey/merkle/proof.hpp>
#include <gigamonkey/work/target.hpp>
#include <gigamonkey/script/instruction.hpp>

namespace Gigamonkey {
    struct chain_loader;
}

namespace Gigamonkey::Bitcoin {

    using TXID = digest256;
    
    struct outpoint;
    
    bool operator == (const outpoint &, const outpoint &);
    
    std::strong_ordering operator <=> (const outpoint &, const outpoint &);
    
    writer &operator << (writer &w, const outpoint &h);
    reader &operator >> (reader &r, outpoint &h);

    std::ostream &operator << (std::ostream &o, const outpoint &p);
    
    struct input;
    
    bool operator == (const input &, const input &);
    
    writer &operator << (writer &w, const input &h);
    reader &operator >> (reader &r, input &h);

    std::ostream &operator << (std::ostream &o, const input &p);
    
    struct output;
    
    bool operator == (const output &, const output &);
    
    writer &operator << (writer &w, const output &h);
    reader &operator >> (reader &r, output &h);

    std::ostream &operator << (std::ostream &o, const output &p);
    
    struct transaction;
    
    bool operator == (const transaction &, const transaction &);
    
    writer &operator << (writer &w, const transaction &h);
    reader &operator >> (reader &r, transaction &h);

    std::ostream &operator << (std::ostream &o, const transaction &p);
    
    struct header;
    
    bool operator == (const header &a, const header &b);
    std::strong_ordering operator <=> (const header &, const header &);
    
    writer &operator << (writer &w, const header &h);
    reader &operator >> (reader &r, header &h);

    std::ostream &operator << (std::ostream &o, const header &h);
    
    struct block;
    
    bool operator == (const block &, const block &);
    
    writer &operator << (writer &w, const block &h);
    reader &operator >> (reader &r, block &h);

    std::ostream &operator << (std::ostream &o, const block &p);

    // The header is the first 80 bytes of a Bitcoin block. 
    struct header {

        using slice = Gigamonkey::slice<const byte, 80>;
        
        static int32_little version (slice);
        static digest256 previous (slice x);
        static digest256 merkle_root (slice x);
        static Bitcoin::timestamp timestamp (slice);
        static Bitcoin::target target (slice);
        static uint32_little nonce (slice);
        static digest256 hash (slice h);
        static bool valid (slice h);
        
        int32_little Version;
        digest256 Previous;
        digest256 MerkleRoot;
        Bitcoin::timestamp Timestamp;
        Bitcoin::target Target;
        uint32_little Nonce;
        
        header () : Version {}, Previous {}, MerkleRoot {}, Timestamp {}, Target {}, Nonce {} {}
        
        header (
            int32_little v,
            digest256 p,
            digest256 mr,
            Bitcoin::timestamp ts,
            Bitcoin::target t,
            uint32_little n) : Version {v}, Previous {p}, MerkleRoot {mr}, Timestamp {ts}, Target {t}, Nonce {n} {}
        
        explicit header (slice x) : header {
            version (x),
            digest256 {previous (x)},
            digest256 {merkle_root (x)},
            Bitcoin::timestamp {timestamp (x)},
            Bitcoin::target {target (x)},
            nonce (x)} {}
        
        byte_array<80> write () const;
        
        const digest256 &hash () const;
        
        // check the proof-of-work on the header.
        bool valid () const;
        
        int16 version () const;
        const transaction &coinbase () const;

    private:
        mutable ptr<digest256> Hash;
        friend struct Gigamonkey::chain_loader;
    };

    // an outpoint is a reference to a previous output. 
    struct outpoint {

        using slice = Gigamonkey::slice<const byte, 36>;
        
        static bool valid (slice);
        static Bitcoin::TXID digest (slice);
        static Bitcoin::index index (slice);
        
        // the hash of a previous transaction. 
        TXID Digest;
        
        // Index of the previous output in the tx. 
        Bitcoin::index Index;
        
        static outpoint coinbase () {
            static outpoint Coinbase {TXID {}, 0xffffffff};
            return Coinbase;
        }

        byte_array<36> write () const;

        static outpoint read (slice x) {
            return outpoint {x};
        }

        bool valid () const {
            return Digest.valid ();
        }

        outpoint () : Digest {0}, Index {0} {}
        outpoint (const TXID &id, const Bitcoin::index &i) : Digest {id}, Index {i} {}
        outpoint (slice x): Digest {digest (x)}, Index {index (x)} {}

    };

    struct input {
        
        static bool valid (slice<const byte>);
        static outpoint::slice previous (slice<const byte>);
        static slice<const byte> script (slice<const byte>);
        static uint32_little sequence (slice<const byte>);
        
        outpoint Reference;
        Bitcoin::script Script;
        uint32_little Sequence;
        
        static constexpr uint32 Finalized {0xFFFFFFFF};
        
        bool valid () const;
        
        input () : Reference {}, Script {}, Sequence {} {}
        input (const outpoint &o, const Bitcoin::script &x, const uint32_little &z = Finalized) :
            Reference {o}, Script {x}, Sequence {z} {}
        explicit input (slice<const byte>);
        
        uint64 serialized_size () const;

        bytes write () const;
        explicit operator bytes () const;
    };
    
    struct output {
        
        static bool valid (slice<const byte> b) {
            return output {b}.valid ();
        }
        
        static satoshi value (slice<const byte>);
        static slice<const byte> script (slice<const byte>);
    
        satoshi Value; 
        Bitcoin::script Script;
        
        output () : Value {-1}, Script {} {}
        output (satoshi v, const Bitcoin::script &x) : Value {v}, Script {x} {}
        
        explicit output (slice<const byte>);
        
        bool valid () const;
        
        uint64 serialized_size () const;

        bytes write () const;
        explicit operator bytes () const;
    };

    struct transaction {
        
        static bool valid (slice<const byte>);
        static int32_little version (slice<const byte>);
        static cross<slice<const byte>> outputs (slice<const byte>);
        static cross<slice<const byte>> inputs (slice<const byte>);
        static slice<const byte> output (slice<const byte>, index);
        static slice<const byte> input (slice<const byte>, index);
        static int32_little lock_time (slice<const byte>);
        
        static TXID id (slice<const byte>);
        
        static constexpr int32 LatestVersion = 2;
        
        int32_little Version;
        list<Bitcoin::input> Inputs;
        list<Bitcoin::output> Outputs;
        uint32_little LockTime;
        
        transaction (int32_little v, list<Bitcoin::input> i,  list<Bitcoin::output> o, uint32_little t = 0) :
            Version {v}, Inputs {i}, Outputs {o}, LockTime {t} {}
        
        transaction (list<Bitcoin::input> i, list<Bitcoin::output> o, uint32_little t = 0) :
            transaction {int32_little {LatestVersion}, i, o, t} {}
            
        transaction () : Version {}, Inputs {}, Outputs {}, LockTime {} {};
        
        explicit transaction (slice<const byte> b);
        
        bool valid () const;
        
        bytes write () const;
        explicit operator bytes () const;
        
        const TXID &id () const;
        
        uint64 serialized_size () const;
        
        uint64 sigops () const;
        
        satoshi sent () const {
            return fold ([] (satoshi x, const Bitcoin::output &o) -> satoshi {
                return x + o.Value;
            }, satoshi {0}, Outputs);
        }

        static constexpr p2p::command Command {"tx"};

    private:
        mutable ptr<TXID> Hash;
        friend struct Gigamonkey::chain_loader;
    };
    
    TXID inline id (const transaction &t) {
        return Hash256 (bytes (t));
    }
    
    digest256 inline merkle_root (const list<transaction> t) {
        return Merkle::root (data::for_each (id, t));
    }
    
    struct block {
        static inline bool valid (slice<const byte> b) {
            return block {b}.valid ();
        }
        
        static Bitcoin::header::slice header (slice<const byte>);
        static std::vector<slice<const byte>> transactions (slice<const byte>);
        
        static digest256 inline merkle_root (slice<const byte> b) {
            list<TXID> ids {};
            for (slice<const byte> x : transactions (b)) ids = ids << Hash256 (x);
            return Merkle::root (ids);
        }
        
        Bitcoin::header Header;
        list<transaction> Transactions;
        
        block () : Header {}, Transactions {} {}
        
        bytes coinbase ();
        bool valid () const {
            if (!Header.valid ()) return false;
            list<transaction> txs = Transactions;
            while(!txs.empty ()) {
                if (!txs.first ().valid ()) return false;
                txs = txs.rest ();
            }
            return true;
        }
        
        explicit block (slice<const byte> b);
        
        explicit operator bytes () const;
        
        uint64 serialized_size () const;
    };
}

namespace Gigamonkey {
    struct chain_loader {
        void set_hash (Bitcoin::header &h, const digest256 &x) {
            if (h.Hash != nullptr) h.Hash = std::make_shared<digest256> (x);
        }

        void set_hash (Bitcoin::transaction &tx, const Bitcoin::TXID &x) {
            if (tx.Hash != nullptr) tx.Hash = std::make_shared<Bitcoin::TXID> (x);
        }
    };
}

namespace Gigamonkey::Bitcoin {
    
    bool inline operator == (const header &a, const header &b) {
        return a.Version == b.Version && a.Previous == b.Previous && a.MerkleRoot == b.MerkleRoot 
            && a.Timestamp == b.Timestamp && a.Target == b.Target && a.Nonce == b.Nonce;
    }
    
    bool inline operator == (const outpoint &a, const outpoint &b) {
        return a.Digest == b.Digest && a.Index == b.Index;
    }
    
    bool inline operator == (const input &a, const input &b) {
        return a.Reference == b.Reference && a.Script == b.Script && a.Sequence == b.Sequence;
    }
    
    bool inline operator == (const output &a, const output &b) {
        return a.Value == b.Value && a.Script == b.Script;
    }
    
    bool inline operator == (const transaction &a, const transaction &b) {
        return a.Version == b.Version && a.Inputs == b.Inputs && a.Outputs == b.Outputs && a.LockTime == b.LockTime;
    }
    
    bool inline operator == (const block &a, const block &b) {
        return a.Header == b.Header && a.Transactions == b.Transactions;
    }
    
    std::ostream inline &operator << (std::ostream &o, const header &h) {
        return o << "header {Version : " << h.Version <<
            ", Previous : " << h.Previous << 
            ", MerkleRoot : " << h.MerkleRoot << 
            ", Timestamp : " << h.Timestamp << 
            ", Target : " << h.Target << 
            ", Nonce : " << h.Nonce << "}";
    }
    
    std::ostream inline &operator << (std::ostream &o, const outpoint &p) {
        return o << "outpoint {" << p.Digest << ":" << p.Index << "}";
    }
    
    std::ostream inline &operator << (std::ostream &o, const input &p) {
        return o << "input {Reference : " << p.Reference << ", Script : " << ASM (p.Script) << ", Sequence : " << p.Sequence << "}";
    }

    std::ostream inline &operator << (std::ostream &o, const output &p) {
        return o << "output {Value : " << p.Value << ", Script : " << ASM (p.Script) << "}";
    }

    std::ostream inline &operator << (std::ostream &o, const transaction &p) {
        return o << "transaction {Version : " << p.Version << ", Inputs : "
            << p.Inputs << ", Outputs: " << p.Outputs << ", " << p.LockTime << "}";
    }
    
    writer inline &operator << (writer &w, const header &h) {
        return w << h.Version << h.Previous << h.MerkleRoot << h.Timestamp << h.Target << h.Nonce;
    }
    
    reader inline &operator >> (reader &r, header &h) {
        return r >> h.Version >> h.Previous >> h.MerkleRoot >> h.Timestamp >> h.Target >> h.Nonce;
    }
    
    writer inline &operator << (writer &w, const outpoint &o) {
        return w << o.Digest << o.Index;
    }
    
    reader inline &operator >> (reader &r, outpoint &o) {
        return r >> o.Digest >> o.Index;
    }
    
    reader inline &operator >> (reader &r, input &in) {
        return r >> in.Reference >> var_string {in.Script} >> in.Sequence;
    }
    
    writer inline &operator << (writer &w, const input &in) {
        return w << in.Reference << var_string {in.Script} << in.Sequence;
    }
    
    reader inline &operator >> (reader &r, output &out) {
        return r >> out.Value >> var_string {out.Script};
    }
    
    writer inline &operator << (writer &w, const output &out) {
        return w << out.Value << var_string {out.Script};
    }
    
    reader inline &operator >> (reader &r, transaction &t) {
        return r >> t.Version >> var_sequence<input> {t.Inputs} >> var_sequence<output> {t.Outputs} >> t.LockTime;
    }

    writer inline &operator << (writer &w, const transaction &t) {
        return w << t.Version << var_sequence<input> {t.Inputs} << var_sequence<output> {t.Outputs} << t.LockTime;
    }

    reader inline &operator >> (reader &r, block &b) {
        return r >> b.Header >> var_sequence<transaction> {b.Transactions};
    }
    
    writer inline &operator << (writer &w, const block &b) {
        return w << b.Header << var_sequence<transaction> {b.Transactions};
    }
   
    digest256 inline header::previous (slice x) {
        return digest256 (x.range<4, 36> ());
    }
    
    digest256 inline header::merkle_root (slice x) {
        return digest256 (x.range<36, 68> ());
    }
    
    digest256 inline header::hash (slice h) {
        return Bitcoin::Hash256 (h);
    }

    const digest256 inline &header::hash () const {
        if (Hash == nullptr) Hash = std::make_shared<digest256> (hash (write ()));
        return *Hash;
    }
        
    const TXID inline &transaction::id () const {
        if (Hash == nullptr) Hash = std::make_shared<TXID> (Bitcoin::id (*this));
        return *Hash;
    }
    
    std::strong_ordering inline operator <=> (const outpoint &a, const outpoint &b) {
        return a.Digest == b.Digest ? a.Index <=> b.Index : a.Digest <=> b.Digest;
    }
    
    std::strong_ordering inline operator <=> (const header &a, const header &b) {
        return a.Timestamp <=> b.Timestamp;
    }
    
    TXID inline transaction::id (slice<const byte> b) {
        return Hash256 (b);
    }
    
    uint64 inline input::serialized_size () const {
        return 40u + var_int::size (Script.size ()) + Script.size ();
    }
    
    uint64 inline output::serialized_size () const {
        return 8u + var_int::size (Script.size ()) + Script.size ();
    }

    bytes inline transaction::write () const {
        return bytes (*this);
    }

    bool inline transaction::valid () const {
        return Inputs.size () > 0 && Outputs.size () > 0 && (
            data::valid (Inputs) ||
            (Inputs.size () == 1 && Inputs[0].Reference == outpoint {}) // coinbase
        ) && data::valid (Outputs);
    }
}

#endif

