// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TIMECHAIN
#define GIGAMONKEY_TIMECHAIN

#include <sv/primitives/block.h>
#include <gigamonkey/hash.hpp>
#include <gigamonkey/satoshi.hpp>
#include <gigamonkey/merkle/proof.hpp>
#include <gigamonkey/work/target.hpp>

namespace Gigamonkey::Bitcoin {
    
    using txid = digest256;
    
    struct outpoint;
    
    bool operator==(const outpoint&, const outpoint&);
    bool operator!=(const outpoint&, const outpoint&);
    
    bool operator>(const outpoint&, const outpoint&);
    bool operator<(const outpoint&, const outpoint&);
    bool operator>=(const outpoint&, const outpoint&);
    bool operator<=(const outpoint&, const outpoint&);
    
    writer operator<<(writer w, const outpoint& h);
    reader operator>>(reader r, outpoint& h);

    std::ostream& operator<<(std::ostream& o, const outpoint& p);
    
    struct input;
    
    bool operator==(const input&, const input&);
    bool operator!=(const input&, const input&);
    
    writer operator<<(writer w, const input& h);
    reader operator>>(reader r, input& h);

    std::ostream& operator<<(std::ostream& o, const input& p);
    
    struct output;
    
    bool operator==(const output&, const output&);
    bool operator!=(const output&, const output&);
    
    writer operator<<(writer w, const output& h);
    reader operator>>(reader r, output& h);

    std::ostream& operator<<(std::ostream& o, const output& p);
    
    struct transaction;
    
    bool operator==(const transaction&, const transaction&);
    bool operator!=(const transaction&, const transaction&);
    
    writer operator<<(writer w, const transaction& h);
    reader operator>>(reader r, transaction& h);

    std::ostream& operator<<(std::ostream& o, const transaction& p);
    
    struct header;
    
    bool operator==(const header& a, const header& b);
    bool operator!=(const header& a, const header& b);
    
    bool operator>(const header&, const header&);
    bool operator<(const header&, const header&);
    bool operator>=(const header&, const header&);
    bool operator<=(const header&, const header&);
    
    writer operator<<(writer w, const header& h);
    reader operator>>(reader r, header& h);

    std::ostream& operator<<(std::ostream& o, const header& h);
    
    struct block;
    
    bool operator==(const block&, const block&);
    bool operator!=(const block&, const block&);
    
    writer operator<<(writer w, const block& h);
    reader operator>>(reader r, block& h);

    std::ostream& operator<<(std::ostream& o, const block& p);

    // The header is the first 80 bytes of a Bitcoin block. 
    struct header {
        
        static int32_little version(const slice<80>);
        static digest256 previous(const slice<80> x);
        static digest256 merkle_root(const slice<80> x);
        static Bitcoin::timestamp timestamp(const slice<80>);
        static Bitcoin::target target(const slice<80>);
        static uint32_little nonce(const slice<80>);
        static digest256 hash(const slice<80> h);
        static bool valid(const slice<80> h);
        
        int32_little Version;
        digest256 Previous;
        digest256 MerkleRoot;
        Bitcoin::timestamp Timestamp;
        Bitcoin::target Target;
        uint32_little Nonce;
        
        header() : Version{}, Previous{}, MerkleRoot{}, Timestamp{}, Target{}, Nonce{} {}
        
        header(
            int32_little v,
            digest256 p,
            digest256 mr,
            Bitcoin::timestamp ts,
            Bitcoin::target t,
            uint32_little n) : Version{v}, Previous{p}, MerkleRoot{mr}, Timestamp{ts}, Target{t}, Nonce{n} {}
            
        static header read(slice<80> x) {
            return header{
                version(x), 
                digest256{previous(x)}, 
                digest256{merkle_root(x)}, 
                Bitcoin::timestamp{timestamp(x)}, 
                Bitcoin::target{target(x)}, 
                nonce(x)};
        }
        
        explicit header(slice<80> x) : header(read(x)) {}
        
        explicit header(const CBlockHeader&);
        
        explicit operator CBlockHeader() const;
        
        uint<80> write() const;
        
        digest256 hash() const {
            return hash256(write());
        }
        
        bool valid() const;
    };

    // an outpoint is a reference to a previous output. 
    struct outpoint {
        
        static bool valid(slice<36>);
        static Bitcoin::txid digest(slice<36>);
        static Gigamonkey::index index(slice<36>);
        
        // the hash of a previous transaction. 
        txid Digest; 
        
        // Index of the previous output in the tx. 
        Gigamonkey::index Index;
        
        static outpoint coinbase() {
            static outpoint Coinbase{txid{}, 0xffffffff};
            return Coinbase;
        }
    };

    struct input {
        
        static bool valid(bytes_view);
        static slice<36> previous(bytes_view);
        static bytes_view script(bytes_view);
        static uint32_little sequence(bytes_view);
        
        outpoint Reference; 
        Gigamonkey::script Script;
        uint32_little Sequence;
        
        static constexpr uint32 Finalized{0xFFFFFFFF};
        
        bool valid() const;
        
        input() : Reference{}, Script{}, Sequence{} {}
        input(const outpoint& o, const Gigamonkey::script& x, const uint32_little& z = Finalized) : 
            Reference{o}, Script{x}, Sequence{z} {}
        
        size_t serialized_size() const;
    };
    
    struct output {
        
        static bool valid(bytes_view b) {
            return output{b}.valid();
        }
        
        static satoshi value(bytes_view);
        static bytes_view script(bytes_view);
    
        satoshi Value; 
        Gigamonkey::script Script;
        
        output() : Value{-1}, Script{} {}
        output(satoshi v, const Gigamonkey::script& x) : Value{v}, Script{x} {}
        
        explicit output(bytes_view);
        
        bool valid() const;
        
        size_t serialized_size() const;
    };

    struct transaction {
        
        static bool valid(bytes_view);
        static int32_little version(bytes_view);
        static cross<bytes_view> outputs(bytes_view);
        static cross<bytes_view> inputs(bytes_view);
        static bytes_view output(bytes_view, index);
        static bytes_view input(bytes_view, index);
        static int32_little locktime(bytes_view);
        
        static txid id(bytes_view);
        
        constexpr static int32 LatestVersion = 2;
        
        int32_little Version;
        list<Bitcoin::input> Inputs;
        list<Bitcoin::output> Outputs;
        uint32_little Locktime;
        
        transaction(int32_little v, list<Bitcoin::input> i,  list<Bitcoin::output> o, uint32_little t = 0) : 
            Version{v}, Inputs{i}, Outputs{o}, Locktime{t} {}
        
        transaction(list<Bitcoin::input> i, list<Bitcoin::output> o, uint32_little t = 0) : 
            transaction{int32_little{LatestVersion}, i, o, t} {}
            
        transaction() : Version{}, Inputs{}, Outputs{}, Locktime{} {};
        
        transaction(bytes_view b) : transaction{read(b)} {}
        
        bool valid() const;
        
        static transaction read(bytes_view);
        bytes write() const;
        
        txid id() const;
        
        size_t serialized_size() const;
        
        uint32 sigops() const;
        
        satoshi sent() const {
            return fold([](satoshi x, const Bitcoin::output& o) -> satoshi {
                return x + o.Value;
            }, satoshi{0}, Outputs);
        }
    };
    
    txid inline id(const transaction& b) {
        return hash256(b.write());
    }
    
    digest256 inline merkle_root(const list<transaction> t) {
        return Merkle::root(for_each(id, t));
    }
    
    struct block {
        static inline bool valid(bytes_view b) {
            return Bitcoin::block::read(b).valid();
        }
        
        static const slice<80> header(bytes_view);
        static std::vector<bytes_view> transactions(bytes_view);
        
        static digest256 inline merkle_root(bytes_view b) {
            list<txid> ids{};
            for (bytes_view x : transactions(b)) ids = ids << hash256(x);
            return Merkle::root(ids);
        }
    
        Bitcoin::header Header;
        list<transaction> Transactions;
        
        block() : Header{}, Transactions{} {}
        
        bytes coinbase();
        bool valid() const {
            if (!Header.valid()) return false;
            list<transaction> txs = Transactions;
            while(!txs.empty()) {
                if (!txs.first().valid()) return false;
                txs = txs.rest();
            }
            return true;
        }
        
        static block read(bytes_view b);
        bytes write() const;
        
        size_t serialized_size() const;
    };
    
    bool inline operator==(const header& a, const header& b) {
        return a.Version == b.Version && a.Previous == b.Previous && a.MerkleRoot == b.MerkleRoot 
            && a.Timestamp == b.Timestamp && a.Target == b.Target && a.Nonce == b.Nonce;
    }
    
    bool inline operator!=(const header& a, const header& b) {
        return !(a == b);
    }
    
    bool inline operator==(const outpoint& a, const outpoint& b) {
        return a.Digest == b.Digest && a.Index == b.Index;
    }
    
    bool inline operator!=(const outpoint& a, const outpoint& b) {
        return !(a == b);
    }
    
    bool inline operator==(const input& a, const input& b) {
        return a.Reference == b.Reference && a.Script == b.Script && a.Sequence == b.Sequence;
    }
    
    bool inline operator!=(const input& a, const input& b) {
        return !(a == b);
    }
    
    bool inline operator==(const output& a, const output& b) {
        return a.Value == b.Value && a.Script == b.Script;
    }
    
    bool inline operator!=(const output& a, const output& b) {
        return !(a == b);
    }
    
    bool inline operator==(const transaction& a, const transaction& b) {
        return a.Version == b.Version && a.Inputs == b.Inputs && a.Outputs == b.Outputs && a.Locktime == b.Locktime;
    }
    
    bool inline operator!=(const transaction& a, const transaction& b) {
        return !(a == b);
    }
    
    bool inline operator==(const block& a, const block& b) {
        return a.Header == b.Header && a.Transactions == b.Transactions;
    }
    
    bool inline operator!=(const block& a, const block& b) {
        return !(a == b);
    }
    
    inline std::ostream& operator<<(std::ostream& o, const header& h) {
        return o << "header{Version : " << h.Version <<
            ", Previous : " << h.Previous << 
            ", MerkleRoot : " << h.MerkleRoot << 
            ", Timestamp : " << h.Timestamp << 
            ", Target : " << h.Target << 
            ", Nonce : " << h.Nonce << "}";
    }

    inline std::ostream& operator<<(std::ostream& o, const outpoint& p) {
        return o << "outpoint{" << p.Digest << ":" << p.Index << "}";
    }
    
    inline std::ostream& operator<<(std::ostream& o, const input& p) {
        return o << "input{Reference : " << p.Reference << ", Script : " << p.Script << ", Sequence : " << p.Sequence << "}";
    }

    inline std::ostream& operator<<(std::ostream& o, const output& p) {
        return o << "output{Value : " << p.Value << ", Script : " << p.Script << "}";
    }

    writer inline operator<<(writer w, const header& h) {
        return w << h.Version << h.Previous << h.MerkleRoot << h.Timestamp << h.Target << h.Nonce;
    }

    reader inline operator>>(reader r, header& h) {
        return r >> h.Version >> h.Previous >> h.MerkleRoot >> h.Timestamp >> h.Target >> h.Nonce;
    }

    writer inline operator<<(writer w, const outpoint& o) {
        return w << o.Digest << o.Index;
    }

    reader inline operator>>(reader r, outpoint& o) {
        return r >> o.Digest >> o.Index;
    }

    reader inline operator>>(reader r, input& in) {
        return r >> in.Reference >> in.Script >> in.Sequence;
    }

    reader inline operator>>(reader r, output& out) {
        return r >> out.Value >> out.Script;
    }
    
    reader inline operator>>(reader r, transaction& t) {
        return r >> t.Version >> t.Inputs >> t.Outputs >> t.Locktime;
    }

    writer inline operator<<(writer w, const transaction& t) {
        return w << t.Version << t.Inputs << t.Outputs << t.Locktime;
    }

    reader inline operator>>(reader r, block& b) {
        return r >> b.Header >> b.Transactions;
    }
    
    writer inline operator<<(writer w, const block& b) {
        return w << b.Header << b.Transactions;
    }
   
    digest256 inline header::previous(const slice<80> x) {
        return digest256(x.range<4, 36>());
    }
    
    digest256 inline header::merkle_root(const slice<80> x) {
        return digest256(x.range<36, 68>());
    }
    
    digest256 inline header::hash(const slice<80> h) {
        return Bitcoin::hash256(h);
    }
        
    txid inline transaction::id() const {
        return Bitcoin::id(*this);
    }
    
    inline block block::read(bytes_view b) {
        block bl;
        reader(b) >> bl;
        return bl;
    }
    
    inline bytes block::write() const {
        bytes b(serialized_size());
        writer(b) << *this;
        return b;
    }
    
    inline bool operator>(const outpoint& a, const outpoint& b) {
        return a.Digest == b.Digest ? a.Index > b.Index : a.Digest > b.Digest;
    }
    
    inline bool operator<(const outpoint& a, const outpoint& b) {
        return a.Digest == b.Digest ? a.Index < b.Index : a.Digest < b.Digest;
    }
    
    inline bool operator>=(const outpoint& a, const outpoint& b) {
        return a.Digest == b.Digest ? a.Index >= b.Index : a.Digest >= b.Digest;
    }
    
    inline bool operator<=(const outpoint& a, const outpoint& b) {
        return a.Digest == b.Digest ? a.Index <= b.Index : a.Digest <= b.Digest;
    }
    
    bool inline operator>(const header& a, const header& b) {
        return a.Timestamp > b.Timestamp;
    }
    
    bool inline operator<(const header& a, const header& b) {
        return a.Timestamp < b.Timestamp;
    }
    
    bool inline operator>=(const header& a, const header& b) {
        return a.Timestamp >= b.Timestamp;
    }
    
    bool inline operator<=(const header& a, const header& b) {
        return a.Timestamp <= b.Timestamp;
    }
    
    txid inline transaction::id(bytes_view b) {
        return hash256(b);
    }
}

#endif

