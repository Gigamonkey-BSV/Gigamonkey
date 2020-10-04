// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TIMECHAIN
#define GIGAMONKEY_TIMECHAIN

#include "primitives/block.h"
#include <gigamonkey/hash.hpp>
#include <gigamonkey/satoshi.hpp>
#include <gigamonkey/merkle.hpp>
#include <gigamonkey/work/target.hpp>

namespace Gigamonkey::Bitcoin {
    
    using txid = digest256;
    
    struct timechain {
        virtual list<uint<80>> headers(uint64 since_height) const = 0;
        virtual bytes transaction(const digest<32>&) const = 0;
        virtual Merkle::path merkle_path(const digest<32>&) const = 0;
        // next 3 should work for both header hash and merkle root.
        virtual uint<80> header(const digest<32>&) const = 0; 
        virtual list<txid> transactions(const digest<32>&) const = 0;
        virtual bytes block(const digest<32>&) const = 0; 
        bool broadcast(const bytes tx);
    };
    
    struct outpoint;
    
    bool operator==(const outpoint&, const outpoint&);
    bool operator!=(const outpoint&, const outpoint&);
    
    bytes_writer operator<<(bytes_writer w, const outpoint& h);
    bytes_reader operator>>(bytes_reader r, outpoint& h);

    std::ostream& operator<<(std::ostream& o, const outpoint& p);
    
    struct input;
    
    bool operator==(const input&, const input&);
    bool operator!=(const input&, const input&);
    
    bytes_writer operator<<(bytes_writer w, const input& h);
    bytes_reader operator>>(bytes_reader r, input& h);

    std::ostream& operator<<(std::ostream& o, const input& p);
    
    struct output;
    
    bool operator==(const output&, const output&);
    bool operator!=(const output&, const output&);
    
    bytes_writer operator<<(bytes_writer w, const output& h);
    bytes_reader operator>>(bytes_reader r, output& h);

    std::ostream& operator<<(std::ostream& o, const output& p);
    
    struct transaction;
    
    bool operator==(const transaction&, const transaction&);
    bool operator!=(const transaction&, const transaction&);
    
    bytes_writer operator<<(bytes_writer w, const transaction& h);
    bytes_reader operator>>(bytes_reader r, transaction& h);

    std::ostream& operator<<(std::ostream& o, const transaction& p);
    
    struct header;
    
    bool operator==(const header& a, const header& b);
    bool operator!=(const header& a, const header& b);
    
    bytes_writer operator<<(bytes_writer w, const header& h);
    bytes_reader operator>>(bytes_reader r, header& h);

    std::ostream& operator<<(std::ostream& o, const header& h);
    
    struct block;
    
    bool operator==(const block&, const block&);
    bool operator!=(const block&, const block&);
    
    bytes_writer operator<<(bytes_writer w, const block& h);
    bytes_reader operator>>(bytes_reader r, block& h);

    std::ostream& operator<<(std::ostream& o, const block& p);

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
        digest<32> Previous;
        digest<32> MerkleRoot;
        Bitcoin::timestamp Timestamp;
        Bitcoin::target Target;
        uint32_little Nonce;
        
        header() : Version{}, Previous{}, MerkleRoot{}, Timestamp{}, Target{}, Nonce{} {}
        
        header(
            int32_little v,
            digest<32> p,
            digest<32> mr,
            Bitcoin::timestamp ts,
            Bitcoin::target t,
            uint32_little n) : Version{v}, Previous{p}, MerkleRoot{mr}, Timestamp{ts}, Target{t}, Nonce{n} {}
            
        static header read(slice<80> x) {
            return header{
                version(x), 
                digest<32>{previous(x)}, 
                digest<32>{merkle_root(x)}, 
                Bitcoin::timestamp{timestamp(x)}, 
                Bitcoin::target{target(x)}, 
                nonce(x)};
        }
        
        explicit header(slice<80> x) : header(read(x)) {}
        
        explicit header(const CBlockHeader&);
        
        explicit operator CBlockHeader() const;
        
        bytes_reader read(bytes_reader r);
        bytes_writer write(bytes_writer w) const;
        
        uint<80> write() const;
        
        digest<32> hash() const {
            return hash256(write());
        }
        
        bool valid() const;
    };

    struct outpoint {
        
        static bool valid(slice<36>);
        static Bitcoin::txid reference(slice<36>);
        static Gigamonkey::index index(slice<36>);
        
        txid Reference; 
        Gigamonkey::index Index;
        
        bytes_writer write(bytes_writer w) const;
        bytes_reader read(bytes_reader r);
        
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
        
        outpoint Outpoint; 
        Gigamonkey::script Script;
        uint32_little Sequence;
        
        bool valid() const;
        
        input() : Outpoint{}, Script{}, Sequence{} {}
        input(const outpoint&, const Gigamonkey::script&, const uint32_little&);
        input(const outpoint&, const Gigamonkey::script&);
        
        bytes_writer write(bytes_writer w) const;
        bytes_reader read(bytes_reader r);
        
        size_t serialized_size() const;
    };
    
    struct output {
        
        static bool valid(bytes_view);
        static satoshi value(bytes_view);
        static bytes_view script(bytes_view);
    
        satoshi Value; 
        Gigamonkey::script Script;
        
        bool valid() const;
        
        bytes_writer write(bytes_writer w) const;
        bytes_reader read(bytes_reader r);
        
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
        
        int32_little Version;
        list<Bitcoin::input> Inputs;
        list<Bitcoin::output> Outputs;
        int32_little Locktime;
        
        transaction(int32_little v, list<Bitcoin::input> i,  list<Bitcoin::output> o, int32_little t) : 
            Version{v}, Inputs{i}, Outputs{o}, Locktime{t} {}
        
        transaction(list<Bitcoin::input> i, list<Bitcoin::output> o, int32_little t) : 
            transaction{int32_little{2}, i, o, t} {}
            
        transaction() : Version{}, Inputs{}, Outputs{}, Locktime{} {};
        
        bool valid() const;
        
        bytes_writer write(bytes_writer w) const;
        bytes_reader read(bytes_reader r);
        
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
        static cross<bytes_view> transactions(bytes_view);
        
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
        
        bytes_writer write(bytes_writer w) const;
        bytes_reader read(bytes_reader r);
        
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
        return a.Reference == b.Reference && a.Index == b.Index;
    }
    
    bool inline operator!=(const outpoint& a, const outpoint& b) {
        return !(a == b);
    }
    
    bool inline operator==(const input& a, const input& b) {
        return a.Outpoint == b.Outpoint && a.Script == b.Script && a.Sequence == b.Sequence;
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
        return o << "outpoint{Reference : " << p.Reference << ", Index : " << p.Index << "}";
    }
    
    inline std::ostream& operator<<(std::ostream& o, const input& p) {
        return o << "input{Outpoint : " << p.Outpoint << ", Script : " << p.Script << ", Sequence : " << p.Sequence << "}";
    }

    inline std::ostream& operator<<(std::ostream& o, const output& p) {
        return o << "output{Value : " << p.Value << ", Script : " << p.Script << "}";
    }

    bytes_writer inline operator<<(bytes_writer w, const header& h) {
        return h.write(w);
    }

    bytes_reader inline operator>>(bytes_reader r, header& h) {
        return h.read(r);
    }

    bytes_writer inline operator<<(bytes_writer w, const outpoint& o) {
        return o.write(w);
    }

    bytes_reader inline operator>>(bytes_reader r, outpoint& o) {
        return o.read(r);
    }

    bytes_writer inline operator<<(bytes_writer w, const input& in) {
        return in.write(w);
    }

    bytes_reader inline operator<<(bytes_reader r, input& in) {
        return in.read(r);
    }

    bytes_writer inline operator<<(bytes_writer w, const output& out) {
        return out.write(w);
    }

    bytes_reader inline operator>>(bytes_reader r, output& out) {
        return out.read(r);
    }

    bytes_writer inline operator<<(bytes_writer w, const transaction& t) {
        return t.write(w);
    }

    bytes_reader inline operator>>(bytes_reader r, transaction& t) {
        return t.read(r);
    }

    bytes_writer inline operator<<(bytes_writer w, const block& b) {
        return b.write(w);
    }

    bytes_reader inline operator>>(bytes_reader r, block& b) {
        return b.read(r);
    }
   
    digest<32> inline header::previous(const slice<80> x) {
        return digest<32>(x.range<4, 36>());
    }
    
    digest<32> inline header::merkle_root(const slice<80> x) {
        return digest<32>(x.range<36, 68>());
    }
    
    digest<32> inline header::hash(const slice<80> h) {
        return Bitcoin::hash256(h);
    }
    
    bytes_writer write_var_int(bytes_writer, uint64);
    
    bytes_reader read_var_int(bytes_reader, uint64&);
    
    size_t var_int_size(uint64);
    
    bytes_writer inline write_data(bytes_writer w, bytes_view b) {
        return write_var_int(w, b.size()) << b;
    }
    
    bytes_reader inline read_data(bytes_reader r, bytes& b) {
        uint64 size;
        r = read_var_int(r, size);
        b = bytes(size);
        return r >> b;
    }
    
    template <typename X> 
    bytes_writer inline write_sequence(bytes_writer w, list<X> l) {
        return data::fold([](bytes_writer w, X x)->bytes_writer{return w << x;}, 
            write_var_int(w, data::size(l)), l);
    }
    
    template <typename X> 
    bytes_reader read_sequence(bytes_reader r, list<X>& l);
    
    inline bytes_writer header::write(bytes_writer w) const {
        return w << Version << Previous << MerkleRoot << Timestamp << Target << Nonce;
    }
    
    inline bytes_reader header::read(bytes_reader r) {
        return r >> Version >> Previous >> MerkleRoot >> Timestamp >> Target >> Nonce;
    }
    
    inline uint<80> header::write() const {
        uint<80> x; // inefficient: unnecessary copy. 
        bytes b = Gigamonkey::write(80, Version, Previous, MerkleRoot, Timestamp, Target, Nonce);
        std::copy(b.begin(), b.end(), x.data());
        return x;
    }
    
    inline bytes_writer outpoint::write(bytes_writer w) const {
        return w << Reference << Index;
    }
    
    inline bytes_reader outpoint::read(bytes_reader r) {
        return r >> Reference >> Index;
    }
    
    inline size_t input::serialized_size() const {
        return 40 + var_int_size(Script.size()) + Script.size();
    }
    
    inline bytes_writer input::write(bytes_writer w) const {
        return write_data(w << Outpoint, Script) << Sequence;
    }
    
    inline bytes_reader input::read(bytes_reader r) {
        return read_data(r >> Outpoint, Script) >> Sequence;
    }
    
    inline bytes_writer output::write(bytes_writer w) const {
        return write_data(w << Value, Script);
    }
    
    inline bytes_reader output::read(bytes_reader r) {
        return read_data(r >> Value, Script);
    }
    
    inline size_t output::serialized_size() const {
        return 8 + var_int_size(Script.size()) + Script.size();
    }
    
    inline bool transaction::valid() const {
        return Inputs.size() > 0 && Outputs.size() > 0 && 
            fold([](bool b, Bitcoin::input i) -> bool {
                return b && i.valid();
            }, true, Inputs) && 
            fold([](bool b, Bitcoin::output o) -> bool {
                return b && o.valid();
            }, true, Outputs);
    }
    
    inline bytes_writer transaction::write(bytes_writer w) const {
        return write_sequence(write_sequence(w << Version, Inputs), Outputs) << Locktime;
    }
    
    inline bytes_reader transaction::read(bytes_reader r) {
        return read_sequence(read_sequence(r >> Version, Inputs), Outputs) >> Locktime;
    }
    
    inline transaction transaction::read(bytes_view b) {
        transaction t;
        bytes_reader(b.data(), b.data() + b.size()) >> t;
        return t;
    }
    
    inline bytes transaction::write() const {
        bytes b(serialized_size());
        bytes_writer w{b.begin(), b.end()};
        w = w << *this;
        return b;
    }
        
    txid inline transaction::id() const {
        return Bitcoin::id(*this);
    }
    
    inline bytes_writer block::write(bytes_writer w) const {
        throw data::method::unimplemented{"block::write"};
    }
    
    inline bytes_reader block::read(bytes_reader r) {
        throw data::method::unimplemented{"block::read"};
    }
    
    inline block block::read(bytes_view b) {
        block bl;
        bytes_reader(b.data(), b.data() + b.size()) >> bl;
        return bl;
    }
    
    inline bytes block::write() const {
        bytes b(serialized_size());
        write(bytes_writer(b.begin(), b.end()));
        return b;
    }
}

#endif

