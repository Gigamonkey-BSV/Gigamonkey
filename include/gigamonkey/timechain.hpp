// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TIMECHAIN
#define GIGAMONKEY_TIMECHAIN

#include <sv/primitives/block.h>
#include <gigamonkey/txid.hpp>
#include <gigamonkey/satoshi.hpp>
#include <gigamonkey/merkle.hpp>
#include <gigamonkey/work/target.hpp>

namespace Gigamonkey::Bitcoin {
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
}

namespace Gigamonkey::header {
    int32_little version(const slice<80>);
    
    const digest256 previous(const slice<80> x);
    
    const digest256 merkle_root(const slice<80> x);
    
    Bitcoin::timestamp timestamp(const slice<80>);
    
    Bitcoin::target target(const slice<80>);
    
    uint32_little nonce(const slice<80>);
    
    digest256 hash(const slice<80> h);
    
    bool valid(const slice<80> h);
}

namespace Gigamonkey::Bitcoin {
    struct header {
        int32_little Version;
        digest<32> Previous;
        digest<32> MerkleRoot;
        timestamp Timestamp;
        target Target;
        uint32_little Nonce;
        
        header() : Version{}, Previous{}, MerkleRoot{}, Timestamp{}, Target{}, Nonce{} {}
        
        header(
            int32_little v,
            digest<32> p,
            digest<32> mr,
            timestamp ts,
            target t,
            uint32_little n) : Version{v}, Previous{p}, MerkleRoot{mr}, Timestamp{ts}, Target{t}, Nonce{n} {}
            
        static header read(slice<80> x) {
            return header{
                Gigamonkey::header::version(x), 
                digest<32>{Gigamonkey::header::previous(x)}, 
                digest<32>{Gigamonkey::header::merkle_root(x)}, 
                timestamp{Gigamonkey::header::timestamp(x)}, 
                target{Gigamonkey::header::target(x)}, 
                Gigamonkey::header::nonce(x)};
        }
        
        explicit header(slice<80> x) : header(read(x)) {}
        
        explicit header(const bsv::CBlockHeader&);
        
        explicit operator bsv::CBlockHeader() const;
        
        bytes_reader read(bytes_reader r);
        bytes_writer write(bytes_writer w) const;
        
        uint<80> write() const;
        
        digest<32> hash() const {
            return hash256(write());
        }
        
        bool valid() const;
        
        bool operator==(const header& h) const;
        bool operator!=(const header& h) const;
    };

    inline std::ostream& operator<<(std::ostream& o, const header& h) {
        return o << "header{Version : " << h.Version <<
            ", Previous : " << h.Previous << 
            ", MerkleRoot : " << h.MerkleRoot << 
            ", Timestamp : " << h.Timestamp << 
            ", Target : " << h.Target << 
            ", Nonce : " << h.Nonce << "}";
    }
}

namespace Gigamonkey::outpoint {
    bool valid(slice<36>);
    const Bitcoin::txid reference(slice<36>);
    Gigamonkey::index index(slice<36>);
}

namespace Gigamonkey::Bitcoin {
    struct outpoint {
        txid Reference; 
        index Index;
        
        bool valid() const {
            return Reference.valid();
        }
        
        bytes_writer write(bytes_writer w) const;
        bytes_reader read(bytes_reader r);
        
        bool operator==(const outpoint& o) const;
        bool operator!=(const outpoint& o) const;
    };

    inline std::ostream& operator<<(std::ostream& o, const outpoint& p) {
        return o << "outpoint{Reference : " << p.Reference << ", Index : " << p.Index << "}";
    }

}

namespace Gigamonkey::input {
    bool valid(bytes_view);
    slice<36> previous(bytes_view);
    bytes_view script(bytes_view);
    uint32_little sequence(bytes_view);
}

namespace Gigamonkey::Bitcoin {
    struct input {
        outpoint Outpoint; 
        bytes Script;
        uint32_little Sequence;
        
        bool valid() const;
        
        bytes_writer write(bytes_writer w) const;
        bytes_reader read(bytes_reader r);
        
        size_t serialized_size() const;
        
        bool operator==(const input& i) const;
        bool operator!=(const input& i) const;
    };
    
    inline std::ostream& operator<<(std::ostream& o, const input& p) {
        return o << "input{Outpoint : " << p.Outpoint << ", Script : " << p.Script << ", Sequence : " << p.Sequence << "}";
    }

}

namespace Gigamonkey::output {
    bool valid(bytes_view);
    satoshi value(bytes_view);
    bytes_view script(bytes_view);
}

namespace Gigamonkey::Bitcoin {
    struct output {
        satoshi Value; 
        bytes Script;
        
        bool valid() const;
        
        bytes_writer write(bytes_writer w) const;
        bytes_reader read(bytes_reader r);
        
        size_t serialized_size() const;
        
        bool operator==(const output& o) const;
        bool operator!=(const output& o) const;
    };

    inline std::ostream& operator<<(std::ostream& o, const output& p) {
        return o << "output{Value : " << p.Value << ", Script : " << p.Script << "}";
    }

}

namespace Gigamonkey::transaction {
    bool valid(bytes_view);
    int32_little version(bytes_view);
    cross<bytes_view> outputs(bytes_view);
    cross<bytes_view> inputs(bytes_view);
    bytes_view output(bytes_view, index);
    bytes_view input(bytes_view, index);
    int32_little locktime(bytes_view);
    
    // Whether this is a coinbase transaction. 
    bool coinbase(bytes_view);
    
    inline Bitcoin::txid txid(bytes_view b) {
        return Bitcoin::id(b);
    }
}

namespace Gigamonkey::Bitcoin {
    struct transaction {
        int32_little Version;
        list<input> Inputs;
        list<output> Outputs;
        int32_little Locktime;
        
        transaction(int32_little v, list<input> i,  list<output> o, int32_little t) : 
            Version{v}, Inputs{i}, Outputs{o}, Locktime{t} {}
        
        transaction(list<input> i, list<output> o, int32_little t) : 
            transaction{int32_little{2}, i, o, t} {}
            
        transaction() : Version{}, Inputs{}, Outputs{}, Locktime{} {};
        
        bool valid() const;
        
        bytes_writer write(bytes_writer w) const;
        bytes_reader read(bytes_reader r);
        
        static transaction read(bytes_view);
        bytes write() const;
        
        txid id() const {
            return Gigamonkey::transaction::txid(write());
        }
        
        bool coinbase() const;
        
        size_t serialized_size() const;
        
        uint32 sigops() const;
        
        satoshi sent() const {
            return fold([](satoshi x, const output& o) -> satoshi {
                return x + o.Value;
            }, satoshi{0}, Outputs);
        }
        
        bool operator==(const transaction& t) const;
        bool operator!=(const transaction& t) const;
    };
}

namespace Gigamonkey::Bitcoin { 
    struct block {
        header Header;
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
        
        bool operator==(const block& b) const;
        bool operator!=(const block& b) const;
    };
}

namespace Gigamonkey::block {
    inline bool valid(bytes_view b) {
        return Bitcoin::block::read(b).valid();
    }
    
    const slice<80> header(bytes_view);
    cross<bytes_view> transactions(bytes_view);
    
    inline digest<32> merkle_root(cross<bytes_view> txs) {
        list<digest256> leaves{};
        for (bytes_view b : txs) {
            leaves = leaves << Bitcoin::hash256(b);
        }
        return Merkle::root(leaves);
    }
}

namespace Gigamonkey::Bitcoin { 

    inline bytes_writer operator<<(bytes_writer w, const header& h) {
        return h.write(w);
    }

    inline bytes_reader operator>>(bytes_reader r, header& h) {
        return h.read(r);
    }

    inline bytes_writer operator<<(bytes_writer w, const outpoint& o) {
        return o.write(w);
    }

    inline bytes_reader operator>>(bytes_reader r, outpoint& o) {
        return o.read(r);
    }

    inline bytes_writer operator<<(bytes_writer w, const input& in) {
        return in.write(w);
    }

    inline bytes_reader operator<<(bytes_reader r, input& in) {
        return in.read(r);
    }

    inline bytes_writer operator<<(bytes_writer w, const output& out) {
        return out.write(w);
    }

    inline bytes_reader operator>>(bytes_reader r, output& out) {
        return out.read(r);
    }

    inline bytes_writer operator<<(bytes_writer w, const transaction& t) {
        return t.write(w);
    }

    inline bytes_reader operator>>(bytes_reader r, transaction& t) {
        return t.read(r);
    }

    inline bytes_writer operator<<(bytes_writer w, const block& b) {
        return b.write(w);
    }

    inline bytes_reader operator>>(bytes_reader r, block& b) {
        return b.read(r);
    }

}

namespace Gigamonkey::header {    
    inline const digest<32> previous(const slice<80> x) {
        return digest<32>(x.range<4, 36>());
    }
    
    inline const digest<32> merkle_root(const slice<80> x) {
        return digest<32>(x.range<36, 68>());
    }
    
    inline digest<32> hash(const slice<80> h) {
        return Bitcoin::hash256(h);
    }
}

namespace Gigamonkey::Bitcoin {
    
    bytes_writer write_var_int(bytes_writer, uint64);
    
    bytes_reader read_var_int(bytes_reader, uint64&);
    
    size_t var_int_size(uint64);
    
    inline bytes_writer write_data(bytes_writer w, bytes_view b) {
        return write_var_int(w, b.size()) << b;
    }
    
    inline bytes_reader read_data(bytes_reader r, bytes& b) {
        uint64 size;
        r = read_var_int(r, size);
        b = bytes(size);
        return r >> b;
    }
    
    template <typename X> 
    inline bytes_writer write_sequence(bytes_writer w, list<X> l) {
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
        
    inline bool header::operator==(const header& h) const {
        return Version == h.Version && Previous == h.Previous && MerkleRoot == h.MerkleRoot 
            && Timestamp == h.Timestamp && Target == h.Target && Nonce == h.Nonce;
    }
        
    inline bool header::operator!=(const header& h) const {
        return !operator==(h);
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
        
    inline bool outpoint::operator==(const outpoint& o) const {
        return Reference == o.Reference && Index == o.Index;
    }
    
    inline bool outpoint::operator!=(const outpoint& o) const {
        return !operator==(o);
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
    
    inline bool input::operator==(const input& i) const {
        return Outpoint == i.Outpoint && Script == i.Script && Sequence == i.Sequence;
    }
    
    inline bool input::operator!=(const input& i) const {
        return !operator==(i);
    }
    
    inline bytes_writer output::write(bytes_writer w) const {
        return write_data(w << Value, Script);
    }
    
    inline bytes_reader output::read(bytes_reader r) {
        return read_data(r >> Value, Script);
    }
    
    inline bool output::operator==(const output& o) const {
        return Value == o.Value && Script == o.Script;
    }
    
    inline bool output::operator!=(const output& o) const {
        return !operator==(o);
    }
    
    inline size_t output::serialized_size() const {
        return 8 + var_int_size(Script.size()) + Script.size();
    }
    
    inline bool transaction::valid() const {
        return Inputs.size() > 0 && Outputs.size() > 0 && 
            fold([](bool b, input i) -> bool {
                return b && i.valid();
            }, true, Inputs) && 
            fold([](bool b, output o) -> bool {
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
    
    inline bool transaction::operator==(const transaction& t) const {
        return Version == t.Version && Inputs == t.Inputs && Outputs == t.Outputs && Locktime == t.Locktime;
    }
    
    inline bool transaction::operator!=(const transaction& t) const {
        return !operator==(t);
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
    
    inline bool block::operator==(const block& b) const {
        return Header == b.Header && Transactions == b.Transactions;
    }
    
    inline bool block::operator!=(const block& b) const {
        return !operator==(b);
    }
}

#endif

