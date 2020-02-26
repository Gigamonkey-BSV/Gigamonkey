// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TIMECHAIN
#define GIGAMONKEY_TIMECHAIN

#include <gigamonkey/txid.hpp>
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
    };
}

namespace Gigamonkey::header {
    int32_little version(slice<80>);
    
    inline const digest<32> previous(slice<80> x) {
        return digest<32>(x.range<4, 36>());
    }
    
    inline const digest<32> merkle_root(slice<80> x) {
        return digest<32>(x.range<36, 68>());
    }
    
    Gigamonkey::timestamp timestamp(slice<80>);
    
    work::target target(slice<80>);
    
    uint32_little nonce(slice<80>);
    
    inline digest<32> hash(slice<80> h) {
        return Bitcoin::hash256(h);
    }
    
    bool valid(slice<80> h);
}

namespace Gigamonkey::Bitcoin {
    struct header {
        int32_little Version;
        digest<32> Previous;
        digest<32> MerkleRoot;
        timestamp Timestamp;
        work::target Target;
        uint32_little Nonce;
        
        header() : Version{}, Previous{}, MerkleRoot{}, Timestamp{}, Target{}, Nonce{} {}
        
        header(
            int32_little v,
            digest<32> p,
            digest<32> mr,
            timestamp ts,
            work::target t,
            uint32_little n) : Version{v}, Previous{p}, MerkleRoot{mr}, Timestamp{ts}, Target{t}, Nonce{n} {}
            
        static header read(slice<80> x) {
            return header{
                Gigamonkey::header::version(x), 
                digest<32>{Gigamonkey::header::previous(x)}, 
                digest<32>{Gigamonkey::header::merkle_root(x)}, 
                timestamp{Gigamonkey::header::timestamp(x)}, 
                work::target{Gigamonkey::header::target(x)}, 
                Gigamonkey::header::nonce(x)};
        }
        
        bytes_reader read(bytes_reader r);
        bytes_writer write(bytes_writer w) const;
        
        uint<80> write() const;
        
        digest<32> hash() const {
            return hash256(write());
        }
        
        bool valid() const;
        
        bool operator==(const header& h) const {
            return Version == h.Version && Previous == h.Previous && MerkleRoot == h.MerkleRoot 
                && Timestamp == h.Timestamp && Target == h.Target && Nonce == h.Nonce;
        }
        
        bool operator!=(const header& h) const {
            return !operator==(h);
        }
    };
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
    };
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
    };
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
    };
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
        
        bytes_writer write(bytes_writer w) const;
        bytes_reader read(bytes_reader r);
        
        static transaction read(bytes_view);
        bytes write() const;
        
        txid id() const {
            return Gigamonkey::transaction::txid(write());
        }
        
        bool coinbase() const;
        
        size_t serialized_size() const;
    };
}

namespace Gigamonkey::block {
    bool valid(bytes_view);
    slice<80> header(bytes_view);
    cross<bytes_view> transactions(bytes_view);
    
    inline digest<32> merkle_root(cross<bytes_view> q) {
        throw data::method::unimplemented{"merkle_root"};
    }
}

namespace Gigamonkey::Bitcoin { 
    struct block {
        header Header;
        list<transaction> Transactions;
        
        block() : Header{}, Transactions{} {}
        
        bytes coinbase();
        bool valid() const {
            return Gigamonkey::block::valid(write());
        }
        
        bytes_writer write(bytes_writer w) const;
        bytes_reader read(bytes_reader r);
        
        static block read(bytes_view b);
        bytes write() const;
        
        size_t serialized_size() const;
    };
}

inline Gigamonkey::bytes_writer operator<<(Gigamonkey::bytes_writer w, const Gigamonkey::Bitcoin::header& h) {
    return h.write(w);
}

inline Gigamonkey::bytes_reader operator>>(Gigamonkey::bytes_reader r,  Gigamonkey::Bitcoin::header& h) {
    return h.read(r);
}

inline Gigamonkey::bytes_writer operator<<(Gigamonkey::bytes_writer w, const Gigamonkey::Bitcoin::outpoint& o) {
    return o.write(w);
}

inline Gigamonkey::bytes_reader operator>>(Gigamonkey::bytes_reader r, Gigamonkey::Bitcoin::outpoint& o) {
    return o.read(r);
}

inline Gigamonkey::bytes_writer operator<<(Gigamonkey::bytes_writer w, const Gigamonkey::Bitcoin::input& in) {
    return in.write(w);
}

inline Gigamonkey::bytes_reader operator<<(Gigamonkey::bytes_reader r, Gigamonkey::Bitcoin::input& in) {
    return in.read(r);
}

inline Gigamonkey::bytes_writer operator<<(Gigamonkey::bytes_writer w, const Gigamonkey::Bitcoin::output& out) {
    return out.write(w);
}

inline Gigamonkey::bytes_reader operator>>(Gigamonkey::bytes_reader r, Gigamonkey::Bitcoin::output& out) {
    return out.read(r);
}

inline Gigamonkey::bytes_writer operator<<(Gigamonkey::bytes_writer w, const Gigamonkey::Bitcoin::transaction& t) {
    return t.write(w);
}

inline Gigamonkey::bytes_reader operator>>(Gigamonkey::bytes_reader r, Gigamonkey::Bitcoin::transaction& t) {
    return t.read(r);
}

inline Gigamonkey::bytes_writer operator<<(Gigamonkey::bytes_writer w, const Gigamonkey::Bitcoin::block& b) {
    return b.write(w);
}

inline Gigamonkey::bytes_reader operator>>(Gigamonkey::bytes_reader r, Gigamonkey::Bitcoin::block& b) {
    return b.read(r);
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
        b = bytes{size};
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
    
    inline uint<80> header::write() const {
        throw data::method::unimplemented{"write"};
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
        bytes b{serialized_size()};
        write(bytes_writer(b.begin(), b.end()));
        return b;
    }
}

#endif

