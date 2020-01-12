// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TIMECHAIN
#define GIGAMONKEY_TIMECHAIN

#include "txid.hpp"
#include "merkle.hpp"
#include "work.hpp"

namespace gigamonkey::bitcoin {
    struct timechain {
        virtual list<uint<80>> headers(uint64 since_height) const = 0;
        virtual bytes transaction(const digest<32>&) const = 0;
        virtual merkle::path merkle_path(const digest<32>&) const = 0;
        // next 3 should work for both header hash and merkle root.
        virtual uint<80> header(const digest<32>&) const = 0; 
        virtual list<txid> transactions(const digest<32>&) const = 0;
        virtual bytes block(const digest<32>&) const = 0; 
    };
}

namespace gigamonkey::header {
    int32_little version(slice<80>);
    
    inline const digest<32> previous(slice<80> x) {
        return digest<32>(x.range<4, 36>());
    }
    
    inline const digest<32> merkle_root(slice<80> x) {
        return digest<32>(x.range<36, 68>());
    }
    
    gigamonkey::timestamp timestamp(slice<80>);
    
    work::target target(slice<80>);
    
    uint32_little nonce(slice<80>);
    
    inline digest<32> hash(slice<80> h) {
        return work::candidate::hash(h);
    }
    
    bool valid(slice<80> h);
}

namespace gigamonkey::bitcoin {
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
                gigamonkey::header::version(x), 
                digest<32>{gigamonkey::header::previous(x)}, 
                digest<32>{gigamonkey::header::merkle_root(x)}, 
                timestamp{gigamonkey::header::timestamp(x)}, 
                work::target{gigamonkey::header::target(x)}, 
                gigamonkey::header::nonce(x)};
        }
        
        bytes_reader read(bytes_reader r);
        bytes_writer write(bytes_writer w) const;
        
        uint<80> write() const;
        
        digest<32> hash() const {
            return hash256(write());
        }
        
        bool valid() const;
        
        work::difficulty difficulty() const {
            return work::difficulty{Target.expand().Digest};
        }
        
        bool operator==(const header& h) const {
            return Version == h.Version && Previous == h.Previous && MerkleRoot == h.MerkleRoot 
                && Timestamp == h.Timestamp && Target == h.Target && Nonce == h.Nonce;
        }
        
        bool operator!=(const header& h) const {
            return !operator==(h);
        }
    };
}

namespace gigamonkey::outpoint {
    bool valid(slice<36>);
    const bitcoin::txid reference(slice<36>);
    gigamonkey::index index(slice<36>);
}

namespace gigamonkey::bitcoin {
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

namespace gigamonkey::input {
    bool valid(bytes_view);
    slice<36> previous(bytes_view);
    bytes_view script(bytes_view);
    uint32_little sequence(bytes_view);
}

namespace gigamonkey::bitcoin {
    struct input {
        outpoint Outpoint; 
        bytes Script;
        uint32_little Sequence;
        
        bool valid() const;
        
        bytes_writer write(bytes_writer w) const;
        bytes_reader read(bytes_reader r);
        
        size_t serialized_size() const {
            return 40 + var_int_size(Script.size()) + Script.size();
        }
    };
}

namespace gigamonkey::output {
    bool valid(bytes_view);
    satoshi value(bytes_view);
    bytes_view script(bytes_view);
}

namespace gigamonkey::bitcoin {
    struct output {
        satoshi Value; 
        bytes Script;
        
        bool valid() const;
        
        bytes_writer write(bytes_writer w) const;
        bytes_reader read(bytes_reader r);
        
        size_t serialized_size() const {
            return 8 + var_int_size(Script.size()) + Script.size();
        }
    };
}

namespace gigamonkey::transaction {
    bool valid(bytes_view);
    int32_little version(bytes_view);
    index outputs(bytes_view);
    index inputs(bytes_view);
    bytes_view output(bytes_view, index);
    bytes_view input(bytes_view, index);
    int32_little locktime(bytes_view);
    
    // Whether this is a coinbase transaction. 
    bool coinbase(bytes_view);
    
    inline bitcoin::txid txid(bytes_view b) {
        return bitcoin::id(b);
    }
}

namespace gigamonkey::bitcoin {
    struct transaction {
        int32_little Version;
        queue<input> Inputs;
        queue<output> Outputs;
        int32_little Locktime;
        
        bytes_writer write(bytes_writer w) const;
        bytes_reader read(bytes_reader r);
        
        static transaction read(bytes_view);
        bytes write() const;
        
        txid id() const {
            return gigamonkey::transaction::txid(write());
        }
        
        bool coinbase() const;
        
        size_t serialized_size() const {
            return 8 + var_int_size(Inputs.size()) + var_int_size(Inputs.size()) + 
                data::fold([](size_t size, const input& i)->size_t{
                    return size + i.serialized_size();
                }, 0, Inputs) + 
                data::fold([](size_t size, const output& i)->size_t{
                    return size + i.serialized_size();
                }, 0, Outputs);
        }
    };
}

namespace gigamonkey::block {
    bool valid(bytes_view);
    slice<80> header(bytes_view);
    vector<bytes_view> transactions(bytes_view);
    
    inline digest<32> merkle_root(vector<bytes_view> q) {
        throw data::method::unimplemented{"merkle_root"};
    }
}

namespace gigamonkey::bitcoin { 
    struct block {
        header Header;
        queue<transaction> Transactions;
        
        block() : Header{}, Transactions{} {}
        
        bytes coinbase();
        bool valid() const {
            return gigamonkey::block::valid(write());
        }
        
        bytes_writer write(bytes_writer w) const;
        bytes_reader read(bytes_reader r);
        
        static block read(bytes_view b);
        bytes write() const;
        
        size_t serialized_size() const {
            return 80 + var_int_size(Transactions.size()) + 
            data::fold([](size_t size, transaction x)->size_t{
                return size + x.serialized_size();
            }, 0, Transactions);
        }
    };
}

inline gigamonkey::bytes_writer operator<<(gigamonkey::bytes_writer w, const gigamonkey::bitcoin::header& h) {
    return h.write(w);
}

inline gigamonkey::bytes_reader operator>>(gigamonkey::bytes_reader r,  gigamonkey::bitcoin::header& h) {
    return h.read(r);
}

inline gigamonkey::bytes_writer operator<<(gigamonkey::bytes_writer w, const gigamonkey::bitcoin::outpoint& o) {
    return o.write(w);
}

inline gigamonkey::bytes_reader operator>>(gigamonkey::bytes_reader r, gigamonkey::bitcoin::outpoint& o) {
    return o.read(r);
}

inline gigamonkey::bytes_writer operator<<(gigamonkey::bytes_writer w, const gigamonkey::bitcoin::input& in) {
    return in.write(w);
}

inline gigamonkey::bytes_reader operator<<(gigamonkey::bytes_reader r, gigamonkey::bitcoin::input& in) {
    return in.read(r);
}

inline gigamonkey::bytes_writer operator<<(gigamonkey::bytes_writer w, const gigamonkey::bitcoin::output& out) {
    return out.write(w);
}

inline gigamonkey::bytes_reader operator>>(gigamonkey::bytes_reader r, gigamonkey::bitcoin::output& out) {
    return out.read(r);
}

inline gigamonkey::bytes_writer operator<<(gigamonkey::bytes_writer w, const gigamonkey::bitcoin::transaction& t) {
    return t.write(w);
}

inline gigamonkey::bytes_reader operator>>(gigamonkey::bytes_reader r, gigamonkey::bitcoin::transaction& t) {
    return t.read(r);
}

inline gigamonkey::bytes_writer operator<<(gigamonkey::bytes_writer w, const gigamonkey::bitcoin::block& b) {
    return b.write(w);
}

inline gigamonkey::bytes_reader operator>>(gigamonkey::bytes_reader r, gigamonkey::bitcoin::block& b) {
    return b.read(r);
}

namespace gigamonkey::bitcoin {
    
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
    
    inline bytes_writer transaction::write(bytes_writer w) const {
        return write_list(write_list(w << Version, Inputs), Outputs) << Locktime;
    }
    
    inline bytes_reader transaction::read(bytes_reader r) {
        return read_list(read_list(r >> Version, Inputs), Outputs) >> Locktime;
    }
    
    inline transaction transaction::read(bytes_view b) {
        transaction t;
        reader(b) >> t;
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
        reader(b) >> bl;
        return bl;
    }
    
    inline bytes block::write() const {
        bytes b{serialized_size()};
        write(writer(b));
        return b;
    }
}

#endif

