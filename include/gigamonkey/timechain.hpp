// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TIMECHAIN
#define GIGAMONKEY_TIMECHAIN

#include "types.hpp"
#include "merkle.hpp"
#include "work.hpp"

namespace gigamonkey::bitcoin {
    struct timechain {
        virtual list<uint<80>> headers(uint64 since_height) const = 0;
        virtual bytes transaction(const digest<32, BigEndian>&) const = 0;
        virtual merkle::path merkle_path(const digest<32, BigEndian>&) const = 0;
        // next 3 should work for both header hash and merkle root.
        virtual uint<80> header(const digest<32, BigEndian>&) const = 0; 
        virtual list<txid> transactions(const digest<32, BigEndian>&) const = 0;
        virtual bytes block(const digest<32, BigEndian>&) const = 0; 
    };
}

namespace gigamonkey::header {
    bool valid(slice<80>);
    int32_little version(slice<80>);
    slice<32> previous(slice<80>);
    slice<32> merkle_root(slice<80>);
    gigamonkey::timestamp timestamp(slice<80>);
    work::target target(slice<80>);
    uint32_little nonce(slice<80>);
    inline bytes_writer write(bytes_writer w, 
        int32_little version, digest<32, LittleEndian> previous, digest<32, LittleEndian> root,
        gigamonkey::timestamp time, work::target target, uint32_little nonce) {
        return w << version << previous << root << time << target << nonce;
    }
}

namespace gigamonkey::bitcoin {
    struct header {
        int32_little Version;
        digest<32, LittleEndian> Previous;
        digest<32, LittleEndian> MerkleRoot;
        timestamp Timestamp;
        work::target Target;
        uint32_little Nonce;
        
        header(
            int32_little v,
            digest<32, LittleEndian> p,
            digest<32, LittleEndian> mr,
            uint32_little ts,
            work::target t,
            uint32_little n) : Version{v}, Previous{p}, MerkleRoot{mr}, Timestamp{ts}, Target{t}, Nonce{n} {}
            
        header(slice<80> x) : 
            Version{gigamonkey::header::version(x)}, 
            Previous{gigamonkey::header::previous(x)}, 
            MerkleRoot{gigamonkey::header::merkle_root(x)}, 
            Timestamp{gigamonkey::header::timestamp(x)}, 
            Target{gigamonkey::header::target(x)}, 
            Nonce{gigamonkey::header::nonce(x)} {}
            
        bytes_writer write(bytes_writer w) const {
            return gigamonkey::header::write(w, Version, Previous, MerkleRoot, Timestamp, Target, Nonce);
        }
        
        uint<80> write() const;
        
        digest<32, BigEndian> hash() const {
            return hash256(write());
        }
        
        bool valid() const {
            return Previous.valid() && MerkleRoot.valid() && Target.valid() && hash() < Target.expand();
        }
        
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

inline gigamonkey::bytes_writer operator<<(gigamonkey::bytes_writer w, const gigamonkey::bitcoin::header& h) {
    return h.write(w);
}

namespace gigamonkey::outpoint {
    bool valid(slice<36>);
    slice<32> reference(slice<36>);
    gigamonkey::index index(slice<36>);
    
    inline bytes_writer write(bytes_writer w, bitcoin::txid t, gigamonkey::index i) {
        return w << t << i;
    }
}

namespace gigamonkey::bitcoin {
    struct outpoint {
        txid Reference; 
        index Index;
        
        bool valid() const {
            return Reference.valid();
        }
        
        bytes_writer write(bytes_writer w) const {
            return gigamonkey::outpoint::write(w, Reference, Index);
        }
    };
}

inline gigamonkey::bytes_writer operator<<(gigamonkey::bytes_writer w, const gigamonkey::bitcoin::outpoint& o) {
    return o.write(w);
}

namespace gigamonkey::input {
    bool valid(bytes_view);
    slice<36> previous(bytes_view);
    bytes_view script(bytes_view);
    uint32_little sequence(bytes_view);
    
    inline bytes_writer write(bytes_writer w, const bitcoin::outpoint& o, bytes_view script, uint32_little sequence) {
        return w << o << script << sequence;
    }
}

namespace gigamonkey::bitcoin {
    struct input {
        outpoint Outpoint; 
        bytes Script;
        uint32_little Sequence;
        
        bool valid() const;
        
        bytes_writer write(bytes_writer w) const {
            return gigamonkey::input::write(w, Outpoint, Script, Sequence);
        }
    };
}

inline gigamonkey::bytes_writer operator<<(gigamonkey::bytes_writer w, const gigamonkey::bitcoin::input& in) {
    return in.write(w);
}

namespace gigamonkey::output {
    bool valid(bytes_view);
    satoshi value(bytes_view);
    bytes_view script(bytes_view);
    
    inline bytes_writer write(bytes_writer w, satoshi value, bytes_view script) {
        return w << value << script;
    }
}

namespace gigamonkey::bitcoin {
    struct output {
        satoshi Value; 
        bytes Script;
        
        bool valid() const;
        
        bytes_writer write(bytes_writer w) const {
            return gigamonkey::output::write(w, Value, Script);
        }
    };
}

inline gigamonkey::bytes_writer operator<<(gigamonkey::bytes_writer w, const gigamonkey::bitcoin::output& out) {
    return out.write(w);
}

namespace gigamonkey::transaction {
    bool valid(bytes_view);
    int32_little version(bytes_view);
    index outputs(bytes_view);
    index inputs(bytes_view);
    bytes_view output(bytes_view, index);
    bytes_view input(bytes_view, index);
    int32_little locktime(bytes_view);
    
    bytes_writer write(bytes_writer w, int32_little version, list<bitcoin::input> in, list<bitcoin::output> out, int32_little locktime) {
        return write_list(write_list(w << version, in), out) << locktime;
    }
}

namespace gigamonkey::bitcoin {
    struct transaction {
        int32_little Version;
        list<input> Inputs;
        list<output> Outputs;
        int32_little Locktime;
        
        bytes_writer write(bytes_writer w) const {
            return gigamonkey::transaction::write(w, Version, Inputs, Outputs, Locktime);
        }
        
        bytes write() const;
    };
}

namespace gigamonkey::block {
    bool valid(bytes_view);
    slice<80> header(bytes_view);
    index transactions(bytes_view);
    bytes_view transaction(bytes_view, index);
}

namespace gigamonkey::bitcoin { 
    struct block {
        header Header;
        list<transaction> Transactions;
        bool valid() const;
    };
}

#endif

