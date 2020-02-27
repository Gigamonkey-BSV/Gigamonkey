// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work/proof.hpp>

namespace Gigamonkey {
    bool header_valid_work(slice<80> h) {
        return work::string::valid(h);
    }
    
    bool header_valid(const Bitcoin::header& h) {
        return h.Version >= 1 && h.MerkleRoot.valid() && h.Timestamp != timestamp{};
    }
}

namespace Gigamonkey::header {
    int32_little version(const slice<80> x) {
        int32_little version;
        slice<4> v = x.range<0, 4>();
        std::copy(v.begin(), v.end(), version.data());
        return version;
    }
    
    Gigamonkey::timestamp timestamp(const slice<80> x) {
        Gigamonkey::timestamp time;
        slice<4> v = x.range<68, 72>();
        std::copy(v.begin(), v.end(), time.data());
        return time;
    }
    
    work::target target(const slice<80> x) {
        work::target work;
        slice<4> v = x.range<72, 76>();
        std::copy(v.begin(), v.end(), work.data());
        return work;
    }
    
    uint32_little nonce(const slice<80> x) {
        uint32_little n;
        slice<4> v = x.range<76, 80>();
        std::copy(v.begin(), v.end(), n.data());
        return n;
    }
    
    bool valid(const slice<80> h) {
        return header_valid(Bitcoin::header::read(h)) && header_valid_work(h);
    }
    
}

namespace Gigamonkey::transaction {
    bool valid(bytes_view) {
        throw data::method::unimplemented{"transaction::valid"};
    }
    
    // Whether this is a coinbase transaction. 
    bool coinbase(bytes_view) {
        throw data::method::unimplemented{"transaction::coinbase"};
    }
}

namespace Gigamonkey::block {
    struct tx_reader {
        bytes_view Next;
        bytes_reader Rest;
        
        bool valid() const;
    };
    
    tx_reader read_next_tx(bytes_reader);
    /*
    digest256 merkle_root(bytes_view block) {
        Merkle::leaves l{};
        bytes_view txs{transactions(block)};
        bytes_reader reading{txs.begin(), txs.end()};
        while(!reading.eof()) {
            tx_reader next = read_next_tx(reading);
            l = l << Bitcoin::hash256(next.Next);
            reading = next.Rest;
        }
        return Merkle::root(l);
    }*/
    
    /*
    bool valid(bytes_view b) {
        // TODO check magic number
        slice<80> h = header(b);
        if (!header::valid(h)) return false;
        cross<uint64> tx_indices = transactions(b);
        if (tx_indices.size() == 0 || !transaction::coinbase(txs[0])) return false;
        for (int i = 1; i < tx_indices.size(); i++) if (!transaction::valid(txs[i])) return false;
        return header::merkle_root(h) == merkle_root(txs);
    }*/
    /*
    cross<uint64> transactions(bytes_view b) {
        bytes_view after_header{b.substr(80)};
        bytes_reader txs = bytes_reader{after_header.begin(), after_header.end()};
        uint64 num_txs;
        txs = Bitcoin::read_var_int(txs, num_txs);
        // TODO
    }
    
    /* TODO
    const slice<80> header(bytes_view b) {
        return data::slice<byte>{b}.range<8, 88>();
    }*/
    
}

namespace Gigamonkey::Bitcoin {
    
    Gigamonkey::uint256 satoshi_uint256_to_uint256(::uint256 x) {
        Gigamonkey::uint256 y;
        std::copy(x.begin(), x.end(), y.begin());
        return y;
    }
    
    header::header(const CBlockHeader& b) : 
        Version{int32_little{b.nVersion}}, 
        Previous{satoshi_uint256_to_uint256(b.hashPrevBlock)}, 
        MerkleRoot{satoshi_uint256_to_uint256(b.hashMerkleRoot)}, 
        Timestamp{uint32_little{b.nTime}}, 
        Target{uint32_little{b.nBits}}, 
        Nonce{b.nNonce} {};
        
    header::operator CBlockHeader() const {
        CBlockHeader h;
        h.nVersion = Version;
        h.nTime = Timestamp.Value;
        h.nBits = Target;
        h.nNonce = Nonce;
        std::copy(Previous.Value.begin(), Previous.Value.end(), h.hashPrevBlock.begin());
        std::copy(MerkleRoot.Value.begin(), MerkleRoot.Value.end(), h.hashMerkleRoot.begin());
        return h;
    }
    
    bytes_writer write_var_int(bytes_writer, uint64) {
        throw data::method::unimplemented{"write_var_int"};
    }
    
    bytes_reader read_var_int(bytes_reader, uint64&) {
        throw data::method::unimplemented{"read_var_int"};
    }
    
    size_t var_int_size(uint64) {
        throw data::method::unimplemented{"var_int_size"};
    }
        
    bool header::valid() const {
        return header_valid_work(write()) && header_valid(*this);
    }
    
    size_t transaction::serialized_size() const {
        return 8 + var_int_size(Inputs.size()) + var_int_size(Inputs.size()) + 
            data::fold([](size_t size, const input& i)->size_t{
                return size + i.serialized_size();
            }, 0, Inputs) + 
            data::fold([](size_t size, const output& i)->size_t{
                return size + i.serialized_size();
            }, 0, Outputs);
    }
        
    size_t block::serialized_size() const {
        return 80 + var_int_size(Transactions.size()) + 
        data::fold([](size_t size, transaction x)->size_t{
            return size + x.serialized_size();
        }, 0, Transactions);
    }
    
}

