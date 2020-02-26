// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work.hpp>

namespace Gigamonkey {
    bool header_valid_work(slice<80> h) {
        return work::string::valid(h);
    }
    
    bool header_valid(const Bitcoin::header& h) {
        return h.Version >= 1 && h.MerkleRoot.valid() && h.Timestamp != timestamp{};
    }
}

namespace Gigamonkey::header {
    int32_little version(slice<80> x) {
        int32_little version;
        slice<4> v = x.range<0, 4>();
        std::copy(v.begin(), v.end(), version.data());
        return version;
    }
    
    Gigamonkey::timestamp timestamp(slice<80> x) {
        Gigamonkey::timestamp time;
        slice<4> v = x.range<68, 72>();
        std::copy(v.begin(), v.end(), time.data());
        return time;
    }
    
    work::target target(slice<80> x) {
        work::target work;
        slice<4> v = x.range<72, 76>();
        std::copy(v.begin(), v.end(), work.data());
        return work;
    }
    
    uint32_little nonce(slice<80> x) {
        uint32_little n;
        slice<4> v = x.range<76, 80>();
        std::copy(v.begin(), v.end(), n.data());
        return n;
    }
    
    bool valid(slice<80> h) {
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
    /*
    bool valid(bytes_view b) {
        slice<80> h = header(b);
        if (!header::valid(h)) return false;
        cross<bytes_view> txs = transactions(b);
        if (txs.size() == 0 || !transaction::coinbase(txs[0])) return false;
        for (int i = 1; i < txs.size(); i++) if (!transaction::valid(txs[i])) return false;
        return digest<32>{header::merkle_root(h)} == merkle_root(txs);
    }
    */
    cross<bytes_view> transactions(bytes_view) {
        throw data::method::unimplemented{"block::transactions"};
    }
    
    slice<80> header(bytes_view) {
        throw data::method::unimplemented{"block::header"};
    }
    
}

namespace Gigamonkey::Bitcoin {
    
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

