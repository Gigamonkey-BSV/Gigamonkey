// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/timechain.hpp>

namespace gigamonkey {
    bool header_valid_work(slice<80> h) {
        return work::candidate::valid(h);
    }
    
    bool header_valid(const bitcoin::header& h) {
        return h.Version >= 1 && h.MerkleRoot.valid() && h.Timestamp != timestamp{};
    }
}

namespace gigamonkey::header {
    
    bool valid(slice<80> h) {
        return header_valid(bitcoin::header::read(h)) && header_valid_work(h);
    }
    
}

namespace gigamonkey::block {
        
    bool valid(bytes_view b) {
        slice<80> h = header(b);
        if (!header::valid(h)) return false;
        queue<bytes_view> txs = transactions(b);
        if (txs.empty() || !transaction::coinbase(txs.first())) return false;
        queue<bytes_view> txs_rest = txs.rest();
        while(!txs_rest.empty()) {
            if (!transaction::valid(txs_rest.first())) return false;
        }
        
        return digest<32>{header::merkle_root(h)} == merkle_root(txs);
    }
    
    queue<bytes_view> transactions(bytes_view) {
        throw data::method::unimplemented{"block::transactions"};
    }
    
    slice<80> header(bytes_view) {
        throw data::method::unimplemented{"block::header"};
    }
    
}

namespace gigamonkey::bitcoin {
        
    bool header::valid() const {
        return header_valid_work(write()) && header_valid(*this);
    }
    
}

