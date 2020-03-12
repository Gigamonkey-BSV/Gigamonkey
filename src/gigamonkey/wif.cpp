// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/wif.hpp>
#include <gigamonkey/address.hpp>
#include <gigamonkey/txid.hpp>

namespace Gigamonkey::Bitcoin {
    
    wif wif::read(string_view s) {
        base58::check b58(s);
        if (!b58.valid()) return wif{};
        wif w{};
        if (b58.Data.size() == 33) {
            w.Compressed = false;
        } else if (b58.Data.size() == 34) {
            w.Compressed = true;
        } else return {};
        bytes_reader r = bytes_reader(b58.Data.data(), b58.Data.data() + b58.Data.size()) >> w.Prefix >> w.Secret; 
        
        if (w.Compressed) {
            byte suffix;
            r >> suffix;
            if (suffix != CompressedSuffix) return wif{};
        } 
        
        return w;
    }
    
    string wif::write(byte prefix, const secret& s, bool compressed) {
        bytes data(compressed ? CompressedSize - 1: UncompressedSize - 1);
        bytes_writer w = bytes_writer(data.begin(), data.end()) << s.Value; 
        if (compressed) w << CompressedSuffix;
        return base58::check{prefix, data}.encode();
    }
    
}

