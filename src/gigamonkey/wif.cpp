// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/wif.hpp>
#include <gigamonkey/address.hpp>
#include <gigamonkey/txid.hpp>

namespace Gigamonkey::Bitcoin {
    
    wif wif::read(string_view s) {
        bytes data;
        if (!base58::check_decode(data, s)) return wif{};
        wif w{};
        bytes_reader r = bytes_reader(data.data(), data.data() + data.size()) >> w.Prefix >> w.Secret; 
        if (!r.empty()) {
            char suffix;
            r >> suffix;
            if (suffix != CompressedSuffix) return wif{};
            w.Compressed = true;
        } else w.Compressed = false;
        return w;
    }
    
    
    string wif::write(char prefix, const secret& s, bool compressed) {
        bytes data(compressed ? CompressedSize : UncompressedSize);
        bytes_writer w = bytes_writer(data.begin(), data.end()) << prefix << s.Value; 
        if (compressed) w << CompressedSuffix;
        return base58::check_encode(data);
    }
    
}

