// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/wif.hpp>
#include <gigamonkey/address.hpp>
#include <gigamonkey/txid.hpp>

namespace gigamonkey::bitcoin {
    
    wif wif::read(string_view s) {
        bytes data;
        if (!base58::check_decode(data, s)) return wif{};
        wif w{};
        txid d;
        bytes_reader r = reader(data) >> w.Prefix >> d; 
        char suffix;
        w.Compressed = (!(r >> suffix).valid()) || suffix == CompressedSuffix; 
        w.Secret.Value = digest<32, BigEndian>(d);
        return w;
    }
    
    
    string wif::write(char prefix, const secret& s, bool compressed) {
        bytes data;
        data.resize(compressed ? CompressedSize : UncompressedSize);
        bytes_writer w = writer(data) << prefix << s; 
        if (compressed) w << CompressedSuffix;
        return base58::check_encode(data);
    }
    
}

