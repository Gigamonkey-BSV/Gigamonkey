// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <bitcoin/wif.hpp>
#include <bitcoin/address.hpp>

namespace gigamonkey::bitcoin {
    
    static wif wif::read(const string& s) {
        wif w{};
        reader r = reader{base58_check_decode(s)} >> &w.Prefix >> &w.Secret.Value;
        char suffix;
        w.Compressed = (!(r >> &suffix).valid()) || suffix == compressed_suffix();  
        return w;
    }
    
    string wif::write(char prefix, const secret& s, bool compressed) {
        string data;
        data.resize(size())
        writer w = writer{data.begin(), data.end()} << prefix << s; 
        if (compressed) w << compressed_suffix() else w;
        return data;
    }
    
}

