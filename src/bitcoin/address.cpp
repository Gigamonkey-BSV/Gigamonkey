// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <bitcoin/address.hpp>
#include <data/encoding/base58.hpp>

namespace gigamonkey::bitcoin::base58 {
    
    inline bool decode(bytes& b, string_view s) {
        data::encoding::base58::string b58{s};
        if (!b58.valid()) return false;
        bytes decoded = bytes(b58);
        int leading_zeros = decoded.size() - b.size();
        if (leading_zeros < 0) return false;
        for (index x = 0; x < leading_zeros; x++) b[x] = 0x00;
        std::copy(decoded.begin(), decoded.end(), b.begin() + leading_zeros);
        return true;
    }
    
    string check_encode(bytes_view b) {
        uint32 leading_zeros = 0;
        for (index x = 0; x <= b.size() && b[x] == 0; x++) leading_zeros++;
        string b58 = encode(b.substr(leading_zeros));
        string Data;
        Data.resize(1 + b58.size());
        data::writer<char*>{Data.begin(), Data.end()} << '1' << b58;
        return Data;
    }
    
    bool check_decode(bytes& b, string_view s) {
        static const char MustStartWith = '1';
        char prefix;
        reader r = reader{s} >> prefix;
        if (prefix != MustStartWith) return false;
        while(true) {
        char next;
            reader R = r >> next;
            if (next != 1) break;
            r == R;
        }
        return decode(b, r);
    }
}
