// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/address.hpp>
#include <data/encoding/base58.hpp>

namespace Gigamonkey::base58 {
    
    string check::encode() const {
        bytes data = Bitcoin::append_checksum(static_cast<bytes>(*this));
        size_t leading_zeros = 0;
        while (leading_zeros < data.size() && data[leading_zeros] == 0) leading_zeros++;
        string b58 = data::encoding::base58::write(bytes_view(data).substr(leading_zeros));
        string ones(leading_zeros, '1');
        std::stringstream ss;
        ss << ones << b58;
        return ss.str();
    }
    
    check check::decode(string_view s) {
        size_t leading_ones = 0;
        while(leading_ones < s.size() && s[leading_ones] == '1') leading_ones++;
        encoding::base58::view b58(s.substr(leading_ones));
        if (!b58.valid()) return {};
        bytes_view decoded = bytes_view(b58);
        return {Bitcoin::remove_checksum(write(leading_ones + decoded.size(), bytes(leading_ones, 0x00), decoded))};
    }
}

namespace Gigamonkey::Bitcoin {
    
    Gigamonkey::checksum checksum(bytes_view b) {
        Gigamonkey::checksum x;
        digest256 digest = hash256(b);
        std::copy(digest.Value.begin(), digest.Value.begin() + 4, x.begin());
        return x;
    }
    
    bytes_view remove_checksum(bytes_view b) {
        if (b.size() < 4) return {};
        Gigamonkey::checksum x;
        std::copy(b.end() - 4, b.end(), x.begin());
        bytes_view without = b.substr(0, b.size() - 4);
        if (x != checksum(without)) return {};
        return without;
    }
    
   address::address(string_view s) : address{} {
        if (s.size() > 35 || s.size() < 5) return;
        base58::check b58(s);
        if (!b58.valid()) return;
        Prefix = type(b58.version());
        if (!valid_prefix(Prefix)) return;
        if (b58.payload().size() > 20) return;
        std::copy(b58.payload().begin(), b58.payload().end(), Digest.Value.begin());
    }
}
