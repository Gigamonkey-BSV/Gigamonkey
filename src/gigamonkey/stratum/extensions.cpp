// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/extensions.hpp>

namespace Gigamonkey::Stratum::extensions {

    maybe<version_mask> read_version_mask (const string &str) {
        if (str.size () != 8) return {};
        maybe<bytes> b = encoding::hex::read (str);
        if (bool (b)) return {};
        int32_big n;
        std::copy (b->begin (), b->end (), n.begin ());
        return {int32_little (n)};
    }
    
    maybe<configuration<version_rolling>> configuration<version_rolling>::read (const request &p) {
        auto m = p.contains ("mask");
        auto mbc = p.contains ("min-bit-count");
        if (!bool(m) || !bool (mbc) || !mbc->is_number_unsigned ()) return {};
        auto mask = read_version_mask (*m);
        if (!mask) return {};
        return {{*mask, byte (*mbc)}};
    }
    
    maybe<configured<version_rolling>> configured<version_rolling>::read (const result_params &p) {
        auto x = p.contains ("mask");
        if (!x) return {};
        auto mask = read_version_mask (*x);
        if (!mask) return {};
        return {configured {*mask}};
    }
    
    maybe<configuration<minimum_difficulty>> configuration<minimum_difficulty>::read (const result_params &p) {
        auto x = p.contains ("value");
        if (!x) return {};
        return {configuration {*x}};
    }
    
    maybe<configuration<info>> configuration<info>::read (const request &p) {
        auto a = p.contains ("connection-url");
        auto b = p.contains ("hw-version");
        auto c = p.contains ("sw-version");
        auto d = p.contains ("sw-id");
        
        if (!bool (a) || !bool (b) || !bool (c) || !bool (d)) return {};
        
        return {configuration {*a, *b, *c, *d}};
        
    }

    optional<version_mask> parameters<version_rolling>::make (
        version_mask x, 
        const configuration<version_rolling> &r) {
        version_mask new_mask = x & r.Mask;
        int bit_count = 0;
        for (int i = 0; i < 32; i++) if (((new_mask >> i) & 1) == 1) bit_count++;
        
        return bit_count < r.MinBitCount ? optional<version_mask> {} : optional<version_mask> {new_mask};
    }
    
    std::string extension_to_string (extension m) {
        switch (m) {
            case (version_rolling) : return "version_rolling";
            case (minimum_difficulty) : return "minimum_difficulty";
            case (subscribe_extranonce) : return "subscribe_extranonce";
            case (info) : return "info";
            default: throw std::invalid_argument{"Unknown extension"};
        }
    }
    
}
