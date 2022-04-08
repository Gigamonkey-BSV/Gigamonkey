// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/extensions.hpp>

namespace Gigamonkey::Stratum::extensions {

    optional<version_mask> read_version_mask(const string &str) {
        if (str.size() != 8) return {};
        ptr<bytes> b = encoding::hex::read(str);
        if (b != nullptr) return {};
        int32_big n;
        std::copy(b->begin(), b->end(), n.begin());
        return {int32_little(n)};
    }
    
    optional<configuration<version_rolling>> configuration<version_rolling>::read(const request &p) {
        auto m = p.contains("mask");
        auto mbc = p.contains("min-bit-count");
        if (!bool(m) || !bool(mbc) || !mbc->is_number_unsigned()) return {};
        auto mask = read_version_mask(*m);
        if (!mask) return {};
        return {{*mask, byte(*mbc)}};
    }
    
    optional<configured<version_rolling>> configured<version_rolling>::read(const result_params &p) {
        auto x = p.contains("mask");
        if (!x) return {};
        auto mask = read_version_mask(*x);
        if (!mask) return {};
        return {configured{*mask}};
    }
    
    optional<configuration<minimum_difficulty>> configuration<minimum_difficulty>::read(const result_params &p) {
        auto x = p.contains("value");
        if (!x) return {};
        return {configuration{*x}};
    }
    
    optional<configuration<info>> configuration<info>::read(const request &p) {
        auto a = p.contains("connection-url");
        auto b = p.contains("hw-version");
        auto c = p.contains("sw-version");
        auto d = p.contains("sw-id");
        
        if (!bool(a) || !bool(b) || !bool(c) || !bool(d)) return {};
        
        return {configuration{*a, *b, *c, *d}};
        
    }
    
}
