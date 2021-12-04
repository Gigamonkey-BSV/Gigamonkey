// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/extensions.hpp>

namespace Gigamonkey::Stratum::extensions {

    optional<version_mask> read_version_mask(const string& str) {
        if (str.size() != 8) return {};
        ptr<bytes> b = encoding::hex::read(str);
        if (b != nullptr) return {};
        int32_big n;
        std::copy(b->begin(), b->end(), n.begin());
        return {int32_little(n)};
    }
    
    std::ostream &operator<<(std::ostream &o, const configuration_result<version_rolling> &r) {
        o << "configuration_request<version_rolling>{";
        if (bool(r)) o << "mask: " << *r;
        else o << "false";
        return o << "}";
    }
    
    std::ostream &operator<<(std::ostream &o, const configuration_request<info> &r) {
        o << "configuration_request<info>";
        list<string> info;
        if (r.ConnectionURL) {
            std::stringstream ss; 
            ss << "connection-url: \"" << *r.ConnectionURL << "\"";
            info = info << ss.str();
        }
        if (r.HWVersion) {
            std::stringstream ss; 
            ss << "hw-version: \"" << *r.HWVersion << "\"";
            info = info << ss.str();
        }
        if (r.SWVersion) {
            std::stringstream ss; 
            ss << "sw-version: \"" << *r.SWVersion << "\"";
            info = info << ss.str();
        }
        if (r.HWID) {
            std::stringstream ss; 
            ss << "hw-id: \"" << *r.HWID << "\"";
            info = info << ss.str();
        }
        return o << info;
    }
    
}
