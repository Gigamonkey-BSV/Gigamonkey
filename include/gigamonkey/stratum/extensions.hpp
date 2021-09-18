// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_EXTENSIONS
#define GIGAMONKEY_STRATUM_EXTENSIONS

#include <gigamonkey/stratum/stratum.hpp>
#include <gigamonkey/stratum/difficulty.hpp>
    
// https://github.com/slushpool/stratumprotocol/blob/master/stratum-extensions.mediawiki

namespace Gigamonkey::Stratum::extensions {
    
    enum extension : uint32 {
        version_rolling, 
        minimum_difficulty, 
        subscribe_extranonce, 
        info
    };
    
    std::string extension_to_string(extension m);
    
    extension extension_from_string(std::string st);
    
    template <extension> struct configuration_request;
    
    template <extension> struct configuration_result {
        bool Accepted;
    };
    
    using version_mask = int32_little;
    
    encoding::hex::fixed<4> write_version_mask(const version_mask& x);
    optional<version_mask> read_version_mask(const string&);
    
    template <> struct configuration_request<version_rolling> {
        version_mask Mask;
        byte MinBitCount;
    };
    
    template <> struct configuration_result<version_rolling> : optional<version_mask> {};
    
    template <> struct configuration_request<minimum_difficulty> : difficulty {};
    
    template <> struct configuration_request<subscribe_extranonce> {};
    
    template <> struct configuration_request<info> {
        optional<string> ConnectionURL;
        optional<string> HWVersion;
        optional<string> SWVersion;
        optional<string> HWID;
    };
    
    inline encoding::hex::fixed<4> write_version_mask(const version_mask& x) {
        return encoding::hex::write(x, encoding::hex::lower);
    }
    
}

#endif
