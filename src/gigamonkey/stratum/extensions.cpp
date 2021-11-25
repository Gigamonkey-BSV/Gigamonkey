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
    
}
