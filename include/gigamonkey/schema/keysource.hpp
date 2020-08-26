// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_KEYSOURCE
#define GIGAMONKEY_SCHEMA_KEYSOURCE

#include <gigamonkey/wif.hpp>

namespace Gigamonkey::Bitcoin {
    
    struct keysource {
        virtual secret first() const = 0;
        virtual ptr<keysource> rest() const = 0;
    };
}

#endif
