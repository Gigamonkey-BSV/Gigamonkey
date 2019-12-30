// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/merkle.hpp>

namespace gigamonkey::merkle {
    
    queue<tree::digest_tree> tree::pairwise_concatinate(queue<digest_tree> l) {
        throw data::method::unimplemented{"tree::pairwise_concatinate"};
    }
    
    merkle::path tree::path(uint32 index) {
        throw data::method::unimplemented{"tree::path"};
    }
    
}
