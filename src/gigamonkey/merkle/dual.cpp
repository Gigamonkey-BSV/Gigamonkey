// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/merkle/dual.hpp>
#include <data/io/wait_for_enter.hpp>

// This file contains a method of serializing and deserializing dual merkle trees. 
namespace Gigamonkey::Merkle {

    // check all proofs.
    bool dual::valid () const {
        if (!Root.valid () || !Paths.valid () || Paths.size () == 0) return false;

        ordst<branch> current;

        for (const auto &e : Paths) current >>= branch {e.Key, e.Value};

        while (true) {
            if (current.size () == 1 && current.first ().Digests.size () == 0) break;

            stack<branch> next;
            for (const auto &b : current) next >>= b;

            current = ordst<branch> {};

            for (const auto &b : next) {
                branch n = b.rest ();
                if (current.size () == 0 || current.first () != n) current >>= n;
            }

        }

        return Root == current.first ().Leaf.Digest;

    }
    
}
