// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TEST_DOT_CROSS
#define GIGAMONKEY_TEST_DOT_CROSS

#include <gigamonkey/types.hpp>

namespace Gigamonkey {

    template <typename f, typename X, typename Y>
    bool dot_cross (f foo, list<X> x, list<Y> y) {
        if (x.size () != y.size ()) return false;
        if (x.size () == 0) return true;
        list<X> input = x;
        list<Y> expected = y;
        while (!empty (input)) {
            list<Y> uuu = expected;
            X in = first (input);
            Y ex = first (uuu);
            
            if (!foo (in, ex)) return false;
            
            uuu = rest (uuu);
        
            while (!empty (uuu)) {
                ex = uuu.first ();
                
                if (foo (in, ex)) return false;
                uuu = rest (uuu);
            }
            
            expected = rest (expected);
            input = rest (input);
        }
        
        return true;
    }

}

#endif
