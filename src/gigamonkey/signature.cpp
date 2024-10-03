// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/signature.hpp>

namespace Gigamonkey::Bitcoin {
    
    digest256 signature::hash (const sighash::document &doc, sighash::directive d) {
        if (!doc.valid () || (sighash::base (d) == sighash::single && doc.InputIndex >= doc.Transaction.Outputs.size ())) return {};
        //Hash256_writer w;
        lazy_bytes_writer w;
        sighash::write (w, doc, d);
        return Hash256 (w.complete ());
    }

}
