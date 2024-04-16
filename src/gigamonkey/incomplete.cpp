// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/incomplete.hpp>

namespace Gigamonkey::Bitcoin {
    
    transaction incomplete::transaction::complete (list<bytes> scripts) const {
        if (scripts.size () != Inputs.size ()) throw std::logic_error {"need one script for each input."};
        return Bitcoin::transaction {Version, data::map_thread ([] (const input &in, const bytes &script) -> Bitcoin::input {
            return in.complete (script);
        }, Inputs, scripts), Outputs, LockTime};
    }
    
    incomplete::transaction::operator bytes () const {
        list<Bitcoin::input> ins;
        for (const input &in : Inputs) ins <<= Bitcoin::input {in.Reference, {}, in.Sequence};
        list<output> outs;
        for (const output &out : Outputs) outs <<= out;
        return bytes (Bitcoin::transaction {Version, ins, outs, LockTime});
    }
    
    incomplete::transaction::transaction (bytes_view b) {
        auto tx = Bitcoin::transaction {b};
        if (!tx.valid ()) throw std::invalid_argument {"invalid transaction"};
        *this = transaction {tx};
    }

}
