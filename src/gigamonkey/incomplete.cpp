// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/incomplete.hpp>

namespace Gigamonkey::Bitcoin {
    
    Bitcoin::transaction incomplete::transaction::complete(cross<bytes> scripts) const {
        if (scripts.size() != Inputs.size()) throw std::logic_error{"need one script for each input."};
        list<Bitcoin::input> ins;
        for (int i = 0; i < scripts.size(); i++) ins <<= Inputs[i].complete(scripts[i]);
        list<output> outs;
        for (const output &out : Outputs) outs <<= out;
        return Bitcoin::transaction{Version, ins, outs, Locktime};
    }
    
    incomplete::transaction::operator bytes() const {
        list<Bitcoin::input> ins;
        for (const input &in : Inputs) ins <<= Bitcoin::input{in.Reference, {}, in.Sequence};
        list<output> outs;
        for (const output &out : Outputs) outs <<= out;
        return bytes(Bitcoin::transaction{Version, ins, outs, Locktime});
    }
    
    incomplete::transaction::transaction(bytes_view b) {
        auto tx = Bitcoin::transaction{b};
        if (!tx.valid()) throw std::invalid_argument{"invalid transaction"};
        *this = transaction{tx};
    }

}
