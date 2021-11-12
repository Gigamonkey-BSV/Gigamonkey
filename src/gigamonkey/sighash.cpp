// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/sighash.hpp>
#include <gigamonkey/script/script.hpp>

namespace Gigamonkey::Bitcoin::sighash {
    
    bytes remove_code_separators(bytes_view script_code) {
        program p = decompile(script_code);
        program r;
        for (const instruction& i : p) if (i.Op != OP_CODESEPARATOR) r = r << i;
        return compile(r);
    }
    
    transaction reconstruct(const document &doc, sighash::directive d) {
        
        list<input> in;
        list<output> out;
        
        if (sighash::is_anyone_can_pay(d)) in <<= doc.Transaction.Inputs[doc.InputIndex].complete(remove_code_separators(doc.ScriptCode));
        else for (int i = 0; i < doc.Transaction.Inputs.size(); i++) 
            in <<= input{doc.Transaction.Inputs[i].Reference,
                i == doc.InputIndex ? remove_code_separators(doc.ScriptCode) : bytes{}, 
                base(d) == sighash::all || i == doc.InputIndex ? doc.Transaction.Inputs[i].Sequence : uint32_little{0}};
        
        if (sighash::base(d) == sighash::single) 
            out <<= doc.Transaction.Outputs[doc.InputIndex]; 
        else if (sighash::base(d) == sighash::all) 
            for (const output& o : doc.Transaction.Outputs)
                out <<= o;
        
        return transaction{doc.Transaction.Version, in, out, doc.Transaction.Locktime};
        
    }
    
    namespace Amaury {
        
        uint256 hash_prevouts(const incomplete::transaction &tx) {
            lazy_hash_writer<32> w(hash256);
            for (const incomplete::input &in : tx.Inputs) outpoint::write(w, in.Reference);
            return w.finalize();
        }
        
        uint256 hash_sequence(const incomplete::transaction &tx) {
            lazy_hash_writer<32> w(hash256);
            for (const incomplete::input &in : tx.Inputs) w << in.Sequence;
            return w.finalize();
        }
        
        uint256 hash_outputs(const incomplete::transaction &tx) {
            lazy_hash_writer<32> w(hash256);
            for (const output &out : tx.Outputs) output::write(w, out);
            return w.finalize();
        }
        
    }
    
}
