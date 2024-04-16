// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/sighash.hpp>
#include <gigamonkey/script.hpp>

namespace Gigamonkey::Bitcoin::sighash {
    
    bytes remove_code_separators (bytes_view script_code) {
        program p = decompile (script_code);
        program r;
        for (const instruction &i : p) if (i.Op != OP_CODESEPARATOR) r = r << i;
        return compile (r);
    }
    
    transaction reconstruct (const document &doc, sighash::directive d) {
        
        list<input> in;
        list<output> out;
        
        if (sighash::is_anyone_can_pay (d))
            in <<= doc.Transaction.Inputs[doc.InputIndex].complete (remove_code_separators (doc.ScriptCode));
        
        else for (int i = 0; i < doc.Transaction.Inputs.size (); i++)
            in <<= input {doc.Transaction.Inputs[i].Reference,
                i == doc.InputIndex ? remove_code_separators (doc.ScriptCode) : bytes {},
                base (d) == sighash::all || i == doc.InputIndex ? doc.Transaction.Inputs[i].Sequence : uint32_little {0}};
        
        if (sighash::base (d) == sighash::single)
            out <<= doc.Transaction.Outputs[doc.InputIndex]; 
        else if (sighash::base (d) == sighash::all)
            for (const output &o : doc.Transaction.Outputs)
                out <<= o;
        
        return transaction {doc.Transaction.Version, in, out, doc.Transaction.LockTime};
        
    }

    using Hash256_writer = crypto::hash::SHA2<32>;
    
    namespace Amaury {
        
        digest256 hash_prevouts (const incomplete::transaction &tx) {
            Hash256_writer w;
            for (const incomplete::input &in : tx.Inputs) w << in.Reference;
            return w.finalize ();
        }
        
        digest256 hash_sequence (const incomplete::transaction &tx) {
            Hash256_writer w;
            for (const incomplete::input &in : tx.Inputs) w << in.Sequence;
            return w.finalize ();
        }
        
        digest256 hash_outputs (const incomplete::transaction &tx) {
            Hash256_writer w;
            for (const output &out : tx.Outputs) w << out;
            return w.finalize ();
        }
        
        // can use cached data, but we didn't. 
        writer &write (writer &w, const document &doc, sighash::directive d) {
            
            if (!sighash::has_fork_id (d)) return write_original (w, doc, d & ~sighash::fork_id);
            
            digest256 hashPrevouts;
            digest256 hashSequence;
            digest256 hashOutputs;
            
            if (!sighash::is_anyone_can_pay (d)) {
                hashPrevouts = Amaury::hash_prevouts (doc.Transaction);
            }
            
            if (!sighash::is_anyone_can_pay (d) &&
                (sighash::base (d) != sighash::single) &&
                (sighash::base (d) != sighash::none)) {
                hashSequence = Amaury::hash_sequence (doc.Transaction);
            }
            
            if ((sighash::base (d) != sighash::single) &&
                (sighash::base (d) != sighash::none)) {
                hashOutputs = Amaury::hash_outputs (doc.Transaction);
            } else if ((sighash::base (d) == sighash::single) && (doc.InputIndex < doc.Transaction.Inputs.size ())) {
                hashOutputs = Hash256 (bytes (doc.Transaction.Outputs[doc.InputIndex]));
            }
            
            // Version
            return w << doc.Transaction.Version
            
                // Input prevouts/nSequence (none/all, depending on flags)
                << hashPrevouts
                << hashSequence
                
                // The input being signed (replacing the scriptSig with scriptCode +
                // amount). The prevout may already be contained in hashPrevout, and the
                // nSequence may already be contain in hashSequence.
                << doc.Transaction.Inputs[doc.InputIndex].Reference 
                << var_string {doc.ScriptCode}
                << doc.RedeemedValue
                << doc.Transaction.Inputs[doc.InputIndex].Sequence
            
                // Outputs (none/one/all, depending on flags)
                << hashOutputs
                // Locktime
                << doc.Transaction.LockTime
                // Sighash type
                << uint32_little {d};
            
        }
        
    }
    
}
