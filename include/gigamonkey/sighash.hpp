// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SIGHASH
#define GIGAMONKEY_SIGHASH

#include "hash.hpp"
#include "incomplete.hpp"

namespace Gigamonkey::Bitcoin {
    namespace sighash {
        
        // The sighash directive is the last byte of a Bitcoin signature. 
        // It determines what parts of a transaction were signed. 
        // By default you would use fork_id | all, until fork_id becomes
        // depricated and then you would just use all. 
        using directive = byte;
    
        enum type : byte {
            unsupported = 0,
            // all outputs are signed
            all = 1,
            // no outputs are signed, meaning they can be changed and the signature is still valid.
            none = 2, 
            // the output with the same index number as the input in which this sig
            single = 3, 
            // added in Bitcoin Cash, used to implement replace protection. The signature algorithm 
            // is different when enabled. Will be depricated eventually. 
            fork_id = 0x40,
            // If enabled, inputs are not signed, meaning anybody can add new inputs to this tx.
            anyone_can_pay = 0x80
        };
        
        type inline base (directive d) {
            return type (d & 0x1f);
        }
        
        bool inline is_anyone_can_pay (directive d) {
            return (d & anyone_can_pay) != 0;
        }
        
        bool inline has_fork_id (directive d) {
            return (d & fork_id) != 0;
        }
        
        bool inline valid (directive d) {
            return !(d & 0x3c);
        }
        
        // the information that contains the information that gets hashed to produce the signature, 
        // depending on the sighash directive. 
        struct document;
        
    };
    
    sighash::directive inline directive (sighash::type t, bool anyone_can_pay = false, bool fork_id = true) {
        return sighash::directive (t + sighash::fork_id * fork_id + sighash::anyone_can_pay * anyone_can_pay);
    }
    
    namespace sighash {
        
        // the document containing the information that is signed. 
        struct document {
            // the amount being redeemed. This is ignored in the original hash
            // algorithm and is only relevant for Amaury hash with fork_id. 
            satoshi RedeemedValue;
        
            // the script code contains the previous output script with the 
            // latest instance of OP_CODESEPARATOR before the signature operation 
            // being evaluated and everything earlier removed. 
            script ScriptCode; 
            
            // the incomplete transaction that will contain this signature 
            // in one of its input scripts. 
            incomplete::transaction Transaction; 
            
            // the index of the input containing the signature. 
            index InputIndex;
            
            bool valid () const {
                return RedeemedValue >= 0 && InputIndex < Transaction.Inputs.size ();
            }
            
            document (satoshi r, bytes_view script_code, incomplete::transaction tx, index i) :
                RedeemedValue {r}, ScriptCode {script_code}, Transaction {tx}, InputIndex {i} {}
            
        };
        
        bytes write (const document&, sighash::directive);
        
        writer &write (writer &w, const document &doc, sighash::directive d);
        
        bytes inline write (const document &doc, sighash::directive d) {
            lazy_bytes_writer w;
            write (w, doc, d);
            return w;
        }
        
        // two different functions are in use, due to the bitcoin Cash hard fork. 
        bytes write_original (const document&, sighash::directive);
        bytes write_Bitcoin_Cash (const document&, sighash::directive);
        
        writer &write_original (writer&, const document&, sighash::directive);
        writer &write_Bitcoin_Cash (writer&, const document&, sighash::directive);
        
        bytes inline write_original (const document &doc, sighash::directive d) {
            lazy_bytes_writer w;
            write_original (w, doc, d);
            return w;
        }
        
        bytes inline write_Bitcoin_Cash (const document &doc, sighash::directive d) {
            lazy_bytes_writer w;
            write_Bitcoin_Cash (w, doc, d);
            return w;
        }
        
        writer inline &write (writer &w, const document &doc, sighash::directive d) {
            return write_Bitcoin_Cash (w, doc, d);
        }
        
        // a fake transaction constructed from an incomplete transaction that is used in the original sighash algorithm. 
        transaction reconstruct (const document &doc, sighash::directive d);
        
        writer inline &write_original (writer &w, const document &doc, sighash::directive d) {
            return w << reconstruct (doc, d) << uint32_little {d};
        }
        
        namespace Amaury {
            bytes write (const document&, sighash::directive);
            writer &write (writer &w, const document &doc, sighash::directive d);
            digest256 hash_prevouts (const incomplete::transaction &);
            digest256 hash_sequence (const incomplete::transaction &);
            digest256 hash_outputs (const incomplete::transaction &);
        }
        
        writer inline &write_Bitcoin_Cash (writer &w, const document &doc, sighash::directive d) {
            return sighash::has_fork_id (d) ? Amaury::write(w, doc, d) : write_original(w, doc, d & ~sighash::fork_id);
        }
        
        namespace Amaury {
        
            bytes inline write (const document &doc, sighash::directive d) {
                lazy_bytes_writer w;
                Amaury::write (w, doc, d);
                return w;
            }
            
            writer &write (writer &w, const document &doc, sighash::directive d);
        }
        
    }
    
}

#endif
