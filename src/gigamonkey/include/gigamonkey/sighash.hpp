// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SIGHASH
#define GIGAMONKEY_SIGHASH

#include <gigamonkey/hash.hpp>
#include <gigamonkey/incomplete.hpp>
#include <gigamonkey/script/instruction.hpp>
#include <data/tools/lazy_writer.hpp>

namespace Gigamonkey::Bitcoin {
    namespace sighash {
        
        // The sighash directive is the last byte of a Bitcoin signature. 
        // It determines what parts of a transaction are signed.
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
            // the incomplete transaction that will contain this signature
            // in one of its input scripts.
            incomplete::transaction &Transaction;

            // the index of the input containing the signature.
            index InputIndex;

            // the amount being redeemed. This is ignored in the original hash
            // algorithm and is only relevant for Amaury hash with fork_id.
            satoshi RedeemedValue;
        
            // the script code contains the previous output script with the 
            // latest instance of OP_CODESEPARATOR before the signature operation 
            // being evaluated and everything earlier removed.
            program ScriptCode;
            
            bool valid () const {
                return RedeemedValue >= 0 && InputIndex < Transaction.Inputs.size ();
            }
            
            document (incomplete::transaction &tx, index i, satoshi r, program script_code) :
                Transaction {tx}, InputIndex {i}, RedeemedValue {r}, ScriptCode {script_code} {}
            
        };
        
        bytes write (const document &, sighash::directive);
        
        writer &write (writer &w, const document &doc, sighash::directive d);
        
        bytes inline write (const document &doc, sighash::directive d) {
            data::lazy_bytes_writer w;
            write (w, doc, d);
            return w;
        }
        
        // two different functions are in use, due to the bitcoin Cash hard fork. 
        bytes write_original (const document &, sighash::directive);
        bytes write_Bitcoin_Cash (const document &, sighash::directive);
        
        writer &write_original (writer &, const document &, sighash::directive);
        writer &write_Bitcoin_Cash (writer &, const document &, sighash::directive);
        
        bytes inline write_original (const document &doc, sighash::directive d) {
            data::lazy_bytes_writer w;
            write_original (w, doc, d);
            return w;
        }
        
        bytes inline write_Bitcoin_Cash (const document &doc, sighash::directive d) {
            data::lazy_bytes_writer w;
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
            bytes write (const document &, sighash::directive);
            writer &write (writer &w, const document &doc, sighash::directive d);
            void hash_prevouts (digest256 &, const incomplete::transaction &);
            void hash_sequence (digest256 &, const incomplete::transaction &);
            void hash_outputs (digest256 &, const incomplete::transaction &);
        }
        
        writer inline &write_Bitcoin_Cash (writer &w, const document &doc, sighash::directive d) {
            return sighash::has_fork_id (d) ? Amaury::write (w, doc, d) : write_original (w, doc, d & ~sighash::fork_id);
        }
        
        namespace Amaury {
        
            bytes inline write (const document &doc, sighash::directive d) {
                data::lazy_bytes_writer w;
                Amaury::write (w, doc, d);
                return w;
            }

            void inline hash_prevouts (digest256 &d, const incomplete::transaction &tx) {
                Hash256_writer w {d};
                for (const incomplete::input &in : tx.Inputs) w << in.Reference;
            }

            void inline hash_sequence (digest256 &d, const incomplete::transaction &tx) {
                Hash256_writer w {d};
                for (const incomplete::input &in : tx.Inputs) w << in.Sequence;
            }

            void inline hash_outputs (digest256 &d, const incomplete::transaction &tx) {
                Hash256_writer w {d};
                for (const output &out : tx.Outputs) w << out;
            }
            
        }
        
    }

    const digest256 inline &incomplete::transaction::hash_prevouts () {
        if (Cached.HashPrevouts == nullptr) {
            Cached.HashPrevouts = new digest256 {};
            sighash::Amaury::hash_prevouts (*Cached.HashPrevouts, *this);
        } return *Cached.HashPrevouts;
    }

    const digest256 inline &incomplete::transaction::hash_sequence () {
        if (Cached.HashSequence == nullptr) {
            Cached.HashSequence = new digest256 {};
            sighash::Amaury::hash_sequence (*Cached.HashSequence, *this);
        } return *Cached.HashSequence;
    }

    const digest256 inline &incomplete::transaction::hash_outputs () {
        if (Cached.HashOutputs == nullptr) {
            Cached.HashOutputs = new digest256 {};
            sighash::Amaury::hash_outputs (*Cached.HashOutputs, *this);
        } return *Cached.HashOutputs;
    }
    
}

#endif
