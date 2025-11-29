// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_INCOMPLETE
#define GIGAMONKEY_INCOMPLETE

#include <gigamonkey/timechain.hpp>

// incomplete types are used to construct the signature hash in Bitcoin transactions. 
// this is necessary because the input script is not known before it is created.
namespace Gigamonkey::Bitcoin::incomplete {
    
    // an incomplete input is missing the script, which cannot be signed because if it 
    // was, it would contain signatures that would have to sign themselves somehow. 
    struct input {
        outpoint Reference;
        uint32_little Sequence;
        
        input () : Reference {}, Sequence {} {}
        input (outpoint r, uint32_little x = Bitcoin::input::Finalized) : 
            Reference {r}, Sequence {x} {}
        input (const Bitcoin::input &in) : Reference {in.Reference}, Sequence {in.Sequence} {}
        
        Bitcoin::input complete (const Bitcoin::script &script) const {
            return Bitcoin::input {Reference, script, Sequence};
        }
    };
    
    // an incomplete transaction is a transaction with no input scripts. 
    // everything is const because some data can be cached for signature verification.
    struct transaction {
        const int32_little Version;
        const list<input> Inputs;
        const list<output> Outputs;
        const uint32_little LockTime;
        
        transaction (int32_little v, list<input> i, list<output> o, uint32_little l = 0) : 
            Version {v}, Inputs {i}, Outputs {o}, LockTime {l} {}
        
        transaction (list<input> i, list<output> o, uint32_little l = 0) : 
            transaction {int32_little {Bitcoin::transaction::LatestVersion}, i, o, l} {}
        
        transaction (const Bitcoin::transaction &tx) : 
            Version {tx.Version}, Outputs {tx.Outputs}, Inputs {
                data::lift ([] (const Bitcoin::input &i) -> input {
                    return input {i};
                }, tx.Inputs)}, LockTime {tx.LockTime} {}
        
        explicit operator bytes () const;
        explicit transaction (byte_slice);
        
        Bitcoin::transaction complete (list<bytes> scripts) const;

        // the stuff below is only used in the Amaury hash algorithm.
        const digest256 &hash_prevouts ();
        const digest256 &hash_sequence ();
        const digest256 &hash_outputs ();

        struct cached {
            ~cached () {
                delete HashPrevouts;
                delete HashSequence;
                delete HashOutputs;
            }

            static const digest256 &zero () {
                static digest256 Zero {};
                return Zero;
            }

            digest256 *HashPrevouts {nullptr};
            digest256 *HashSequence {nullptr};
            digest256 *HashOutputs {nullptr};
        };

    private:
        cached Cached;
    };
    
    std::ostream &operator << (std::ostream &, const input &);
    std::ostream &operator << (std::ostream &, const transaction &);
    
    std::ostream inline &operator << (std::ostream &o, const input &i) {
        return o << "input {" << i.Reference << ", ___, " << i.Sequence << "}";
    }
}

#endif

