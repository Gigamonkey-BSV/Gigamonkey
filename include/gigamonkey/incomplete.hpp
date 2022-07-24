// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_INCOMPLETE
#define GIGAMONKEY_INCOMPLETE

#include "timechain.hpp"

// incomplete types are used to construct the signature hash in Bitcoin transactions. 
// this is necessary because the input script is not known before it is created.
namespace Gigamonkey::Bitcoin::incomplete {
    
    // an incomplete input is missing the script, which cannot be signed because if it 
    // was, it would contain signatures that would have to sign themselves somehow. 
    struct input {
        outpoint Reference;
        uint32_little Sequence;
        
        input() : Reference{}, Sequence{} {}
        input(outpoint r, uint32_little x = Bitcoin::input::Finalized) : 
            Reference{r}, Sequence{x} {}
        input(const Bitcoin::input &in) : Reference{in.Reference}, Sequence{in.Sequence} {}
        
        Bitcoin::input complete(bytes_view script) const {
            return Bitcoin::input{Reference, script, Sequence};
        }
    };
    
    // an incomplete transaction is a transaction with no input scripts. 
    struct transaction {
        int32_little Version;
        list<input> Inputs;
        list<output> Outputs;
        uint32_little Locktime;
        
        transaction(int32_little v, list<input> i, list<output> o, uint32_little l = 0) : 
            Version{v}, Inputs{i}, Outputs{o}, Locktime{l} {}
        
        transaction(list<input> i, list<output> o, uint32_little l = 0) : 
            transaction{int32_little{Bitcoin::transaction::LatestVersion}, i, o, l} {}
        
        transaction(const Bitcoin::transaction& tx) : 
            Version{tx.Version}, Outputs{tx.Outputs}, Inputs{
                data::for_each([](const Bitcoin::input& i) -> input {
                    return input{i};
                }, tx.Inputs)}, Locktime{tx.Locktime} {}
        
        explicit operator bytes() const;
        explicit transaction(bytes_view);
        
        Bitcoin::transaction complete(list<bytes> scripts) const;
        
    };
    
    std::ostream &operator<<(std::ostream &, const input &);
    std::ostream &operator<<(std::ostream &, const transaction &);
    
    std::ostream inline &operator<<(std::ostream &o, const input &i) {
        return o << "input{" << i.Reference << ", ___, " << i.Sequence << "}";
    }
}

#endif

