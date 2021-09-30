// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SIGNATURE
#define GIGAMONKEY_SIGNATURE

#include "secp256k1.hpp"
#include "hash.hpp"
#include "timechain.hpp"

namespace Gigamonkey::Bitcoin {
    // The sighash directive is the last byte of a Bitcoin signature. 
    // It determines what parts of a transaction were signed. 
    // By default you would use fork_id | all, until fork_id becomes
    // depricated and then you would just use all. 
    namespace sighash {
        
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
        
        inline type base(directive d) {
            return type(uint32(d) & 0x1f);
        }
        
        inline bool is_anyone_can_pay(directive d) {
            return (uint32(d) & anyone_can_pay) != 0;
        }
        
        inline bool has_fork_id(directive d) {
            return (uint32(d) & fork_id) != 0;
        }
        
    };
    
    inline sighash::directive directive(sighash::type t, bool fork_id = true, bool anyone_can_pay = false) {
        return sighash::directive(t + sighash::fork_id * fork_id + sighash::anyone_can_pay * anyone_can_pay);
    }
    
    // a Bitcoin signature. It consists of an secp256k1::signature with a
    // sighash directive at the end. This is what goes in an input script. 
    struct signature : bytes {
        constexpr static size_t MaxSignatureSize = secp256k1::signature::MaxSignatureSize + 1;
        
        signature() : bytes{} {}
        explicit signature(const bytes_view data) : bytes{data} {}
        
        signature(const secp256k1::signature raw, sighash::directive d) : bytes(raw.size() + 1) {
            bytes_writer(bytes::begin(), bytes::end()) << raw << d;
        } 
        
        Bitcoin::sighash::directive sighash() const {
            return bytes::operator[](-1);
        } 
        
        secp256k1::signature raw() const {
            secp256k1::signature x;
            if (bytes::size() != 0) {
                x.resize(bytes::size() - 1);
                std::copy(bytes::begin(), bytes::end() - 1, x.begin());
            }
            return x;
        } 
        
        // the document that is signed to produce the signature. 
        struct document;
        
        static signature sign(const secp256k1::secret& s, sighash::directive d, const document&);
        
        static bool verify(const signature& x, const secp256k1::pubkey& p, const document&);
        
    };
    
    // incomplete types are used to construct the signature hash in Bitcoin transactions. 
    // this is necessary because the input script is not known before it is created.
    namespace incomplete {
        
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
            std::vector<input> Inputs;
            std::vector<output> Outputs;
            uint32_little Locktime;
            
            transaction(int32_little v, list<input> i, list<output> o, uint32_little l = 0);
            transaction(list<input> i, list<output> o, uint32_little l = 0) : 
                transaction{int32_little{Bitcoin::transaction::LatestVersion}, i, o, l} {}
            transaction(const Bitcoin::transaction& tx) : 
                transaction(tx.Version, 
                    data::for_each([](const Bitcoin::input& i) -> input {
                        return input{i};
                    }, tx.Inputs), tx.Outputs, tx.Locktime) {}
            
            bytes write() const;
            static transaction read(bytes_view);
            
            Bitcoin::transaction complete(list<bytes> scripts) const;
        };
        
        std::ostream &operator<<(std::ostream &, const input &);
        std::ostream &operator<<(std::ostream &, const transaction &);
    }
    
    struct signature::document {
    
        // the preveious output that is being redeemed by the
        // input that will contain the signature of this document. 
        output Previous; 
        
        // the incomplete transaction that will contain this signature 
        // in one of its input scripts. 
        incomplete::transaction Transaction; 
        
        // the index of the input containing the signature. 
        index InputIndex;
        
        digest256 hash(sighash::directive d) const;
        bytes write() const;
        
    };
    
    signature inline signature::sign(const secp256k1::secret& s, sighash::directive d, const document& doc) {
        return signature{s.sign(doc.hash(d)), d};
    }
    
    bool inline signature::verify(const signature& x, const secp256k1::pubkey& p, const document& doc) {
        return p.verify(doc.hash(x.sighash()), x.raw());
    }
    
    namespace incomplete {
        std::ostream inline &operator<<(std::ostream &o, const input &i) {
            return o << "input{" << i.Reference << ", ___, " << i.Sequence << "}";
        }
    }
    
    std::ostream inline &operator<<(std::ostream& o, const signature& x) {
        return o << "signature{" << data::encoding::hex::write(bytes_view(x)) << "}";
    }
    
}

#endif
