// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SIGNATURE
#define GIGAMONKEY_SIGNATURE

#include "secp256k1.hpp"
#include "hash.hpp"
#include "ledger.hpp"

namespace Gigamonkey::Bitcoin {
    
    namespace sighash {
        
        using directive = byte;
    
        enum type : byte {
            unsupported = 0,
            all = 1,
            none = 2,
            single = 3,
            fork_id = 0x40,
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
    
    // this represents a signature that will appear in a Bitcoin script. 
    struct signature : bytes {
        constexpr static size_t MaxSignatureSize = 73;
        
        bytes Data;
        
        signature() : bytes{} {}
        explicit signature(const bytes_view data) : Data{data} {}
        
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
        
        // the document that is signed by the signature. 
        struct document;
        
        static signature sign(const secp256k1::secret& s, sighash::directive d, const document&);
        
        static bool verify(const signature& x, const secp256k1::pubkey& p, sighash::directive d, const document&);
        
    };
    
    std::ostream inline &operator<<(std::ostream& o, const signature& x) {
        return o << "signature{" << data::encoding::hex::write(x.Data) << "}";
    }
    
    namespace incomplete {
        
        struct input {
            outpoint Reference;
            uint32_little Sequence;
            
            Bitcoin::input complete(bytes_view script) {
                return Bitcoin::input{Reference, script, Sequence};
            }
        };
    
        // an incomplete transaction is a transaction with no input scripts. 
        struct transaction {
            cross<input> Inputs;
            cross<output> Outputs;
            uint32_little Locktime;
            
            transaction(list<input> i, list<output> o, uint32_little l = 0);
                
            bytes write() const;
        };
    }
    
    struct signature::document {
    
        output Previous; 
        incomplete::transaction Transaction; 
        index Index;
        
        digest256 hash(sighash::directive d) const;
        
    };
    
    signature inline signature::sign(const secp256k1::secret& s, sighash::directive d, const document& doc) {
        return signature{s.sign(doc.hash(d)), d};
    }
    
    bool inline signature::verify(const signature& x, const secp256k1::pubkey& p, sighash::directive d, const document& doc) {
        return p.verify(doc.hash(d), x.raw());
    }
    
}

#endif
