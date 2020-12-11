// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SIGNATURE
#define GIGAMONKEY_SIGNATURE

#include "secp256k1.hpp"
#include "hash.hpp"
#include "timechain.hpp"

namespace Gigamonkey::Bitcoin {
    
    namespace sighash {
        
        using directive = byte;
    
        enum type : byte {
            unsupported = 0,
            all = 1,
            none = 2,
            single = 3
        };
        
        const byte anyone_can_pay = 0x80;
        
        const byte fork_id = 0x40;
        
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
    
    inline sighash::directive directive(sighash::type t, bool anyone_can_pay = false, bool fork_id = true) {
        return sighash::directive(t + sighash::fork_id * fork_id + sighash::anyone_can_pay * anyone_can_pay);
    }
    
    struct signature : bytes {
        constexpr static size_t MaxSignatureSize = 71;
        
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
        
    };
    
    struct input_index {
        output Output;
        bytes Transaction;
        index Index;
    };
    
    digest256 signature_hash_original(const input_index& v, sighash::directive d);
    digest256 signature_hash_forkid(const input_index& v, sighash::directive d);
    
    inline digest256 signature_hash(const input_index& v, sighash::directive d) {
        if (sighash::has_fork_id(d)) return signature_hash_forkid(v, d);
        return signature_hash_original(v, d);
    }
    
    inline signature sign(const input_index& i, sighash::directive d, const secp256k1::secret& s) {
        return signature{s.sign(signature_hash(i, d)), d};
    }
    
    inline bool verify(const signature& x, const input_index& i, sighash::directive d, const pubkey& p) {
        return p.verify(signature_hash(i, d), x.raw());
    }
    
    inline std::ostream& operator<<(std::ostream& o, const Gigamonkey::Bitcoin::signature& x) {
        return o << "signature{" << data::encoding::hex::write(x.Data) << "}";
    }
}

#endif
