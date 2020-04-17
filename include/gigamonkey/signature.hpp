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
    
    constexpr uint32 DerSignatureExpectedSize{72};
    
    struct signature {
        bytes Data;
        
        signature() : Data{} {}
        explicit signature(const bytes_view data) : Data{data} {}
        signature(const secp256k1::signature raw, sighash::directive d) : Data{65} {
            bytes_writer(Data.begin(), Data.end()) << raw << d;
        } 
        
        bool der() const;
        
        Bitcoin::sighash::directive sighash() const {
            return Data[Data.size() - 1];
        }
        
        secp256k1::signature raw() const;
        
        operator bytes_view() const {
            return Data;
        }
        
        bool operator==(const signature& s) const {
            return Data == s.Data;
        }
        
        bool operator!=(const signature& s) const {
            return Data != s.Data;
        }
    };
    
    struct input_index {
        output Output;
        bytes Transaction;
        index Index;
    };
    
    digest<32> signature_hash(const input_index& v, sighash::directive d);
    
    signature sign(const digest<32>&, const secp256k1::secret&);
    
    bool verify(const signature&, const digest<32>&, const pubkey&);
    
    inline signature sign(const input_index& i, sighash::directive d, const secp256k1::secret& s) {
        return sign(signature_hash(i, d), s);
    }
    
    inline bool verify(const signature& x, const input_index& i, sighash::directive d, const pubkey& p) {
        return verify(x, signature_hash(i, d), p);
    }
}

inline std::ostream& operator<<(std::ostream& o, const Gigamonkey::Bitcoin::signature& x) {
    return o << "signature{" << data::encoding::hex::write(x.Data) << "}";
}

#endif
