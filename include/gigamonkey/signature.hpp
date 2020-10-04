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
        
        signature();
        explicit signature(const bytes_view data) : Data{data} {}
        signature(const secp256k1::signature raw, sighash::directive d) : Data{65} {
            bytes_writer(Data.begin(), Data.end()) << raw << d;
        } 
        
        bool DER() const;
        
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
    
    digest256 signature_hash(const input_index& v, sighash::directive d);
    
    signature sign(const digest256&, const secp256k1::secret&);
    
    bool verify(const signature&, const digest256&, const pubkey&);
    
    inline signature sign(const input_index& i, sighash::directive d, const secp256k1::secret& s) {
        return sign(signature_hash(i, d), s);
    }
    
    inline bool verify(const signature& x, const input_index& i, sighash::directive d, const pubkey& p) {
        return verify(x, signature_hash(i, d), p);
    }

    inline std::ostream& operator<<(std::ostream& o, const Gigamonkey::Bitcoin::signature& x) {
        return o << "signature{" << data::encoding::hex::write(x.Data) << "}";
    }
    
    inline signature::signature() : Data(72) {
        Data[0] = 0x30;
        Data[1] = 69;
        Data[2] = 0x02;
        Data[3] = 33;
        Data[4] = 0x01;
        // everything in between here will be zero
        Data[37] = 0x02;
        Data[38] = 32;
        Data[39] = 0x01;
        // here too. 
        Data[71] = byte(directive(sighash::all));
    }
}

#endif
