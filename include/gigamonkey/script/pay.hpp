// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_PAY
#define GIGAMONKEY_SCRIPT_PAY

#include <gigamonkey/script.hpp>
#include <gigamonkey/address.hpp>
#include <gigamonkey/signature.hpp>
#include "pattern.hpp"

namespace gigamonkey::bitcoin::script {
    
    struct pay_to_pubkey {
        static script::pattern pattern(bytes& pubkey) {
            return {alternatives{
                push_size{secp256k1::CompressedPubkeySize, pubkey}, 
                push_size{secp256k1::UncompressedPubkeySize, pubkey}}, OP_CHECKSIG};
        }
        
        static bytes script(bytes_view pubkey) {
            return compile(program{pubkey, OP_CHECKSIG});
        }
        
        pubkey Pubkey;
        
        bool valid() const {
            return Pubkey.valid();
        }
        
        bytes script() const {
            return script(Pubkey);
        }
        
        pay_to_pubkey(bytes_view script) : Pubkey{} {
            pattern(Pubkey.Value.Value).match(script);
        }
        
        static bytes redeem(const signature& s) {
            return compile(instruction::push_data(s));
        }
    };
    
    struct pay_to_address {
        static script::pattern pattern(bytes& address) {
            return {OP_DUP, OP_HASH160, push_size{20, address}, OP_EQUALVERIFY, OP_CHECKSIG};
        }
        
        static bytes script(bytes_view a) {
            return compile(program{OP_DUP, OP_HASH160, a, OP_EQUALVERIFY, OP_CHECKSIG});
        }
        
        digest<20> Address;
        
        bool valid() const {
            return Address.valid();
        }
        
        bytes script() const {
            return script(Address);
        }
        
        pay_to_address(bytes_view script) : Address{} {
            bytes addr;
            addr.resize(20);
            pattern(addr).match(script);
            std::copy(addr.begin(), addr.end(), Address.Digest.Array.begin());
        }
        
        static bytes redeem(const signature& s, const pubkey& p) {
            return compile(program{} << instruction::push_data(s) << instruction::push_data(p));
        }
    };
    
}

#endif


