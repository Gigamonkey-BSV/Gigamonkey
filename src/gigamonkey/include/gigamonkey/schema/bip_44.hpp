// Copyright (c) 2020-2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_BIP_44
#define GIGAMONKEY_SCHEMA_BIP_44

#include <gigamonkey/schema/hd.hpp>

// HD is a format for infinite sequences of keys that 
// can be derived from a single master. This key format
// will be depricated but needs to be supported for 
// older wallets. 
namespace Gigamonkey::HD::BIP_44 {
    
    constexpr uint32 purpose = BIP_32::harden (44); // Purpose = 44'
    
    constexpr uint32 coin_type_Bitcoin = BIP_32::harden (0); // BSV = 0'
    
    constexpr uint32 coin_type_Bitcoin_Cash = BIP_32::harden (145); 
    
    constexpr uint32 coin_type_Bitcoin_SV = BIP_32::harden (236); 
    
    constexpr uint32 coin_type_testnet = BIP_32::harden (1); // BSV Testnet = 1'
    
    constexpr uint32 receive_index = 0; 
    
    constexpr uint32 change_index = 1; 
    
    list<uint32> inline derivation_path (uint32 account, bool change, uint32 index, uint32 coin_type = coin_type_Bitcoin) {
        return list<uint32> {purpose, coin_type, BIP_32::harden (account), uint32 (change), index};
    }
    
    struct account_pubkey {
        BIP_32::pubkey Pubkey;
        
        account_pubkey (const BIP_32::pubkey& p) : Pubkey {p} {}
        
        Bitcoin::address::decoded receive (uint32 index) const {
            return Bitcoin::address::decoded (Pubkey.derive ({receive_index, index}));
        }
        
        Bitcoin::address::decoded change (uint32 index) const {
            return Bitcoin::address::decoded (Pubkey.derive ({change_index, index}));
        }
        
        BIP_32::pubkey account (uint32 a) const {
            return Pubkey.derive ({a});
        }
    };
    
    struct account_secret {
        BIP_32::secret Secret;
        
        account_pubkey to_public () const {
            return account_pubkey {Secret.to_public ()};
        }
        
        account_secret (const BIP_32::secret &s) : Secret {s} {}
        
        Bitcoin::secret receive (uint32 index) const {
            return Bitcoin::secret (Secret.derive ({receive_index, index}));
        }
        
        Bitcoin::secret change (uint32 index) const {
            return Bitcoin::secret (Secret.derive ({change_index, index}));
        }
    };
    
    BIP_32::secret inline from_root (const BIP_32::secret &x, uint32 coin_type, uint32 account) {
        return x.derive ({purpose, coin_type, BIP_32::harden (account)});
    }
    
    struct master {
        BIP_32::secret Secret;
        
        account_secret account (uint32 coin_type, uint32 account = 0) {
            return account_secret {from_root (Secret, coin_type, account)};
        }
        
    };
    
    // coin types for standard wallets. 
    constexpr uint32 simply_cash_coin_type = coin_type_Bitcoin_Cash;
    
    constexpr uint32 moneybutton_coin_type = coin_type_Bitcoin;
    
    constexpr uint32 relay_x_coin_type = coin_type_Bitcoin_SV;
    
    constexpr uint32 electrum_sv_coin_type = coin_type_Bitcoin_Cash;

    constexpr uint32 centbee_coin_type = 0;
    
}

#endif

