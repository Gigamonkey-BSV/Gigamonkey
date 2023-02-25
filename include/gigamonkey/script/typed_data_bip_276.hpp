// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_TYPED_DATA_BIP_276
#define GIGAMONKEY_SCRIPT_TYPED_DATA_BIP_276

#include <gigamonkey/types.hpp>

namespace Gigamonkey {

    struct typed_data {
        enum type {
            bitcoin_script
        };
        
        enum network : byte {
            not_applicable = 0, 
            mainnet = 1, 
            testnet = 2
        };
        
        static string write (type, byte version, network, const bytes&);
        
        static string inline write (network n, const bytes& b) {
            return write (bitcoin_script, 1u, n, b);
        }
        
        static constexpr auto pattern = ctll::fixed_string {"bitcoin-script:(([0-9a-f][0-9a-f])*)|(([0-9A-F][0-9A-F])*)"};
        
        type Type;
        byte Version;
        network Network;
        bytes Data;
        
        bool valid () const {
            return Version != 0;
        }
        
        string write () const {
            return write (Type, Version, Network, Data);
        }
        
        static typed_data read (string_view);
        
    private:
        typed_data (type t, byte version, network n, const bytes &b):
            Type {t}, Version {version}, Network {n}, Data {b} {}
        typed_data (): Type {}, Version {0}, Network {}, Data {} {}
    };
}

#endif 

