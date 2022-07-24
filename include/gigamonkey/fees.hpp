// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_FEES
#define GIGAMONKEY_FEES

#include "ledger.hpp"
#include <cmath>

namespace Gigamonkey {
    
    struct satoshi_per_byte {
        Bitcoin::satoshi Satoshis;
        uint64 Bytes;
        
        operator double() {
            if (Bytes == 0) throw data::math::division_by_zero{};
            return double(Satoshis) / double(Bytes);
        } 
        
        std::partial_ordering operator<=>(satoshi_per_byte x) {
            return operator double() <=> double(x);
        }
        
        bool valid() const {
            return Bytes != 0;
        }
    };
    /*
    std::weak_ordering inline operator<=>(const satoshi_per_byte &a, const satoshi_per_byte &b) {
        return math::fraction<Bitcoin::satoshi, uint64>{a.Satoshis, a.Bytes} <=> math::fraction<Bitcoin::satoshi, uint64>{b.Satoshis, b.Bytes}
    }*/
    
    bool inline operator==(const satoshi_per_byte &a, const satoshi_per_byte &b) {
        return math::fraction<int64, uint64>(int64(a.Satoshis), a.Bytes) == math::fraction<int64, uint64>(int64(b.Satoshis), b.Bytes);
    }
    
    // given a tx size, what fee should we pay? 
    Bitcoin::satoshi inline calculate_fee(satoshi_per_byte v, uint64 size) {
        if (v.Bytes == 0) throw data::math::division_by_zero{};
        return std::ceil(double(v.Satoshis) * double(size) / double(v.Bytes));
    }
    
    // Bitcoin signatures within a transaction sign part of the transaction. Thus, 
    // we need to have the transacton partly created when we make the signatures. 
    // transaction_design is for determining if the fee is correct and generating the
    // signatures. 
    struct transaction_design {
        
        // we cannot construct a real input until after the signatures have been made. 
        // however, we must estimate the size of the inputs before we sign because the
        // transaction fee is included in the signature, and we don't know what a good
        // tx fee is going to be without knowing the size of the final transaction. 
        struct input {
            // the output being redeemed. 
            Bitcoin::prevout Prevout; 
            
            // the expected size of the input script. 
            uint64 ExpectedScriptSize;
            
            uint32_little Sequence;
            
            // The signature may sometimes sign part of the input script, 
            // if OP_CODESEPARATOR is used and FORKID is not used. This allows
            // one signature to sign previous signatures. This will contain 
            // a part of the input script that has been previously generated. 
            bytes InputScriptSoFar; 
            
            input(Bitcoin::prevout p, uint64 x, uint32_little q = Bitcoin::input::Finalized, bytes z = {}): 
                Prevout{p}, ExpectedScriptSize{x}, Sequence{q}, InputScriptSoFar{z} {}
            
            operator Bitcoin::incomplete::input() const {
                return {Prevout.Key, Sequence};
            }
            
            uint64 serialized_size() const {
                return 40 + Bitcoin::var_int::size(ExpectedScriptSize) + ExpectedScriptSize;
            }
        };
        
        int32_little Version; 
        list<input> Inputs;
        list<Bitcoin::output> Outputs;
        uint32_little Locktime; 
        
        // compare this to a satoshi_per_byte value to see if the fee is good enough. 
        uint64 expected_size() const {
            uint64 size = 8u + Bitcoin::var_int::size(Inputs.size()) + Bitcoin::var_int::size(Inputs.size()); + 
                data::fold([](uint64 size, const input &i) -> uint64 {
                    return size + i.serialized_size();
                }, 0u, Inputs) + 
                data::fold([](uint64 size, const Bitcoin::output &o) -> uint64 {
                    return size + o.serialized_size();
                }, 0u, Outputs);
            return size;
        }
        
        Bitcoin::satoshi spent() const {
            return data::fold([](Bitcoin::satoshi x, const input &in) -> Bitcoin::satoshi {
                return in.Prevout.value() + x;
            }, Bitcoin::satoshi{0}, Inputs);
        }
        
        Bitcoin::satoshi sent() const {
            return data::fold([](Bitcoin::satoshi x, const Bitcoin::output &out) -> Bitcoin::satoshi {
                return out.Value + x;
            }, Bitcoin::satoshi{0}, Outputs);
        }
        
        Bitcoin::satoshi fee() const {
            return spent() - sent();
        }
        
        // convert to an incomplete tx for signing. 
        explicit operator Bitcoin::incomplete::transaction() const {
            return Bitcoin::incomplete::transaction {Version, data::for_each([](const input &in) -> Bitcoin::incomplete::input {
                return in;
            }, Inputs), Outputs, Locktime};
        }
        
        // construct the signature documents for each input. 
        list<Bitcoin::sighash::document> documents() const {
            Bitcoin::incomplete::transaction incomplete(*this);
            uint32 index = 0;
            return data::for_each([&incomplete, &index](const input &in) -> Bitcoin::sighash::document {
                return Bitcoin::sighash::document{in.Prevout.value(), 
                    bytes::write(in.Prevout.script().size() + in.InputScriptSoFar.size(), in.Prevout.script(), in.InputScriptSoFar), 
                    incomplete, index};
            }, Inputs);
        }
        
    };
    
}

#endif 
