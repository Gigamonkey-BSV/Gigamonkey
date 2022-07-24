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
    
    bool inline operator==(const satoshi_per_byte &a, const satoshi_per_byte &b);
    
    // given a tx size, what fee should we pay? 
    Bitcoin::satoshi inline calculate_fee(satoshi_per_byte v, uint64 size) {
        if (v.Bytes == 0) throw data::math::division_by_zero{};
        return std::ceil(double(v.Satoshis) * double(size) / double(v.Bytes));
    }
    
    // this is the first step in creating a transaction and and it has to do with
    // ensuring that the fee is correct. 
    struct transaction_design {
        
        // we cannot construct a real input until after the signatures have been made. 
        // however, we must estimate the size of the inputs before we sign because the
        // transaction fee is included in the signature, and we don't know what a good
        // tx fee is going to be without knowing the size of the final transaction. 
        struct input {
            prevout Prevout; 
            uint64 ExpectedScriptSize;
            uint32_little Sequence;
            
            input(prevout p, uint64 x, uint32_little q = Bitcoin::input::Finalized): 
                Prevout{p}, ExpectedScriptSize{x}, Sequence{q} {}
            
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
        uint64 serialized_size() const {
            uint64 size = 8 + Bitcoin::var_int::size(Inputs.size()) + Bitcoin::var_int::size(Inputs.size()); + 
                data::fold([](size_t size, const input& i) -> size_t {
                    return size + i.serialized_size();
                }, 0, Inputs) + 
                data::fold([](size_t size, const Bitcoin::output& i) -> size_t {
                    return size + i.serialized_size();
                }, 0, Outputs);
            return size;
        }
        
        // convert to an incomplete tx for signing. 
        explicit operator Bitcoin::incomplete::transaction() const {
            return Bitcoin::incomplete::transaction {Version, data::for_each([](const input &in) -> Bitcoin::incomplete::input {
                return in;
            }, Inputs), Outputs, Locktime};
        }
        
        // construct a signature document for the ith input. 
        // (This assumes that script_code == the output script, 
        // which isn't necessarily true in general but is true 
        // at least until the original signature algorithm is
        // re-enabled. 
        Bitcoin::sighash::document document(index i) const {
            if (i >= Inputs.size()) throw std::out_of_range{"index is bigger than the number of inputs"};
            return Bitcoin::sighash::document{Inputs[i].Prevout.value(), Inputs[i].Prevout.script(), Bitcoin::incomplete::transaction(*this), i};
        }
        
    };
    
}

#endif 
