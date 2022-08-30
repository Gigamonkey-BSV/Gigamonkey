// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/interpreter.hpp>
#include <gigamonkey/script/bitcoin_core.hpp>
#include <sv/script/script.h>
#include <sv/script/script_num.h>
#include <sv/policy/policy.h>

constexpr auto bits_per_byte{8};

namespace Gigamonkey::Bitcoin { 
    
    const CScriptNum &machine::script_zero() {
        static CScriptNum Zero(0);
        return Zero;
    }
        
    const CScriptNum &machine::script_one() {
        static CScriptNum One(1);
        return One;
    }
    
    machine machine::make(uint32 flags, script_config config) { 
        return machine({}, {}, {}, {}, 0, flags, config);
    }
    
    machine::machine(std::vector<element> stack, std::vector<element> alt, 
        std::vector<bool> ex, std::vector<bool> el, long count, uint32 flags, script_config config) : 
        Flags{flags}, Config{config},  
        Stack{Config.MaxStackMemoryUsage, stack}, 
        AltStack{Stack.makeChildStack(alt)}, Exec{}, Else{}, OpCount{0}, 
        UTXOAfterGenesis{static_cast<bool>(Flags & SCRIPT_UTXO_AFTER_GENESIS) != 0}, 
        RequireMinimal{static_cast<bool>(Flags & SCRIPT_VERIFY_MINIMALDATA)} {}
    
    machine::element::operator bool() const {
        for (size_t i = 0; i < this->size(); i++) {
            if ((*this)[i] != 0) {
                // Can be negative zero
                if (i == this->size() - 1 && (*this)[i] == 0x80) {
                    return false;
                }
                return true;
            }
        }
        return false;
    }
    
    ScriptError machine::verify() {
        // (true -- ) or
        // (false -- false) and return
        if (Stack.size() < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
        
        bool v = bool(Stack.stacktop(-1).GetElement());
        Stack.pop_back();
        
        return v ? SCRIPT_ERR_OK : SCRIPT_ERR_VERIFY;
    }
    
    ScriptError machine::drop() {
        // (x -- )
        if (Stack.size() < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
        Stack.pop_back();
        return SCRIPT_ERR_OK;
    }
    
    ScriptError machine::equal() {
        // (x1 x2 - bool)
        if (Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
        
        bool fEqual = (Stack.stacktop(-2).GetElement() == Stack.stacktop(-1).GetElement());
        Stack.pop_back();
        Stack.pop_back();
        Stack.push_back(fEqual ? script_true() : script_false());
        
        return SCRIPT_ERR_OK;
    }
    
    ScriptError machine::equal_verify() {
        // (x1 x2 - bool)
        if (Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
        
        bool fEqual = (Stack.stacktop(-2).GetElement() == Stack.stacktop(-1).GetElement());
        Stack.pop_back();
        Stack.pop_back();
        
        return fEqual ? SCRIPT_ERR_OK : SCRIPT_ERR_EQUALVERIFY;
        
    }
    
    inline uint8_t make_rshift_mask(size_t n) {
        static uint8_t mask[] = {0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80}; 
        return mask[n]; 
    } 

    inline uint8_t make_lshift_mask(size_t n) {
        static uint8_t mask[] = {0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01}; 
        return mask[n]; 
    } 

    // shift x right by n bits, implements OP_RSHIFT
    static machine::element RShift(const machine::element &x, int n) {
        machine::element::size_type bit_shift = n % 8;
        machine::element::size_type byte_shift = n / 8;
    
        uint8_t mask = make_rshift_mask(bit_shift); 
        uint8_t overflow_mask = ~mask; 
    
        bytes result(x.size(), 0x00); 
        for (machine::element::size_type i = 0; i < x.size(); i++) {
            machine::element::size_type k = i + byte_shift;
            if (k < x.size()) {
                uint8_t val = (x[i] & mask); 
                val >>= bit_shift;
                result[k] |= val; 
            } 

            if (k + 1 < x.size()) {
                uint8_t carryval = (x[i] & overflow_mask); 
                carryval <<= 8 - bit_shift; 
                result[k + 1] |= carryval;
            } 
        } 
        return machine::element{result}; 
    } 

    // shift x left by n bits, implements OP_LSHIFT
    static machine::element LShift(const machine::element &x, int n) {
        machine::element::size_type bit_shift = n % 8;
        machine::element::size_type byte_shift = n / 8;

        uint8_t mask = make_lshift_mask(bit_shift); 
        uint8_t overflow_mask = ~mask; 

        bytes result(x.size(), 0x00); 
        for (machine::element::size_type index = x.size(); index > 0; index--) {
            machine::element::size_type i = index - 1;
            
            // make sure that k is always >= 0
            if (byte_shift <= i) {
                machine::element::size_type k = i - byte_shift;
                uint8_t val = (x[i] & mask);
                val <<= bit_shift;
                result[k] |= val;

                if (k >= 1) {
                    uint8_t carryval = (x[i] & overflow_mask);
                    carryval >>= 8 - bit_shift;
                    result[k - 1] |= carryval;
                }
            }
        }
        
        return machine::element{result}; 
    } 
    
    ScriptError machine::left_shift() {
        // (x n -- out)
        if(Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
        
        const LimitedVector vch1 = Stack.stacktop(-2);
        const auto& top{Stack.stacktop(-1).GetElement()};
        CScriptNum n{top, RequireMinimal, Config.MaxScriptNumLength, UTXOAfterGenesis};
        
        if (n < 0) return SCRIPT_ERR_INVALID_NUMBER_RANGE;

        Stack.pop_back();
        Stack.pop_back();
        auto values{vch1.GetElement()};

        if (n >= values.size() * bits_per_byte)
            fill(begin(values), end(values), 0);
        else {
            do {
                values = LShift(values, n.getint());
                n -= UTXOAfterGenesis
                            ? CScriptNum{bsv::bint{INT32_MAX}}
                            : CScriptNum{INT32_MAX};
            } while(n > 0);
        }
        
        Stack.push_back(values);
        
        return SCRIPT_ERR_OK;
    }
    
    ScriptError machine::right_shift() {
        // (x n -- out)
        if(Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;

        const LimitedVector vch1 = Stack.stacktop(-2);
        const auto& top{Stack.stacktop(-1).GetElement()};
        CScriptNum n{top, RequireMinimal, Config.MaxScriptNumLength, UTXOAfterGenesis};
        
        if (n < 0) return SCRIPT_ERR_INVALID_NUMBER_RANGE;

        Stack.pop_back();
        Stack.pop_back();
        auto values{vch1.GetElement()};

        if (n >= values.size() * bits_per_byte)
            fill(begin(values), end(values), 0);
        else
        {
            do
            {
                values = RShift(values, n.getint());
                n -= UTXOAfterGenesis
                            ? CScriptNum{bsv::bint{INT32_MAX}}
                            : CScriptNum{INT32_MAX};
            } while(n > 0);
        }
        
        Stack.push_back(values);
        
        return SCRIPT_ERR_OK;
    }
    
    ScriptError machine::cat() {
        // (x1 x2 -- out)
        if (Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;

        LimitedVector &vch1 = Stack.stacktop(-2);
        // We make copy of last element on stack (vch2) so we can pop the last
        // element before appending it to the previous element.
        // If appending would be first, we could exceed stack size in the process
        // even though OP_CAT actually reduces total stack size.
        LimitedVector vch2 = Stack.stacktop(-1);

        if (!UTXOAfterGenesis && (vch1.size() + vch2.size() > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS))
            return SCRIPT_ERR_PUSH_SIZE;

        Stack.pop_back();
        vch1.append(vch2);
        
        return SCRIPT_ERR_OK;
    }
    
    ScriptError machine::split() {
        // (in position -- x1 x2)
        if(Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;

        const LimitedVector& data = Stack.stacktop(-2);

        // Make sure the split point is apropriate.
        const auto& top{Stack.stacktop(-1).GetElement()};
        const CScriptNum n{top, RequireMinimal, Config.MaxScriptNumLength, UTXOAfterGenesis};
        if(n < 0 || n > data.size()) return SCRIPT_ERR_INVALID_SPLIT_RANGE;

        const auto position{n.to_size_t_limited()};

        // Prepare the results in their own buffer as `data`
        // will be invalidated.
        element n1(data.begin(), data.begin() + position);
        element n2(data.begin() + position, data.end());
                        
        Stack.pop_back();
        Stack.pop_back();

        // Replace existing stack values by the new values.
        Stack.push_back(n1);
        Stack.push_back(n2);
        
        return SCRIPT_ERR_OK;
    }
    
    ScriptError machine::bin_2_num() {
        // (in size -- out)
        if (Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;

        const auto& arg_1 = Stack.stacktop(-1).GetElement();
        const CScriptNum n{arg_1, RequireMinimal, Config.MaxScriptNumLength, UTXOAfterGenesis};
        
        if(n < 0 || n > std::numeric_limits<int32_t>::max()) return SCRIPT_ERR_PUSH_SIZE;

        const auto size{n.to_size_t_limited()};
        if(!UTXOAfterGenesis && (size > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS))
            return SCRIPT_ERR_PUSH_SIZE;

        Stack.pop_back();
        LimitedVector &rawnum = Stack.stacktop(-1);

        // Try to see if we can fit that number in the number of
        // byte requested.
        rawnum.MinimallyEncode();
        if (rawnum.size() > size) return SCRIPT_ERR_IMPOSSIBLE_ENCODING;

        // We already have an element of the right size, we
        // don't need to do anything.
        if (rawnum.size() == size) return SCRIPT_ERR_OK;

        uint8_t signbit = 0x00;
        if (rawnum.size() > 0) {
            signbit = rawnum.GetElement().back() & 0x80;
            rawnum[rawnum.size() - 1] &= 0x7f;
        }

        rawnum.padRight(size, signbit);
        
        return SCRIPT_ERR_OK;
    }
    
    ScriptError machine::num_2_bin() {
        // (in -- out)
        if (Stack.size() < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

        LimitedVector &n = Stack.stacktop(-1);
        n.MinimallyEncode();

        // The resulting number must be a valid number.
        if (!n.IsMinimallyEncoded(Config.MaxScriptNumLength)) return SCRIPT_ERR_INVALID_NUMBER_RANGE;
        
        return SCRIPT_ERR_OK;
    }
        
    ScriptError machine::check_sequence_verify(const redemption_document *doc) {
        if (!(Flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY) || UTXOAfterGenesis) {
            // not enabled; treat as a NOP3
            return (Flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) ?
                SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS : SCRIPT_ERR_OK;
        }

        if (Stack.size() < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

        // nSequence, like nLockTime, is a 32-bit unsigned
        // integer field. See the comment in CHECKLOCKTIMEVERIFY
        // regarding 5-byte numeric operands.
        const CScriptNum nSequence(Stack.stacktop(-1).GetElement(), RequireMinimal, 5);

        // In the rare event that the argument may be < 0 due to
        // some arithmetic being done first, you can always use
        // 0 MAX CHECKSEQUENCEVERIFY.
        if (nSequence < 0) return SCRIPT_ERR_NEGATIVE_LOCKTIME;

        // To provide for future soft-fork extensibility, if the
        // operand has the disabled lock-time flag set,
        // CHECKSEQUENCEVERIFY behaves as a NOP.
        if ((nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != script_zero()) return SCRIPT_ERR_OK;

        // Compare the specified sequence number with the input.
        return (doc && !doc->check_sequence(nSequence)) ? 
            SCRIPT_ERR_UNSATISFIED_LOCKTIME : SCRIPT_ERR_OK;
        
    }
    
    ScriptError machine::check_locktime_verify(const redemption_document *doc) {
        if (!(Flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY) || UTXOAfterGenesis) {
            // not enabled; treat as a NOP2
            return (Flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) ? 
                SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS :
                SCRIPT_ERR_OK;
        }

        if (Stack.size() < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

        // Note that elsewhere numeric opcodes are limited to
        // operands in the range -2**31+1 to 2**31-1, however it
        // is legal for opcodes to produce results exceeding
        // that range. This limitation is implemented by
        // CScriptNum's default 4-byte limit.
        //
        // If we kept to that limit we'd have a year 2038
        // problem, even though the nLockTime field in
        // transactions themselves is uint32 which only becomes
        // meaningless after the year 2106.
        //
        // Thus as a special case we tell CScriptNum to accept
        // up to 5-byte bignums, which are good until 2**39-1,
        // well beyond the 2**32-1 limit of the nLockTime field
        // itself.
        const CScriptNum nLockTime(Stack.stacktop(-1).GetElement(), RequireMinimal, 5);

        // In the rare event that the argument may be < 0 due to
        // some arithmetic being done first, you can always use
        // 0 MAX CHECKLOCKTIMEVERIFY.
        if (nLockTime < 0) return SCRIPT_ERR_NEGATIVE_LOCKTIME;

        // Actually compare the specified lock time with the
        // transaction.
        return (doc && !doc->check_locktime(nLockTime)) ? SCRIPT_ERR_UNSATISFIED_LOCKTIME : SCRIPT_ERR_OK;
    }
}
