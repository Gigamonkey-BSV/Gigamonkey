// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_MACHINE
#define GIGAMONKEY_SCRIPT_MACHINE

#include <gigamonkey/script/script.hpp>
#include <gigamonkey/script/config.hpp>
#include <sv/script/int_serialization.h>

class stack_overflow_error : public std::overflow_error
{
public:
    explicit stack_overflow_error(const std::string& str)
        : std::overflow_error(str) {}
};

namespace Gigamonkey::Bitcoin { 
    
    struct machine {
    
        struct element : bytes {
            
            element(int64 x) : bytes{bytes(Z{x})} {}
            
            explicit element(std::vector<byte>&& v) {
                std::vector<byte>::operator=(v);
            }
            
            explicit element(const std::vector<byte>& v) : element(v.begin(), v.end()) {}
            
            explicit operator bool() const;
            explicit operator Z() const;
            
            bool minimal_bool() const;
            bool minimal_true() const;
            bool minimal_false() const;
            
            bool minimal_number() const {
                return Z::minimal(*this);
            }
            
            element(vector<byte>::const_iterator a, vector<byte>::const_iterator b) {
                resize(b - a);
                std::copy(a, b, this->begin());
            }
            
            explicit element(bytes_view b) : bytes{b} {}
        };
        
        class LimitedStack;
        
        class LimitedVector {
        private:
            element stackElement;
            std::reference_wrapper<LimitedStack> stack;
            
            LimitedVector(const element& stackElementIn, LimitedStack& stackIn);
            
            // WARNING: modifying returned element will NOT adjust stack size
            element& GetElementNonConst();
        public:
            
            // Memory usage of one stack element (without data). This is a consensus rule. Do not change.
            // It prevents someone from creating stack with millions of empty elements.
            static constexpr unsigned int ELEMENT_OVERHEAD = 32;
            
            // Warning: returned reference is invalidated if parent stack is modified.
            const element& GetElement() const;
            uint8_t& front();
            uint8_t& back();
            const uint8_t& front() const;
            const uint8_t& back() const;
            uint8_t& operator[](uint64_t pos);
            const uint8_t& operator[](uint64_t pos) const;
            
            size_t size() const;
            bool empty() const;
            
            void push_back(uint8_t element);
            void append(const LimitedVector& second);
            void padRight(size_t size, uint8_t signbit);
            
            typename element::iterator begin();
            typename element::iterator end();
            
            const typename element::const_iterator begin() const;
            const typename element::const_iterator end() const;
            
            bool MinimallyEncode();
            bool IsMinimallyEncoded(uint64_t maxSize) const;
            
            const LimitedStack& getStack() const;
            
            friend class LimitedStack;
        };
        
        class LimitedStack {
        private:
            uint64_t combinedStackSize = 0;
            uint64_t maxStackSize = 0;
            std::vector<LimitedVector> stack;
            LimitedStack* parentStack { nullptr };
            void decreaseCombinedStackSize(uint64_t additionalSize);
            ScriptError increaseCombinedStackSize(uint64_t additionalSize);

            LimitedStack(const LimitedStack&) = default;
            LimitedStack() = default;

        public:
            LimitedStack(uint64_t maxStackSizeIn, const std::vector<element>& stackElements = {});
            
            LimitedStack(LimitedStack&&) = default;
            LimitedStack& operator=(LimitedStack&&) = default;
            LimitedStack& operator=(const LimitedStack&) = delete;
            
            // Compares the stacks but ignores the parent.
            bool operator==(const LimitedStack& other) const;
            
            // Warning: returned reference is invalidated if stack is modified.
            LimitedVector& stacktop(int index);
            
            const LimitedVector& front() const;
            const LimitedVector& back() const;
            const LimitedVector& at(uint64_t i) const;
            
            uint64_t getCombinedStackSize() const;
            size_t size() const;
            bool empty() const;
            
            void pop_back();
            ScriptError push_back(const LimitedVector &element);
            ScriptError push_back(const element& element);
            
            // erase elements from including (top - first). element until excluding (top - last). element
            // first and last should be negative numbers (distance from the top)
            void erase(int first, int last);
            
            // index should be negative number (distance from the top)
            void erase(int index);
            
            // position should be negative number (distance from the top)
            void insert(int position, const LimitedVector& element);
            
            void swapElements(size_t index1, size_t index2);
            
            void moveTopToStack(LimitedStack& otherStack);
            
            void MoveToValtypes(std::vector<element>& script);
        
            LimitedStack makeChildStack(const std::vector<element>& stackElements = {});

            // parent must be null
            LimitedStack makeRootStackCopy();

            const LimitedStack* getParentStack() const;

            friend class LimitedVector;
            
            typename std::vector<LimitedVector>::const_iterator begin() const {
                return stack.begin();
            }
            
            typename std::vector<LimitedVector>::const_iterator end() const {
                return stack.end();
            }
        };
        
        uint32 Flags;
        script_config Config;
        
        LimitedStack Stack;
        LimitedStack AltStack;
            
        std::vector<bool> Exec;
        std::vector<bool> Else;
        
        long OpCount;
        
        static machine make(uint32 flags = StandardScriptVerifyFlags(true, true), script_config config = get_standard_script_config(true, true));
        
        machine(std::vector<element> stack, std::vector<element> alt = {}, std::vector<bool> ex = {}, std::vector<bool> el = {}, 
            long count = 0, uint32 flags = StandardScriptVerifyFlags(true, true), script_config config = get_standard_script_config(true, true));
        
        uint64 memory_usage() const {
            return Stack.getCombinedStackSize();
        }
        
        // If SCRIPT_VERIFY_CLEANSTACK is set, then the
        // result is successful if the stack size is 1. 
        // Otherwise, it is always successful.
        ScriptError halt() const;
        
        ScriptError step(const instruction&);
        
        ScriptError push(bytes_view);
        ScriptError push(const element &);
        
        ScriptError drop();
        ScriptError drop_two();
        ScriptError duplicate();
        ScriptError duplicate_two();
        ScriptError duplicate_three();
        ScriptError duplicate_if();
        ScriptError over();
        ScriptError over_two();
        ScriptError rotate();
        ScriptError rotate_two();
        ScriptError swap();
        ScriptError swap_two();
        ScriptError depth();
        ScriptError nip();
        ScriptError tuck();
        ScriptError pick();
        ScriptError roll();
        
        ScriptError verify();
        ScriptError control_if();
        ScriptError control_not_if();
        ScriptError control_else();
        ScriptError control_end_if();
        ScriptError control_return();
        
        ScriptError to_alt();
        ScriptError from_alt();
        
        ScriptError cat();
        ScriptError split();
        ScriptError bin_2_num();
        ScriptError num_2_bin();
        ScriptError size();
        
        ScriptError bit_and();
        ScriptError bit_or();
        ScriptError bit_xor();
        ScriptError invert();
        ScriptError left_shift();
        ScriptError right_shift();
        
        ScriptError increment();
        ScriptError decrement();
        ScriptError abs();
        ScriptError negate();
        ScriptError add();
        ScriptError subtract();
        ScriptError multiply();
        ScriptError divide();
        ScriptError mod();
        ScriptError min();
        ScriptError map();
        
        ScriptError equal();
        ScriptError equal_verify();
        ScriptError number_equal();
        ScriptError number_equal_verify();
        ScriptError number_not_equal();
        ScriptError less();
        ScriptError greater();
        ScriptError less_equal();
        ScriptError greater_equal();
        ScriptError within();
        
        ScriptError bool_not();
        ScriptError bool_and();
        ScriptError bool_or();
        ScriptError not_zero();
        
        ScriptError RIPEMD160();
        ScriptError SHA1();
        ScriptError Hash256();
        ScriptError Hash160();
        
        ScriptError check_sig(const digest256 &);
        ScriptError check_sig_verify(const digest256 &);
        ScriptError check_multisig(const digest256 &);
        ScriptError check_multisig_verify(const digest256 &);
        
        ScriptError version();
        ScriptError version_if();
        ScriptError version_not_if();
        
        ScriptError check_sequence_verify(const redemption_document *);
        ScriptError check_locktime_verify(const redemption_document *);
        
        const bool UTXOAfterGenesis;
        const bool RequireMinimal;
        
        static const element &script_false() {
            static element False{{}};
            return False;
        }
        
        static const element &script_true() {
            static element True{{0x01}};
            return True;
        }
        
        static const element &script_bool(bool b) {
            return b ? script_true() : script_false();
        }
        
        static const CScriptNum &script_zero();
        static const CScriptNum &script_one();
        
    };
    
    bool operator==(const machine &, const machine &);
    
    ScriptError inline machine::halt() const {
        return ((Flags & SCRIPT_VERIFY_CLEANSTACK) != 0 && Stack.size() != 1) ? SCRIPT_ERR_CLEANSTACK : SCRIPT_ERR_OK;
    }
    
    ScriptError inline machine::push(bytes_view b) {
        return Stack.push_back(element{b});
    }
    
    ScriptError inline machine::push(const element &b) {
        return Stack.push_back(b);
    }
    
}

#endif
