// Copyright (c) 2019 Bitcoin Association
// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_INTERPRETER_STACK
#define GIGAMONKEY_INTERPRETER_STACK

//#include <data/tools/store.hpp>
#include <gigamonkey/numbers.hpp>
#include <gigamonkey/script/config.hpp>
#include <gigamonkey/script/error.h>

namespace Gigamonkey::Bitcoin {

    // Maximum number of bytes pushable to the stack -- replaced with DEFAULT_STACK_MEMORY_USAGE after Genesis
    static const unsigned int MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS = 520;

    // Maximum number of elements on the stack -- replaced with DEFAULT_STACK_MEMORY_USAGE after Genesis
    static const unsigned int MAX_STACK_ELEMENTS_BEFORE_GENESIS = 1000;

    // Threshold for nLockTime: below this value it is interpreted as block number,
    // otherwise as UNIX timestamp. Thresold is Tue Nov 5 00:53:20 1985 UTC
    static const unsigned int LOCKTIME_THRESHOLD = 500000000;

    // before genesis, limited_two_stack has separate values
    // for maximum element size and for maximum number of elements.
    // after genesis, this was replaced by a requirement for maximum
    // estimate of the amount of memory used by the stack.
    template <bool genesis> struct limited_two_stack;

    struct two_stack {
    protected:
        cross<integer> Stack;
        cross<integer> AltStack;
    public:

        // Warning: returned reference is invalidated if stack is modified.
        bytes &top (int index = -1);

        const bytes &at (uint64_t i) const;

        size_t size () const;
        size_t alt_size () const;
        size_t combined_size () const;
        bool empty () const;

        virtual void pop_back () = 0;
        virtual void push_back (slice<const byte>) = 0;

        // erase elements from including (top - first). element until excluding (top - last). element
        // first and last should be negative numbers (distance from the top)
        virtual void erase (int first, int last) = 0;

        // index should be negative number (distance from the top)
        virtual void erase (int index) = 0;

        // position should be negative number (distance from the top)
        virtual void insert (int position, slice<const byte>) = 0;

        Error to_alt ();
        Error from_alt ();

        void swap (size_t index1, size_t index2);

        virtual void modify_top (std::function<void (bytes &)>, int index = -1) = 0;

        void replace_back (const bytes &element) {
            modify_top ([&element] (bytes &val) {
                val = element;
            });
        }

        typename std::vector<integer>::const_iterator begin () const;
        typename std::vector<integer>::const_iterator end () const;
        typename std::vector<integer>::iterator begin ();
        typename std::vector<integer>::iterator end ();

        virtual ~two_stack () {}

        friend std::ostream inline &operator << (std::ostream &o, const two_stack &i) {
            return o << std::hex << "{Stack: " << i.Stack << ", AltStack: " << i.AltStack << "}";
        }

    };

    template <> struct limited_two_stack<false> : two_stack {
        uint32 MaxScriptElementSize;
        uint32 MaxStackElements;

        limited_two_stack (uint32 mxxz = MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS, uint32 mxe = MAX_STACK_ELEMENTS_BEFORE_GENESIS) :
            MaxScriptElementSize {mxxz}, MaxStackElements {mxe} {}

        bool valid () const;

        void pop_back () override;
        void push_back (slice<const byte>) override;

        // erase elements from including (top - first). element until excluding (top - last). element
        // first and last should be negative numbers (distance from the top)
        void erase (int first, int last) override;

        // index should be negative number (distance from the top)
        void erase (int index) override;

        // position should be negative number (distance from the top)
        void insert (int position, slice<const byte>) override;

        void modify_top (std::function<void (bytes &)> f, int index = -1) override;

    };

    template <> struct limited_two_stack<true> : two_stack {
        // Memory usage of one stack element (without data). This is a consensus rule. Do not change.
        // It prevents someone from creating stack with millions of empty elements.
        static constexpr unsigned int ELEMENT_OVERHEAD = 32;

        // max combined size
        uint64 MaxMemoryUsage;
        // combined size of both stacks.
        uint64 MemoryUsage;

        bool valid () const;

        limited_two_stack (uint64 max_memory_usage) : two_stack {},
            MaxMemoryUsage {max_memory_usage}, MemoryUsage {0} {}

        void increase_memory_usage (uint64_t additionalSize);
        void decrease_memory_usage (uint64_t additionalSize);

        void pop_back () override;
        void push_back (slice<const byte>) override;

        // erase elements from including (top - first). element until excluding (top - last). element
        // first and last should be negative numbers (distance from the top)
        void erase (int first, int last) override;

        // index should be negative number (distance from the top)
        void erase (int index) override;

        // position should be negative number (distance from the top)
        void insert (int position, slice<const byte>) override;

        void modify_top (std::function<void (bytes &)> f, int index = -1) override;
    };

    // stack operations
    Error swap (two_stack &);
    Error swap_two (two_stack &);
    Error duplicate (two_stack &);
    Error duplicate_two (two_stack &);
    Error duplicate_three (two_stack &);
    Error drop (two_stack &);
    Error drop_two (two_stack &);
    Error over (two_stack &);
    Error over_two (two_stack &);
    Error rotate (two_stack &);
    Error rotate_two (two_stack &);
    Error nip (two_stack &);
    Error tuck (two_stack &);
    Error depth (two_stack &);
    Error top_size (two_stack &);
    Error if_dup (two_stack &);

    Error pick (two_stack &);
    Error roll (two_stack &);

    // bitwise
    template <bool genesis> Error script_bit_and (limited_two_stack<genesis> &stack);
    template <bool genesis> Error script_bit_or (limited_two_stack<genesis> &stack);
    template <bool genesis> Error script_bit_xor (limited_two_stack<genesis> &stack);
    template <bool genesis> Error script_bit_invert (limited_two_stack<genesis> &stack);
    template <bool genesis> Error shift_left (limited_two_stack<genesis> &stack);
    template <bool genesis> Error shift_right (limited_two_stack<genesis> &stack);
    template <bool genesis> Error script_equal (limited_two_stack<genesis> &stack);

    // string
    template <bool genesis> Error concatinate (limited_two_stack<genesis> &stack);
    template <bool genesis> Error split (limited_two_stack<genesis> &stack);
    template <bool genesis> Error bin_2_num (limited_two_stack<genesis> &stack);
    template <bool genesis> Error num_2_bin (limited_two_stack<genesis> &stack);

    // hash
    template <bool genesis> Error script_RIPEMD160 (limited_two_stack<genesis> &stack);
    template <bool genesis> Error script_SHA1 (limited_two_stack<genesis> &stack);
    template <bool genesis> Error script_SHA256 (limited_two_stack<genesis> &stack);
    template <bool genesis> Error script_HASH160 (limited_two_stack<genesis> &stack);
    template <bool genesis> Error script_HASH256 (limited_two_stack<genesis> &stack);

    // numeric unary
    template <bool genesis> Error script_increment (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_decrement (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_negate (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_abs (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_not (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_nonzero (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);

    // numeric binary
    template <bool genesis> Error script_add (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_subtract (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_multiply (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_divide (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_mod (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_bool_and (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_bool_or (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_numeric_equal (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_unequal (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_less (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_greater (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_less_equal (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_greater_equal (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_min (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> Error script_max (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);

    // numeric trinary
    template <bool genesis> Error script_within (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);

    template <bool genesis> struct state : limited_two_stack<genesis> {
        cross<bool> Exec;
        cross<bool> Else;
    };

    size_t inline two_stack::size () const {
        return Stack.size ();
    }

    size_t inline two_stack::alt_size () const {
        return AltStack.size ();
    }

    size_t inline two_stack::combined_size () const {
        return size () + alt_size ();
    }

    bool inline two_stack::empty () const {
        return Stack.empty ();
    }

    bytes inline &two_stack::top (int index) {
        if (index >= 0) throw std::invalid_argument ("Invalid argument - index should be < 0.");
        return Stack.at (Stack.size () + index);
    }

    void inline two_stack::swap (size_t index1, size_t index2) {
        std::swap (Stack.at (index1), Stack.at (index2));
    }

    const bytes inline &two_stack::at (uint64_t i) const {
        return Stack.at (i);
    }

    Error inline two_stack::from_alt () {
        if (alt_size () < 1) return Error::INVALID_ALTSTACK_OPERATION;
        // Moving element to other stack does not change the total size of stack.
        // Just use internal functions to move the element.
        Stack.push_back (std::move (AltStack.at (AltStack.size () - 1)));
        AltStack.pop_back ();
        return {};
    }

    Error inline two_stack::to_alt () {
        if (size () < 1) return Error::INVALID_STACK_OPERATION;
        // Moving element to other stack does not change the total size of stack.
        // Just use internal functions to move the element.
        AltStack.push_back (std::move (Stack.at (Stack.size () - 1)));
        Stack.pop_back ();
        return {};
    }

    typename std::vector<integer>::const_iterator inline two_stack::begin () const {
        return Stack.begin ();
    }

    typename std::vector<integer>::const_iterator inline two_stack::end () const {
        return Stack.end ();
    }

    typename std::vector<integer>::iterator inline two_stack::begin () {
        return Stack.begin ();
    }

    typename std::vector<integer>::iterator inline two_stack::end () {
        return Stack.end ();
    }

    void inline limited_two_stack<true>::decrease_memory_usage (uint64_t additionalSize) {
        MemoryUsage -= additionalSize;
    }

    void inline limited_two_stack<true>::increase_memory_usage (uint64_t additionalSize) {
        if (MemoryUsage + additionalSize > MaxMemoryUsage)
            throw invalid_program {Error::STACK_SIZE};

        MemoryUsage += additionalSize;
    }

    void inline limited_two_stack<true>::push_back (slice<const byte> element) {
        increase_memory_usage (element.size () + ELEMENT_OVERHEAD);
        Stack.emplace_back (element);
    }

    void inline limited_two_stack<false>::push_back (slice<const byte> element) {
        if (element.size () > MaxScriptElementSize)
            throw invalid_program {Error::PUSH_SIZE};

        if (this->combined_size () == MaxStackElements)
            throw invalid_program {Error::STACK_SIZE};

        Stack.emplace_back (element);
    }

    void inline limited_two_stack<false>::pop_back () {
        if (Stack.empty ()) throw std::runtime_error ("popstack(): stack empty");
        Stack.pop_back ();
    }

}

#endif
