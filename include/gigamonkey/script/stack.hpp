// Copyright (c) 2019 Bitcoin Association
// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_INTERPRETER_STACK
#define GIGAMONKEY_INTERPRETER_STACK

#include <gigamonkey/types.hpp>
#include <gigamonkey/script/config.hpp>
#include <gigamonkey/script/flags.h>
#include <gigamonkey/script/error.h>

namespace Gigamonkey::Bitcoin {

    // Maximum number of bytes pushable to the stack -- replaced with DEFAULT_STACK_MEMORY_USAGE after Genesis
    static const unsigned int MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS = 520;

    // Maximum number of elements on the stack -- replaced with DEFAULT_STACK_MEMORY_USAGE after Genesis
    static const unsigned int MAX_STACK_ELEMENTS_BEFORE_GENESIS = 1000;

    // Threshold for nLockTime: below this value it is interpreted as block number,
    // otherwise as UNIX timestamp. Thresold is Tue Nov 5 00:53:20 1985 UTC
    static const unsigned int LOCKTIME_THRESHOLD = 500000000;

    void inline throw_stack_overflow_exception () {
        throw script_exception {SCRIPT_ERR_STACK_SIZE};
    };

    void inline throw_push_size_exception () {
        throw script_exception {SCRIPT_ERR_PUSH_SIZE};
    };

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
        virtual void push_back (bytes_view) = 0;

        // erase elements from including (top - first). element until excluding (top - last). element
        // first and last should be negative numbers (distance from the top)
        virtual void erase (int first, int last) = 0;

        // index should be negative number (distance from the top)
        virtual void erase (int index) = 0;

        // position should be negative number (distance from the top)
        virtual void insert (int position, bytes_view) = 0;

        void to_alt ();
        void from_alt ();

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
        void push_back (bytes_view) override;

        // erase elements from including (top - first). element until excluding (top - last). element
        // first and last should be negative numbers (distance from the top)
        void erase (int first, int last) override;

        // index should be negative number (distance from the top)
        void erase (int index) override;

        // position should be negative number (distance from the top)
        void insert (int position, bytes_view) override;

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
        void push_back (bytes_view) override;

        // erase elements from including (top - first). element until excluding (top - last). element
        // first and last should be negative numbers (distance from the top)
        void erase (int first, int last) override;

        // index should be negative number (distance from the top)
        void erase (int index) override;

        // position should be negative number (distance from the top)
        void insert (int position, bytes_view) override;

        void modify_top (std::function<void (bytes &)> f, int index = -1) override;
    };

    // stack operations
    ScriptError to_alt (two_stack &stack);
    ScriptError from_alt (two_stack &stack);
    ScriptError swap (two_stack &stack);
    ScriptError swap_two (two_stack &stack);
    template <bool genesis> ScriptError duplicate (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError duplicate_two (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError duplicate_three (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError drop (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError drop_two (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError over (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError over_two (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError rotate (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError rotate_two (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError nip (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError tuck (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError pick (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError roll (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError depth (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError script_size (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError script_if_dup (limited_two_stack<genesis> &);

    // bitwise
    template <bool genesis> ScriptError script_bit_and (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError script_bit_or (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError script_bit_xor (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError script_bit_invert (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError shift_left (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError shift_right (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError script_equal (limited_two_stack<genesis> &stack);

    // string
    template <bool genesis> ScriptError concatinate (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError split (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError bin_2_num (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError num_2_bin (limited_two_stack<genesis> &stack);

    // hash
    template <bool genesis> ScriptError script_RIPEMD160 (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError script_SHA1 (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError script_SHA256 (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError script_HASH160 (limited_two_stack<genesis> &stack);
    template <bool genesis> ScriptError script_HASH256 (limited_two_stack<genesis> &stack);

    // numeric unary
    template <bool genesis> ScriptError script_increment (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_decrement (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_negate (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_abs (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_not (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_nonzero (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);

    // numeric binary
    template <bool genesis> ScriptError script_add (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_subtract (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_multiply (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_divide (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_mod (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_bool_and (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_bool_or (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_numeric_equal (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_unequal (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_less (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_greater (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_less_equal (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_greater_equal (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_min (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);
    template <bool genesis> ScriptError script_max (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);

    // numeric trinary
    template <bool genesis> ScriptError script_within (limited_two_stack<genesis> &stack, bool require_minimal, uint64 max_num_length);

    template <bool genesis> struct state : limited_two_stack<genesis> {
        cross<bool> Exec;
        cross<bool> Else;
    };

    // control operations
    template <bool genesis> ScriptError script_if (state<genesis> &);
    template <bool genesis> ScriptError script_not_if (state<genesis> &);
    template <bool genesis> ScriptError script_else (state<genesis> &);
    template <bool genesis> ScriptError script_end_if (state<genesis> &);
    template <bool genesis> ScriptError script_verify (limited_two_stack<genesis> &);
    ScriptError script_return (limited_two_stack<true> &);
    ScriptError script_return (limited_two_stack<false> &);

    // depricated
    ScriptError check_locktime_verify (limited_two_stack<false> &, bool require_minimal);
    ScriptError check_sequence_verify (limited_two_stack<false> &, bool require_minimal);

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

    void inline two_stack::from_alt () {
        // Moving element to other stack does not change the total size of stack.
        // Just use internal functions to move the element.
        Stack.push_back (std::move (AltStack.at (AltStack.size () - 1)));
        AltStack.pop_back ();
    }

    void inline two_stack::to_alt () {
        // Moving element to other stack does not change the total size of stack.
        // Just use internal functions to move the element.
        AltStack.push_back (std::move (Stack.at (Stack.size () - 1)));
        Stack.pop_back ();
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
        if (MemoryUsage + additionalSize > MaxMemoryUsage) throw_stack_overflow_exception ();
        MemoryUsage += additionalSize;
    }

    void inline limited_two_stack<true>::push_back (bytes_view element) {
        increase_memory_usage (element.size () + ELEMENT_OVERHEAD);
        Stack.emplace_back (element);
    }

    void inline limited_two_stack<false>::push_back (bytes_view element) {
        if (element.size () > MaxScriptElementSize) throw_push_size_exception ();
        if (this->combined_size () == MaxStackElements) throw_stack_overflow_exception ();
        Stack.emplace_back (element);
    }

    void inline limited_two_stack<false>::pop_back () {
        if (Stack.empty ()) throw std::runtime_error ("popstack(): stack empty");
        Stack.pop_back ();
    }

}

#endif
