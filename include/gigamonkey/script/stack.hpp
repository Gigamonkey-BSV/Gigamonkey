// Copyright (c) 2019 Bitcoin Association
// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_INTERPRETER_STACK
#define GIGAMONKEY_INTERPRETER_STACK

#include <gigamonkey/types.hpp>
#include <gigamonkey/script/config.hpp>
#include <gigamonkey/script/flags.h>
#include <gigamonkey/script/error.h>
#include <sv/script/script.h>
#include <sv/script/int_serialization.h>

namespace Gigamonkey::Bitcoin {

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
    template <bool after_genesis> struct limited_two_stack;

    struct two_stack {
    protected:
        cross<integer> Stack;
        cross<integer> AltStack;
    public:

        // Warning: returned reference is invalidated if stack is modified.
        integer &top (int index = -1);

        const integer &at (uint64_t i) const;

        size_t size () const;
        size_t alt_size () const;
        size_t combined_size () const;
        bool empty () const;

        virtual void pop_back () = 0;
        virtual void push_back (const integer &element) = 0;

        // erase elements from including (top - first). element until excluding (top - last). element
        // first and last should be negative numbers (distance from the top)
        virtual void erase (int first, int last) = 0;

        // index should be negative number (distance from the top)
        virtual void erase (int index) = 0;

        // position should be negative number (distance from the top)
        virtual void insert (int position, const integer &element) = 0;

        void to_alt ();
        void from_alt ();

        void swap (size_t index1, size_t index2);

        virtual void modify_top (std::function<void (integer &)>, int index = -1) = 0;

        void replace_back (const integer &element) {
            modify_top ([&element] (integer &val) {
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

    template <> struct limited_two_stack<false> final : two_stack {
        uint32 MaxScriptElementSize;
        uint32 MaxStackElements;

        limited_two_stack (uint32 mxxz = MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS, uint32 mxe = MAX_STACK_ELEMENTS_BEFORE_GENESIS) :
            MaxScriptElementSize {mxxz}, MaxStackElements {mxe} {}

        bool valid () const;

        void pop_back () override;
        void push_back (const integer &element) override;

        // erase elements from including (top - first). element until excluding (top - last). element
        // first and last should be negative numbers (distance from the top)
        void erase (int first, int last) override;

        // index should be negative number (distance from the top)
        void erase (int index) override;

        // position should be negative number (distance from the top)
        void insert (int position, const integer &element) override;

        void modify_top (std::function<void (integer &)> f, int index = -1) override;

    };

    template <> struct limited_two_stack<true> final : two_stack {
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
        void push_back (const integer &element) override;

        // erase elements from including (top - first). element until excluding (top - last). element
        // first and last should be negative numbers (distance from the top)
        void erase (int first, int last) override;

        // index should be negative number (distance from the top)
        void erase (int index) override;

        // position should be negative number (distance from the top)
        void insert (int position, const integer &element) override;

        void modify_top (std::function<void (integer &)> f, int index = -1) override;
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

    integer inline &two_stack::top (int index) {
        if (index >= 0) throw std::invalid_argument ("Invalid argument - index should be < 0.");
        return Stack.at (Stack.size () + index);
    }

    void inline two_stack::swap (size_t index1, size_t index2) {
        std::swap (Stack.at (index1), Stack.at (index2));
    }

    const integer inline &two_stack::at (uint64_t i) const {
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

    void inline limited_two_stack<true>::push_back (const integer &element) {
        increase_memory_usage (element.size () + ELEMENT_OVERHEAD);
        Stack.push_back (element);
    }

    void inline limited_two_stack<false>::push_back (const integer &element) {
        if (element.size () > MaxScriptElementSize) throw_push_size_exception ();
        if (this->combined_size () == MaxStackElements) throw_stack_overflow_exception ();
        Stack.push_back (element);
    }

    void inline limited_two_stack<false>::pop_back () {
        if (Stack.empty ()) throw std::runtime_error ("popstack(): stack empty");
        Stack.pop_back ();
    }

}

#endif
