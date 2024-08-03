// Copyright (c) 2019 Bitcoin Association
// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_INTERPRETER_STACK
#define GIGAMONKEY_INTERPRETER_STACK

#include <gigamonkey/types.hpp>
#include <sv/script/int_serialization.h>

namespace Gigamonkey::Bitcoin::interpreter {

    class stack_overflow_error : public std::overflow_error {
    public:
        explicit stack_overflow_error (const std::string &str)
            : std::overflow_error (str) {}
    };

    template <typename valtype> class LimitedStack;

    using stack = LimitedStack<integer>;

    struct limited_two_stack {
        // max combined size
        uint64 MaxMemoryUsage;
        // combined size of both stacks.
        uint64 MemoryUsage;
        cross<integer> Stack;
        cross<integer> AltStack;

        limited_two_stack (uint64 max_memory_usage) :
            MaxMemoryUsage {max_memory_usage}, MemoryUsage {0}, Stack {}, AltStack {} {}

        void increase_memory_usage (uint64_t additionalSize);
        void decrease_memory_usage (uint64_t additionalSize);

        // Memory usage of one stack element (without data). This is a consensus rule. Do not change.
        // It prevents someone from creating stack with millions of empty elements.
        static constexpr unsigned int ELEMENT_OVERHEAD = 32;

        // Warning: returned reference is invalidated if stack is modified.
        integer &top (int index = -1);
        integer &alt_top (int index = -1);

        const integer &at (uint64_t i) const;

        size_t size () const {
            return Stack.size ();
        }

        size_t alt_size () const {
            return AltStack.size ();
        }

        size_t combined_size () const {
            return size () + alt_size ();
        }

        bool empty () const {
            return Stack.empty ();
        }

        void pop_back ();
        void push_back (const integer &element);

        template <typename ... P>
        void emplace_back (P ... p) {
            Stack.emplace_back (p...);
            increase_memory_usage (top ().size ());
        }

        bool modify_back (std::function<bool (integer &)> f) {
            auto &val = top (-1);
            size_t before_size = val.size ();
            bool result = f (val);
            size_t after_size = val.size ();
            if (before_size > after_size) decrease_memory_usage (before_size - after_size);
            else increase_memory_usage (after_size - before_size);
            return result;
        }

        void replace_back (const integer &element) {
            modify_back ([&element] (integer &val) -> bool {
                val = element;
                return true;
            });
        }

        // erase elements from including (top - first). element until excluding (top - last). element
        // first and last should be negative numbers (distance from the top)
        void erase (int first, int last);

        // index should be negative number (distance from the top)
        void erase (int index);

        // position should be negative number (distance from the top)
        void insert (int position, const integer &element);

        void swap (size_t index1, size_t index2);

        void to_alt ();
        void from_alt ();

        typename std::vector<integer>::const_iterator begin () const {
            return Stack.begin ();
        }

        typename std::vector<integer>::const_iterator end () const {
            return Stack.end ();
        }

        typename std::vector<integer>::iterator begin () {
            return Stack.begin ();
        }

        typename std::vector<integer>::iterator end () {
            return Stack.end ();
        }

    };

    std::ostream inline &operator << (std::ostream &o, const limited_two_stack &i) {
        return o << "{Stack: " << i.Stack << ", AltStack: " << i.AltStack << "}";
    }

    void inline limited_two_stack::decrease_memory_usage (uint64_t additionalSize) {
        MemoryUsage -= additionalSize;
    }

    void inline limited_two_stack::increase_memory_usage (uint64_t additionalSize) {
        if (MemoryUsage + additionalSize > MaxMemoryUsage) throw stack_overflow_error ("pushstack(): stack oversized");
        MemoryUsage += additionalSize;
    }

    void inline limited_two_stack::push_back (const integer &element) {
        increase_memory_usage (element.size () + ELEMENT_OVERHEAD);
        Stack.push_back (element);
    }

    integer inline &limited_two_stack::top (int index) {
        if (index >= 0) throw std::invalid_argument ("Invalid argument - index should be < 0.");
        return Stack.at (Stack.size () + index);
    }

    integer inline &limited_two_stack::alt_top (int index) {
        if (index >= 0) throw std::invalid_argument ("Invalid argument - index should be < 0.");
        return AltStack.at (AltStack.size () + index);
    }

    void inline limited_two_stack::swap (size_t index1, size_t index2) {
        std::swap (Stack.at (index1), Stack.at (index2));
    }

    void inline limited_two_stack::from_alt () {
        // Moving element to other stack does not change the total size of stack.
        // Just use internal functions to move the element.
        Stack.push_back (std::move (alt_top ()));
        AltStack.pop_back ();
    }

    void inline limited_two_stack::to_alt () {
        // Moving element to other stack does not change the total size of stack.
        // Just use internal functions to move the element.
        AltStack.push_back (std::move (top ()));
        Stack.pop_back ();
    }

}

#endif
