
#include <gigamonkey/script/stack.hpp>

namespace Gigamonkey::Bitcoin::interpreter {

    void limited_two_stack<false>::modify_back (std::function<void (integer &)> f) {
        auto &val = Stack.at (Stack.size () - 1);
        size_t before_size = val.size ();
        f (val);
        size_t after_size = val.size ();
        if (after_size > MaxScriptElementSize) throw_push_size_exception ();
    }

    void limited_two_stack<true>::modify_back (std::function<void (integer &)> f) {
        auto &val = Stack.at (Stack.size () - 1);
        size_t before_size = val.size ();
        f (val);
        size_t after_size = val.size ();
        if (before_size > after_size) decrease_memory_usage (before_size - after_size);
        else increase_memory_usage (after_size - before_size);
    }

    void limited_two_stack<true>::pop_back () {
        if (Stack.empty ()) throw std::runtime_error ("popstack(): stack empty");

        decrease_memory_usage (top ().size () + ELEMENT_OVERHEAD);
        Stack.pop_back ();
    }

    void limited_two_stack<true>::erase (int first, int last) {
        if (last >= 0 || last <= first)
            throw std::invalid_argument ("Invalid argument - first and last should be negative, also last should be larger than first.");

        for (typename std::vector<integer>::iterator it = Stack.end () + first; it != Stack.end () + last; it++)
            decrease_memory_usage (it->size () + ELEMENT_OVERHEAD);

        Stack.erase (Stack.end () + first, Stack.end () + last);
    }

    void limited_two_stack<false>::erase (int first, int last) {
        if (last >= 0 || last <= first)
            throw std::invalid_argument ("Invalid argument - first and last should be negative, also last should be larger than first.");

        Stack.erase (Stack.end () + first, Stack.end () + last);
    }

    void limited_two_stack<true>::erase (int index) {
        if (index >= 0) throw std::invalid_argument ("Invalid argument - index should be < 0.");

        decrease_memory_usage (Stack.at (Stack.size () + index).size () + ELEMENT_OVERHEAD);
        Stack.erase (Stack.end () + index);
    }

    void limited_two_stack<false>::erase (int index) {
        if (index >= 0) throw std::invalid_argument ("Invalid argument - index should be < 0.");
        Stack.erase (Stack.end () + index);
    }

    void limited_two_stack<true>::insert (int position, const integer &element) {

        if (position >= 0) throw std::invalid_argument ("Invalid argument - position should be < 0.");

        increase_memory_usage (element.size () + ELEMENT_OVERHEAD);
        Stack.insert (Stack.end () + position, element);
    }

    void limited_two_stack<false>::insert (int position, const integer &element) {
        if (position >= 0) throw std::invalid_argument ("Invalid argument - position should be < 0.");

        if (element.size () > MaxScriptElementSize || this->combined_size () == MaxStackElements)
            throw_stack_overflow_exception ();

        Stack.insert (Stack.end () + position, element);
    }
}
