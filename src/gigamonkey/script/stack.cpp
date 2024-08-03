
#include <gigamonkey/script/stack.hpp>

namespace Gigamonkey::Bitcoin::interpreter {

    void limited_two_stack::pop_back () {
        if (Stack.empty ()) throw std::runtime_error ("popstack(): stack empty");

        decrease_memory_usage (top ().size () + ELEMENT_OVERHEAD);
        Stack.pop_back ();
    }

    void limited_two_stack::erase (int first, int last) {
        if (last >= 0 || last <= first)
            throw std::invalid_argument ("Invalid argument - first and last should be negative, also last should be larger than first.");

        for (typename std::vector<integer>::iterator it = Stack.end () + first; it != Stack.end () + last; it++)
            decrease_memory_usage (it->size () + ELEMENT_OVERHEAD);

        Stack.erase (Stack.end () + first, Stack.end () + last);
    }

    void limited_two_stack::erase (int index) {
        if (index >= 0) throw std::invalid_argument ("Invalid argument - index should be < 0.");

        decrease_memory_usage (Stack.at (Stack.size () + index).size () + ELEMENT_OVERHEAD);
        Stack.erase (Stack.end () + index);
    }

    void limited_two_stack::insert (int position, const integer &element) {

        if (position >= 0) throw std::invalid_argument ("Invalid argument - position should be < 0.");

        increase_memory_usage (element.size () + ELEMENT_OVERHEAD);
        Stack.insert (Stack.end () + position, element);
    }
}
