
#include <gigamonkey/script/stack.hpp>

namespace Gigamonkey::Bitcoin {

    void limited_two_stack<false>::modify_top (std::function<void (bytes &)> f, int index) {
        if (index >= 0)
            throw std::invalid_argument ("Invalid argument - index should be < 0.");

        auto &val = MainStack.at (MainStack.size () + index);
        size_t before_size = val.size ();
        f (val);
        size_t after_size = val.size ();
        if (after_size > MaxScriptElementSize)
            throw invalid_program {Error::PUSH_SIZE};
    }

    void limited_two_stack<true>::modify_top (std::function<void (bytes &)> f, int index) {
        if (index >= 0)
            throw std::invalid_argument ("Invalid argument - index should be < 0.");

        auto &val = MainStack.at (MainStack.size () + index);
        size_t before_size = val.size ();
        f (val);
        size_t after_size = val.size ();
        if (before_size < after_size) increase_memory_usage (after_size - before_size);
        else decrease_memory_usage (before_size - after_size);
    }

    void limited_two_stack<true>::pop_down () {
        if (MainStack.empty ())
            throw std::runtime_error ("popstack(): stack empty");

        decrease_memory_usage (top ().size () + ELEMENT_OVERHEAD);
        MainStack.pop_back ();
    }

    void limited_two_stack<true>::erase (int first, int last) {
        if (last >= 0 || last <= first)
            throw std::invalid_argument ("Invalid argument - first and last should be negative, also last should be larger than first.");

        for (typename std::vector<integer>::iterator it = MainStack.end () + first; it != MainStack.end () + last; it++)
            decrease_memory_usage (it->size () + ELEMENT_OVERHEAD);

        MainStack.erase (MainStack.end () + first, MainStack.end () + last);
    }

    void limited_two_stack<false>::erase (int first, int last) {
        if (last >= 0 || last <= first)
            throw std::invalid_argument ("Invalid argument - first and last should be negative, also last should be larger than first.");

        MainStack.erase (MainStack.end () + first, MainStack.end () + last);
    }

    void limited_two_stack<true>::erase (int index) {
        if (index >= 0) throw std::invalid_argument ("Invalid argument - index should be < 0.");

        decrease_memory_usage (MainStack.at (MainStack.size () + index).size () + ELEMENT_OVERHEAD);
        MainStack.erase (MainStack.end () + index);
    }

    void limited_two_stack<false>::erase (int index) {
        if (index >= 0) throw std::invalid_argument ("Invalid argument - index should be < 0.");
        MainStack.erase (MainStack.end () + index);
    }

    void limited_two_stack<true>::insert (int position, byte_slice element) {

        if (position >= 0) throw std::invalid_argument ("Invalid argument - position should be < 0.");

        increase_memory_usage (element.size () + ELEMENT_OVERHEAD);
        MainStack.insert (MainStack.end () + position, integer {element});
    }

    void limited_two_stack<false>::insert (int position, byte_slice element) {
        if (position >= 0) throw std::invalid_argument ("Invalid argument - position should be < 0.");

        if (element.size () > MaxScriptElementSize || this->size () == MaxStackElements)
            throw invalid_program {Error::STACK_SIZE};

        MainStack.insert (MainStack.end () + position, integer {element});
    }

    Error swap (two_stack &stacks) {
        if (stacks.size_down () < 2) return Error::INVALID_STACK_OPERATION;
        stacks.swap (stacks.size_down () - 2, stacks.size_down () - 1);

        return Error::OK;
    }

    Error swap_two (two_stack &stacks) {
        if (stacks.size_down () < 4) return Error::INVALID_STACK_OPERATION;

        stacks.swap (stacks.size_down () - 4, stacks.size_down () - 2);
        stacks.swap (stacks.size_down () - 3, stacks.size_down () - 1);

        return Error::OK;
    }

    Error duplicate (two_stack &stacks) {
        if (stacks.size_down () < 1)
            return Error::INVALID_STACK_OPERATION;

        auto vch = stacks.top ();
        stacks.push_down (vch);

        return Error::OK;
    }

    Error duplicate_two (two_stack &stacks) {
        if (stacks.size_down () < 2)
            return Error::INVALID_STACK_OPERATION;

        auto vch1 = stacks.top (-2);
        auto vch2 = stacks.top ();

        stacks.push_down (vch1);
        stacks.push_down (vch2);

        return Error::OK;
    }

    Error duplicate_three (two_stack &stacks) {
        if (stacks.size_down () < 3) return Error::INVALID_STACK_OPERATION;

        auto vch1 = stacks.top (-3);
        auto vch2 = stacks.top (-2);
        auto vch3 = stacks.top ();

        stacks.push_down (vch1);
        stacks.push_down (vch2);
        stacks.push_down (vch3);

        return Error::OK;
    }

    Error drop (two_stack &stacks) {
        if (stacks.size_down () < 1)
            return Error::INVALID_STACK_OPERATION;

        stacks.pop_down ();

        return Error::OK;
    }

    Error drop_two (two_stack &stacks) {
        if (stacks.size_down () < 2) return Error::INVALID_STACK_OPERATION;

        stacks.pop_down ();
        stacks.pop_down ();

        return Error::OK;
    }

    Error over (two_stack &stacks) {
        if (stacks.size_down () < 2) return Error::INVALID_STACK_OPERATION;
        auto vch = stacks.top (-2);
        stacks.push_down (vch);

        return Error::OK;
    }

    Error over_two (two_stack &stacks) {
        if (stacks.size_down () < 4)
            return Error::INVALID_STACK_OPERATION;

        auto vch1 = stacks.top (-4);
        auto vch2 = stacks.top (-3);
        stacks.push_down (vch1);
        stacks.push_down (vch2);

        return Error::OK;
    }

    Error rotate (two_stack &stacks) {
        if (stacks.size_down () < 3)
            return Error::INVALID_STACK_OPERATION;

        stacks.swap (stacks.size_down () - 3, stacks.size_down () - 2);
        stacks.swap (stacks.size_down () - 2, stacks.size_down () - 1);

        return Error::OK;
    }

    Error rotate_two (two_stack &stacks) {
        if (stacks.size_down () < 6) return Error::INVALID_STACK_OPERATION;

        auto vch1 = stacks.top (-6);
        auto vch2 = stacks.top (-5);

        stacks.erase (-6, -4);
        stacks.push_down (vch1);
        stacks.push_down (vch2);

        return Error::OK;
    }

    Error nip (two_stack &stacks) {
        if (stacks.size_down () < 2)
            return Error::INVALID_STACK_OPERATION;

        stacks.erase (-2);
        return Error::OK;
    }

    Error tuck (two_stack &stacks) {
        if (stacks.size_down () < 2)
            return Error::INVALID_STACK_OPERATION;

        auto vch = stacks.top ();
        stacks.insert (-2, vch);
        return Error::OK;
    }

    Error depth (two_stack &stacks) {
        stacks.push_down (integer {stacks.size_down ()});
        return Error::OK;
    }

    Error top_size (two_stack &stacks) {
        if (stacks.size_down () < 1)
            return Error::INVALID_STACK_OPERATION;

        stacks.push_down (integer {stacks.top ().size ()});

        return Error::OK;
    }

    Error if_dup (two_stack &stacks) {
        if (stacks.size_down () < 1)
            return Error::INVALID_STACK_OPERATION;

        auto vch = stacks.top ();

        if (nonzero (vch)) stacks.push_down (vch);

        return Error::OK;
    }
}
