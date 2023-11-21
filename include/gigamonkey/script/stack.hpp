// Copyright (c) 2019 Bitcoin Association
// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_INTERPRETER_STACK
#define GIGAMONKEY_INTERPRETER_STACK

#include <gigamonkey/number.hpp>
#include <sv/script/int_serialization.h>

namespace Gigamonkey::Bitcoin::interpreter {

    class stack_overflow_error : public std::overflow_error {
    public:
        explicit stack_overflow_error (const std::string &str)
            : std::overflow_error (str) {}
    };

    template <typename valtype> class LimitedStack;

    template <typename valtype>
    class LimitedVector
    {
    private:
        valtype stackElement;
        std::reference_wrapper<LimitedStack<valtype>> stack;

        LimitedVector (const valtype& stackElementIn, LimitedStack<valtype>& stackIn);

        // WARNING: modifying returned element will NOT adjust stack size
        valtype& GetElementNonConst ();
    public:

        // Memory usage of one stack element (without data). This is a consensus rule. Do not change.
        // It prevents someone from creating stack with millions of empty elements.
        static constexpr unsigned int ELEMENT_OVERHEAD = 32;

        // Warning: returned reference is invalidated if parent stack is modified.
        const valtype &GetElement () const;
        uint8_t &front ();
        uint8_t &back ();
        const uint8_t &front () const;
        const uint8_t &back () const;
        uint8_t& operator [] (uint64_t pos);
        const uint8_t &operator [] (uint64_t pos) const;

        size_t size () const;
        bool empty () const;

        void push_back (uint8_t element);
        void append (const LimitedVector &second);
        void padRight (size_t size, uint8_t signbit);

        typename valtype::iterator begin ();
        typename valtype::iterator end ();

        const typename valtype::const_iterator begin () const;
        const typename valtype::const_iterator end () const;

        bool MinimallyEncode ();
        bool IsMinimallyEncoded (uint64_t maxSize) const;

        const LimitedStack<valtype> &getStack () const;

        friend class LimitedStack<valtype>;
    };
    
    template <typename valtype> 
    class LimitedStack
    {
    private:
        uint64_t combinedStackSize = 0;
        uint64_t maxStackSize = 0;
        std::vector<LimitedVector<valtype>> stack;
        LimitedStack* parentStack { nullptr };
        void decreaseCombinedStackSize (uint64_t additionalSize);
        void increaseCombinedStackSize (uint64_t additionalSize);

        LimitedStack (const LimitedStack &) = default;
        LimitedStack () = default;

    public:
        LimitedStack (uint64_t maxStackSizeIn);
        LimitedStack (const std::vector<valtype>& stackElements, uint64_t maxStackSizeIn);

        LimitedStack (LimitedStack &&) = default;
        LimitedStack &operator = (LimitedStack &&) = default;
        LimitedStack &operator = (const LimitedStack &) = delete;

        // Compares the stacks but ignores the parent.
        bool operator == (const LimitedStack& other) const;

        // Warning: returned reference is invalidated if stack is modified.
        LimitedVector<valtype> &stacktop (int index);

        const LimitedVector<valtype> &front () const;
        const LimitedVector<valtype> &back () const;
        const LimitedVector<valtype> &at (uint64_t i) const;

        uint64_t getCombinedStackSize () const;
        size_t size () const;
        bool empty () const;

        void pop_back ();
        void push_back (const LimitedVector<valtype> &element);
        void push_back (const valtype &element);

        // erase elements from including (top - first). element until excluding (top - last). element
        // first and last should be negative numbers (distance from the top)
        void erase (int first, int last);

        // index should be negative number (distance from the top)
        void erase (int index);

        // position should be negative number (distance from the top)
        void insert (int position, const LimitedVector<valtype> &element);

        void swapElements (size_t index1, size_t index2);

        void moveTopToStack (LimitedStack& otherStack);

        void MoveToValtypes (std::vector<valtype> &script);

        LimitedStack makeChildStack ();

        // parent must be null
        LimitedStack makeRootStackCopy ();

        const LimitedStack* getParentStack () const;

        friend class LimitedVector<valtype>;
        
        typename std::vector<LimitedVector<valtype>>::const_iterator begin () const {
            return stack.begin ();
        }
        
        typename std::vector<LimitedVector<valtype>>::const_iterator end () const {
            return stack.end ();
        }
    };
    
    template <typename valtype> std::ostream &operator << (std::ostream &o, const LimitedStack<valtype> &stack) {
        o << "{";

        if (stack.size () > 0) {
            auto i = stack.begin ();
            auto e = stack.end ();
            while (true) {
                o << i->GetElement ();
                i++;
                if (i == e) break;
                o << ", ";
            }
        }

        return o << "}";
    }
    
    template <typename valtype>
    LimitedVector<valtype>::LimitedVector (const valtype &stackElementIn, LimitedStack<valtype> &stackIn) :
        stackElement (stackElementIn), stack (stackIn) {}
    
    template <typename valtype>
    const valtype& LimitedVector<valtype>::GetElement () const {
        return stackElement;
    }
    
    template <typename valtype>
    valtype& LimitedVector<valtype>::GetElementNonConst () {
        return stackElement;
    }
    
    template <typename valtype>
    size_t LimitedVector<valtype>::size () const {
        return stackElement.size ();
    }
    
    template <typename valtype>
    bool LimitedVector<valtype>::empty () const {
        return stackElement.empty ();
    }
    
    template <typename valtype>
    uint8_t& LimitedVector<valtype>::operator [] (uint64_t pos) {
        return stackElement[pos];
    }
    
    template <typename valtype>
    const uint8_t &LimitedVector<valtype>::operator [] (uint64_t pos) const {
        return stackElement[pos];
    }
    
    template <typename valtype>
    void LimitedVector<valtype>::push_back (uint8_t element)
    {
        stack.get ().increaseCombinedStackSize (1);
        stackElement.push_back (element);
    }
    
    template <typename valtype>
    void LimitedVector<valtype>::append (const LimitedVector &second) {
        stack.get ().increaseCombinedStackSize (second.size ());
        stackElement.insert (stackElement.end (), second.begin (), second.end ());
    }
    
    template <typename valtype>
    void LimitedVector<valtype>::padRight (size_t size, uint8_t signbit) {
        if (size > stackElement.size ()) {
            size_t sizeDifference = size - stackElement.size ();

            stack.get ().increaseCombinedStackSize (sizeDifference);

            static_cast<bytes> (stackElement).resize (size, 0x00);
            stackElement.back () = signbit;
        }
    }
    
    template <typename valtype>
    typename valtype::iterator LimitedVector<valtype>::begin () {
        return stackElement.begin ();
    }
    
    template <typename valtype>
    typename valtype::iterator LimitedVector<valtype>::end () {
        return stackElement.end ();
    }
    
    template <typename valtype>
    const typename valtype::const_iterator LimitedVector<valtype>::begin () const {
        return stackElement.begin ();
    }
    
    template <typename valtype>
    const typename valtype::const_iterator LimitedVector<valtype>::end () const {
        return stackElement.end ();
    }
    
    template <typename valtype>
    uint8_t &LimitedVector<valtype>::front () {
        return stackElement.front ();
    }
    
    template <typename valtype>
    uint8_t &LimitedVector<valtype>::back () {
        return stackElement.back ();
    }
    
    template <typename valtype>
    const uint8_t &LimitedVector<valtype>::front () const {
        return stackElement.front();
    }
    
    template <typename valtype>
    const uint8_t &LimitedVector<valtype>::back () const {
        return stackElement.back ();
    }
    
    template <typename valtype>
    bool LimitedVector<valtype>::MinimallyEncode () {
        stack.get ().decreaseCombinedStackSize (stackElement.size ());
        bool successfulEncoding = bsv::MinimallyEncode (stackElement);
        stack.get ().increaseCombinedStackSize (stackElement.size ());

        return successfulEncoding;
    }
    
    template <typename valtype>
    bool LimitedVector<valtype>::IsMinimallyEncoded (uint64_t maxSize) const {
        return bsv::IsMinimallyEncoded (stackElement, maxSize);
    }
    
    template <typename valtype>
    const LimitedStack<valtype> &LimitedVector<valtype>::getStack () const {
        return stack.get ();
    }
    
    template <typename valtype>
    LimitedStack<valtype>::LimitedStack (uint64_t maxStackSizeIn) {
        maxStackSize = maxStackSizeIn;
        parentStack = nullptr;
    }
    
    template <typename valtype>
    LimitedStack<valtype>::LimitedStack(const std::vector<valtype> &stackElements, uint64_t maxStackSizeIn) {
        maxStackSize = maxStackSizeIn;
        parentStack = nullptr;
        for (const auto &element : stackElements)
            push_back (element);
    }
    
    template <typename valtype>
    bool LimitedStack<valtype>::operator == (const LimitedStack<valtype> &other) const {
        if (stack.size () != other.size ())
            return false;

        for (size_t i = 0; i < stack.size (); i++)
            if (stack.at (i).GetElement () != other.at (i).GetElement ())
                return false;

        return true;
    }
    
    template <typename valtype>
    void LimitedStack<valtype>::decreaseCombinedStackSize (uint64_t additionalSize) {
        if (parentStack != nullptr)
            parentStack->decreaseCombinedStackSize(additionalSize);
        else combinedStackSize -= additionalSize;
    }
    
    template <typename valtype>
    void LimitedStack<valtype>::increaseCombinedStackSize (uint64_t additionalSize) {
        if (parentStack != nullptr)
            parentStack->increaseCombinedStackSize (additionalSize);
        else {
            if (getCombinedStackSize () + additionalSize > maxStackSize)
                throw stack_overflow_error ("pushstack(): stack oversized");

            combinedStackSize += additionalSize;
        }
    }
    
    template <typename valtype>
    void LimitedStack<valtype>::pop_back () {
        if (stack.empty ())
            throw std::runtime_error ("popstack(): stack empty");

        decreaseCombinedStackSize (stacktop (-1).size () + LimitedVector<valtype>::ELEMENT_OVERHEAD);
        stack.pop_back ();
    }
    
    template <typename valtype>
    void LimitedStack<valtype>::push_back(const LimitedVector<valtype> &element) {
        if (&element.getStack () != this)
            throw std::invalid_argument
                ("Invalid argument - element that is added should have the same parent stack as the one we are adding to.");

        increaseCombinedStackSize (element.size () + LimitedVector<valtype>::ELEMENT_OVERHEAD);
        stack.push_back (element);
    }
    
    template <typename valtype>
    void LimitedStack<valtype>::push_back (const valtype &element) {
        increaseCombinedStackSize (element.size () + LimitedVector<valtype>::ELEMENT_OVERHEAD);
        stack.push_back (LimitedVector {element, *this});
    }
    
    template <typename valtype>
    LimitedVector<valtype> &LimitedStack<valtype>::stacktop (int index) {
        if (index >= 0)
            throw std::invalid_argument ("Invalid argument - index should be < 0.");

        return stack.at (stack.size () + (index));
    }
    
    template <typename valtype>
    uint64_t LimitedStack<valtype>::getCombinedStackSize () const {
        if (parentStack != nullptr)
            return parentStack->getCombinedStackSize ();

        return combinedStackSize;
    }

    template <typename valtype>
    void LimitedStack<valtype>::erase (int first, int last) {
        if (last >= 0 || last <= first)
            throw std::invalid_argument ("Invalid argument - first and last should be negative, also last should be larger than first.");

        for (typename std::vector<LimitedVector<valtype>>::iterator it = stack.end () + first; it != stack.end () + last; it++)
            decreaseCombinedStackSize (it->size () + LimitedVector<valtype>::ELEMENT_OVERHEAD);

        stack.erase (stack.end () + first, stack.end () + last);
    }

    template <typename valtype>
    void LimitedStack<valtype>::erase (int index) {
        if (index >= 0) throw std::invalid_argument ("Invalid argument - index should be < 0.");

        decreaseCombinedStackSize (stack.at (stack.size () + index).size () + LimitedVector<valtype>::ELEMENT_OVERHEAD);
        stack.erase (stack.end () + index);
    }

    template <typename valtype>
    void LimitedStack<valtype>::insert (int position, const LimitedVector<valtype> &element) {
        if (&element.getStack () != this)
            throw std::invalid_argument
                ("Invalid argument - element that is added should have the same parent stack as the one we are adding to.");

        if (position >= 0) throw std::invalid_argument ("Invalid argument - position should be < 0.");

        increaseCombinedStackSize (element.size () + LimitedVector<valtype>::ELEMENT_OVERHEAD);
        stack.insert (stack.end () + position, element);
    }
    
    template <typename valtype>
    void LimitedStack<valtype>::swapElements (size_t index1, size_t index2) {
        std::swap (stack.at (index1), stack.at (index2));
    }

    // this method does not change combinedSize
    // it is allowed only for relations parent-child
    template <typename valtype>
    void LimitedStack<valtype>::moveTopToStack (LimitedStack& otherStack) {
        if (parentStack == &otherStack || otherStack.getParentStack() == this) {
            // Moving element to other stack does not change the total size of stack.
            // Just use internal functions to move the element.
            stack.push_back (std::move (otherStack.stacktop (-1)));
            otherStack.stack.pop_back ();
        } else throw std::runtime_error ("Method moveTopToStack is allowed only for relations parent-child.");
    }
    
    template <typename valtype>
    size_t LimitedStack<valtype>::size () const {
        return stack.size ();
    }
    
    template <typename valtype>
    const LimitedVector<valtype> &LimitedStack<valtype>::front () const {
        return stack.front ();
    }
    
    template <typename valtype>
    const LimitedVector<valtype> &LimitedStack<valtype>::back () const {
        return stack.back ();
    }
    
    template <typename valtype>
    const LimitedVector<valtype> &LimitedStack<valtype>::at (uint64_t i) const {
        return stack.at (i);
    }
    
    template <typename valtype>
    bool LimitedStack<valtype>::empty () const {
        return stack.empty ();
    }
    
    template <typename valtype>
    void  LimitedStack<valtype>::MoveToValtypes (std::vector<valtype> &valtypes) {
        for (LimitedVector<valtype> &it : stack) {
            decreaseCombinedStackSize (it.size () + LimitedVector<valtype>::ELEMENT_OVERHEAD);
            valtypes.push_back (std::move (it.GetElementNonConst ()));
        }

        stack.clear ();
    }
    
    template <typename valtype>
    LimitedStack<valtype> LimitedStack<valtype>::makeChildStack () {
        LimitedStack stack;
        stack.parentStack = this;

        return stack;
    }
    
    template <typename valtype>
    LimitedStack<valtype> LimitedStack<valtype>::makeRootStackCopy () {
        if (parentStack != nullptr)
            throw std::runtime_error
                ("Parent stack must be null if you are creating stack copy.");

        return *this;
    }
    
    template <typename valtype>
    const LimitedStack<valtype> *LimitedStack<valtype>::getParentStack () const {
        return parentStack;
    }

}

#endif
