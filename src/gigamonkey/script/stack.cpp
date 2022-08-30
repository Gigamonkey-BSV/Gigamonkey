// Copyright (c) 2019 Bitcoin Association
// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/machine.hpp>

namespace Gigamonkey::Bitcoin {
    
    machine::LimitedVector::LimitedVector(const machine::element& stackElementIn, machine::LimitedStack& stackIn) : 
        stackElement(stackElementIn), stack(stackIn) {}
    
    const machine::element& machine::LimitedVector::GetElement() const {
        return stackElement;
    }
    
    machine::element& machine::LimitedVector::GetElementNonConst() {
        return stackElement;
    }
    
    size_t machine::LimitedVector::size() const {
        return stackElement.size();
    }
    
    bool machine::LimitedVector::empty() const {
        return stackElement.empty();
    }
    
    uint8_t& machine::LimitedVector::operator[](uint64_t pos) {
        return stackElement[pos];
    }
    
    const uint8_t& machine::LimitedVector::operator[](uint64_t pos) const {
        return stackElement[pos];
    }
    
    void machine::LimitedVector::push_back(uint8_t element) {
        stack.get().increaseCombinedStackSize(1);
        stackElement.push_back(element);
    }
    
    void machine::LimitedVector::append(const LimitedVector& second) {
        stack.get().increaseCombinedStackSize(second.size());
        stackElement.insert(stackElement.end(), second.begin(), second.end());
    }
    
    void machine::LimitedVector::padRight(size_t size, uint8_t signbit) {
        if (size > stackElement.size())
        {
            size_t sizeDifference = size - stackElement.size();

            stack.get().increaseCombinedStackSize(sizeDifference);

            stackElement.resize(size, 0x00);
            stackElement.back() = signbit;
        }
    }
    
    typename machine::element::iterator machine::LimitedVector::begin() {
        return stackElement.begin();
    }
    
    typename machine::element::iterator machine::LimitedVector::end() {
        return stackElement.end();
    }
    
    const typename machine::element::const_iterator machine::LimitedVector::begin() const {
        return stackElement.begin();
    }
    
    const typename machine::element::const_iterator machine::LimitedVector::end() const {
        return stackElement.end();
    }
    
    uint8_t& machine::LimitedVector::front() {
        return stackElement.front();
    }
    
    uint8_t& machine::LimitedVector::back() {
        return stackElement.back();
    }
    
    const uint8_t& machine::LimitedVector::front() const {
        return stackElement.front();
    }
    
    const uint8_t& machine::LimitedVector::back() const {
        return stackElement.back();
    }
    
    bool machine::LimitedVector::MinimallyEncode() {
        stack.get().decreaseCombinedStackSize(stackElement.size());
        bool successfulEncoding = bsv::MinimallyEncode(stackElement);
        stack.get().increaseCombinedStackSize(stackElement.size());

        return successfulEncoding;
    }
    
    bool machine::LimitedVector::IsMinimallyEncoded(uint64_t maxSize) const {
        return bsv::IsMinimallyEncoded(stackElement, maxSize);
    }
    
    const machine::LimitedStack& machine::LimitedVector::getStack() const {
        return stack.get();
    }
    
    machine::LimitedStack::LimitedStack(uint64_t maxStackSizeIn, const std::vector<machine::element>& stackElements) {
        maxStackSize = maxStackSizeIn;
        parentStack = nullptr;
        for (const auto& element : stackElements) push_back(element);
    }
    
    bool machine::LimitedStack::operator==(const LimitedStack& other) const {
        if (stack.size() != other.size()) return false;

        for (size_t i = 0; i < stack.size(); i++) if (stack.at(i).GetElement() != other.at(i).GetElement()) return false;

        return true;
    }
    
    void machine::LimitedStack::decreaseCombinedStackSize(uint64_t additionalSize) {
        if (parentStack != nullptr) parentStack->decreaseCombinedStackSize(additionalSize);
        else combinedStackSize -= additionalSize;
    }
    
    ScriptError machine::LimitedStack::increaseCombinedStackSize(uint64_t additionalSize) {
        if (parentStack != nullptr) return parentStack->increaseCombinedStackSize(additionalSize);
        if (getCombinedStackSize() + additionalSize > maxStackSize) return SCRIPT_ERR_STACK_SIZE;

        combinedStackSize += additionalSize;
        
        return SCRIPT_ERR_OK;
    }
    
    void machine::LimitedStack::pop_back() {
        if (stack.empty()) throw std::runtime_error("popstack(): stack empty");
        decreaseCombinedStackSize(stacktop(-1).size() + machine::LimitedVector::ELEMENT_OVERHEAD);
        stack.pop_back();
    }
    
    ScriptError machine::LimitedStack::push_back(const machine::LimitedVector &element) {
        if (&element.getStack() != this) 
            throw std::invalid_argument("Invalid argument - element that is added should have the same parent stack as the one we are adding to.");
        auto err = increaseCombinedStackSize(element.size() + LimitedVector::ELEMENT_OVERHEAD);
        if (err != SCRIPT_ERR_OK) return err;
        stack.push_back(element);
        return SCRIPT_ERR_OK;
    }
    
    ScriptError machine::LimitedStack::push_back(const machine::element& element) {
        auto err = increaseCombinedStackSize(element.size() + LimitedVector::ELEMENT_OVERHEAD);
        if (err != SCRIPT_ERR_OK) return err;
        stack.push_back(LimitedVector{element, *this});
        return SCRIPT_ERR_OK;
    }
    
    machine::LimitedVector& machine::LimitedStack::stacktop(int index) {
        if (index >= 0) throw std::invalid_argument("Invalid argument - index should be < 0.");
        return stack.at(stack.size() + (index));
    }
    
    uint64_t machine::LimitedStack::getCombinedStackSize() const {
        if (parentStack != nullptr) return parentStack->getCombinedStackSize();

        return combinedStackSize;
    }
    
    void machine::LimitedStack::erase(int first, int last) {
        if (last >= 0 || last <= first) 
            throw std::invalid_argument("Invalid argument - first and last should be negative, also last should be larger than first.");
        for (typename std::vector<LimitedVector>::iterator it = stack.end() + first; it != stack.end() + last; it++)
            decreaseCombinedStackSize(it->size() + LimitedVector::ELEMENT_OVERHEAD);

        stack.erase(stack.end() + first, stack.end() + last);
    }
    
    void machine::LimitedStack::erase(int index) {
        if (index >= 0) throw std::invalid_argument("Invalid argument - index should be < 0.");
        decreaseCombinedStackSize(stack.at(stack.size() + index).size() + LimitedVector::ELEMENT_OVERHEAD);
        stack.erase(stack.end() + index); 
    }
    
    void machine::LimitedStack::insert(int position, const LimitedVector& element) {
        if (&element.getStack() != this)
            throw std::invalid_argument("Invalid argument - element that is added should have the same parent stack as the one we are adding to.");

        if (position >= 0)
            throw std::invalid_argument("Invalid argument - position should be < 0.");
        
        increaseCombinedStackSize(element.size() + LimitedVector::ELEMENT_OVERHEAD);
        stack.insert(stack.end() + position, element);
    }
    
    void machine::LimitedStack::swapElements(size_t index1, size_t index2) {
        std::swap(stack.at(index1), stack.at(index2));
    }
    
    // this method does not change combinedSize
    // it is allowed only for relations parent-child
    void machine::LimitedStack::moveTopToStack(machine::LimitedStack& otherStack) {
        if (parentStack == &otherStack || otherStack.getParentStack() == this)
        {
            // Moving element to other stack does not change the total size of stack.
            // Just use internal functions to move the element.
            stack.push_back(std::move(otherStack.stacktop(-1)));
            otherStack.stack.pop_back();
        }
        else throw std::runtime_error("Method moveTopToStack is allowed only for relations parent-child.");
    }
    
    size_t machine::LimitedStack::size() const {
        return stack.size();
    }
    
    const machine::LimitedVector& machine::LimitedStack::front() const {
        return stack.front();
    }
    
    const machine::LimitedVector& machine::LimitedStack::back() const {
        return stack.back();
    }
    
    const machine::LimitedVector& machine::LimitedStack::at(uint64_t i) const {
        return stack.at(i);
    }
    
    bool machine::LimitedStack::empty() const {
        return stack.empty();
    }
    
    void machine::LimitedStack::MoveToValtypes(std::vector<machine::element>& valtypes) {
        for (LimitedVector& it : stack)
        {
            decreaseCombinedStackSize(it.size() + LimitedVector::ELEMENT_OVERHEAD);
            valtypes.push_back(std::move(it.GetElementNonConst()));
        }

        stack.clear();
    }
    
    machine::LimitedStack machine::LimitedStack::makeChildStack(const std::vector<element>& stackElements) {
        LimitedStack stack{};
        stack.parentStack = this;
        for (const auto& element : stackElements) stack.push_back(element);
        return stack;
    }
    
    machine::LimitedStack machine::LimitedStack::makeRootStackCopy() {
        if (parentStack != nullptr)
        {
            throw std::runtime_error("Parent stack must be null if you are creating stack copy.");
        }

        return *this;
    }
    
    const machine::LimitedStack *machine::LimitedStack::getParentStack() const {
        return parentStack;
    }

}

