// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BSV_SUPPORT_ALLOCATORS_SECURE_H
#define BSV_SUPPORT_ALLOCATORS_SECURE_H

#include <sv/support/cleanse.h>
#include <sv/support/lockedpool.h>

#include <string>

namespace bsv {

//
// Allocator that locks its contents from being paged
// out of memory and clears its contents before deletion.
//
template <typename T> struct secure_allocator : public std::allocator<T> {
    // MSVC8 default copy constructor is broken
    typedef std::allocator<T> base;
    typedef typename base::size_type size_type;
    typedef typename base::difference_type difference_type;
    typedef T* pointer;
    typedef const T* const_pointer;
    typedef T& reference;
    typedef const T& const_reference;
    typedef typename base::value_type value_type;
    secure_allocator() throw() {}
    secure_allocator(const secure_allocator &a) throw() : base(a) {}
    template <typename U>
    secure_allocator(const secure_allocator<U> &a) throw() : base(a) {}
    ~secure_allocator() throw() {}
    template <typename _Other> struct rebind {
        typedef secure_allocator<_Other> other;
    };

    T *allocate(std::size_t n, const void *hint = 0) {
        return static_cast<T *>(
            LockedPoolManager::Instance().alloc(sizeof(T) * n));
    }

    void deallocate(T *p, std::size_t n) {
        if (p != nullptr) {
            memory_cleanse(p, sizeof(T) * n);
        }
        LockedPoolManager::Instance().free(p);
    }
};

// This is exactly like std::string, but with a custom allocator.
typedef std::basic_string<char, std::char_traits<char>, secure_allocator<char>>
    SecureString;
    
}

#endif // BSV_SUPPORT_ALLOCATORS_SECURE_H

