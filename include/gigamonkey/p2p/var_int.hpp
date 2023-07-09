// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_VAR_INT
#define GIGAMONKEY_P2P_VAR_INT

#include <gigamonkey/types.hpp>

// types that are used for reading and writing serialized formats. 
namespace Gigamonkey::Bitcoin {
    
    struct var_int;
    
    writer &operator << (writer &w, const var_int &x);
    reader &operator >> (reader &r, var_int &x);
    
    struct var_string;
    
    writer &operator << (writer &w, const var_string &x);
    reader &operator >> (reader &r, var_string x);
    
    template <typename X> struct var_sequence;
    
    template <typename X> writer inline &operator << (writer &w, const var_sequence<X> &x);
    template <typename X> reader inline &operator >> (reader &r, var_sequence<X> &x);
    
    struct var_int {
        uint64 Value;
        
        static size_t size (uint64 x) {
            return x <= 0xfc ? 1 : x <= 0xffff ? 3 : x <= 0xffffffff ? 5 : 9;
        }
        
        static uint64 read (reader &r);
        
        static writer &write (writer &w, uint64 x);
        
        operator uint64 const () {
            return Value;
        }
        
    };
    
    writer inline &operator << (writer &w, const var_int &x) {
        return var_int::write(w, x.Value);
    }
    
    reader inline &operator >> (reader &r, var_int &x) {
        x.Value = var_int::read (r);
        return r;
    }
    
    struct var_string {
        bytes &String;
        
        var_string (const bytes &b) : String {const_cast<bytes&> (b)} {};
        var_string (bytes &b) : String {b} {};
        
        static reader &read (reader &r, bytes &b);
        
        static writer inline &write (writer &w, const bytes& b) {
            return w << var_int {b.size ()} << b;
        }
    
    };
    
    writer inline &operator << (writer &w, const var_string &x) {
        return var_string::write (w, x.String);
    }
    
    reader inline &operator >> (reader &r, var_string x) {
        return var_string::read (r, x.String);
    }
    
    template <typename X>
    struct var_sequence {
        list<X> &List;
        
        var_sequence (const list<X> &b) : List {const_cast<list<X> &> (b)} {};
        var_sequence (list<X> &b) : List {b} {};
        
        static reader &read (reader &r, list<X> &l) {
            l = {};
            var_int size;
            r >> size;

            for (int i = 0; i < size; i++) {
                X x;
                r >> x;
                l = l << x;
            }

            return r;
        }
        
        static writer &write (writer &w, list<X> l) {
            w << var_int {data::size (l)};
            for (const X &x: l) w << x;
            return w;
        }
    
    };
    
    template <typename X>
    writer inline &operator << (writer &w, const var_sequence<X> &x) {
        return var_sequence<X>::write (w, x.List);
    }
    
    template <typename X>
    reader inline &operator >> (reader &r, var_sequence<X> x) {
        return var_sequence<X>::read (r, x.List);
    }
    
}

#endif 
