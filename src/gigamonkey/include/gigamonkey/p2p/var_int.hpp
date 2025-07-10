// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_VAR_INT
#define GIGAMONKEY_P2P_VAR_INT

#include <gigamonkey/types.hpp>

// types that are used for reading and writing serialized formats. 
namespace Gigamonkey::Bitcoin {
    
    // var_int is a way of representing a uint64 that
    // takes up fewer bytes for smaller numbers.
    struct var_int;
    
    writer &operator << (writer &w, const var_int &x);
    reader &operator >> (reader &r, var_int &x);
    
    // var_string is an arbitrary size string that is prefixed by a var_int
    // so that you know how long it is.
    struct var_string;
    
    writer &operator << (writer &w, const var_string &x);
    reader &operator >> (reader &r, var_string x);
    
    // var_sequence is a sequence of whatever prefixed by a var_int.
    template <typename X> struct var_sequence;
    
    template <typename X> requires requires (writer &w, const X &x) {
        { w << x } -> data::Same<writer &>;
    } writer &operator << (writer &w, const var_sequence<X> x);

    template <typename X> requires requires (reader &r, X &x) {
        { r >> x } -> data::Same<reader &>;
    } reader &operator >> (reader &r, var_sequence<X> x);
    
    struct var_int {
        uint64 Value;
        
        static uint64 size (uint64 x);
        uint64 size () const;

        static uint64 read (reader &r);
        static writer &write (writer &w, uint64 x);
        
        operator uint64 const () {
            return Value;
        }
        
    };
    
    writer inline &operator << (writer &w, const var_int &x) {
        return var_int::write (w, x.Value);
    }
    
    reader inline &operator >> (reader &r, var_int &x) {
        x.Value = var_int::read (r);
        return r;
    }
    
    struct var_string {
        bytes &String;
        
        var_string (const bytes &b) : String {const_cast<bytes &> (b)} {};
        var_string (bytes &b) : String {b} {};
        
        static reader &read (reader &r, bytes &b);
        static writer &write (writer &w, const bytes &b);

        static uint64 size (int64 string_size);
        uint64 size () const {
            return size (String.size ());
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
        
        template <data::Stack<X> Q> static reader &read (reader &r, Q &l);
        template <data::SequenceOf<X> Q> static writer &write (writer &w, Q l);
        static uint64 size (list<X> q);
        uint64 size () const {
            return size (*this);
        }
    
    };

    uint64 inline var_int::size (uint64 x) {
        return x <= 0xfc ? 1 : x <= 0xffff ? 3 : x <= 0xffffffff ? 5 : 9;
    }

    uint64 inline var_int::size () const {
        return size (Value);
    }

    writer inline &var_string::write (writer &w, const bytes &b) {
        return w << var_int {b.size ()} << b;
    }

    uint64 inline var_string::size (int64 string_size) {
        return string_size + var_int::size (string_size);
    }

    template <typename X> requires requires (writer &w, const X &x) {
        { w << x } -> data::Same<writer &>;
    } writer inline &operator << (writer &w, const var_sequence<X> x) {
        return var_sequence<X>::write (w, x.List);
    }

    template <typename X> requires requires (reader &r, X &x) {
        { r >> x } -> data::Same<reader &>;
    } reader inline &operator >> (reader &r, var_sequence<X> x) {
        return var_sequence<X>::read (r, x.List);
    }

    template <typename X> template <data::Stack<X> Q>
    reader &var_sequence<X>::read (reader &r, Q &l) {
        l = Q {};
        var_int size;
        r >> size;

        for (int i = 0; i < size; i++) {
            X x;
            r >> x;
            l = data::prepend (l, x);
        }

        l = data::reverse (l);

        return r;
    }

    template <typename X> template <data::SequenceOf<X> Q>
    writer inline &var_sequence<X>::write (writer &w, Q l) {
        w << var_int {data::size (l)};
        for (const X &x: l) w << x;
        return w;
    }

    template <typename X>
    uint64 inline var_sequence<X>::size (list<X> q) {
        uint64 x = var_int::size (q.size ());
        for (const auto &n : q) x += n.serialized_size ();
        return x;
    }
    
}

#endif 
