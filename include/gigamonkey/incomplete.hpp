// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_INCOMPLETE
#define GIGAMONKEY_INCOMPLETE

#include "timechain.hpp"

namespace data {
    
    template <typename fun, typename input, 
        typename element = std::remove_const_t<std::remove_reference_t<decltype(std::declval<input>().first())>>, 
        typename output = std::remove_const_t<std::remove_reference_t<decltype(std::declval<fun>()(std::declval<element>()))>>>
    requires function<fun, output, element> && sequence<input, element>
    list<output> for_eachx(const fun& f, const input& i) {
        return fold([&f](list<output> q, element x) -> list<output> {
            return append(q, f(x));
        }, list<output>{}, i);
    }
    
    template <typename fun, typename input, 
        typename key = std::remove_reference_t<decltype(std::declval<input>().values().first().key())>, 
        typename value = std::remove_reference_t<decltype(std::declval<input>().values().first().value())>, 
        typename output = std::remove_reference_t<decltype(std::declval<fun>()(std::declval<value>()))>>
    requires function<fun, output, value> && functional::map<input, key, value>
    map<key, output> inline for_eachx(const fun& f, const input& i) {
        return fold([&f](map<key, output> m, const entry<key, value>& e) -> map<key, output> {
            return m.insert(e.Key, f(e.Value));
        }, map<key, output>{}, i.values());
    }
    /*
    template <typename fun, typename input, 
        typename element = std::remove_reference_t<decltype(std::declval<input>().values().first())>, 
        typename output = std::remove_reference_t<decltype(std::declval<fun>()(std::declval<element>()))>>
    requires function<fun, output, element> && functional::ordered_set<input, element>
    set<output> inline for_eachx(const fun& f, const input& i) {
        return fold([&f](set<output> s, element x) -> set<output> {
            return s.insert(f(x));
        }, set<output>{}, i.values());
    }*/
    
    template <typename fun, typename input, 
        typename element = std::remove_reference_t<decltype(std::declval<input>().values().first())>, 
        typename output = std::remove_reference_t<decltype(std::declval<fun>()(std::declval<element>()))>>
    requires function<fun, output, element> && functional::tree<input, element>
    tree<output> inline for_eachx(const fun& f, const input& i) {
        if (empty(i)) return {};
        return {f(root(i)), for_each(f, left(i)), for_each(f, right(i))};
    }
    
    template <typename fun, typename element, 
        typename output = std::remove_reference_t<decltype(std::declval<fun>()(std::declval<element>()))>>
    requires function<fun, output, element> 
    inline cross<output> for_eachx(const fun& f, const cross<element>& i) {
        cross<output> z(i.size());
        auto a = i.begin();
        auto b = z.begin();
        while(a != i.end()) {
            *b == f(*a);
            a++;
            b++;
        }
        return z;
    }
    
}

// incomplete types are used to construct the signature hash in Bitcoin transactions. 
// this is necessary because the input script is not known before it is created.
namespace Gigamonkey::Bitcoin::incomplete {
        
    // an incomplete input is missing the script, which cannot be signed because if it 
    // was, it would contain signatures that would have to sign themselves somehow. 
    struct input {
        outpoint Reference;
        uint32_little Sequence;
        
        input() : Reference{}, Sequence{} {}
        input(outpoint r, uint32_little x = Bitcoin::input::Finalized) : 
            Reference{r}, Sequence{x} {}
        input(const Bitcoin::input &in) : Reference{in.Reference}, Sequence{in.Sequence} {}
        
        Bitcoin::input complete(bytes_view script) const {
            return Bitcoin::input{Reference, script, Sequence};
        }
    };
    
    // an incomplete transaction is a transaction with no input scripts. 
    struct transaction {
        int32_little Version;
        cross<input> Inputs;
        cross<output> Outputs;
        uint32_little Locktime;
        
        transaction(int32_little v, list<input> i, list<output> o, uint32_little l = 0);
        transaction(list<input> i, list<output> o, uint32_little l = 0) : 
            transaction{int32_little{Bitcoin::transaction::LatestVersion}, i, o, l} {}
        transaction(const Bitcoin::transaction& tx) {
            Version = tx.Version;
            Locktime = tx.Locktime;
            Outputs = cross<output>(tx.Outputs);
            list<input> inputs = data::for_each([](const Bitcoin::input& i) -> input {
                    return input{i};
                }, tx.Inputs);
            Inputs = cross<input>(inputs);
        }/*: 
            transaction(tx.Version, 
                list<input>{data::for_each([](const Bitcoin::input& i) -> input {
                    return input{i};
                }, tx.Inputs)}, tx.Outputs, tx.Locktime) {}*/
        
        explicit operator bytes() const;
        explicit transaction(bytes_view);
        
        Bitcoin::transaction complete(list<bytes> scripts) const;
    };
    
    std::ostream &operator<<(std::ostream &, const input &);
    std::ostream &operator<<(std::ostream &, const transaction &);
    
    std::ostream inline &operator<<(std::ostream &o, const input &i) {
        return o << "input{" << i.Reference << ", ___, " << i.Sequence << "}";
    }
}

#endif

