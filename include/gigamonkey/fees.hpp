// Copyright (c) 2019-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_FEES
#define GIGAMONKEY_FEES

#include "ledger.hpp"
#include <cmath>

namespace Gigamonkey {

    struct satoshi_per_byte {
        Bitcoin::satoshi Satoshis;
        uint64 Bytes;

        operator double () const;
        bool valid () const;
    };

    std::weak_ordering inline operator <=> (const satoshi_per_byte &a, const satoshi_per_byte &b);

    bool operator == (const satoshi_per_byte &a, const satoshi_per_byte &b);

    // given a tx size, what fee should we pay?
    Bitcoin::satoshi calculate_fee (satoshi_per_byte v, uint64 size);

    // Bitcoin signatures within a transaction sign part of the transaction. Thus,
    // we need to have the transacton partly created when we make the signatures.
    // transaction_design is for determining if the fee is correct and generating the
    // signatures.
    struct transaction_design {

        // we cannot construct a real input until after the signatures have been made.
        // however, we must estimate the size of the inputs before we sign because the
        // transaction fee is included in the signature, and we don't know what a good
        // tx fee is going to be without knowing the size of the final transaction.
        struct input {
            // the output being redeemed.
            Bitcoin::prevout Prevout;

            // the expected size of the input script.
            uint64 ExpectedScriptSize;

            uint32_little Sequence;

            // The signature may sometimes sign part of the input script,
            // if OP_CODESEPARATOR is used and FORKID is not used. This allows
            // one signature to sign previous signatures. This will contain
            // a part of the input script that has been previously generated.
            bytes InputScriptSoFar;

            input (Bitcoin::prevout p, uint64 x, uint32_little q = Bitcoin::input::Finalized, bytes z = {});
            operator Bitcoin::incomplete::input () const;
            uint64 expected_size () const;
            bytes script_code () const;
        };

        int32_little Version;
        list<input> Inputs;
        list<Bitcoin::output> Outputs;
        uint32_little Locktime;

        // compare this to a satoshi_per_byte value to see if the fee is good enough.
        uint64 expected_size () const;
        Bitcoin::satoshi spent () const;
        Bitcoin::satoshi sent () const;
        Bitcoin::satoshi fee () const;
        satoshi_per_byte fee_rate () const;

        // convert to an incomplete tx for signing.
        explicit operator Bitcoin::incomplete::transaction () const;

        // construct the documents for each input (the documents represent the data structure that gets signed).
        list<Bitcoin::sighash::document> documents () const;

        // come
        ledger::vertex complete (list<Bitcoin::script> redeem) const;

    };

    inline satoshi_per_byte::operator double () const {
        if (Bytes == 0) throw data::math::division_by_zero {};
        return double (Satoshis) / double (Bytes);
    }

    bool inline satoshi_per_byte::valid () const {
        return Bytes != 0;
    }

    std::weak_ordering inline operator <=> (const satoshi_per_byte &a, const satoshi_per_byte &b) {
        return math::fraction<int64, uint64> (int64 (a.Satoshis), a.Bytes) <=> math::fraction<int64, uint64> (int64 (b.Satoshis), b.Bytes);
    }

    bool inline operator == (const satoshi_per_byte &a, const satoshi_per_byte &b) {
        return math::fraction<int64, uint64> (int64 (a.Satoshis), a.Bytes) == math::fraction<int64, uint64> (int64 (b.Satoshis), b.Bytes);
    }

    Bitcoin::satoshi inline calculate_fee (satoshi_per_byte v, uint64 size) {
        if (v.Bytes == 0) throw data::math::division_by_zero {};
        return std::ceil (double (v.Satoshis) * double (size) / double (v.Bytes));
    }

    inline transaction_design::input::input (Bitcoin::prevout p, uint64 x, uint32_little q, bytes z):
        Prevout {p}, ExpectedScriptSize {x}, Sequence {q}, InputScriptSoFar {z} {}

    inline transaction_design::input::operator Bitcoin::incomplete::input () const {
        return {Prevout.Key, Sequence};
    }

    uint64 inline transaction_design::input::expected_size () const {
        return 40 + Bitcoin::var_int::size (ExpectedScriptSize) + ExpectedScriptSize;
    }

    bytes inline transaction_design::input::script_code () const {
        return write_bytes (Prevout.script ().size () + InputScriptSoFar.size (), Prevout.script (), InputScriptSoFar);
    }

    uint64 inline transaction_design::expected_size () const {
        return 8u + Bitcoin::var_int::size (Inputs.size ()) + Bitcoin::var_int::size (Inputs.size ()) +
            data::fold ([] (uint64 size, const input &i) -> uint64 {
                return size + i.expected_size ();
            }, 0u, Inputs) +
            data::fold ([] (uint64 size, const Bitcoin::output &o) -> uint64 {
                return size + o.serialized_size ();
            }, 0u, Outputs);
    }

    Bitcoin::satoshi inline transaction_design::spent () const {
        return data::fold ([] (Bitcoin::satoshi x, const input &in) -> Bitcoin::satoshi {
            return in.Prevout.value () + x;
        }, Bitcoin::satoshi {0}, Inputs);
    }

    Bitcoin::satoshi inline transaction_design::sent () const {
        return data::fold ([] (Bitcoin::satoshi x, const Bitcoin::output &out) -> Bitcoin::satoshi {
            return out.Value + x;
        }, Bitcoin::satoshi {0}, Outputs);
    }

    Bitcoin::satoshi inline transaction_design::fee () const {
        return spent () - sent ();
    }

    satoshi_per_byte inline transaction_design::fee_rate () const {
        return satoshi_per_byte {fee () / expected_size ()};
    }

    // convert to an incomplete tx for signing.
    inline transaction_design::operator Bitcoin::incomplete::transaction () const {
        return Bitcoin::incomplete::transaction {Version, data::for_each ([] (const input &in) -> Bitcoin::incomplete::input {
            return in;
        }, Inputs), Outputs, Locktime};
    }

    // construct the documents for each input (the documents represent the data structure that gets signed).
    list<Bitcoin::sighash::document> inline transaction_design::documents () const {
        Bitcoin::incomplete::transaction incomplete (*this);
        uint32 index = 0;
        return data::for_each ([&incomplete, &index] (const input &in) -> Bitcoin::sighash::document {
            return Bitcoin::sighash::document {
                in.Prevout.value (),
                Bitcoin::remove_until_last_code_separator (in.script_code ()),
                incomplete,
                index++};
        }, Inputs);
    }

    ledger::vertex inline transaction_design::complete (list<Bitcoin::script> redeem) const {
        return ledger::vertex
            {Bitcoin::incomplete::transaction (*this).complete (redeem),
                data::fold ([] (data::map<Bitcoin::outpoint, Bitcoin::output> m,
                    const input &i) -> data::map<Bitcoin::outpoint, Bitcoin::output> {
                    return m.insert (i.Prevout);
                }, data::map<Bitcoin::outpoint, Bitcoin::output> {},
                Inputs)};
    }

}

#endif

