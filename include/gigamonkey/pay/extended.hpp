// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_PAY_EXTENDED
#define GIGAMONKEY_PAY_EXTENDED

#include <gigamonkey/incomplete.hpp>
#include <gigamonkey/script.hpp>

// the format that is returned when we construct a new transaction is described in
// https://bitcoin-sv.github.io/arc/#/BIP-239
// it is a transaction that includes all previous outputs so that we can check
// scripts and fees and so on.
namespace Gigamonkey::extended {

    struct input;
    struct transaction;

    std::ostream &operator << (std::ostream &o, const input &p);
    std::ostream &operator << (std::ostream &o, const transaction &p);

    std::ostream &operator >> (std::ostream &o, const input &p);
    std::ostream &operator >> (std::ostream &o, const transaction &p);

    struct input : Bitcoin::input {
        Bitcoin::output Prevout;

        input () : Bitcoin::input {}, Prevout {} {}
        input (
            Bitcoin::satoshi val,
            const bytes &lock,
            const Bitcoin::outpoint &r,
            const bytes &unlock,
            uint32_little x = Bitcoin::input::Finalized) :
            Bitcoin::input {r, unlock, x}, Prevout {val, lock} {}
        input (const Bitcoin::output &prev, const Bitcoin::input &in) : Bitcoin::input {in}, Prevout {prev} {}

        bool valid () const;

        // the extended tx has a serialized form for broadcasting.
        uint64 serialized_size () const;
        bytes write () const;
        explicit operator bytes () const;

        // evaluate script without signature operations.
        Bitcoin::result evaluate (uint32 flags = StandardScriptVerifyFlags (true, true));

        // Evaluate script with real signature operations.
        Bitcoin::result evaluate (
            const Bitcoin::incomplete::transaction &,
            uint32 input_index,
            uint32 flags = StandardScriptVerifyFlags (true, true)) const;
    };

    struct transaction {

        int32_little Version;
        list<input> Inputs;
        list<Bitcoin::output> Outputs;
        uint32_little LockTime;

        transaction (): Version {0}, Inputs {}, Outputs {}, LockTime {} {}
        transaction (int32_little v, list<input> i, list<Bitcoin::output> o, uint32_little l = 0) :
            Version {v}, Inputs {i}, Outputs {o}, LockTime {l} {}

        transaction (list<input> i, list<Bitcoin::output> o, uint32_little l = 0) :
            transaction {int32_little {Bitcoin::transaction::LatestVersion}, i, o, l} {}

        // check all scripts and check that the fee is non-negative.
        bool valid (uint32 flags = StandardScriptVerifyFlags (true, true)) const;

        explicit operator Bitcoin::transaction () const;

        Bitcoin::TXID id () const;

        // the extended tx has a serialized form for broadcasting.
        uint64 serialized_size () const;
        bytes write () const;
        explicit operator bytes () const;

        Bitcoin::satoshi spent () const;
        Bitcoin::satoshi sent () const;
        Bitcoin::satoshi fee () const;
        satoshi_per_byte fee_rate () const;
    };

    writer inline &operator << (writer &w, const input &in) {
        return w << in.Reference << Bitcoin::var_string {in.Script} << in.Sequence << in.Prevout;
    }

    reader inline &operator >> (reader &r, input &in) {
        return r >> in.Reference >> Bitcoin::var_string {in.Script} >> in.Sequence >> in.Prevout;
    }

    reader inline &operator >> (reader &r, transaction &t) {
        r >> t.Version;
        r.skip (6);
        return r >> Bitcoin::var_sequence<input> {t.Inputs} >> Bitcoin::var_sequence<Bitcoin::output> {t.Outputs} >> t.LockTime;
    }

    writer inline &operator << (writer &w, const transaction &t) {
        return w << t.Version << *encoding::hex::read ("0000000000EF") <<
            Bitcoin::var_sequence<input> {t.Inputs} << Bitcoin::var_sequence<Bitcoin::output> {t.Outputs} << t.LockTime;
    }

    Bitcoin::satoshi inline transaction::spent () const {
        return data::fold ([] (Bitcoin::satoshi x, const input &in) -> Bitcoin::satoshi {
            return in.Prevout.Value + x;
        }, Bitcoin::satoshi {0}, Inputs);
    }

    Bitcoin::satoshi inline transaction::sent () const {
        return data::fold ([] (Bitcoin::satoshi x, const Bitcoin::output &out) -> Bitcoin::satoshi {
            return out.Value + x;
        }, Bitcoin::satoshi {0}, Outputs);
    }

    Bitcoin::satoshi inline transaction::fee () const {
        return spent () - sent ();
    }

    satoshi_per_byte inline transaction::fee_rate () const {
        return satoshi_per_byte {fee () / serialized_size ()};
    }

    bool inline input::valid () const {
        return static_cast<const Bitcoin::input &> (*this).valid () && Prevout.valid ();
    }

    uint64 inline input::serialized_size () const {
        return static_cast<const Bitcoin::input &> (*this).serialized_size () + Prevout.serialized_size ();
    }

    Bitcoin::result inline input::evaluate (uint32 flags) {
        return Bitcoin::evaluate (this->Script, Prevout.Script, flags);
    }

    Bitcoin::result inline input::evaluate (const Bitcoin::incomplete::transaction &tx, uint32 input_index, uint32 flags) const {
        std::cout << "    evaluating script " << Bitcoin::decompile (this->Script) << Bitcoin::decompile (Prevout.Script) << std::endl;
        return Bitcoin::evaluate (this->Script, Prevout.Script,
            Bitcoin::redemption_document {Prevout.Value, tx, input_index}, flags);
    }

    bytes inline input::write () const {
        return bytes (*this);
    }

    bytes inline transaction::write () const {
        return bytes (*this);
    }

    inline transaction::operator Bitcoin::transaction () const {
        return Bitcoin::transaction {Version, for_each ([] (const input &in) -> Bitcoin::input {
            return static_cast<Bitcoin::input> (in);
        }, Inputs), Outputs, LockTime};
    }

    Bitcoin::TXID inline transaction::id () const {
        return Bitcoin::transaction (*this).id ();
    }
}

#endif
