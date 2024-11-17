// Copyright (c) 2019-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_FEES
#define GIGAMONKEY_FEES

#include <gigamonkey/pay/extended.hpp>
#include <gigamonkey/sighash.hpp>
#include <cmath>

// This file is for making it easy to design a transaction to meet your
// specifications before signing it. transaction_design is an incomplete
// transaction with more built in to check that the fee is good and that
// scripts are valid.

namespace Gigamonkey::Bitcoin {

    struct prevout : data::entry<Bitcoin::outpoint, Bitcoin::output> {
        using data::entry<Bitcoin::outpoint, Bitcoin::output>::entry;

        Bitcoin::outpoint outpoint () const {
            return this->Key;
        }

        Bitcoin::satoshi value () const {
            return this->Value.Value;
        }

        bytes script () const {
            return this->Value.Script;
        }
    };
}

namespace Gigamonkey {

    // Bitcoin signatures within a transaction sign part of the transaction. Thus,
    // we need to have the transacton partly created when we make the signatures.
    // transaction_design is for determining if the fee is correct and generating the
    // signatures.
    struct transaction_design {

        // we cannot construct a real input until after the signatures have been made.
        // however, we must estimate the size of the inputs before we sign because the
        // transaction fee is included in the signature, and we don't know what a good
        // tx fee is going to be without knowing the size of the final transaction.
        struct input : Bitcoin::incomplete::input {
            // the output being redeemed.
            Bitcoin::output Prevout;

            // the expected size of the input script.
            uint64 ExpectedScriptSize;

            // The signature may sometimes sign part of the input script,
            // if OP_CODESEPARATOR is used and FORKID is not used. This allows
            // one signature to sign previous signatures. This will contain
            // a part of the input script that has been previously generated.
            bytes InputScriptSoFar;

            input (Bitcoin::prevout p, uint64 x, uint32_little q = Bitcoin::input::Finalized, bytes z = {});
            uint64 expected_size () const;

            bytes script_so_far () const;

            extended::input complete (bytes_view script) const {
                return extended::input {Prevout, static_cast<const Bitcoin::incomplete::input &> (*this).complete (script)};
            }
        };

        int32_little Version;
        list<input> Inputs;
        list<Bitcoin::output> Outputs;
        uint32_little LockTime;

        // compare this to a satoshis_per_byte value to see if the fee is good enough.
        uint64 expected_size () const;
        Bitcoin::satoshi spent () const;
        Bitcoin::satoshi sent () const;
        Bitcoin::satoshi fee () const;
        satoshis_per_byte fee_rate () const;

        // convert to an incomplete tx for signing.
        explicit operator Bitcoin::incomplete::transaction () const;

        extended::transaction complete (list<Bitcoin::script> redeem) const;

    };

    inline transaction_design::input::input (Bitcoin::prevout p, uint64 x, uint32_little q, bytes z):
        Bitcoin::incomplete::input {p.Key, q}, Prevout {p.Value},
        ExpectedScriptSize {x}, InputScriptSoFar {z} {}

    uint64 inline transaction_design::input::expected_size () const {
        return 40 + Bitcoin::var_int::size (ExpectedScriptSize) + ExpectedScriptSize;
    }

    bytes inline transaction_design::input::script_so_far () const {
        return write_bytes (Prevout.Script.size () + InputScriptSoFar.size () + 1,
            InputScriptSoFar, byte (OP_CODESEPARATOR), Prevout.Script);
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
            return in.Prevout.Value + x;
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

    satoshis_per_byte inline transaction_design::fee_rate () const {
        return satoshis_per_byte {fee (), expected_size ()};
    }

    // convert to an incomplete tx for signing.
    inline transaction_design::operator Bitcoin::incomplete::transaction () const {
        return Bitcoin::incomplete::transaction {Version, data::for_each ([] (const input &in) -> Bitcoin::incomplete::input {
            return in;
        }, Inputs), Outputs, LockTime};
    }

    extended::transaction inline transaction_design::complete (list<Bitcoin::script> scripts) const {
        if (scripts.size () != Inputs.size ()) throw std::logic_error {"need one script for each input."};
        return extended::transaction {Version, data::map_thread ([] (const input &in, const bytes &script) -> extended::input {
            return in.complete (script);
        }, Inputs, scripts), Outputs, LockTime};
    }

}


#endif

