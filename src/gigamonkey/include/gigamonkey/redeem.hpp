// Copyright (c) 2019-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_REDEEM
#define GIGAMONKEY_REDEEM

#include <gigamonkey/pay/extended.hpp>
#include "fees.hpp"
#include "wif.hpp"
#include <cmath>

namespace Gigamonkey {

    // information required to produce a signature, given a partially complete script.
    // there could be many signatures per script.
    struct sigop {
        Bitcoin::secret Key;
        Bitcoin::sighash::directive Directive;

        sigop (const Bitcoin::secret &k): Key {k}, Directive {Bitcoin::directive (Bitcoin::sighash::all)} {}
        sigop (const Bitcoin::secret &k, const Bitcoin::sighash::directive &d) : Key {k}, Directive {d} {}
    };

    // A type representing a redeem function. This function has the ability to look up
    // the necessary keys based on an output script and produce the appropriate input script.
    // There could be many such functions depending on the types of scripts that are known.
    using redeem = data::function<
        Bitcoin::script (
            const Bitcoin::output &,
            const Bitcoin::sighash::document &,
            list<sigop>, const bytes &script_code)>;

    // default redeem function.
    Bitcoin::script redeem_p2pkh_and_p2pk (const Bitcoin::output &, const Bitcoin::sighash::document &, list<sigop>, const bytes &script_code);

    struct redeemer : transaction_design::input {
        list<sigop> Signatures;
        redeemer (list<sigop> y, Bitcoin::prevout p, uint64 x, uint32_little q = Bitcoin::input::Finalized, bytes z = {}):
            transaction_design::input {p, x, q, z}, Signatures {y} {}
    };

    // an almost-complete transaction that has all the information necessary to redeem it.
    struct redeemable_transaction : transaction_design {
        redeemable_transaction (int32_little version, list<redeemer> inputs, list<Bitcoin::output> outputs, uint32_little locktime);

        list<list<sigop>> Signatures;

        extended::transaction redeem (const Gigamonkey::redeem &) const;
    };

    inline redeemable_transaction::redeemable_transaction
    (int32_little version, list<redeemer> inputs, list<Bitcoin::output> outputs, uint32_little locktime):
        transaction_design {version, lift ([] (const redeemer r) -> transaction_design::input {
            return static_cast<transaction_design::input> (r);
        }, inputs), outputs, locktime}, Signatures {lift ([] (const redeemer r) -> list<sigop> {
            return r.Signatures;
        }, inputs)} {}
    
}

#endif 
