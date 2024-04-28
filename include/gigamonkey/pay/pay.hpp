// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_PAY_PAY
#define GIGAMONKEY_PAY_PAY

// https://tsc.bsvblockchain.org/standards/direct-payment-protocol/

#include <gigamonkey/SPV.hpp>
#include <data/net/email.hpp>

namespace Gigamonkey::nChain::direct_payment_protocol {

    struct Beneficiary : JSON {
        string name () const;
        net::email email () const;
        string address () const;
        string paymentReference () const;
        avatar string () const;

        bool valid () const;

        static valid (const JSON &);

        Beneficiary (JSON &&);
    };

    struct Policies : JSON {
        list<string> requiredOriginatorFields () const;

        Policies (JSON &&);
    };

    struct PaymentTerms : JSON {

        string network () const;
        string version () const;
        list<Bitcoin::output> outputs () const;
        Bitcoin::timestamp creationTimestamp () const;
        Bitcoin::timestamp expirationTimestamp () const;
        maybe<string> memo () const;
        net::URL payment_URL () const;
        maybe<Beneficiary> beneficiary () const;
        JSON::object_t modes () const;
        Policies policies () const;

        bool valid () const;

        static valid (const JSON &);

        PaymentTerms (
            list<Bitcoin::output> outputs,
            Bitcoin::timestamp creation, Bitcoin::timestamp expiration,
            const string &memo = {});

        PaymentTerms (JSON &&);

        static string network (const JSON &);
        static string version (const JSON &);
        static list<Bitcoin::output> outputs (const JSON &);
        static Bitcoin::timestamp creationTimestamp (const JSON &);
        static Bitcoin::timestamp expirationTimestamp (const JSON &);
        static maybe<string> memo (const JSON &);
        static net::URL payment_URL (const JSON &);
        static maybe<Beneficiary> beneficiary (const JSON &);
        static JSON::object_t modes (const JSON &);
        static Policies policies (const JSON &);
    };

    struct Originator : JSON {
        string name () const; // string. required.
        maybe<string> paymail () const; // string. optional.
        maybe<string> return_address () const; // string. optional
        maybe<string> return_script () const; // string. optional
        maybe<string> avatar () const; // string. optional.
        maybe<JSON::object_t> extendedData () const; // object. optional, freestyle object.

        Originator (JSON &&);
    };

    struct Payment : JSON {
        Payment (const JSON &) const;
        string modeID () const;
        JSON::object_t mode () const;
        maybe<Originator> originator () const;
        maybe<string> transaction () const;
        maybe<string> memo ();

        Payment (JSON &&);
    };

    struct PaymentACK : JSON {
        Payment (const JSON &) const;
        string modeID () const;
        JSON::object_t mode () const;
        maybe<JSON::object_t> peerChannel () const // object. optional
        maybe<string> redirectUrl () const // string. optional

        PaymentACK (JSON &&);
    };

    inline Beneficiary (JSON &&j) : JSON {std::move (j)} {}

    inline Policies (JSON &&j) : JSON {std::move (j)} {}

    inline PaymentTerms (JSON &&j) : JSON {std::move (j)} {}

    inline Originator (JSON &&j) : JSON {std::move (j)} {}

    inline Payment (JSON &&j) : JSON {std::move (j)} {}

    inline PaymentACK (JSON &&j) : JSON {std::move (j)} {}

}

#endif
