// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_PAY_SPV_ENVELOPE
#define GIGAMONKEY_PAY_SPV_ENVELOPE

#include <gigamonkey/merkle/serialize.hpp>
#include <gigamonkey/pay/MAPI.hpp>
#include <gigamonkey/SPV.hpp>

// https://tsc.bsvblockchain.org/standards/transaction-ancestors/

namespace Gigamonkey::nChain {

    struct SPV_envelope {

        maybe<Bitcoin::TXID> TXID;
        bytes RawTx;

        // optional for root node; other unconfirmed nodes must
        // either all have MAPI responses or not at all.
        list<MAPI::transaction_status_response> MAPIResponses;

        struct node {

            bytes RawTx;

            // MAPI responses must be included or not included for all nodes.
            list<MAPI::transaction_status_response> MAPIResponses;

            // If proof is not includedd, then there must be input
            // nodes for each transaction input.
            maybe<proofs_serialization_standard> Proof;
            map<Bitcoin::TXID, ptr<node>> Inputs;

            node (const bytes &raw, const proofs_serialization_standard &proof, list<MAPI::transaction_status_response> = {});
            node (const bytes &raw, map<Bitcoin::TXID, ptr<node>>, list<MAPI::transaction_status_response> = {});
        };

        map<Bitcoin::TXID, node> Inputs;

        explicit SPV_envelope (const SPV::proof &);
        explicit SPV_envelope (const JSON &);
        explicit operator JSON () const;

        // envelope is valid if the root transaction is valid,
        // if all input transactions are included, and for each
        // of those, either the merkle proof is included or all
        // input transactions included and have proofs or input
        // transactions are included etc.
        bool valid () const;

        // validate means that we actually check all the merkle
        // against the block headers.
        bool validate (const SPV::database &) const;

        SPV::proof read_SPV_proof (const SPV::database &) const;
    };


    inline SPV_envelope::node::node (const bytes &raw, const proofs_serialization_standard &proof, list<MAPI::transaction_status_response> r):
        RawTx {raw}, MAPIResponses {r}, Proof {proof}, Inputs {} {}

    inline SPV_envelope::node::node (const bytes &raw, map<Bitcoin::TXID, ptr<node>> inputs, list<MAPI::transaction_status_response> r):
        RawTx {raw}, MAPIResponses {r}, Proof {}, Inputs {inputs} {}

}


#endif
