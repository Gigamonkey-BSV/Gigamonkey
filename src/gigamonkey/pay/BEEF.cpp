// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/pay/BEEF.hpp>
#include <gigamonkey/pay/extended.hpp>

namespace Gigamonkey {

    BEEF::operator bytes () const {
        bytes b (serialized_size ());
        bytes_writer w {b.begin (), b.end ()};
        w << *this;
        return b;
    }

    reader &operator >> (reader &r, BEEF::transaction &h) {
        r >> h.Transaction;
        byte has_bump;
        r >> has_bump;
        if (has_bump) {
            Bitcoin::var_int bump_index {};
            r >> bump_index;
            h.BUMPIndex = bump_index.Value;
        } else h.BUMPIndex = maybe<uint64> {};
        return r;
    }

    list<digest256> BEEF::roots () const {

        list<digest256> result;
        // the set of BUMP indicies that we have checked already.
        set<uint64> checked_already;
        map<digest256, uint32> previous_txs;

        auto index = 0;
        for (const auto &tx : Transactions) {
            digest256 id = tx.Transaction.id ();

            // does this transaction have a merkle proof?
            if (bool (tx.BUMPIndex)) {
                // does the given BUMP have the proof?
                const auto &bump = BUMPs[*tx.BUMPIndex];

                bool found = false;
                for (const auto &n : bump.Path.first ()) if (bool (n.Digest) && id == *n.Digest) {
                    found = true;
                    break;
                }

                if (!found) return {};

                // have we checked the proof already?
                if (!checked_already.contains (*tx.BUMPIndex)) {
                    checked_already = checked_already.insert (*tx.BUMPIndex);
                    auto root = bump.root ();
                    if (!root.valid ()) return {};
                    result <<= root;
                }

                previous_txs = previous_txs.insert (id, index);
            } else {
                // does this tx depend on previous txs?
                list<extended::input> extended_inputs;
                for (const auto &in : tx.Transaction.Inputs) {
                    auto p = previous_txs.contains (in.Reference.Digest);
                    if (!p) return {};
                    extended_inputs <<= extended::input {Transactions[*p].Transaction.Outputs[in.Reference.Index], in};
                }

                // check scripts on this tx.
                if (!extended::transaction {
                    tx.Transaction.Version,
                    extended_inputs,
                    tx.Transaction.Outputs,
                    tx.Transaction.LockTime}.valid ()) return {};
            }

            index++;
        }

        return result;
    }

    namespace {
        struct SPV_proof_reader {
            BEEF &Beef;
            map<digest256, uint32> RootToIndex {};
            cross<Merkle::BUMP> Bumps {};
            SPV_proof_reader (BEEF &beef, const SPV::proof &p);
        };

        void read_node (const Bitcoin::TXID &id, const SPV::proof::node &tx, SPV_proof_reader &spv) {
            if (std::holds_alternative<SPV::proof::confirmation> (tx.Proof)) {
                const auto &conf = std::get<SPV::proof::confirmation> (tx.Proof);

                // do we already have a BUMP for this block?
                auto i = spv.RootToIndex.contains (conf.Header.MerkleRoot);
                if (bool (i)) {
                    spv.Bumps[*i] += Merkle::branch {id, conf.Path};
                    spv.Beef.Transactions <<= BEEF::transaction {Bitcoin::transaction {tx.Transaction}, *i};
                } else {
                    uint64 index = spv.Beef.BUMPs.size ();
                    spv.Bumps.push_back (Merkle::BUMP {uint64 (conf.Height), Merkle::branch {id, conf.Path}});
                    spv.RootToIndex = spv.RootToIndex.insert (conf.Header.MerkleRoot, index);
                    spv.Beef.Transactions <<= BEEF::transaction {Bitcoin::transaction {tx.Transaction}, index};
                }

            } else {
                for (const auto &e : std::get<map<Bitcoin::TXID, ptr<SPV::proof::node>>> (tx.Proof)) read_node (e.Key, *e.Value, spv);
                spv.Beef.Transactions <<= BEEF::transaction {Bitcoin::transaction {tx.Transaction}};
            }
        }

        inline SPV_proof_reader::SPV_proof_reader (BEEF &beef, const SPV::proof &p): Beef {beef} {
            for (const auto &e: p.Proof) read_node (e.Key, e.Value, *this);
        }
    }

    BEEF::BEEF (const SPV::proof &p) {
        SPV_proof_reader {*this, p};
    }
}

