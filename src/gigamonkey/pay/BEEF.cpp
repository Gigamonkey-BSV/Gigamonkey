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
        using namespace Bitcoin;

        struct SPV_proof_reader {
            BEEF &Beef;
            map<digest256, uint32> RootToIndex {};
            cross<Merkle::BUMP> Bumps {};
            SPV_proof_reader (BEEF &beef, const SPV::proof &p);
        };

        void read_node (const TXID &id, const SPV::proof::node &tx, SPV_proof_reader &spv) {
            if (std::holds_alternative<SPV::proof::confirmation> (tx.Proof)) {
                const auto &conf = std::get<SPV::proof::confirmation> (tx.Proof);

                // do we already have a BUMP for this block?
                auto i = spv.RootToIndex.contains (conf.Header.MerkleRoot);
                if (bool (i)) {
                    spv.Bumps[*i] += Merkle::branch {id, conf.Path};
                    spv.Beef.Transactions <<= BEEF::transaction {transaction {tx.Transaction}, *i};
                } else {
                    uint64 index = spv.Beef.BUMPs.size ();
                    spv.Bumps.push_back (Merkle::BUMP {uint64 (conf.Height), Merkle::branch {id, conf.Path}});
                    spv.RootToIndex = spv.RootToIndex.insert (conf.Header.MerkleRoot, index);
                    spv.Beef.Transactions <<= BEEF::transaction {transaction {tx.Transaction}, index};
                }

            } else {
                for (const auto &e : std::get<map<TXID, ptr<SPV::proof::node>>> (tx.Proof)) read_node (e.Key, *e.Value, spv);
                spv.Beef.Transactions <<= BEEF::transaction {transaction {tx.Transaction}};
            }
        }

        inline SPV_proof_reader::SPV_proof_reader (BEEF &beef, const SPV::proof &p): Beef {beef} {
            for (const auto &e: p.Proof) read_node (e.Key, e.Value, *this);
        }
    }

    BEEF::BEEF (const SPV::proof &p) {
        SPV_proof_reader {*this, p};
    }

    namespace {

        map<TXID, SPV::proof::node> read_SPV_proof (
            const BEEF::transaction &tx,
            list<entry<uint64, Merkle::map>> merks,
            list<entry<TXID, BEEF::transaction>> txs,
            const SPV::database &db);

        map<TXID, ptr<SPV::proof::node>> read_SPV_tree (
            const BEEF::transaction &tx,
            list<entry<uint64, Merkle::map>> merks,
            list<entry<TXID, BEEF::transaction>> txs,
            const SPV::database &db);
    }

    SPV::proof BEEF::read_SPV_proof (const SPV::database &db) const {
        auto all_txs = data::reverse (Transactions);

        SPV::proof p;
        p.Transaction = Bitcoin::transaction (data::first (all_txs).Transaction);

        // calculate all txids
        list<entry<Bitcoin::TXID, BEEF::transaction>> txs = for_each ([] (const BEEF::transaction &tx) -> auto {
            return entry<Bitcoin::TXID, BEEF::transaction> {tx.Transaction.id (), tx};
        }, data::rest (all_txs));

        // calculate all merkle maps
        list<entry<uint64, Merkle::map>> merks = for_each ([] (const Merkle::BUMP &b) -> auto {
            return entry<uint64, Merkle::map> {b.BlockHeight, b.paths ()};
        }, BUMPs);

        p.Proof = Gigamonkey::read_SPV_proof (p.Transaction, merks, txs.rest (), db);

        return p;
    }

    namespace {

        ptr<SPV::proof::node> read_SPV_ptr_node (
            const entry<TXID, BEEF::transaction> &tx,
            list<entry<uint64, Merkle::map>> merks,
            list<entry<TXID, BEEF::transaction>> txs,
            const SPV::database &db) {

            if (tx.Value.BUMPIndex) {
                const entry<uint64, Merkle::map> &merk = merks[*tx.Value.BUMPIndex];
                return ptr<SPV::proof::node> {new SPV::proof::node
                    {tx.Value.Transaction, SPV::proof::confirmation
                        {merk.Value[tx.Key], merk.Key, *db.header (data::N {merk.Key})}}};
            }

            return ptr<SPV::proof::node> {new SPV::proof::node
                {tx.Value.Transaction, read_SPV_tree (tx.Value, merks, txs, db)}};
        }

        map<TXID, ptr<SPV::proof::node>> read_SPV_tree (
            const BEEF::transaction &tx,
            list<entry<uint64, Merkle::map>> merks,
            list<entry<TXID, BEEF::transaction>> txs,
            const SPV::database &db) {

            map<TXID, ptr<SPV::proof::node>> p;
            for (const input &in : tx.Transaction.Inputs) if (!p.contains (in.Reference.Digest)) {
                auto dependencies = txs;
                while (dependencies.first ().Key != in.Reference.Digest)
                    dependencies = dependencies.rest ();

                p = p.insert (in.Reference.Digest,
                    read_SPV_ptr_node (dependencies.first (), merks, dependencies.rest (), db));
            }

            return p;
        }

        SPV::proof::node read_SPV_node (
            const entry<TXID, BEEF::transaction> &tx,
            list<entry<uint64, Merkle::map>> merks,
            list<entry<TXID, BEEF::transaction>> txs,
            const SPV::database &db) {

            if (tx.Value.BUMPIndex) {
                const entry<uint64, Merkle::map> &merk = merks[*tx.Value.BUMPIndex];
                return SPV::proof::node {tx.Value.Transaction,
                    SPV::proof::confirmation {merk.Value[tx.Key], merk.Key, *db.header (data::N {merk.Key})}};
            }

            return SPV::proof::node {tx.Value.Transaction, read_SPV_tree (tx.Value, merks, txs, db)};
        }

        map<Bitcoin::TXID, SPV::proof::node> read_SPV_proof (
            const BEEF::transaction &tx,
            list<entry<uint64, Merkle::map>> merks,
            list<entry<TXID, BEEF::transaction>> txs,
            const SPV::database &db) {

            map<Bitcoin::TXID, SPV::proof::node> p;
            for (const Bitcoin::input &in : tx.Transaction.Inputs) if (!p.contains (in.Reference.Digest)) {
                auto dependencies = txs;
                while (dependencies.first ().Key != in.Reference.Digest)
                    dependencies = dependencies.rest ();

                p = p.insert (in.Reference.Digest,
                    read_SPV_node (dependencies.first (), merks, dependencies.rest (), db));
            }

            return p;
        }
    }
}

