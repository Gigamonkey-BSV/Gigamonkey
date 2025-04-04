// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/pay/BEEF.hpp>
#include <gigamonkey/pay/extended.hpp>

namespace Gigamonkey {

    reader &operator >> (reader &r, BEEF::transaction &h) {
        r >> static_cast<Bitcoin::transaction &> (h);
        byte has_bump;
        r >> has_bump;
        if (has_bump) {
            Bitcoin::var_int bump_index {};
            r >> bump_index;
            h.BUMPIndex = bump_index.Value;
        } else h.BUMPIndex = maybe<uint64> {};
        return r;
    }

    BEEF::operator bytes () const {
        bytes b (serialized_size ());
        it_wtr w {b.begin (), b.end ()};
        w << *this;
        return b;
    }

    bool BEEF::valid () const {
        if (Version <= 0xEFBE0000 || data::size (Transactions) == 0 || !data::valid (Transactions) || !data::valid (BUMPs))
            return false;

        set<Bitcoin::TXID> previously_read;
        for (const auto &tx : Transactions) {
            Bitcoin::TXID txid = tx.id ();
            // all txs in list must be unique.
            if (previously_read.contains (txid)) return false;

            // Does this BEEF contain the merkle proof?
            // if not, then we have to check if all prevout txs are among the previous txs.
            if (!tx.Merkle_proof_included ())
                for (const Bitcoin::input &in : tx.Inputs)
                    if (!previously_read.contains (in.Reference.Digest)) return false;

            previously_read = previously_read.insert (txid);
        }

        return true;
    }

    stack<digest256> BEEF::roots () const {
        list<digest256> result;
        for (const auto &bump : BUMPs) {
            auto r = bump.root ();
            if (!r.valid ()) return {};
            result <<= r;
        }
        return result;
    }

    namespace {
        using namespace Bitcoin;

        using node = SPV::proof::node;
        using accepted = SPV::proof::accepted;
        using spvmap = SPV::proof::map;
        using conf = SPV::confirmation;
        using proof = SPV::proof;

        struct SPV_proof_writer {
            BEEF Beef;
            set<Bitcoin::TXID> TXIDs;
            map<digest256, uint32> RootToIndex {};
            cross<Merkle::BUMP> Bumps {};
            SPV_proof_writer (const proof &p);

            void read_node (const TXID &id, const node &tx, SPV_proof_writer &spv) {
                if (TXIDs.contains (id)) return;
                TXIDs = TXIDs.insert (id);

                if (tx.Proof.is<conf> ()) {
                    const auto &c = tx.Proof.get<conf> ();

                    // do we already have a BUMP for this block?
                    if (auto i = spv.RootToIndex.contains (c.Header.MerkleRoot); bool (i)) {
                        spv.Bumps[*i] += Merkle::branch {id, c.Path};
                        spv.Beef.Transactions <<= BEEF::transaction {tx.Transaction, *i};
                    } else {
                        uint64 index = spv.Bumps.size ();
                        spv.Bumps.push_back (Merkle::BUMP {uint64 (c.Height), Merkle::branch {id, c.Path}});
                        spv.RootToIndex = spv.RootToIndex.insert (c.Header.MerkleRoot, index);
                        spv.Beef.Transactions <<= BEEF::transaction {tx.Transaction, index};
                    }

                } else {
                    for (const auto &e : tx.Proof.get<SPV::proof::map> ()) read_node (e.Key, *e.Value, spv);
                    spv.Beef.Transactions <<= BEEF::transaction {tx.Transaction};
                }
            }
        };

        // create a BEEF from an SPV proof.
        inline SPV_proof_writer::SPV_proof_writer (const proof &p): Beef {} {
            for (const auto &[txid, nodep]: p.Proof) read_node (txid, *nodep, *this);

            for (const auto &tx : p.Payment) Beef.Transactions <<= BEEF::transaction {tx};
            Beef.Transactions = data::reverse (Beef.Transactions);
            for (auto b = Bumps.rbegin (); b != Bumps.rend (); b++) Beef.BUMPs <<= *b;
        }

        entry<Bitcoin::TXID, SPV::proof::accepted> read_SPV_proof_leaf (
            const Bitcoin::transaction &tx,
            std::pair<uint64, Merkle::map> merkle,
            SPV::database &db) {

            entry<Bitcoin::TXID, SPV::proof::accepted> result {tx.id (), SPV::proof::accepted {}};

            // check if the block header referenced by the proof exists.
            N height {merkle.first};
            const Bitcoin::header *header = db.header (height);
            if (header == nullptr) return result;

            result.Value = std::make_shared<node> (tx, conf {merkle.second[result.Key], height, *header});

            return result;

        }

        struct SPV_proof_reader {
            // all merkle maps by block height
            cross<std::pair<uint64, Merkle::map>> Merks;
            // list of node txids in order.
            list<Bitcoin::TXID> NodeTXIDs;
            // all nodes to be found in this proof.
            spvmap Nodes;
            // the root nodes.
            set<Bitcoin::TXID> Roots;
            proof Proof;

            SPV_proof_reader (const BEEF &beef, SPV::database &db) {

                // reconstruct all merkle paths by block height.
                Merks.resize (beef.BUMPs.size ());
                {
                    int index = 0;
                    for (const Merkle::BUMP &b : beef.BUMPs) Merks[index++] = {b.BlockHeight, b.paths ()};
                }

                for (const auto &tx : beef.Transactions) {

                    entry<TXID, accepted> node = tx.Merkle_proof_included () ?
                        read_SPV_proof_leaf (tx, Merks[*tx.BUMPIndex], db) :
                        read_SPV_proof_node (tx);

                    if (node.Value == nullptr) return;

                    Nodes = Nodes.insert (node.Key, node.Value, [] (const accepted &, const accepted &) -> accepted {
                        throw exception {} << "duplicate tx found in BEEF";
                    });
                }

                proof p;

                // go through remaining roots and make them the payment.
                for (const auto &txid : NodeTXIDs) {
                    // skip all non-root nodes.
                    if (!Roots.contains (txid)) continue;

                    // retrieve the node.
                    auto nodep = Nodes[txid];

                    p.Payment <<= nodep->Transaction;

                    // top level nodes should maps to earlier transactions.
                    if (nodep->Proof.is<conf> ()) return;

                    for (const auto &[txid, nodep] : nodep->Proof.get<spvmap> ())
                        // we merge all the maps and assume that entries with the same txid are equal without checking.
                        p.Proof = p.Proof.insert (txid, nodep, [] (const accepted &o, const accepted &n) -> accepted {
                            return o;
                        });

                }

                p.Payment = data::reverse (p.Payment);

                Proof = p;

            }

            entry<TXID, accepted> read_SPV_proof_node (const transaction &tx) {

                entry<TXID, accepted> result {tx.id (), accepted {}};

                spvmap prev;

                for (const auto &in : tx.Inputs) {
                    const auto *v = Nodes.contains (in.Reference.Digest);
                    if (v == nullptr) return result;

                    prev = prev.insert (in.Reference.Digest, *v, [] (const proof::accepted &a, const proof::accepted &b) {
                        return a;
                    });

                    // we know now that the prevout is not a root node, so we remove it.
                    Roots = Roots.remove (in.Reference.Digest);
                }

                result.Value = std::make_shared<node> (tx, prev);
                NodeTXIDs <<= result.Key;
                Roots = Roots.insert (result.Key);

                return result;
            }
        };
    }

    BEEF::BEEF (const SPV::proof &p) : BEEF {SPV_proof_writer {p}.Beef} {}

    SPV::proof BEEF::read_SPV_proof (SPV::database &db) const {
        return SPV_proof_reader {*this, db}.Proof;
    }

    BEEF::operator JSON () const {
        JSON::array_t bumps;

        for (const Merkle::BUMP &bump : BUMPs) bumps.push_back (JSON (bump));

        JSON::array_t txs;

        for (const transaction &tx : Transactions) {
            JSON::array_t ins;
            for (const Bitcoin::input &in : tx.Inputs)
                ins.push_back (JSON::object_t {
                    {"prevout", JSON::object_t {
                        {"txid", encoding::hexidecimal::write (in.Reference.Digest)},
                        {"index", uint32 (in.Reference.Index)}}},
                    {"script", encoding::hex::write (in.Script)},
                    {"sequence", uint32 (in.Sequence)}});

            JSON::array_t outs;
            for (const Bitcoin::output &out : tx.Outputs)
                outs.push_back (JSON::object_t {
                    {"value", uint64 (out.Value)},
                    {"script", encoding::hex::write (out.Script)}});

            JSON::object_t o {
                {"version", uint32 (tx.Version)},
                {"inputs", ins},
                {"outputs", outs},
                {"lockTime", uint32 (tx.LockTime)}};

            if (bool (tx.BUMPIndex)) o["BUMPIndex"] = *tx.BUMPIndex;

            txs.push_back (o);
        }

        return JSON::object_t {{"version", uint32 (Version)}, {"BUMPs", bumps}, {"Transactions", txs}};
    }
}

