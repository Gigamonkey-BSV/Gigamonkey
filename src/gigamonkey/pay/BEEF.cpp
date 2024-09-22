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

    bool BEEF::valid () const {
        if (Version <= 0xEFBE0000 || data::size (Transactions) == 0 || !data::valid (Transactions) || !data::valid (BUMPs))
            return false;

        set<Bitcoin::TXID> previously_read;

        for (const auto &tx : Transactions) {
            Bitcoin::TXID txid = tx.Transaction.id ();

            // Does this transaction contain the merkle proof?
            // if not, then we have to check if all prevout txs are among the previous txs.
            if (!tx.Merkle_proof_included () && !previously_read.contains (txid)) return false;

            previously_read = previously_read.insert (txid);
        }

        return true;
    }

    list<digest256> BEEF::roots () const {
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
            map<digest256, uint32> RootToIndex {};
            cross<Merkle::BUMP> Bumps {};
            SPV_proof_writer (const proof &p);
        };

        void read_node (const TXID &id, const node &tx, SPV_proof_writer &spv) {
            if (tx.Proof.is<conf> ()) {
                const auto &c = tx.Proof.get<conf> ();

                // do we already have a BUMP for this block?
                if (auto i = spv.RootToIndex.contains (c.Header.MerkleRoot); bool (i)) {
                    spv.Bumps[*i] += Merkle::branch {id, c.Path};
                    spv.Beef.Transactions <<= BEEF::transaction {transaction {tx.Transaction}, *i};
                } else {
                    uint64 index = spv.Bumps.size ();
                    spv.Bumps.push_back (Merkle::BUMP {uint64 (c.Height), Merkle::branch {id, c.Path}});
                    spv.RootToIndex = spv.RootToIndex.insert (c.Header.MerkleRoot, index);
                    spv.Beef.Transactions <<= BEEF::transaction {transaction {tx.Transaction}, index};
                }

            } else {
                for (const auto &e : tx.Proof.get<SPV::proof::map> ()) read_node (e.Key, *e.Value, spv);
                spv.Beef.Transactions <<= BEEF::transaction {transaction {tx.Transaction}};
            }
        }

        inline SPV_proof_writer::SPV_proof_writer (const proof &p): Beef {} {
            for (const auto &[txid, nodep]: p.Proof) read_node (txid, *nodep, *this);
            for (const auto &bump : Bumps) Beef.BUMPs <<= bump;
            for (const auto &tx : p.Payment) Beef.Transactions <<= BEEF::transaction {tx};
        }

        entry<Bitcoin::TXID, SPV::proof::accepted> read_final_SPV_node (
            const Bitcoin::transaction &tx,
            std::pair<uint64, Merkle::map> merkle,
            SPV::database &db) {

            entry<Bitcoin::TXID, SPV::proof::accepted> result {tx.id (), SPV::proof::accepted {}};

            N height {merkle.first};

            const Bitcoin::header *header = db.header (height);

            if (header == nullptr) return result;

            result.Value = std::make_shared<node> (tx, conf {merkle.second[result.Key], height, *header});

            return result;

        }

        struct SPV_proof_reader {
            // all merkle maps by block height
            cross<std::pair<uint64, Merkle::map>> Merks;
            spvmap Nodes;
            spvmap Top;
            proof Proof;

            SPV_proof_reader (const BEEF &beef, SPV::database &db) {
                Merks.resize (beef.BUMPs.size ());
                {
                    int index = 0;
                    for (const Merkle::BUMP &b : beef.BUMPs) Merks[index++] = {b.BlockHeight, b.paths ()};
                }

                for (const auto &tx : beef.Transactions) {
                    entry<TXID, accepted> node = tx.Merkle_proof_included () ?
                        read_final_SPV_node (tx.Transaction, Merks[*tx.BUMPIndex], db) :
                        read_intermediate_SPV_node (tx.Transaction);

                    if (node.Value == nullptr) return;

                    Nodes = Nodes.insert (node);
                    Top = Top.insert (node);
                }

                proof p;

                for (const auto &[txid, nodep] : Top) {
                    p.Payment <<= nodep->Transaction;

                    // top level nodes should maps to earlier transactions.
                    if (nodep->Proof.is<conf> ()) return;

                    for (const auto &[txid, nodep] : nodep->Proof.get<spvmap> ())
                        // we merge all the maps and assume that entries with the same txid are equal without checking.
                        p.Proof.insert (txid, nodep, [] (const accepted &o, const accepted &n) -> accepted {
                            return o;
                        });

                }

                Proof = p;

            }

            entry<TXID, accepted> read_intermediate_SPV_node (const transaction &tx) {

                entry<TXID, accepted> result {tx.id (), accepted {}};

                spvmap prev;

                for (const auto &in : tx.Inputs) {
                    const auto *v = Nodes.contains (in.Reference.Digest);
                    if (v == nullptr) return result;
                    prev = prev.insert (in.Reference.Digest, *v);
                    Top = Top.remove (in.Reference.Digest);
                }

                result.Value = std::make_shared<node> (tx, prev);

                return result;

            }
        };
    }

    BEEF::BEEF (const SPV::proof &p) : BEEF {SPV_proof_writer {p}.Beef} {}

    SPV::proof BEEF::read_SPV_proof (SPV::database &db) const {
        return SPV_proof_reader {*this, db}.Proof;
    }
}

