// Copyright (c) 2019-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/SPV.hpp>
#include <gigamonkey/script/interpreter.hpp>

namespace Gigamonkey::Bitcoin {
    
    block genesis () {
        static block Genesis = block {bytes (encoding::hex::string {std::string {} +
            "0100000000000000000000000000000000000000000000000000000000000000" +
            "000000003BA3EDFD7A7B12B27AC72C3E67768F617FC81BC3888A51323A9FB8AA" +
            "4B1E5E4A29AB5F49FFFF001D1DAC2B7C01010000000100000000000000000000" +
            "00000000000000000000000000000000000000000000FFFFFFFF4D04FFFF001D" +
            "0104455468652054696D65732030332F4A616E2F32303039204368616E63656C" +
            "6C6F72206F6E206272696E6B206F66207365636F6E64206261696C6F75742066" +
            "6F722062616E6B73FFFFFFFF0100F2052A01000000434104678AFDB0FE554827" +
            "1967F1A67130B7105CD6A828E03909A67962E0EA1F61DEB649F6BC3F4CEF38C4" +
            "F35504E51EC112DE5C384DF7BA0B8D578A4C702B6BF11D5FAC00000000"})};
        return Genesis;
    }
}

namespace Gigamonkey::SPV {

    const Bitcoin::header *database::memory::header (const N &n) const {
        auto h = ByHeight.find (n);
        if (h == ByHeight.end ()) return {};
        return &h->second->Header.Value;
    }

    const data::entry<N, Bitcoin::header> *database::memory::header (const digest256 &n) const {
        auto h = ByHash.find (n);

        if (h == ByHash.end ()) {
            h = ByRoot.find (n);
            if (h == ByRoot.end ()) return {};
        }

        return &h->second->Header;
    }

    Merkle::dual database::memory::dual_tree (const digest256 &d) const {
        auto h = ByHash.find (d);

        if (h == ByHash.end ()) {
            h = ByRoot.find (d);
            if (h == ByRoot.end ()) return {};
        }

        return Merkle::dual {h->second->Paths, h->second->Header.Value.MerkleRoot};
    }

    bool database::memory::insert (const data::N &height, const Bitcoin::header &h) {

        if (!h.valid ()) return false;

        auto old = ByHeight.find (height);
        if (old != ByHeight.end ()) {
            if (old->second->Header.Value == h) return true;
            // if we replace one header with another, we assume this is a reorg and replace all subsequent blocks.

            auto o = old;
            do {
                for (const auto &e : o->second->Paths) {
                    // all txs in paths go into pending.
                    ByTXID.erase (e.Key);
                    Pending = Pending.insert (e.Key);
                }

                ByRoot.erase (o->second->Header.Value.MerkleRoot);
                ByHash.erase (o->second->Header.Value.hash ());

                ByHeight.erase (o++);

            } while (o != ByHeight.end ());

            // this block becomes latest.
            Latest = nullptr;
        }

        ptr<entry> new_entry {new entry {height, h}};
        ByHeight[height] = new_entry;

        ByHash[h.hash ()] = new_entry;
        ByRoot[h.MerkleRoot] = new_entry;

        if (height == 0 || Latest == nullptr || Latest->Header.Key < height) Latest = new_entry;
        if (height > 0) if (auto i = ByHeight.find (height - 1); i != ByHeight.end ())
            new_entry->Last = i->second;

        if (auto i = ByHeight.find (height + 1); i != ByHeight.end ()) i->second->Last = new_entry;
        return true;
    }

    database::confirmed database::memory::tx (const Bitcoin::TXID &t) const {
        auto tx = Transactions.find (t);
        ptr<const Bitcoin::transaction> tt {tx == Transactions.end () ? ptr<const Bitcoin::transaction> {} : tx->second};
        auto h = ByTXID.find (t);
        return h == ByTXID.end () ? confirmed {tt} :
            confirmed {tt, proof::confirmation {
                Merkle::path (Merkle::dual {h->second->Paths, h->second->Header.Value.MerkleRoot}[t].Branch),
                h->second->Header.Key,
                h->second->Header.Value}};
    }

    namespace {

        bool unconfirmed_validate (const proof::node &u, const database *d) {
            if (u.Proof.is<proof::confirmation> ()) {
                const proof::confirmation &conf = u.Proof.get<proof::confirmation> ();
                if (d != nullptr && d->header (conf.Header.MerkleRoot) == nullptr) return false;
                return proof::valid (u.Transaction, conf.Path, conf.Header);
            }

            if (!SPV::proof::extended_transactions ({u.Transaction}, u.Proof.get<proof::map> ()).valid ()) return false;

            for (const entry<Bitcoin::TXID, ptr<proof::node>> &p : u.Proof.get<proof::map> ())
                if (p.Value == nullptr || p.Key != p.Value->Transaction.id () || !unconfirmed_validate (*p.Value, d)) return false;

            return true;
        }

        bool proof_validate (const proof &u, const database *d) {
            if (!list<extended::transaction> (u).valid ()) return false;

            for (const entry<Bitcoin::TXID, ptr<proof::node>> &p : u.Proof)
                if (p.Key != p.Value->Transaction.id () || !unconfirmed_validate (*p.Value, d)) return false;

            return true;
        }
    }

    bool proof::valid () const {
        return proof_validate (*this, nullptr);
    }

    // check valid and check that all headers are in our database.
    bool proof::validate (const SPV::database &d) const {
        return proof_validate (*this, &d);
    }

    namespace {

        ptr<proof::node> generate_proof_node (const database &d, const Bitcoin::TXID &x) {

            database::confirmed n = d.tx (x);
            // if we don't know about this tx then we can't construct a proof.
            if (!n.valid ()) return {};
            if (n.has_proof ()) return ptr<proof::node> {new proof::node {*n.Transaction, n.Confirmation}};

            std::cout << "    searching for further antecedent transactions" << std::endl;
            map<Bitcoin::TXID, ptr<proof::node>> antecedents;

            for (const Bitcoin::input &in : Bitcoin::transaction {x}.Inputs) {
                ptr<proof::node> u = generate_proof_node (d, in.Reference.Digest);
                if (u == nullptr) return {};
                antecedents = antecedents.insert (in.Reference.Digest, u);
            }

            return ptr<proof::node> {new proof::node {*n.Transaction, antecedents}};
        }
    }

    // attempt to generate a given SPV proof for an unconfirmed transaction.
    // this proof can be sent to a merchant who can use it to confirm that
    // the transaction is valid.
    maybe<proof> generate_proof (const database &d, list<Bitcoin::transaction> payment) {
        std::cout << " generating spv proof for " << payment.size () << " transaction" << std::endl;
        proof p;

        for (const Bitcoin::transaction &b : payment) {

            Bitcoin::TXID x = b.id ();
            std::cout << "  generating proof for tx with id " << x << std::endl;

            // the transaction should not have a proof already because
            // this is supposed to be a payment that is unconfirmed.
            database::confirmed n = d.tx (x);
            if (n.has_proof ()) return {};

            p.Payment <<= b;

            for (const Bitcoin::input &in : b.Inputs)
                if (!p.Proof.contains (in.Reference.Digest)) {
                    std::cout << "   searching for sub proof with id " << in.Reference.Digest << std::endl;
                    ptr<proof::node> u = generate_proof_node (d, in.Reference.Digest);
                    if (u == nullptr) return {};
                    p.Proof = p.Proof.insert (in.Reference.Digest, u);
                }
        }

        return p;
    }

    void database::memory::insert (const Bitcoin::transaction &t) {
        auto txid = t.id ();
        Transactions[txid] = ptr<Bitcoin::transaction> {new Bitcoin::transaction {t}};
        // Do we have a merkle proof for this tx? If not put it in pending.
        if (auto e = ByTXID.find (txid); e == ByTXID.end ()) Pending = Pending.insert (txid);
    }

    bool database::memory::insert (const Merkle::proof &p) {
        auto h = ByRoot.find (p.Root);
        if (h == ByRoot.end ()) return false;
        auto d = Merkle::dual {h->second->Paths, h->second->Header.Value.MerkleRoot} + p;
        if (!d.valid ()) return false;
        h->second->Paths = d.Paths;
        ByTXID[p.Branch.Leaf.Digest] = h->second;
        // do we have a tx for this proof? If we do, remove from pending.
        if (auto e = Transactions.find (p.Branch.Leaf.Digest); e == Transactions.end ())
            Pending = Pending.remove (p.Branch.Leaf.Digest);
        return true;
    }

    void database::memory::remove (const Bitcoin::TXID &txid) {
        if (!Pending.contains (txid)) return;
        Pending = Pending.remove (txid);
        Transactions.erase (txid);
    }
}
