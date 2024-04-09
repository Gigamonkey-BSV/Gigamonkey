// Copyright (c) 2019-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/SPV.hpp>
#include <gigamonkey/script/machine.hpp>

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

        return Merkle::dual {h->second->Tree, h->second->Header.Value.MerkleRoot};
    }

    database::confirmed database::memory::tx (const Bitcoin::txid &t) const {
        auto tx = Transactions.find (t);
        ptr<const bytes> tt {tx == Transactions.end () ? ptr<const bytes> {} : tx->second};
        auto h = ByTxid.find (t);
        return h == ByTxid.end () ? confirmed {tt, proof::confirmation {}} :
            confirmed {tt, proof::confirmation {
                Merkle::path (Merkle::dual {h->second->Tree, h->second->Header.Value.MerkleRoot}[t].Branch),
                h->second->Header.Value}};
    }

    void database::memory::insert (const data::N &height, const Bitcoin::header &h) {
        ptr<entry> new_entry {new entry {height, h}};

        auto old = ByHeight.find (height);
        if (old != ByHeight.end ()) {
            // TODO take into account the case of a reorg.
            // all proofs associated with this block have to be reset.
        } else ByHeight[height] = new_entry;

        ByHash[h.hash ()] = new_entry;
        ByRoot[h.MerkleRoot] = new_entry;

        if (height == 0 || Latest->Header.Key < height) Latest = new_entry;
        if (height > 0) if (auto i = ByHeight.find (height - 1); i != ByHeight.end ())
            new_entry->Last = i->second;

        if (auto i = ByHeight.find (height + 1); i != ByHeight.end ()) i->second->Last = new_entry;
    }

    bool database::memory::insert (const Merkle::proof &p) {
        auto h = ByRoot.find (p.Root);
        if (h == ByRoot.end ()) return false;
        auto d = Merkle::dual {h->second->Tree, h->second->Header.Value.MerkleRoot} + p;
        if (!d.valid ()) return false;
        h->second->Tree = d.Paths;
        ByTxid[p.Branch.Leaf.Digest] = h->second;
        return true;
    }

    bool unconfirmed_validate (const proof::node &u, const database *d) {
        if (std::holds_alternative<proof::confirmation> (u.Proof)) {
            const proof::confirmation &conf = std::get<proof::confirmation> (u.Proof);
            if (d != nullptr && d->header (conf.Header.MerkleRoot) == nullptr) return false;
            return conf.Header.valid () && conf.Path.derive_root (Bitcoin::transaction::id (u.Transaction)) != conf.Header.MerkleRoot;
        }

        for (const entry<Bitcoin::txid, ptr<proof::node>> &p : std::get<map<Bitcoin::txid, ptr<proof::node>>> (u.Proof))
            if (p.Value == nullptr || p.Key != Bitcoin::transaction::id (p.Value->Transaction) || !unconfirmed_validate (*p.Value, d)) return false;

        return true;
    }

    bool proof_validate (const proof &u, const database *d) {
        for (const entry<Bitcoin::txid, proof::node> &p : u.Proof)
            if (p.Key != Bitcoin::transaction::id (p.Value.Transaction) || !unconfirmed_validate (p.Value, d)) return false;

        Bitcoin::transaction decoded {u.Transaction};

        if (!decoded.valid ()) return false;

        Bitcoin::satoshi spent {0};
        for (const Bitcoin::input &in : decoded.Inputs) {
            Bitcoin::transaction prev {u.Proof[in.Reference.Digest].Transaction};
            if (!prev.valid ()) return false;

            const Bitcoin::output &out = prev.Outputs[in.Reference.Index];

            if (!Bitcoin::evaluate (in.Script, out.Script,
                Bitcoin::redemption_document {out.Value, Bitcoin::incomplete::transaction {decoded}, in.Reference.Index})) return false;

            spent += out.Value;
        }

        return decoded.sent () > spent;
    }

    bool proof::valid () const {
        return proof_validate (*this, nullptr);
    }

    // check valid and check that all headers are in our database.
    bool proof::validate (const SPV::database &d) const {
        return proof_validate (*this, &d);
    }

    Bitcoin::satoshi proof::spent () const {
        Bitcoin::transaction decoded {Transaction};

        Bitcoin::satoshi spent {0};
        for (const Bitcoin::input &in : decoded.Inputs)
            spent += Bitcoin::transaction {Proof[in.Reference.Digest].Transaction}.Outputs[in.Reference.Index].Value;

        return spent;
    }

    ptr<proof::node> generate_unconfirmed (const database &d, const Bitcoin::txid &x) {
        //
        database::confirmed n = d.tx (x);
        if (n.Transaction == nullptr) return {};

        if (bool (n.Confirmation)) return ptr<proof::node> {new proof::node {*n.Transaction, proof::tree {*n.Confirmation}}};

        map<Bitcoin::txid, ptr<proof::node>> antecedents;

        for (const Bitcoin::input &in : Bitcoin::transaction {x}.Inputs) {
            ptr<proof::node> u = generate_unconfirmed (d, in.Reference.Digest);
            if (u == nullptr) return {};
            antecedents = antecedents.insert (in.Reference.Digest, u);
        }

        return ptr<proof::node> {new proof::node {*n.Transaction, proof::tree {antecedents}}};
    }

    // attempt to generate a given SPV proof for an unconfirmed transaction.
    // this proof can be sent to a merchant who can use it to confirm that
    // the transaction is valid.
    maybe<proof> generate_proof (const database &d, const bytes &b) {
        Bitcoin::txid x = Bitcoin::transaction::id (b);
        database::confirmed n = d.tx (x);
        if (bool (n.Confirmation)) return {};
        map<Bitcoin::txid, proof::node> antecedents;

        for (const Bitcoin::input &in : Bitcoin::transaction {x}.Inputs) {
            ptr<proof::node> u = generate_unconfirmed (d, in.Reference.Digest);
            if (u == nullptr) return {};
            antecedents = antecedents.insert (in.Reference.Digest, *u);
        }

        return {proof {b, antecedents}};
    }
}
