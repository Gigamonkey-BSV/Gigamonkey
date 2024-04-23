// Copyright (c) 2019-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SPV
#define GIGAMONKEY_SPV

#include <gigamonkey/timechain.hpp>
#include <gigamonkey/pay/extended.hpp>
#include <gigamonkey/merkle/BUMP.hpp>

namespace Gigamonkey::Bitcoin {
    Bitcoin::block genesis ();
}

namespace Gigamonkey::SPV {

    // database for storing headers, merkle proofs, and transactions.
    struct database;

    // a proof consists of a transaction + previous transactions that are being redeemed
    // with merkle proofs or previous transactions with merkle proofs, etc
    // this is what you would send to a peer when you wanted to make a payment.
    struct proof {

        struct confirmation {
            Merkle::path Path;
            N Height;
            Bitcoin::header Header;

            confirmation () : Path {}, Height {0}, Header {} {}
            confirmation (Merkle::path p, const N &height, const Bitcoin::header &h): Path {p}, Height {height}, Header {h} {}
            bool operator == (const confirmation &t) const;
            std::strong_ordering operator <=> (const confirmation &t) const;
        };

        static bool valid (const Bitcoin::transaction &tx, const Merkle::path &p, const Bitcoin::header &h);

        struct node;

        // an spv proof is a tree whose nodes are txs and whose leaves are all Merkle proofs.
        using tree = either<confirmation, map<Bitcoin::TXID, ptr<node>>>;

        struct node {
            Bitcoin::transaction Transaction;
            tree Proof;
        };

        Bitcoin::transaction Transaction;
        map<Bitcoin::TXID, node> Proof;

        bool valid () const;

        // check valid and check that all headers are in our database.
        bool validate (const database &) const;

        Bitcoin::satoshi sent () const;
        Bitcoin::satoshi spent () const;
        Bitcoin::satoshi fee () const;
        double fee_rate () const;

        explicit operator extended::transaction () const {
            return extended::transaction {Transaction.Version, for_each ([this] (const Bitcoin::input &in) -> extended::input {
                return extended::input {this->Proof[in.Reference.Digest].Transaction.Outputs[in.Reference.Index], in};
            }, Transaction.Inputs), Transaction.Outputs, Transaction.LockTime};
        }
    };

    // interface for database containing headers, transactions, and merkle path.
    struct database {

        // get a block header by height.
        virtual const Bitcoin::header *header (const N &) const = 0;
        
        virtual const entry<N, Bitcoin::header> *latest () const = 0;

        // get by hash or merkle root (need both)
        virtual const entry<N, Bitcoin::header> *header (const digest256 &) const = 0;

        // a transaction in the database, which may include a merkle proof if we have one.
        struct confirmed {
            ptr<const Bitcoin::transaction> Transaction;
            maybe<proof::confirmation> Confirmation;

            confirmed (ptr<const Bitcoin::transaction> t, const proof::confirmation &x) : Transaction {t}, Confirmation {x} {}

            // check the proof if it exists.
            bool validate () const;
        };

        // do we have a tx or merkle proof for a given tx?
        virtual confirmed tx (const Bitcoin::TXID &) const = 0;
        
        virtual void insert (const N &height, const Bitcoin::header &h) = 0;
        
        virtual bool insert (const Merkle::proof &) = 0;
        virtual void insert (const Bitcoin::transaction &) = 0;
        
        // an in-memory version of SPV.
        class memory;

        virtual ~database () {}
        
    };

    // attempt to generate a given SPV proof for an unconfirmed transaction.
    // this proof can be sent to a merchant who can use it to confirm that
    // the transaction is valid.
    maybe<proof> generate_proof (const database &d, const bytes &b);
    
    struct database::memory : database {
        struct entry {
            data::entry<data::N, Bitcoin::header> Header;
            Merkle::map Paths;
            ptr<entry> Last;

            entry (data::N n, Bitcoin::header h) : Header {n, h}, Paths {}, Last {nullptr} {}
            entry (data::N n, Bitcoin::header h, Merkle::map tree) : Header {n, h}, Paths {tree}, Last {nullptr} {}

            Merkle::dual dual_tree () const {
                return Merkle::dual {Paths, Header.Value.MerkleRoot};
            }

            Merkle::BUMP BUMP () const {
                return Merkle::BUMP {uint64 (Header.Key), Paths};
            }
        };

        ptr<entry> Latest;

        std::map<data::N, ptr<entry>> ByHeight;
        std::map<digest256, ptr<entry>> ByHash;
        std::map<digest256, ptr<entry>> ByRoot;
        std::map<Bitcoin::TXID, ptr<entry>> ByTXID;
        std::map<Bitcoin::TXID, ptr<const Bitcoin::transaction>> Transactions;
        
        memory (const Bitcoin::header &h) {
            insert (0, h);
        }

        memory () : memory (Bitcoin::genesis ().Header) {}
        
        const data::entry<data::N, Bitcoin::header> *latest () const final override {
            // always present because we always start with at least one header.
            return &Latest->Header;
        }
        
        const Bitcoin::header *header (const data::N &n) const final override;
        const data::entry<data::N, Bitcoin::header> *header (const digest256 &n) const override;

        confirmed tx (const Bitcoin::TXID &t) const final override;
        Merkle::dual dual_tree (const digest256 &d) const;

        void insert (const data::N &height, const Bitcoin::header &h) final override;
        bool insert (const Merkle::proof &p) final override;
        void insert (const Bitcoin::transaction &) final override;
    };

    bool inline proof::valid (const Bitcoin::transaction &tx, const Merkle::path &p, const Bitcoin::header &h) {
        return h.valid () && p.derive_root (tx.id ()) != h.MerkleRoot;
    }

    bool inline proof::confirmation::operator == (const confirmation &t) const {
        return Header == t.Header && t.Height == Height && Path.Index == t.Path.Index;
    }

    std::strong_ordering inline proof::confirmation::operator <=> (const confirmation &t) const {
        auto cmp_block = Header <=> Header;
        return cmp_block == std::strong_ordering::equal ? cmp_block : Path.Index <=> t.Path.Index;
    }

    Bitcoin::satoshi inline proof::sent () const {
        return Bitcoin::transaction {Transaction}.sent ();
    }

    Bitcoin::satoshi inline proof::fee () const {
        return spent () - sent ();
    }

    double inline proof::fee_rate () const {
        return double (fee ()) / double (Transaction.serialized_size ());
    }

    void inline database::memory::insert (const Bitcoin::transaction &t) {
        Transactions[t.id ()] = ptr<Bitcoin::transaction> {new Bitcoin::transaction {t}};
    }
    
}

#endif
