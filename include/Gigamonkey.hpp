// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_NUMBER
#define GIGAMONKEY_NUMBER

// Bitcoin has two concepts numbers. The script uses a 
// little-endian two's complement representation of 
// integers as arbitrar size byte strings. For the 
// purpose of checking proof of work, hash digestst 
// are interpreted as unsigned little endian numbers. 
#include <gigamonkey/number.hpp>

// Bitcoin uses several hash functions. The script has 
// op codes for SHA1, SHA2_256, and RIPEMD160, which 
// are standard hash functions. It also has Hash160 and 
// Hash256, which are defined to be RIPEMD160 * SHA2_256
// and SHA2_256 * SHA2_256 respectively. 
#include <gigamonkey/hash.hpp>

// Bitcoin keys, defined in https://www.secg.org/sec2-v2.pdf 
#include <gigamonkey/secp256k1.hpp> 

// Bitcoin block format, including transactions and headers.
#include <gigamonkey/timechain.hpp> 
// a block consists of a header and a list of transactions. 
// a header contains a timestamp, a previous block hash, 
// a merkle root, and PoW proof. 

// A transaction consists of a list of inputs, a list of
// outputs, and a locktime value. An output contains a
// satoshi value and a script defining the conditions of
// redemption. An input consists of a reference to a
// previous output and the arguments to the function
// defined in the previous output which makes it return
// true. Inputs also have a sequence number. The sequence
// numbers along with the locktime value determine whether 
// the transaction is finalized. If any sequence number 
// is not final (0xffffffff), then the transaction is 
// not final until after the locktime value is past. The 
// locktime value is the block height if it is below 
// 500000000 and the unix time if above. 

// incomplete has to do with the messages that get signed
// in Bitcoin. The messages consist of transactions that 
// are incomplete to varying degrees depending on the 
// sighash, the input index in which the signature will
// appear, and part of the script that is being run (by 
// default the previous output script and none of the 
// input script). 
#include <gigamonkey/incomplete.hpp> 

// Sighash defines the function by which a transaction is 
// processed before being included in the document which
// is hashed and signed to make signatures that appear in 
// Bitcoin script. sighash::all means that all outputs are
// signed, meaning that the script containing the signature
// will no longer be valid if any of the outputs is changed.
// sighash::none means that none of the outputs are signed
// and sighash::single means that the output with the same
// index as the input in which this signature appears is
// signed. sighash::anyone_can_pay means that none of the
// other incomplete inputs are signed, so that other 
// people could add new inputs to the tx. 
#include <gigamonkey/sighash.hpp> 
// Currently, we use sighash FORKID, which also requires 
// the number of satoshis being redeemed to be included. 
// Eventually we will have the option of not using FORKID 
// and using the original sighash algorithm. In the
// original sighash algorithm, the script part that is 
// included in the signature is everything up to the last 
// OP_CODESEPARATOR before the signature. There is always
// an OP_CODESEPARATOR inserted between the output and
// input scripts, so this is why the output script is 
// signed by default. When we use FORKID, the output
// script is always used. 

// A Bitcoin signature is an secp256k1 signature plus 
// a sighash byte at the end which determines the function 
// that is called to generate the hash that gets signed. 
#include <gigamonkey/signature.hpp> 

// A Bitcoin script instruction.  
#include <gigamonkey/script/instruction.hpp>

// Bitcoin script evaluation. 
#include <gigamonkey/script/script.hpp>

// Bitcoin script interpreter that lets you step through
// an evaluation. 
#include <gigamonkey/script/machine.hpp>

// Bitcoin proof-of-work. 
#include <gigamonkey/work/proof.hpp>

// Bitcoin merkle proofs. 
#include <gigamonkey/merkle/proof.hpp>

// Bitcoin addresses, which ae hashes of public keys
// with information about the network being used 
// (main or test). 
#include <gigamonkey/address.hpp> 

// Bitcoin WIF format, which is used to export private 
// keys. It consists of an secp256k1 key, information 
// about the network (main or test) and whether the 
// corresponding private key is compressed or not. 
#include <gigamonkey/wif.hpp> 

// Bitcoin script patterns. In particular, this 
// includes functions on standard script formats such
// as op return data and pay-to-address, including 
// how to create and redeem them. 
#include <gigamonkey/script/pattern.hpp> 

// HD keys, described in BIP32, BIP39, and BIP44
#include <gigamonkey/schema/hd.hpp>

// Ledger is for processed transactions that include 
// Merkle proofs. 
#include <gigamonkey/ledger.hpp> 

// fees has to do with determining the correct tx fee. 
#include <gigamonkey/fees.hpp> 

// MAPI implementation. I think it's an earlier version
// so it might need to be updated. 
#include <gigamonkey/mapi/mapi.hpp>
