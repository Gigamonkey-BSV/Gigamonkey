# Gigamonkey

A library with basic Bitcoin functions. 

## Dependencies

* The Bitcoin SV reference implementation. 
* libsecp256k1
* crypto++
* My library Data which contains tools for high level programming, which in turn depends on.
    * GMP and GMP++
    * ctre

## Tour

* types.hpp - basic types imported from data and elsewhere. In particular, types for big numbers. 
    * N, Z - natural numbers and integers provided by GMP. 
    * N_bytes, Z_bytes - natural numbers and integers represented as byte strings, as they are in
      Bitcoin script.
    * uint, integer - signed and unsigned types of arbitry fixed size. 
* hash.hpp - hash functions used in Bitcoin. Provided by crypto++. 
* secp256k1.hpp - wrapper types for functions in libsecp256k1. 
* wif.hpp - Bitcoin wallet import format. 
* address.hpp - Bitcoin addresses. 
* work.hpp - proof-of-work functions. No work provider right now. 
* txid.hpp - the txid of transactions. 
* timechain.hpp - formated types of the Bitcoin blockchain. 
* script.hpp - the Bitcoin script language. Interpreptation provided by the reference implementation. 
* signature.hpp - the Bitcoin signature algrithm. Provided by the reference implementation (not connected yet);
* spendable.hpp - abstract types representing outputs in the blockchain that can be spent and including all data
  needed to be able to spend them. 
* redeem.hpp - function to redeem inputs to make a new Bitcoin transaction. Here the benefits of 
  the high-level programming constructs from Data shine clearly. 

## Future Plans

* wallet
* Bitcoin key encryption 
* standard script types. 
* op_return
* spv types
* cpu mining

## Name

Gigamonkey is my name for the Bitcoin egregore. 
