# Stratum Protocol

Stratum is the protocol that Bitcoin miners use to communicate with Bitcoin
mining pools. The mining pool provides the miners with hash puzzles that
correspond to new Bitcoin blocks. The miners respond with shares, which are
solutions to the hash puzzle at a much lower difficulty. The mining pool
adjusts the difficulty based on the hashpower of the miners, which it can
estimate from the frequency of shares submitted. The miners are paid by the
total difficulty for all shares submitted. Eventually one of these shares will
solve the block and the mining pool gets paid. The miner has no reason not to
submit this share because he can't use it for his own purposes but to him it's
worth no more than any other share.

Stratum can also be used with the [Boost POW](https://bitcoinfiles.org/t/7332808b5283f8acedcc6240a42f669cc3d305413201527852061fd5b283d0d8) protocol, a method of buying
proof-of-work from miners. 

Stratum is poorly documented. We have relied on three sources to produce the
specification given here. This document unravels all clues that are spread out
among our sources.
* [Stratum Mining Protocol v2.1](https://docs.google.com/document/d/1ocEC8OdFYrvglyXbag1yi8WoskaZoYuR5HGhwf0hWAY/edit#heading=h.3rdcrjn) -
  This document is a draft of a version of Stratum that would later become
  Stratum with extensions. It contains information about the base protocol as
  well as information that was later superseded by the next source.
* [Stratum-Extensions](https://github.com/slushpool/stratumprotocol/blob/master/stratum-extensions.mediawiki) -
  A description of Stratum extensions, including `mining.configure` and
  extension **version_rolling**, which is necessary to support [ASICBoost](https://arxiv.org/pdf/1604.00575.pdf%E3%80%82).
* [Stratum v1 Docs](https://braiins.com/stratum-v1/docs) - This article
  contains a worked example that provides details not available elsewhere but
  is not a comprehensive description of Stratum.
* [pooler/cpuminer](https://github.com/pooler/cpuminer) - An implementation of
  a Stratum client in c.

## Overall description of Stratum

Stratum begins with an optional `mining.configure` request from the client. If
this message is sent, then the extended version of Stratum is being used.

Next, the client may send either a `mining.authorize`, or `mining.subscribe`
request. After the server responds to a `mining.subscribe` request, it sends
`mining.set_difficulty` and `mining.notify`. At this point, the client has
enough information to start mining. However, the server might not accept shares
until after the client has been authorized.

While the client is mining, it sends a `mining.submit` message every time it
solves a share. Periodically, the server sends `mining.set_difficulty` and
`mining.notify` messages to the client. If the **set_extranonce** extension has
been enabled in `mining.configure`, the server may also send
`mining.set_extranonce` messages.

## Message types

Stratum is a biderectional stream of lines containing JSON objects in
[JSON RPC](https://www.jsonrpc.org/specification_v1) format. Each message is a
JSON object on one line terminated by a new line. Three message types are
defined in [JSON RPC](https://www.jsonrpc.org/specification_v1).

* **request**: `{id: <integer or string>, method: <string>, params: <array of JSON values>}`
* **response**: `{id: <integer or string>, error: null | [<integer>, <string>], result: <JSON value>}`
* **notification**: `{id: null, method: <string>, params: <array of JSON values>}`

A **response** corresponds to a **request** and must have the same id. Message
ids should be updated with each request. However, we note that
[pooler/cpuminer](https://github.com/pooler/cpuminer) does not do this properly.
Servers ought to be able to expect that message ids will be different for
requests that are being handled at the same time.

Unlike a typical JSON RPC protocol, Stratum methods may be client-to-server or
server-to-client.

## Errors

**Response** messages contain an error field. This field may be `null` if there
is no error. Otherwise it is an array containing an error code and error
message. If a response contains an error, the result field may be null
regardless of the type of message it is.

There is no standard for the meaning of the error codes. Proposed error codes
for mining service are

* `20: Other/Unknown`
* `21: Job not found (=stale)`
* `22: Duplicate share`
* `23: Low difficulty share`
* `24: Unauthorized worker`
* `25: Not subscribed`

## Methods

### `mining.authorize` (client to server)

The purpose of the authorize message is to log in so that the mining pool knows
who to pay for the miner's submitted shares.

Request params:

* *workername*: `string`
* *password*: `string` (optional)

Response result: `true|false`

A subtlety of methods with boolean responses is that result which is
logically false response may come with an error, which means that the result
is allowed to be `null`.

### `mining.subscribe` (client to server)

Request params:

* *user agent/version*: `string`
* *extranonce1*: `hex` (optional, 4 bytes) - *extranonce1* is a value that
  is provided by the mining pool in the subscription response and is also
  called the session id. A user may optionally request a session id in the
  subscription request. This may be desired because the client had to reconnect
  and was already doing work with a given session id.

Response result: `[[<subscription>...], <extranonce1>, <extranonce2_size>]` where

* *subscription*: `[<method>, <subscription id>]` - These values are not actually
  used. For the original Stratum protocol, there will be two subscriptions, for
  `mining.notify`, and `mining.set_difficulty`. The extended protocol may have
  additional subscriptions for `mining.set_extranonce` and `mining.set_version_mask`
  if extensions **set_extranonce** or **version_rolling** are respectively enabled.
  The subscription id can be some random hex string. It is not used.
* *extranonce1*: `hex` (4 bytes) - aka the session id. The string is written
  exactly as it appears in the coinbase. 
* *extranonce2_size*: `natural` - required because *extranonce2_size* fits
  into the coinbase script, which is preceeded by size specifier. Thus, the
  size of the coinbase. Thus the miner cannot choose the size of *extranonce2*.

### `mining.set_difficulty` (server to client)

Set a new difficulty for the client. Goes into effect upon the next job received
via `mining.notify`. 

Notification params:

* *difficulty*: `natural | float` - Many Stratum clients appear 
  not to support difficulty as a floating point. This is fine for building 
  blocks because the difficulty is so high that the number of significant digits
  it has as an integer is good enough. It is not good for small values, which
  might be found when mining [Boost POW](https://bitcoinfiles.org/t/7332808b5283f8acedcc6240a42f669cc3d305413201527852061fd5b283d0d8). 

### `mining.notify` (server to client)

Notification params:

* *jobID*: `string` - used by the client to specify the job they are claiming
  to have worked on later in `mining.submit`. It does not need to have any 
  particular format. 
* *previous block hash*: `hex` (32 bytes) - The correct format is to take the hex 
  string of the previous block hash with every four bytes reversed. The hex
  string as a whole is *not* reversed, as a Bitcoin hash would typically be 
  in a human-readible format. This format is completely weird and there is 
  no explanation for it anywhere or any overt description in any of our
  sources but the worked example in
  [Stratum v1 Docs](https://braiins.com/stratum-v1/docs) proves it correct. 
* *generation tx 1*: `hex` - The beginning of the coinbase. 
* *generation tx 2*: `hex` - The end of the coinbase. 
* *merkle branch*: `[hex...]` - List of hashes in hex. These hashes, 
  unlike *previous block hash*, are written just as they really are, but 
  in hex. They are not reversed, as you would normally see in some Bitcoin 
  human-readable format for hashes. Each is 32 bytes long. 
* *version*: `hex` (4 bytes) - reversed from the way it is written in the block header. 
* *target*: `hex` (4 bytes) - reversed from the way it is written in the block header. 
* *timestamp*: `hex` (4 bytes) - reversed from the way it is written in the block header. 
* *clean*: boolean - whether solutions to previous jobs will be rejected. 
  This is needed because as a block is being built, many jobs will be 
  generated as new txs are processed but old ones still define a valid block
  that is worth money for the mining pool. However, when a new block comes
  out, all previous jobs no longer correspond to a valid block. 

### `mining.submit` (client to server)

Request params:

* *worker name*: string - No particular format
* *jobID*: string - same as in `mining.notify` above. 
* *extranonce2*: `hex` - written as it appears in the block, not reversed. 
  Must have the same number of bytes as the value of *extranonce2_size*. 
* *timestamp*: `hex` (4 bytes) - reversed from the way it is written in the block header.
* *nonce*: `hex` (4 bytes) - reversed from the way it is written in the block header.
* *version*: `hex` (4 bytes, only present if extension
  **version_rolling** was enabled) - reversed from the way it is written in the block header.

Response result: `true|false`

Typically, a false result will come with an error message, in which case the 
result is allowed to be `null`.

### `mining.configure` (client to server)

The original version of Stratum did not include the `mining.configure` message. If 
extensions are[Stratum-Extensions](https://github.com/slushpool/stratumprotocol/blob/master/stratum-extensions.mediawiki) supported, `mining.configure` is the first message of the protocol 
and is used to agree on the extensions that are enabled for this session and 
to define their parameters.

Request params:

* *extensions*: `[string...]` - A list of names of requested extensions.
* *extensions-parameters*: `string => <JSON value>` - A map of parameter
  values for the requested extensions. For a given extension **x** and 
  parameter value **v**, 
  values in the map are given as `"x.v": <JSON value>`. 

Response result: `string => <JSON value>` - For every given extension **x** 
that was requested, the map must include an entry `"x": true|false|string` 
that indicates whether the server will support extension **x**.
The string is an error message and interpreted as a false value. 
Additionally, for every parameter **v** of every extension that is supported, 
the map must include an entry `"x.v": <JSON value>` to a valid value
of that parameter, according to the specification of the given extension **x**.

Example (from [Stratum-Extensions](https://github.com/slushpool/stratumprotocol/blob/master/stratum-extensions.mediawiki))

Request:
```
 {"method": "mining.configure",
  "id": 1,
  "params": [["minimum-difficulty", "version-rolling"],
    {"minimum-difficulty.value": 2048,
     "version-rolling.mask": "1fffe000", "version-rolling.min-bit-count": 2}]}
```
Response:
```
 {"error": null,
  "id": 1,
  "result": {"version-rolling": true,
    "version-rolling.mask": "18000000",
    "minimum-difficulty": true}}
```

### `mining.set_extranonce` (server to client)

This method requires extension **set_extranonce** to be enabled. The params are
the same as the last two in the `mining.subscribe` response. As with
`mining.set_difficulty`, the new extranonce goes into effect with the next job
received via `mining.notify`.

Notification params:

* *extranonce1*: `hex` (4 bytes) - not considered to be a session id this
  time. Instead it is just an update to the value used in *extranonce1*.
* *extranonce2_size*: `natural`

### `mining.set_version_mask` (server to client)

This method requires extension **rolling_version** to be enabled. 

Unlike with `mining.set_difficulty` and `mining.set_extranonce`, the new 
version mask is applied immediately, not after the next job. 

Notification params:

* *mask*: `hex` (4 bytes) - reversed from the way that the *version* field
  would appear in the block header. 

### Other Messages

Other methods are described in [Stratum Mining Protocol v2.1](https://docs.google.com/document/d/1ocEC8OdFYrvglyXbag1yi8WoskaZoYuR5HGhwf0hWAY/edit#heading=h.3rdcrjn)
which are not required to do mining and may not all be supported by this library.

* `mining.get_transactions` (client to server, request/response) - This method,
  in particular, cannot be supported by modern implementations because the
  server cannot afford to send the client an entire block whenever it asks for
  it. This method derives from a bad way of thinking about the economics of
  mining, which is that the mining pool serves the miners rather than the
  bitcoin users. Miners provide hashpower and they get paid whether or not the
  mining pool's block is orphaned. Thus, they don't care what the block looks
  like and shouldn't want a method like this. The mining pool serves the
  Bitcoin users by processing their transactions into a block.
* `mining.suggest_difficulty` (client to server, notification) - 
* `mining.suggest_target` (client to server, notification) - same as the previous
  method except that the difficulty is given in a different format. 
* `client.get_version` (server to client, request/response) - request the version
  of the client software from the client. 
* `client.reconnect` (server to client, notification)
* `client.show_message` (server to client, notification) - display a human-readable
  message to the user. 

## Extensions

When this first version of Stratum proved to be inadequate, ways of extending
it were defined. In particular, the discovery of ASICBoost meant that miners
would want to adjust bits earlier in the blockheader than the nonce in order to
search for a solution more efficiently. If some option was not provided to
better support ASICBoost, then the best option for miners in original Stratum
was to adjust the timestamp field. This is not desirable insofar as doing so
interferes with with Bitcoin's function as a timestamp server. Hence, an
extension called *version_rolling* was defined which enables miners to adjust
the version field. The orignial extensions document for Stratum specifies three
additional extensions: *set_extranonce*, *minimum_difficulty*, and *info*. We
describe *version_rolling* and *set_extranonce* in this document because these
are necessary to support 
[Boost POW](https://bitcoinfiles.org/t/7332808b5283f8acedcc6240a42f669cc3d305413201527852061fd5b283d0d8) 
with 
[ASICBoost](https://arxiv.org/pdf/1604.00575.pdf%E3%80%82). 

### version_rolling

Enables client and server to agree on some bits in the *version* field that the
client can edit and will be used like more extra nonce bits. 
Required to support [ASICBoost](https://arxiv.org/pdf/1604.00575.pdf%E3%80%82).

Adds method `mining.set_version_mask` and adds an extra field to `mining.submit`. 

request parameters: 

* *mask*: `hex` (4 bytes) - Reversed from the way that the *version* field is 
  written in the block header. A proposed mask that would determine 
  which bits of the *version* field that can be altered by the client. 
  The positive bits would be the ones that can be edited.  
* *min_bit_count*: natural number - the minimum number of bits that the client
  desires to be editable in the *version* field. 

response parameters: 

* *mask*: `hex` (4 bytes) - Reversed from the way that the *version* field is 
  written in the block header. The number of positive bits must be at least 
  *min_bit_count* and must be compatible with the mask sent by the client. 
  In other words, it cannot have positive bits that are not positive in 
  the client mask. 

### set_extranonce

Adds method `mining.set_extranonce`. This extension has no parameters. 

## How to Generate a Block Header

```
generationTX1 = hex2bin(notify_params[2]) 

extranonce1 = hex2bin(subscribe_response_result[1])

extranonce2 = hex2bin(submit_request_params[3])

generationTX2 = hex2bin(notify_params[3])

coinbase = cat(generationTX1, extranonce1, extranonce2, generationTX2)

merkle_branch = notify_params[4]

merkle_root = fold((hash, node) -> Hash256(cat(hash, hex2bin(node))), 
    Hash256(coinbase), merkle_branch)

/* case 1: original protocol */
version = reverse(hex2bin(notify_params[5]))
    
/* case 2: version_rolling extension */
version_mask = reverse(hex2bin(configure_params[1]["version_rolling.mask"]))
version = (reverse(hex2bin(notify_params[5])) & ~version_mask) | (reverse(hex2bin(submit_request_params[5])) & version_mask)

prev_hash = reverse_every_4_bytes(hex2bin(notify_params[1]))

target = reverse(hex2bin(notify_params[9]))

timestamp = reverse(hex2bin(submit_request_params[3]))

nonce = reverse(hex2bin(submit_request_params[4]))

block_header = cat(version, prev_hash, merkle_root, target, timestamp, nonce)
```

## Worked Example

An example from [Stratum v1 Docs](https://braiins.com/stratum-v1/docs) provides 
some information not given elsewhere that clarifies the format of 
*mining.subscribe*, *mining.notify*, and *mining.submit*, which are the three 
methods used to construct the block header. In particular, the 
*previous block hash* field in `mining.notify` has a very strange format that is 
not explained properly in any of the sources we used. It is given with every 
four bytes reversed.

* `mining.subscribe` response result: `{"id": 1, "result": [ [ ["mining.set_difficulty", "b4b6693b72a50c7116db18d6497cac52"], ["mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f"]], "08000002", 4], "error": null}`
* `mining.notify` params: `{"params": ["bf", "4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000", "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008","072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000", [], "00000002", "1c2ac4af", "504e86b9", false], "id": null, "method": "mining.notify"}`
* `mining.submit` request params: `{"params": ["slush.miner1", "bf", "00000001", "504e86ed", "b2957c02"], "id": 4, "method": "mining.submit"}`

**Coinbase**: `"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e50080800000200000001072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000"`

**Hash256 of Coinbase**: `0xec9d69b1c30dd91529e2f5a5636354a310a79b9b83622cfd79c8da9daa4d4132`

**Merkle Root**: `0xec9d69b1c30dd91529e2f5a5636354a310a79b9b83622cfd79c8da9daa4d4132`

**Prev Hash**: `0x00000000440b921e1b77c6c0487ae5616de67f788f44ae2a5af6e2194d16b6f8`

**Block Header**: `"02000000f8b6164d19e2f65a2aae448f787fe66d61e57a48c0c6771b1e920b440000000032414daa9ddac879fd2c62839b9ba710a3546363a5f5e22915d90dc3b1699deced864e50afc42a1c027c95b2"`

**Hash256 of Block Header**: `0x000000002076870fe65a2b6eeed84fa892c0db924f1482243a6247d931dcab32`

From this worked example we can verify the correct format for fields such as *previous block hash* in the original protocol.
The example does not explain the format for the merkle branch since it is empty. To check what we have said about that, one 
has to look into an implementation such as [pooler/cpuminer](https://github.com/pooler/cpuminer). 
