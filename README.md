# he_wallet

A [Helium](https://helium.com) wallet implementation.

This is a simple wallet implementation that enables the creation and
use of an encrypted wallet.

**NOTE:** This wallet is _not_ the absolute safest way to create and
store a private key. No guarantees are implied as to it's safety and
suitability for use as a wallet associated with Helium crypto-tokens.

## Installation

You will need to have Erlang 22.1 installed on your system and enough
of a development environment to be able compile C code.

Clone this git repository and build it using:

```
   cd he_wallet
   make
```

The resulting `bin/wallet` executable is ready for use.

## Usage

At any time use `-h` or `--help` to get more help for a command.

### Create a wallet:

```
    bin/wallet create
```

The wallet will be stored in `wallet.key` after specifying an
encryption password on the command line. Options exist to specify the
wallet output file and to force overwriting an existing wallet.

### Verify a wallet:

```
    bin/wallet verify
```

The wallet in `wallet.key` will be verified for decryption after
passing the encryption password on the command line. Options exist to
specify a different wallet file.

### Public Key

```
    bin/wallet info
```

The wallet in `wallet.key` will be read and the public key for the
wallet displayed.


### Balance

```
    bin/wallet balance
```

The wallet in `wallet.key` will be read and the balances for the
wallet retrieved from blockchain using the Helium Explorer API.

## Key Sharding

Sharding wallet keys is supported via [Shamir's Secret Sharing](https://github.com/dsprenkels/sss).  A key
can be broken into N shards such that recovering the original key
needs K distinct shards. This can be done by passing options to
`create`:

```
    bin/wallet create -n 5 -k 3
```

This will create wallet.key.1 through wallet.key.5 (the base name of
the wallet file can be supplied with the `-o` parameter).

When keys are sharded using `verify` will require at least K distinct
keys:

```
    bin/wallet verify -f wallet.key.1 -f wallet.key.2 -f wallet.key.5
```

The password will also be needed when verifying a sharded key.

## Implementation details

A ed25519 key is generated via libsodium. The provided password is run
through PBKDF2, with a configurable number of iterations and a random
salt, and the resulting value is used as an AES key. When sharding is
enabled, an additional AES key is randomly generated and the 2 keys
are combined using a sha256 HMAC into the final AES key.

The private key is then encrypted with AES256-GCM and stored in the
file along with the sharding information, the key share (if
applicable), the AES initialization vector, the PBKDF2 salt and
iteration count and the AES-GCM authentication tag.
