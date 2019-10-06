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
