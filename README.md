# Hypercat Sig

This project demonstrates one possible way of cryptographically signing a Hypercat file. By adding a digital signature to a catalogue, the provenance can be automatically verified ensuring that no changes have been made.

In order to allow for whitespace ordering and other changes to JSON which would result in identical data, keys are sorted before hashing.

## Disclaimer

The implementation, scheme and approach have not been security audited. This should be considered a proof of concept and is provided with no guarantees of correctness, security or safety.

An example keypair is provided, do not use these for anything other than testing.

No mechanism for key distribution is provided. It is assumed that all parties have an existing chain of trust.

## Usage

To install dependencies:

    npm install


To sign a catalogue:

    ./hypercat-sig.js --sign cat.json --privkey private_key.pem --pubkey public_key.pem > signed.json


To verify the signature on a catalogue:

    ./hypercat-sig.js --verify signed.json --pubkey public_key.pem


