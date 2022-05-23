# certnotar
Notarizing x509 certificates on Ethereum

This is a simple demo of notarizing (time-stamping) an x509 certificate on an Ethereum blockchain.
A certificate is generated attesting a DILITHIUM r3 public key from an IBM card with an RSA cert chain.
The serial number of the new certificate points to an address, chainid and nonce on some Ethereum network - this transaction calldata contains the certificate's signature (RSA)
