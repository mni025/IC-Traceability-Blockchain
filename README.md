This repository contains the necessary codes for implementing IC traceability via blockchains and smart contracts. The repository is divided into three main sections: codes for creating a custom blockchain, code for committing a custom trasnaction to a blockchain and smart contract implementation for Ethereum.

# Creating a custom blockchain

The main function for creating a transaction is transaction.py

User needs to provide Private key, previous transaction hash, recipient's address as input.

Sample Private key in WIF (Wallet Interchange Format): 5Kb6aGpijtrb8X28GzmWtbcGZCG8jHQWFJcWugqo3MwKRvC8zyu
Previous Transaction Hash: c39e394d41e6be2ea58c2d3a78b8c644db34aeff865215c633fe6937933078a9
Recipient's Address: 1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa

Addresses and keys can be checked from this site: https://www.mobilefish.com/services/cryptocurrency/cryptocurrency.html

The main function for creating a block consisting of valid transactions is block.py
