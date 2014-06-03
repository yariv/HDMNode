
HDMNode
=======

HDMNode is an open source toolkit for building HDM Bitcoin wallets. HDMNode is based on Node.js.

HDM (Hierarchical-Determistic Multisig) wallets use multisig to protect coins from loss by splitting their keys on multiple machines. A typical single-user HDM wallet stores coins in 2-of-3 addresses, where the server has a key, the client has a key, and the user has a 3rd key in offline storage.

This architecture combines the best security features of offline, client side and hosted wallets. Coins are protected from both server side hacks and client side malware. If the server becomes inaccessible, the user can recover her coins using the backup key. The server can enforce security rules such as 2FA and daily spend limits, which single-key client side wallets can't provide. And, as opposed to pure offline wallets, if the offline wallet containing the backup key is destroyed or compromised the coins can still be recovered using the client and server keys.

The hierarchical-deterministic property (based on [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)) of HDM wallets gives them stronger privacy than multisig wallets that reuse private keys. Key reuse compromises on-blockchain privacy because, when the wallet broadcasts a transaction to the blockchain, the transaction record includes the public keys from which script of the [P2SH](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki)) address is composed. This makes it possible for anyone to link the wallet's addresses and derive the user's transaction history. HDM wallets don't have this weakness because they can store coins in an arbitrary number of addresses derived from deterministically generated key sets.

HDM wallets borrow additional benefits from non-multisig HD wallets. They make backing up wallets easy because the wallet's seed contains all the information needed to restore the wallet. They also allow setting up an arbitrary tree of subwallets for groups/organizations, where users who have access to a specific branch can also access its sub-branches but not its parent or sibling branches.

For more background, see the full [announcement](http://yarivsblog.blogspot.com/2014/06/announcing-hdmnode-nodejs-based-hdm.html).

Contributions will be welcome!

Written by Yariv Sadan (twitter: [@yarivs](http://twitter.com/yarivs) email: [yarivsblog@gmail.com](mailto://yarivsblog@gmail.com)).

Technical Notes
---

- HDMNode includes an API server, an API client, and a test suite. The APIs provide functionality for user management, wallet creation, address creation, balance checking, and spending.
- HDMNode aims to have 100% test coverage, at least of the API layer. If HDMNode includes UI in the future this requirement may be relaxed (though UI tests would be helpful as well).
- The server currently uses a MySQL database to store its data. HDMNode uses Sequelize, a lightweight ORM, to interface with the database, so it should be easy to plug in other database servers.
- The server doesn't cache the results of DB queries. Adding caching via memcache is advised for high-load production environments.
- You must run HDMNode no Node.js runtime version > 0.11.x. HDMNode uses generators extensively so you must run it with the --harmony flag on NodeJS version 0.11.x.
- Both the client and server code currently uses a fork of bitcoinjs-lib for low-level Bitcoin functions. Ideally, these calls should be migrated to BitCore [link], which is better documented and more actively maintained than the bitcoinjs-lib fork.
- The server uses the blockchain.info API to query the unspent txouts. It would be good to make other backends (esp BitCore insights) an option.
- We use [SJCL](http://crypto.stanford.edu/sjcl/) for all encryption and most hashing operations rather than the built in Node.js crypto module. On the client side, this minimizes dependency on Node.js and should make it easier to run the code in a browser (it hasn't been tested in the browser yet though). On the server side, SJCL is used to ensure ubiquitous support for AES-GCM mode (which SJCL implements) and to facilitate more code sharing with the client. It may be advantageous to move away from SJCL on the server side for perf reasons.

Warning
---
This code is alpha quality. Some of the functionality (notably spending) isn't fully fleshed out yet. It hasn't undergone a serious security audit. Use it at your own risk.

Installation Instructions
---

```
git clone https://github.com/yariv/HDMNode.git
cd HDMNode
npm install
```

Create a local MySQL database that the server could access. Update the database connection settings in the line that calls 'new Sequelize()' at the top of serverdb.js.

To run the server call

```
node --harmony lib/server/server.js
```

To run the tests call

```
node --harmony test/runtests.js
```
