"use strict"

var rpc = require('jsonrpc2');
var assert = require('assert');
var scrypt = require('js-scrypt');
var btcutil = require('../btcutil.js');
var ECKey = require('bitcoinjs-lib').Key;
var convert = require('bitcoinjs-lib').convert;
var Script = require('bitcoinjs-lib').Script;
var base58 = require('bitcoinjs-lib').base58;
var bitcoinjsutil = require('bitcoinjs-lib').Util;
var BIP32key = require('bitcoinjs-lib').BIP32key;
var Transaction = require('bitcoinjs-lib').Transaction;
var Address = require('bitcoinjs-lib').Address;
var suspend = require('suspend');
var sjcl = require('sjcl');
var resume = suspend.resume;
var gen = btcutil.gen;

ECKey.compressByDefault = true;

var log = console.log;

var makeSession = function(
    // The session key
    sessionKey,

    // The user's email
    email, 

    // The user's AES key, which is used to encrypt/decrypt the client-side
    // Bitcoin private keys. This AES key is encrypted with a key that's
    // derived from the user's password+randomSalt. We use this AES key so that
    // changing the user's password only involves re-encrypting a single string.
    // (HDMNode currently only supports a single wallet per user so the number of
    // strings that require re-encryption is just 1 but in the future we may
    // want to allow more than one wallet/key per user.)
    encryptedAESKey,

    // A symmetric signature key. It's currently used for signing the walletInfo
    // that's stored on the server and verified on the client
    // when the user logs in. This protects the client against the server's giving it
    // false information about the original seeds that created the wallet. Without
    // this protection, the server could cause the client to generate receiving addresses
    // that don't belong to the wallet and thereby steal the coins that are sent
    // to those addresses. This design makes the client/server relationship as trustless
    // as possible and reduces the theft risk to which a compromised server could
    // expose the user.
    // Similar to the user's AES key, the signature key is derived from
    // the user's password and randomSalt (see below).
    signatureKey,

    // A 128 bit random string that's used as the salt for hashing (using scrypt)
    // the user's password when deriving the authToken that the client sends
    // to the server on login. Not using a random salt could weaken the password
    // hash and make it vulnerable to rainbow table attacks. Because we use the password
    // to encrypt the user's keys that we later store server side this is important
    // to protect against.
    // (Storing the randomSalt on the server side is a convenient option for allowing
    // users to easily log in from different devices but not
    // a necessity. It could be offered as an option for the user to store her client-side
    // data elsewhere (e.g Dropbox) to make it more secure.)
    randomSalt,

    // The walletInfo objects that contains the wallets's data. It may be null
    // if createWallet hasn't been called.
    // walletInfo contains the following values:
    //   serializedClientMainPublicKey: the client's main extended public key
    //   serializedClientBackupPublicKey: the client's backup extended public key
    //   serializedServerPublicKey: the server public key
    //   userData: an arbirary string that the client may store on the server
    //   signature: the signature the client has set for the wallet in setWalletSignature
    //   id: the wallet ID (TODO derive it from the public keys rather than
    //       creating it randomly)
    //   lastAddressIndex: The BIP32 child index of the last address created for the wallet.
    walletInfo) {
  return {sessionKey: sessionKey,
          email: email,
          encryptedAESKey: encryptedAESKey,
          signatureKey: signatureKey,
          randomSalt: randomSalt,
          walletInfo: walletInfo};
};

var Client = function(port, hostname) {
  this.rpcClient = new rpc.Client(port, hostname);
  this.session = null;
};

// This variable should ONLY be overridden in unit tests to make
// the tests run faster.
Client.AVOID_SCRYPT = false;
Client.setAvoidScrypt = function(val) {
  Client.AVOID_SCRYPT = true;
};

Client.prototype._call = gen(function*(method, params) {
  if (this.session) {
    params.sessionKey = this.session.sessionKey;
  }
  params = params || {};
  return (yield this.rpcClient.call(method, params, {}, resume()));
});


// The secret hash is derived from calling
// scrypt(plaintext=password, salt=toBase64("HDMToolkit:"+email+randomSalt)).
//
// The global constant and the email are included in the salt to lower
// the risk of rainbow table attacks against the password hash in case randomSalt
// isn't truly random. This is worth protecting against because the client has to request
// the randomSalt from the server before logging in if the randomSalt isn't already cached in
// local storage, which could give the server an opportunity to lie to the client
// and provide it with a low entropy salt against which the server could construct
// a rainbow table. Depending on where the server is hosted this could be low risk
// but it's worth doing for the extra security.

// It's used as the basis for the authToken and the user's signature key.
// It's also used to encrypt the user's AES key.
var getSecretHash = gen(function*(email, password, randomSalt) {
  var authTokenSalt = convert.bytesToBase64(
    convert.stringToBytes('HDMToolkit:' + email).concat(randomSalt));

  // This should be ONLY used for testing
  if (Client.AVOID_SCRYPT) {
    return new sjcl.hash.sha256().update(password+authTokenSalt).finalize()
  }

  var secretHash = yield scrypt.hash(
      password,
      authTokenSalt,
      {cost: 16384, blocksize: 8, parallel: 8, size: 32},
      resume());

  return sjcl.codec.bytes.toBits(secretHash);
});

// Get the user's secret hash from the user's password. The client is assumed to
// have an active session.
Client.prototype.getSecretHash = gen(function*(password) {
  return (yield getSecretHash(
    this.session.email, password, this.session.randomSalt));
});

// Get the user's authToken from her password. The client is assumed to
// have an active session.
Client.prototype.getAuthToken = gen(function*(password) {
  return (yield Client.getAuthToken(
    this.session.email, password, this.session.secretHashSalt));
});

// Get the auth token without relying on the client's active session.
Client.getAuthToken = gen(function*(email, password, randomSalt) {
  var secretHash = yield getSecretHash(email, password, randomSalt);
  return Client.getAuthTokenFromSecretHash(secretHash);
});

// Get the auth token from the user's secret hash.
Client.getAuthTokenFromSecretHash = function(secretHash) {

  // We use HMAC with a fixed message body to derive the auth token
  // from the secret hash. This allows us to derive other values
  // (e.g. the signature key) by using a different message body.
  return btcutil.hmac256('HDMToolkit:authToken', secretHash);
}

// Returns the signature key derived from the user's secret hash.
Client.getSignatureKey = function(secretHash) {
  return btcutil.hmac256("HDMToolkit:signatureKey", secretHash);
};

// Register the user.
Client.prototype.register = gen(function*(email, password) {
  btcutil.checkPassword(password);

  var randomSalt = convert.bytesToBase64(btcutil.getRandomBytes(16));

  // Generate a new unique per-user AES key. This key will be used
  // to encrypt any private bitcoin keys generated client side and
  // stored server side. This key itself will be encrypted with the
  // user's secretHash and stored on the server. This design
  // has the advantage of requiring that we only re-encrypt
  // the user's AES key if the user changes her credentials.
  var secretHash = yield getSecretHash(
    email, password, randomSalt);

  var signatureKey = Client.getSignatureKey(secretHash);

  // Create a random 256 bit AES key and encrypt it with the user's
  // secret hash.
  var aesKey = sjcl.codec.bytes.toBits(btcutil.getRandomBytes(32));
  var encryptedAESKey = btcutil.aesEncrypt(aesKey, secretHash);

  // Derive the authToken from the secret hash.
  var authToken = Client.getAuthTokenFromSecretHash(secretHash);

  // Send the request to the server.
  var result = yield this._call(
    'register', {
      email: email,
      authToken: authToken,
      randomSalt: randomSalt,

      // We store the encrypted AES key in the userData field because the server
      // doesn't know or care about encryptedAESKey. The server only allows
      // the client the store this value server side for convenience.
      userData: JSON.stringify({
        encryptedAESKey: encryptedAESKey,
      }),
    });
  this.session = makeSession(
    result.sessionKey,
    email,
    encryptedAESKey,
    signatureKey,
    randomSalt,
    null); // walletID
  return this.session;
});

// Check that the session values match the server's values. This should only
// be used for testing.
// TODO remove?
Client.prototype.checkSession = gen(function*(session) {
  var encryptedAESKey = session.encryptedAESKey;
  var userData = JSON.stringify(
    {encryptedAESKey: session.encryptedAESKey});
  yield this._call(
    'checkSession',
    {sessionKey: session.sessionKey,
     email: session.email,
     userData: userData});
  return true;
});

// Log the user in.
Client.prototype.login = gen(function*(email, password) {

  // Before logging in, we have to get the randomSalt that the client originally
  // stored on the server (see register()). It's possible to avoid storing this value
  // at all on the server for greater security. See the comment avoid randomSalt in
  // makeSession().
  var res = yield this._call('getRandomSalt', {email: email});
  if (!res.randomSalt) {
    throw new Error('Couldn\'t obtain the user\'s random salt.');
  }
  var secretHash = yield getSecretHash(
    email, password, res.randomSalt);

  var authToken = Client.getAuthTokenFromSecretHash(secretHash);
  var loginResult = yield this._call(
    'login', {email: email, authToken: authToken});
  try {
    var userData = JSON.parse(loginResult.userData);
  } catch (e) {
    throw new Error('The server returned invalid user data.');
  }

  var signatureKey = Client.getSignatureKey(secretHash);
  this.session = makeSession(
    loginResult.sessionKey,
    email,
    userData.encryptedAESKey,
    signatureKey,
    res.randomSalt);

  // Only if the user has successfully created a wallet would the loginResult
  // include the walletInfo.
  var walletInfo = loginResult.walletInfo;
  if (walletInfo) {

    // IMPORTANT: Check the walletInfo's signature to verify it matched the
    // expected signature derived from the user's secretHash. This prevents
    // attacks whereby the server could cause the client to generate receiving
    // addresses that don't belong to the user's wallet.
    this._checkWalletInfoSig(walletInfo);

    this.session.walletInfo = walletInfo;
  }

  return this.session;
});

// Log the user out.
Client.prototype.logout = gen(function*() {
  if (!this.session) {
    throw new Error('Not logged in.');
  }
  var res = yield this._call('logout', {});
  this.session = null;
  return res;
});

// Get the user's AES key after decrypting it with the secret hash. The
// client is assumed to be logged in.
Client.prototype.getEncryptionKey = function(secretHash) {
  try  {
    return btcutil.aesDecrypt(this.session.encryptedAESKey, secretHash);
  } catch (e) {
    throw new Error('INVALID_PASSWORD');
  }
};

// Create a new wallet. This should be called right after register().
// Currently it can only be called once per user but this restriction
// may be relaxed in the future.
Client.prototype.createWallet = gen(function*(
  password, clientBackupPublicKey) {

  assert(this.session);

  var secretHash = yield this.getSecretHash(password);
  var encryptionKey = this.getEncryptionKey(secretHash);

  // Create the client's main key from a 256 bit random seed.
  var randomSeed = btcutil.getRandomBytes(32);
  var clientMainKey = BIP32key.fromMasterKey(randomSeed);

  // Encrypt the client's main key with the user's AES key. 
  var plaintext = sjcl.codec.utf8String.toBits(clientMainKey.serialize());
  var encryptedClientMainKey = btcutil.aesEncrypt(
    plaintext, encryptionKey);

  var clientMainPublicKey = clientMainKey.getPub();
  var serializedClientMainPublicKey = clientMainPublicKey.serialize();
  var serializedClientBackupPublicKey = clientBackupPublicKey.serialize();

  // Derive the wallet key.
  var walletKey = Client.getWalletKey(serializedClientMainPublicKey, secretHash);

  // We store the encrypted main wallet key on the server in the userData
  // field. This is optional and the server doesn't have to know or care about it.
  var userData = JSON.stringify(
    {encryptedClientMainKey:
      encryptedClientMainKey});
  

  // Ask the server to create the wallet.
  var result = yield this._call(
    "createWallet",
    {
      walletKey: walletKey,
      serializedClientMainPublicKey: serializedClientMainPublicKey,
      serializedClientBackupPublicKey: serializedClientBackupPublicKey,
      userData: userData,
    });

  // If all went well, the server should have returned its serialized BIP32 extended
  // public key. We can use this key together with the extended client main and backup keys
  // to derive the public seed for the wallet.
  var serializedServerPublicKey = result.serializedServerPublicKey;

  // Throw an error if the server returned an invalid public key
  var serverPublicKey;
  try {
    serverPublicKey = BIP32key.deserialize(serializedServerPublicKey);
  } catch (e) {
    throw new Error('The server returned an invalid key.');
  }

  // A few sanity checks. Unlikely to ever be called.
  if (serverPublicKey.type !== 'pub') {
    throw new Error('The server key should be public.');
  }
  if (serializedServerPublicKey === serializedClientMainPublicKey) {
    throw new Error('The server key should be different from the main client key.');
  }
  if (serializedServerPublicKey === serializedClientBackupPublicKey) {
    throw new Error('The server key should be different from the backup client key.');
  }

  // We sign the wallet's public seed and store this signature on the server.
  // This can protect against attacks where the server returns to the client
  // invalid walletInfo data on login() to cause the client to create
  // receiving addresses that don't belong to the user's wallet.
  var signature = this._getWalletSignature(
    result.walletID,
    serializedClientMainPublicKey,
    serializedClientBackupPublicKey,
    serializedServerPublicKey);

  yield this._call('setWalletSignature',
    {walletID: result.walletID,
     signature: signature});

  // We have the full walletInfo data so we store it in the session.
  this.session.walletInfo = 
      {serializedClientMainPublicKey: serializedClientMainPublicKey,
       serializedClientBackupPublicKey: serializedClientBackupPublicKey,
       serializedServerPublicKey: serializedServerPublicKey,
       userData: userData,
       signature: signature,
       id: result.walletID,
       lastAddressIndex: -1};
  return {
    walletID: result.walletID,
    serializedServerPublicKey: serializedServerPublicKey,
    signature: signature,
    clientMainKey: clientMainKey,
  };
});

// Get the wallet's key by computing HMAC(message=clientMainPublicKey, key=secretHash).
// This makes it possible for the client to always derive the same key for
// the wallet while making it impossible for anyone else to derive this key without
// knowing the user's password.
Client.getWalletKey = function(
    serializedClientMainPublicKey, secretHash) {
  return btcutil.hmac256(serializedClientMainPublicKey, secretHash);
};

Client.prototype.getWalletKey = gen(function*(password) {
  var secretHash = yield this.getSecretHash(password)
  return Client.getWalletKey(this.session.walletInfo.serializedClientMainPublicKey,
    secretHash);
});


// Compute the wallet's signature from the its public keys and ID, hashed
// with the user's signatureKey.
Client.prototype._getWalletSignature = function(
  walletID,
  serializedClientMainPublicKey,
  serializedClientBackupPublicKey,
  serializedServerPublicKey) {
  var combinedKey =
    walletID +
    serializedClientMainPublicKey +
    serializedClientBackupPublicKey +
    serializedServerPublicKey;
  return btcutil.hmac256(
    combinedKey, this.session.signatureKey);
};

// Check the wallet's signature.
Client.prototype._checkWalletInfoSig = function(info) {
  var userData = JSON.parse(info.userData);
  var expectedWalletSignature = this._getWalletSignature(
    info.id,
    info.serializedClientMainPublicKey,
    info.serializedClientBackupPublicKey,
    info.serializedServerPublicKey);

  if (!btcutil.secureStrEqual(expectedWalletSignature,
      info.signature)) {
    // TODO handle this error.
    throw new Error('Failed to verify the wallet signature.');
  }
}

var getDeserializedKeys = function(walletInfo) {
  var keys =
    [walletInfo.serializedClientMainPublicKey,
     walletInfo.serializedClientBackupPublicKey,
     walletInfo.serializedServerPublicKey];
  return keys.map(BIP32key.deserialize);
}

// According to benchmarking I did, calculating an HMAC is 2312x faster
// than deriving a new determinstic address when using the NodeJS
// HMAC API and 603x faster when using the Crypto JS API. Therefore,
// it makes sense to store the computed addresses on the server
// and verify their HMAC signatures on the client instead of expecting the
// server and client to re-derive them every time they're used.
// This function starts with the last index that was created, generates
// the specified number of addresses, and stores them on the server
// side in a batch.
Client.prototype.createAddresses = gen(function*(numAddresses) {
  var addresses = [];
  var walletInfo = this.session.walletInfo;
  var keys = getDeserializedKeys(walletInfo);
  var childIndex;
  for (var i = 1; i <= numAddresses; i++) {
    childIndex = walletInfo.lastAddressIndex+i;
    var addressString = btcutil.getDeterministicP2SHAddress(
      childIndex,
      keys,
      2);

    // The signature is used to make it possible for the client to quickly
    // verify that this address belongs to the wallet when this address comes
    // from the server.
    var signature = this._getAddressSignature(
      childIndex, addressString, walletInfo.id);
    addresses.push(
      {childIndex: childIndex,
       address: addressString,
       signature: signature});
  }
  yield this._call(
    'storeAddresses',
    {walletID: walletInfo.id,
     addresses: addresses});
  walletInfo.lastAddressIndex = childIndex;
  return addresses;
});

Client.prototype._getAddressSignature = function(childIndex, addressString, walletID) {
  return btcutil.hmac256(
    childIndex+':'+addressString+':'+walletID,
    this.session.signatureKey);
};

// Query the addresses that the client has stored on the server (TODO add paging).
Client.prototype.getAddresses = gen(function*() {
  var result = yield this._call(
    'getAddresses', {walletID: this.session.walletInfo.id});

  var addresses = result.addresses;
  addresses.forEach(function(address) {
    this._verifyAddressSignature(address, this.session.walletInfo.id);
  }.bind(this));
  return result;
});

Client.prototype._verifyAddressSignature = function(address, walletID) {
  var signature = this._getAddressSignature(
    address.childIndex, address.address, walletID);
  if (!btcutil.secureStrEqual(signature, address.signature)) {
    throw new Error('Invalid address signature\.');
  }  
};

// Spend some coins.
Client.prototype.postTransaction = gen(function*(
    password, walletInfo, destinationAddressString, amount) {

  // Before creating a new transaction we need to query the wallet's
  // unspent transaction outputs. The current implementation relies
  // on the server to query the blockchain and return this data to the client.
  // It's possible to modify the client to get this data from other sources
  // (e.g. some remote API or from a local Bitcoin-Qt node).
  var unspent = (yield this._call('getUnspent',
    {walletID: walletInfo.id,
     amount: amount}));
  if (unspent.totalAmount < amount) {
    throw new Error('The wallet doesn\'t have sufficient funds.');
  }
  var transaction = new Transaction();
  transaction.addOutput(destinationAddressString, amount*100000000);

  // TODO ADD CHANGE ADDRESS + TX FEES

  var inputs = unspent.outputs;
  inputs.forEach(function(input) {
    var inputAddress = input.address;

    // Each unspent txout has an address, a txid, and an index
    // The address contains the signature computed in createAddresses.
    this._verifyAddressSignature(inputAddress, walletInfo.id);

    // The signature is only necessary for client-side verification. When we
    // pass the address back down to the server when calling postTransaction
    // we don't need this signature anymore.
    delete inputAddress['signature'];
    
    transaction.addInput(input.txid, input.index);
  }.bind(this));

  var secretHash = yield this.getSecretHash(password);
  var encryptionKey = this.getEncryptionKey(secretHash);

  // Decrypt the client's main key, which will be used to sign
  // the transaction.
  var serializedClientMainKey = btcutil.aesDecrypt(
    walletInfo.encryptedClientMainKey,
    encryptionKey);

  serializedClientMainKey = sjcl.codec.utf8String.fromBits(serializedClientMainKey);
  encryptionKey = null;
  var clientMainKey = BIP32key.deserialize(serializedClientMainKey);

  // For each input, create its redeemScript, add it to the transaction, and sign it.
  var postTransactionRequestInputs = inputs.map(function(input) {
    var inputAddress = input.address;

    // Create the redeemScript from the wallet's extended public keys and the
    // address's BIP32 child index.
    var publicKeys = getDeserializedKeys(walletInfo)
    var redeemScript = btcutil.getDeterministicP2SHScript(
      inputAddress.childIndex,
      publicKeys,
      2);

    // sanity check
    var scriptHash = redeemScript.toScriptHash();
    var addressString = new Address(scriptHash, 5).toString();
    assert(addressString === inputAddress.address);

    // Derive the client's private key that corresponds to the public key that
    // generated the address using the BIP32 kdf.
    var clientMainKeyAtChildIndex = clientMainKey.ckd(inputAddress.childIndex).getKey();
    var clientSig = transaction.p2shsign(input.index, redeemScript,
      clientMainKeyAtChildIndex);

    var clientSigHex = convert.bytesToHex(clientSig);
    return {
      signature: clientSigHex,
      index: input.index,
      txid: input.txid,
      address: inputAddress,
      script: input.script,
    };
  });

  // Ship it.
  yield this._call('postTransaction', {
      walletKey: Client.getWalletKey(walletInfo.serializedClientMainPublicKey, secretHash),
      walletID: walletInfo.id,
      inputs: postTransactionRequestInputs,
      destinationAddress: destinationAddressString,
      amount: amount,
   });
});


exports.Client = Client;

