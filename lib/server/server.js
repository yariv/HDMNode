"use strict"

// TODO generate unique ids everywhere

var _ = require('underscore');
var btcutil = require('../btcutil.js');
var rpc = require('jsonrpc2');
var crypto = require('crypto');
var assert = require('assert');
var util = require('util');
var serverdb = require('./serverdb.js');
var BIP32key = require('bitcoinjs-lib').BIP32key;
var Script = require('bitcoinjs-lib').Script;
var Transaction = require('bitcoinjs-lib').Transaction;
var Address = require('bitcoinjs-lib').Address;
var base58 = require('bitcoinjs-lib').base58;;
var config = require('./config.js');
var https = require('https');
var suspend = require('suspend');
var resume = suspend.resume;
var Validator = require('jsonschema').Validator;
var convert = require('bitcoinjs-lib').convert;
var sjcl = require('sjcl');
var Sequelize = require('sequelize');
var Promise = require('promise');
var errorMessages = require('../errors.js').errorMessages;

var AUTH_TOKEN_LENGTH = 32;
var ENCRYPTED_CLIENT_MAIN_PRIVATE_KEY_LENGTH = 112;
var SESSION_KEY_VERSION = '1';
var SESSION_KEY_ID_LENGTH = 32;

var log = console.log;

var gen = btcutil.gen;

var getBitcoindClient = function() {
	var port =  8332;
  var hostname = 'localhost';
	var user = 'bitcoinrpc';
	var password = '645d0f32c47ced50a7bb7661682422323b1fa2024678f59e98962633b7b953df';

  return new rpc.Client(port, hostname, user, password);
};

/**
 * Make a JSON RPC call into a local bitcoind server.
 * Used for posting transactions to the network.
 */
var _callBitcoin = gen(function*(method, params) {
  console.log('calling bitcoind %s %s', method, params);
  var client = getBitcoindClient();
  return (yield client.call(method, params, resume()));
});

/**
 * An error type for all errors caused by bad inputs from the client.
 */
function UserError(errorKey, details) {
  if (!errorMessages[errorKey]) {
    throw new Error('invalid errorKey ' + errorKey);
  }
  this.message = errorKey;
  if (details) {
    this.message += ': ' + details;
  }
}

/**
 * A wrapper for executing multiple SQL updates in the same transaction.
 * The parameter is a generator that makes a sequence of SQL updates.
 */
var transaction = function(generator) {
  return new Promise(function(resolve, reject) {
    new Sequelize().transaction(function(tx) {
      suspend.run(function*() {
          var res = yield gen(generator)();
          yield tx.commit();
          resolve(res);
        }, function(err) {
          tx.rollback();
          reject(err);
      });
    });
  });
};

/**
 * Create a new session object and store it in the database.
 */
var createSession = gen(function*(user) {
  // get the app's secret HMAC key
  var key = new Buffer(config.HMAC_SECRET_KEY, 'base64');

  // generate a 32 byte random salt, hex encoded
  var sessionKeyID = crypto.randomBytes(SESSION_KEY_ID_LENGTH).toString('hex');

  // comute the HMAC for the salt using the app's secret key
  var signature = btcutil.hmac256(sessionKeyID, key, 'hex');

  // serialize the session key
  var sessionKey = SESSION_KEY_VERSION+':'+signature+':'+sessionKeyID;

  // store the sesion key in the database
  yield serverdb.Session.create(
    {key: getStoredSessionKey(sessionKey), userID: user.id});
  return sessionKey;
});

/**
 * We store in the DB a hash derived from the session key to prevent attackers
 * that could get read access to the database from hijacking user sessions.
 */
var getStoredSessionKey = function(sessionKey) {
  return btcutil.hmac256('btcfortress session key', sessionKey, 'base64');
}

/**
 * Load the Session object associated with the session key. Before querying the DB,
 * this function checks the session key signature. This is a (likely premature)
 * performance optimization.
 */
var loadSession = gen(function*(sessionKey) {
  // deserialize the session key
  var tokens = sessionKey.split(':');
  if (tokens.length !== 3) {
    return false;
  }

  // check the session key version
  if (tokens[0] !== SESSION_KEY_VERSION) {
    return false;
  }

  // get the app's secret HMAC key
  var key = new Buffer(config.HMAC_SECRET_KEY, 'base64');

  // compute the HMAC from the session key's salt
  var hmac = btcutil.hmac256(tokens[2], key, 'hex');

  // verify the HMAC key from the passed in session key matches the
  // computed HMAC key
  if (!btcutil.secureStrEqual(hmac, tokens[1])) {
    return false;
  }

  // check that the session key could be found in the database.
  // TODO check if the session has expired and delete it
  return (yield serverdb.Session.find({where: {key: getStoredSessionKey(sessionKey)}}));
});

/**
 * Wrap the input function with a function that checks that the API call included a
 * valid session key. If the session is valid, the first parameter to the function
 * will be the Session object with the logged in User object as an added property.
 * All authenticated API handlers should use this function to enforce session checks.
 */
var authWrapper = function(func) {
  return gen(function*() {
    var args = Array.prototype.slice.call(arguments);
    var params = args[1];
    var sessionKey = params.sessionKey;
    if (!sessionKey) {
      throw new UserError('SESSION_KEY_REQUIRED');
    }
    var session = yield loadSession(sessionKey);
    if (!session) {
      throw new UserError('INVALID_SESSION_KEY');
    }
    var user = yield serverdb.User.find({where: {id: session.userID}});
    
    // We dangle the user off of the session object. It's admittedly not
    // the cleanest approach because 'user' isn't defined as a field in
    // serverdb.Session's schema.
    session.user = user;
    args.splice(1, 0, session);
    args.push(resume());
    return (yield gen(func).apply(null, args));
  });
};

// This dictionary contains all the server side API calls.
// Each API call is specified as a dictionary with a 'params' and a
// 'func' field. 'params' is a JSON schema object that describes the
// input parameters. This JSON schema is automatically enforced on every
// API call. 'func' is a function that takes two parameters: 'opt' and 'params'.
// 'opt' is the raw HTTP server connection data. 'params' is a dictionary containing
// the parsed input parameters. 
var api = {};

/**
 * Register a new user account.
 */
api.register = {params:
  {email: {},  // The user's email
   authToken: {}, // An auth token that's a hash of the password + a random salt.
   randomSalt: {}, // The random salt that was used to derive the authToken.
   userData: {} // An arbitrary string that the server will return to the client on login.
   }}; 
api.register.func = gen(function*(opt, params) {
  var user = yield loadUser(params.email);
  if (user) {
    throw new UserError('EMAIL_ALREADY_REGISTERED');
  }

  if (new Buffer(params.authToken, 'base64').length !== 32) {
    throw new UserError('INVALID_AUTH_TOKEN');
  }
  if (new Buffer(params.randomSalt, 'base64').length !== 16) {
    throw new UserError('INVALID_RANDOM_SALT');
  }

  var serverAuthTokenSalt = new crypto.randomBytes(16);
  var authTokenHash = getAuthTokenHash(
    new Buffer(params.authToken, 'base64'), serverAuthTokenSalt);

  var user = yield serverdb.User.create(
    {email: params.email,
     authTokenHash: authTokenHash,
     userData: params.userData,
     clientRandomSalt: params.randomSalt,
     serverAuthTokenSalt: serverAuthTokenSalt.toString('base64')});
  
  // Note: createSession doesn't have to be called in the same transaction
  // as serverdb.User.create. Even if createSession fails, a new session
  // will be created for the user on the next login attempt.
  var sessionKey = (yield createSession(user));
  return {sessionKey: sessionKey};
});

/**
 * Return the hash of the auth token plus a random server side salt.
 */
var getAuthTokenHash = function(authToken, salt) {
  // A KDF is already applied on the client side to compute the authToken so
  // a simple HMAC call is sufficient from a security perspective to derive
  // the hash of the authToken + salt.
  return crypto.createHmac('sha256', salt).update(authToken).digest('base64');
};

/**
 * Return true if the the computed auth token hash matches the expected
 * auth token hash.
 */
var checkAuthToken = gen(function*(
    authToken, serverAuthTokenSalt, expectedAuthTokenHash) {
  var authTokenHash = getAuthTokenHash(
    authToken, serverAuthTokenSalt);
  return btcutil.secureStrEqual(authTokenHash, expectedAuthTokenHash);
});

/**
 * Load the User object with the provided email address.
 */
var loadUser = gen(function*(email) {
  return (yield serverdb.User.find({where: {email: email}}));
});

/**
 * Return the randomSalt value that the client passed in in the register call.
 * This is necessary so that the client can compute the same authToken that
 * was used for registration, as we can't expect users to remember a long
 * random salt in addition to their passwords.
 *
 * Security note: This could potentially make user passwords vulnerable to a rainbow
 * table attacks from the server if the server decided to return the same
 * salt value to all users and then look up the resulting password hashes in
 * a specially crafted rainbow table. To mitigate the risk of such attack, clients should
 * include the user's email as well as a global constant in the salt. Doing so would
 * set a higher minimum level of enthropy on the passwords' salts.
 * Another security concern is that attackers could guess user's emails and try
 * to access those users' salts. I don't think this attack would yield any value
 * to the attacker because the salts are just random strings that are useless by
 * themselves. The most an attacker could gain from this is a list of valid emails
 * but that could hopefully be mitigated with effective rate limiting.
 *
 * Despite these security concerns, we kept this method because in the worst case it
 * adds no security to the password hashes but in the normal case it increases such
 * security.
 */
api.getRandomSalt = {params: {
  email: {}}};
api.getRandomSalt.func = gen(function*(opt, params) {
  // TODO 2FA
  var user = yield loadUser(params.email);
  if (!user) {
    throw new UserError('INVALID_EMAIL');
  }
  return {randomSalt: user.clientRandomSalt};
});

/**
 * Log in the user.
 */
api.login = {params:
  {email: {}, // the user's email
   authToken: {} // the same authToken that the client passed to register()
  }};
api.login.func = gen(function*(opt, params) {
  var throwParamErr = function() {
    throw new UserError('INVALID_EMAIL_OR_PASSWORD');
  }
  var user = yield loadUser(params.email);
  if (!user) {
    throwParamErr();
  }

  if (!(yield checkAuthToken(
      new Buffer(params.authToken, 'base64'),
      new Buffer(user.serverAuthTokenSalt, 'base64'),
      user.authTokenHash))) {
    throwParamErr();
  }

  var wallet;
  if (user.externalWalletID) {
    wallet = yield getUserWallet(user, user.externalWalletID);
    if (!wallet.signature) {
      // the client failed to store the wallet's signature,
      // most likely due to a network error. rather than returning this wallet
      // id, we'll just return a null wallet id.
      // this will force the client to create a new wallet and hopefully
      // successfully store its signature as well.
      user.externalWalletID = null;
      wallet = null;
      yield user.save();
    }
  }
  var sessionKey = yield createSession(user);
  var res =
    {sessionKey: sessionKey,
     userData: user.userData};
  if (wallet) {
    res.walletInfo =
      {serializedClientMainPublicKey: wallet.serializedClientMainPublicKey,
       serializedClientBackupPublicKey: wallet.serializedClientBackupPublicKey,
       serializedServerPublicKey: wallet.serializedServerPublicKey,
       userData: wallet.userData,
       signature: wallet.signature,
       id: wallet.externalID,
       lastAddressIndex: wallet.lastAddressIndex};
  }
  return res;
});

/**
 * Check if the session key is valid and that it matches a session that belongs to
 * the user with the given email and userData fields.
 * TODO only enable this method for testing.
 */ 
api.checkSession =
  {params:
   {sessionKey: {},
    email: {},
    userData: {}}},
api.checkSession.func = gen(function*(opt, params) {
  var session = yield loadSession(params.sessionKey);
  if (!session) {
    throw new UserError('INVALID_SESSION_KEY');
  }
  var user = yield serverdb.User.find({where: {id: session.userID}});
  if (!user) {
    throw new Error('USER_NOT_FOUND');
  }
  if (user.email !== params.email) {
    throw new UserError('INVALID_EMAIL');
  }
  if (user.userData !== params.userData) {
    throw new UserError('INVALID_USER_DATA');
  }
});

api.logout = {params: {}};
api.logout.func = authWrapper(function*(opt, session) {
  yield session.destroy();
  return true;
});

/**
 * Create a new wallet for the user. This should be called right after register().
 */
api.createWallet = {params:
  {walletKey: {}, // A 256 bit value encoded in base64. The client must send the same
                  // value when calling postTransaction(). This value is used to encrypt
                  // the server's private key in the server's DB (the server only needs
                  // its own private key when co-signing transactions so there's no need
                  // to store it in an unencrypted form).
   serializedClientMainPublicKey: {}, // the public key for the client's main
                                      // (online) private key.
   serializedClientBackupPublicKey: {}, // the public key for the client's
                                        //backup (offline) private key
   userData: {} // Arbitrary data (such as encrypted private keys)
                // the client may store with the wallet.
   }};
api.createWallet.func = authWrapper(function*(opt, session, params) {

  if (session.user.externalWalletID) {
    throw new UserError('USER_WALLET_ALREADY_EXISTS');
  }

  if (new Buffer(params.walletKey, 'base64').length !== 32) {
    throw new UserError('INVALID_WALLET_KEY');
  }

  var clientMainPublicKey = checkPublicKeyParam(
    params.serializedClientMainPublicKey);
  var clientBackupPublicKey = checkPublicKeyParam(
    params.serializedClientBackupPublicKey);
  if (params.serializedClientMainPublicKey ===
      params.serializedClientBackupPublicKey) {
    throw new UserError('INVALID_PUBLIC_KEY');
  }

  // Generate the server's private key
  var randomSeed = btcutil.getRandomBytes(32);
  var serverPrivateKey = BIP32key.fromMasterKey(randomSeed);
  var serializedServerPrivateKey = serverPrivateKey.serialize();

  // Encrypt the server's private key with the wallet key
  var serverPrivateKeyEncryptedWithWalletKey =
    btcutil.aesEncrypt(
      sjcl.codec.utf8String.toBits(serializedServerPrivateKey),
      sjcl.codec.base64.toBits(params.walletKey));

  var serverPublicKey = serverPrivateKey.getPub();
  var serializedServerPublicKey = serverPublicKey.serialize();

  // Create a random string to identify the wallet.
  // TODO switch this to a deterministic value derived from the wallet's public keys(?).
  var externalID = base58.encode(
    Array.prototype.slice.apply(crypto.randomBytes(16)));

  session.user.externalWalletID = externalID;
  yield transaction(function*() {
    var wallet = yield serverdb.Wallet.create({
      externalID: externalID,
      userID: session.user.id,
      serverPrivateKeyEncryptedWithWalletKey:
        serverPrivateKeyEncryptedWithWalletKey,
      serializedClientMainPublicKey: params.serializedClientMainPublicKey,
      serializedClientBackupPublicKey: params.serializedClientBackupPublicKey,
      serializedServerPublicKey: serializedServerPublicKey,
      userData: params.userData});
    yield session.user.save();
  });

  return {
    serializedServerPublicKey: serializedServerPublicKey,
    walletID: externalID,
  };
    
});

var checkPublicKeyParam = function(serializedPublicKey) {
  var throwErr = function() { throw new UserError('INVALID_PUBLIC_KEY'); };
  var publicKey;
  try {
    publicKey = BIP32key.deserialize(
      serializedPublicKey);
  } catch (e) {
    throwErr();
  }
  if (publicKey.type !== 'pub') {
    throwErr();
  }
  return publicKey;
}

var getUserWallet = gen(function*(user, walletID) {
  // TODO ensure this call uses an index
  // (maybe query the wallet by another field?)
  var wallet = yield serverdb.Wallet.find({where: {externalID: walletID}});
  if (!wallet || (wallet.userID !== user.id)) {
    throw new UserError('INVALID_WALLET_ID');
  }
  return wallet;
});

/**
 * The client should call this after createWallet(). The signature is derived in
 * Client.prototype._getWalletSignature(). On future sessions,
 * this ensures the client that the wallet info is accurate.
 */ 
api.setWalletSignature = {params: {
  walletID: {},
  signature: {}}};
api.setWalletSignature.func = authWrapper(
  function*(opt, session, params) {

  var sigBuf = new Buffer(params.signature, 'base64');
  if (sigBuf.length != btcutil.SIGNATURE_LENGTH) {
    throw new UserError('INVALID_SIGNATURE');
  }

  var wallet = yield getUserWallet(session.user, params.walletID);

  if (wallet.signature) {
    throw new UserError('SIGNATURE_ALREADY_WRITTEN');
  }
  wallet.signature = params.signature;

  // TODO only update the signature field
  yield wallet.save();
  return {};
});

/**
 * Store server side an array of addresses that belong to this wallet. Although
 * the addresses can be derived deterministically, generating an address from
 * 3 derived keys is pretty slow. Rather than recomputing the addresses every time
 * we need to query the wallet's balance we store them once and use their cached
 * values.
 */ 
api.storeAddresses = {params: {
  walletID: {},
  addresses: {
    type: 'array',
    minItems: 1,
    required: true,
    items: [{
      childIndex: {type: 'integer', require: true, minimum: 0},
      addressString: {type: 'string', required: true},
      signature: {type: 'string', required: true}}]}}};
api.storeAddresses.func = authWrapper(function*(
    opt, session, params) {
  
  var wallet = yield getUserWallet(session.user, params.walletID);
  var lastAddressIndex = wallet.lastAddressIndex;

  var addresses = params.addresses.map(function(addressParam) {
    if (addressParam.childIndex <= lastAddressIndex) {
      throw new UserError('ADDRESS_ALREADY_CREATED');
    }
    if (addressParam.childIndex !== (lastAddressIndex+1)) {
      throw new UserError('ADDRESS_NOT_SEQUENTIAL');
    }

    var expectedAddressString = getWalletAddressString(
      wallet, addressParam.childIndex);
    if (addressParam.address !== expectedAddressString) {
      throw new UserError('INVALID_ADDRESS_STRING_AND_CHILD_NUM');
    }
    lastAddressIndex = addressParam.childIndex;
    return {
      childIndex: addressParam.childIndex,
      addressString: addressParam.address,
      walletID: wallet.id,
      signature: addressParam.signature}
  });
  wallet.lastAddressIndex = lastAddressIndex;

  yield transaction(function*() {
    yield serverdb.Address.bulkCreate(addresses);
    yield wallet.save();
  });
  return {};
});

var getWalletPublicKeys = function(wallet) {
  return [
    BIP32key.deserialize(wallet.serializedClientMainPublicKey),
    BIP32key.deserialize(wallet.serializedClientBackupPublicKey),
    BIP32key.deserialize(wallet.serializedServerPublicKey)
  ];
};

var getWalletAddressScript = function(wallet, childIndex) {
  return btcutil.getDeterministicP2SHScript(
    childIndex,
    getWalletPublicKeys(wallet),
    2);
};

var getWalletAddressString = function(wallet, childIndex) {
  return btcutil.getDeterministicP2SHAddress(
    childIndex,
    getWalletPublicKeys(wallet),
    2);
};

/**
 * Return the addresses that belong to the wallet.
 * TODO implement pagination.
 */
api.getAddresses = {params: {
  walletID: {}}};
api.getAddresses.func = authWrapper(function*(opt, session, params) {
  var wallet = yield getUserWallet(session.user, params.walletID);
  var addresses = yield getWalletAddresses(wallet);
  var resultAddresses = addresses.map(getAddressResult, addresses);
  return {addresses: resultAddresses};
});

var getAddressResult = function(address) {
  return {
    childIndex: address.childIndex,
    address: address.addressString,
    signature: address.signature,
  };
}

var getWalletAddresses = gen(function*(wallet) {
  var addresses = yield serverdb.Address.findAll(
    {where: {walletID: wallet.id}});
  return addresses;
});


/**
 * Return the unspent txouts for the wallet, stopping after the given amount has
 * been accumulated.
 */
api.getUnspent = {params: {
  walletID: {},
  amount: {type: 'float'}}};
api.getUnspent.func = authWrapper(function*(
    opt, session, params) {
  var amount = params.amount;
  if (!amount || (amount <= 0)) {
    throw new UserError('INVALID_AMOUNT');
  }

  var wallet = yield getUserWallet(session.user, params.walletID);
  return (yield getUnspent(session.user, wallet, amount));
});

var getUnspent = gen(function*(user, wallet, amount) {
  var addresses = yield getWalletAddresses(wallet);
  var addressStringsToAddresses = {};
  var addressStrings = addresses.map(function(address) {
    addressStringsToAddresses[address.addressString] = address;
    return address.addressString;
  });

  // TODO make it possible to use bitcore insights or other API providers.
  var url = "https://blockchain.info/unspent?active="+addressStrings.join('|');
  var res;
  try {
    res = (yield btcutil.httpsGetJSON(url));
  } catch (err) {
    if ((err.code === 500) && (err.message === 'No free outputs to spend')) {
      return {outputs: [], totalAmount: 0};
    }
  }

  var unspentOutputs = res.unspent_outputs;
  var result = [];
  var totalAmount = 0;
  for (var i = 0; i < unspentOutputs.length; i++) {
    var unspentOutput  = unspentOutputs[i];
    var value = unspentOutput.value;
    var outputIndex = unspentOutput.tx_output_n;
    var script = new Script(unspentOutput.script);

    // This is hacky but Script.toAddress() is broken for this
    // use case.
    var address = new Address(script.chunks[1], 5);
    var outputAddressString = address.toString();
    var outputAddress = addressStringsToAddresses[outputAddressString];
    if (!outputAddress) {
      // this shouldn't happen
      throw new Error('Unexpected address.');
    }
    
    // reverse the hex encoded tx_hash to get the correct tx_hash
    // (this is apparently a 'feature' of the blockchain.info api. sigh)
    // (i'm sure there's a cleverer way of doing this)
    var chunks = [];
    var txHash = unspentOutput.tx_hash;
    for (var i = 0; i < txHash.length; i += 2) {
      chunks.push(txHash.slice(i, i+2));
    }
    chunks.reverse();
    var txHashReversed = '';
    for (var i = 0; i < chunks.length; i++) {
      txHashReversed += chunks[i];
    }

    result.push({
      txid: txHashReversed,
      index: outputIndex,
      address: getAddressResult(outputAddress),
    });
    totalAmount += value/Math.pow(10,3);
    if ((amount > 0) && (totalAmount >= amount)) {
      break;
    }
  }

  return {outputs: result,
          totalAmount: totalAmount}
});

// Describes the inputs parameter for the postTransaction() method.
var INPUTS_SCHEMA = {
  type: 'array',
  items: {
    type: 'object',
    properties: {
      signature: {
        type: 'string',
        required: true,
      },
      index: {
        type: 'integer',
        required: true,
        minimum: 0,
      },
      txid: {
        type: 'string',
        required: true,
        minLength: 64,
        maxLength: 64,
      },
      address: {
        type: 'object',
        properties: {
          address: {
            type: 'string',
            required: true,
          },
          childIndex: {
            type: 'integer',
            minimum: 0,
            required: true,
          }
        },
        required: true,
      },
    },
  },
  minItems: 1,
};

/**
 * Post a transaction to the blockchain.
 *
 * NOTE this implementation isn't complete. The transaction does NOT
 * get posted at the moment.
 */
api.postTransaction = {params: {
  walletID: {}, // the id of the wallet
  walletKey: {}, // the 256 bit value that was passed into createWallet()
  inputs: INPUTS_SCHEMA, // the unspent txouts that should be used as inputs
                         // for the transaction
  destinationAddress: {}, // the destination address
  amount: {type: 'integer', minimum: 0}}}; // in satoshis
api.postTransaction.func = authWrapper(function*(opt, session, params) {
  var amount = params.amount/Math.pow(10,5);

  try {
    var destinationAddress = new Address(params.destinationAddress);
  } catch (e) {
    throw new UserError('INVALID_DESTINATION_ADDRESS');
  }

  var wallet = yield getUserWallet(session.user, params.walletID);

  var walletKeyBytes = convert.base64ToBytes(params.walletKey);
  if (walletKeyBytes.length !== 32) {
    throw new UserError('INVALID_WALLET_KEY');
  }

  try {
    var serializedServerPrivateKey = btcutil.aesDecrypt(
      wallet.serverPrivateKeyEncryptedWithWalletKey,
      sjcl.codec.bytes.toBits(walletKeyBytes));
  } catch (e) {
    throw new UserError('INVALID_WALLET_KEY');
  }


  var addressStrings = params.inputs.map(function(input) {
    var inputAddress = input.address;

    try {
      var address = new Address(inputAddress.address);
    } catch (e) {
      throw new UserError('INVALID_INPUT_ADDRESS');
    }

    return inputAddress.address;
  });

  var addresses = yield serverdb.Address.findAll(
    {where: {addressString: addressStrings}});

  if (addresses.length === 0) {
    throw new UserError('INVALID_INPUT_ADDRESS');
  }

  addresses.forEach(function(address) {
    if (address.walletID !== wallet.id) {
      throw new UserError('INVALID_INPUT_ADDRESS');
    }
  });

  var serverPrivateKey = BIP32key.deserialize(
    sjcl.codec.utf8String.fromBits(serializedServerPrivateKey));
  
  var transaction = new Transaction();
  transaction.addOutput(params.destinationAddress, amount*Math.pow(10,8));

  // TODO query the blockchain and verify that the inputs
  // haven't been spent?

  params.inputs.forEach(function(input, inIndex) {

    transaction.addInput(input.txid, input.index);

    var redeemScriptBytes = getWalletAddressScript(
      wallet, input.address.childIndex);

    var inputAddress = input.address;

    var redeemScript = new Script(redeemScriptBytes);
    var scriptAddress = new Address(redeemScript.toScriptHash(), 5);
    if (scriptAddress.toString() !== inputAddress.address) {
      throw new UserError('INPUT_ADDRESS_MISMATCH');
    }

    var serverPrivateKeyAtchildIndex =
      serverPrivateKey.ckd(inputAddress.childIndex);
    
    var scriptPubKey = Script.createOutputScript(scriptAddress);

    var serverSig = transaction.p2shsign(
      inIndex, scriptPubKey, serverPrivateKeyAtchildIndex.getKey());
    var clientSig = convert.base64ToBytes(input.signature);

    transaction.applyMultisigs(
      inIndex, redeemScript, [clientSig, serverSig]);
  });

  var txHex = transaction.serializeHex();

  // TODO post to the network
});

var start = gen(function*(port, hostname) {
  if (!serverdb.initialized()) {
    yield serverdb.init();
  }

  var server = new rpc.Server();
  expose(server, 'register', api.register);
  expose(server, 'getRandomSalt', api.getRandomSalt);
  expose(server, 'login', api.login);
  expose(server, 'logout', api.logout);
  expose(server, 'checkSession', api.checkSession);
  expose(server, 'createWallet', api.createWallet);
  expose(server, 'setWalletSignature', api.setWalletSignature);
  expose(server, 'storeAddresses', api.storeAddresses);
  expose(server, 'getAddresses', api.getAddresses);
  expose(server, 'getUnspent', api.getUnspent);
  expose(server, 'postTransaction', api.postTransaction);

  var httpServer = server.listen(port, hostname);
  httpServer.on('error', console.error);
});

var expose = function(server, name, handler) {
  for (var paramName in handler.params) {
    var param = handler.params[paramName];
    if (!param.type) {
      param.type = 'string';
    }
    if (!param.required) {
      param.required = true;
    }
  }
  var schema = {
    type: 'object',
    properties: handler.params
  };

  server.expose(name, suspend.async(function*(params, opt) {
    try {
      var res = (new Validator()).validate(params, schema);
      if (res.errors.length) {
        // for now we just return the first error to avoid overly
        // complex error messages
        throw new UserError('INVALID_PARAM', res.errors[0].stack);
      }
      return (yield handler.func.apply(null, [opt, params, resume()]));
    } catch (err) {
      if (err instanceof UserError) {
        throw err.message;
      }
      // only Error objects have a stack
      console.trace(err.stack ? err.stack : err);
      throw 'Internal error';
    }
  }));
};

exports.start = start;

var main = function(){
  var host = 'localhost';
  start(8080, host, function(err, res) {
    log([err, res]);
  });
}

if (require.main === module) {
    main();
}
