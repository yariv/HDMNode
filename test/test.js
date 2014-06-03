"use strict"

var config = require('../lib/server/config.js');

// override the config vals with the hardcoded one for the test
var testConfig = require('./testconfig.js');
for (var name in config) {
  config[name] = testConfig[name];
}

var rpc = require('jsonrpc2');
var Server = require('../lib/server/server.js');

var Client = require('../lib/client/client.js').Client;
var btcutil = require('../lib/btcutil.js');
var serverdb = require('../lib/server/serverdb.js');
var assert = require('assert');
var _ = require('underscore');
var BIP32key = require('bitcoinjs-lib').BIP32key;
var crypto = require('crypto');
var Script = require('bitcoinjs-lib').Script;
var Crypto = require('bitcoinjs-lib').Crypto;
var Transaction = require('bitcoinjs-lib').Transaction;
var ECKey = require('bitcoinjs-lib').ECKey;
var convert = require('bitcoinjs-lib').convert;

var fs = require('fs');
var suspend = require('suspend');
var Promise = require('promise');
var errorMessages = require('../lib/errors.js').errorMessages;
var sjcl = require('sjcl');
var gen = btcutil.gen;

Client.setAvoidScrypt(true);

var getUniqueEmail = function() {
  return 'foo'+new Date().getTime()+'@bar.com';
}

var PASSWORD = 'password';
var PORT = 1337;
var HOSTNAME = 'localhost';
var KEY_LENGTH = 66;

var getClient = function() {
  return new Client(PORT, HOSTNAME);
}

var getLoggedInClient = gen(function*(email) {
  email = email || getUniqueEmail();
  var client = getClient();
  yield client.register(email, PASSWORD);
  return client;
});

var log = console.log;

var serverStarted = false;
var setUp = suspend.async(function*() {
  // Make sure any tables that failed to be dropped from
  // any previous unfinished runs are dropped before the start of
  // a new test.
  yield serverdb.destroy();
  
  // We need to start the server once and only once per test
  // suite run.
  if (!serverStarted) {
    yield Server.start(PORT, HOSTNAME);
    serverStarted = true;
  } else {
    yield serverdb.init();
  }
});

var tearDown = suspend.async(function*() {
  // Delete all the data at the end of each test to provide
  // test isolation.
  yield serverdb.destroy();
});

// A wrapper for all test generator functions.
var testFunc = function(func) {
  return function(test) {
    suspend.run(
      function*() {
        yield gen(func)(test);
      },
      function(err) {
        if (err) {
          console.log(err.stack ? err.stack : err);
        }
        test.equal(err, null);
        test.done();
      });
  };
};

// NodeUnit's test.throws is incompatible with generators so we
// use this wrapper instead. It takes the test object, a generator
// function and the expected error as a regexp or a string.
var throws = function(test, func, expectedErr) {
  return new Promise(function(resolve, reject) {
    suspend.run(func, function(err, res) {
      if (typeof expectedErr === 'string') {
        expectedErr = new RegExp(expectedErr);
      }
      test.ok(expectedErr.test(err), expectedErr + ' didn\'t match ' + err);
      if (!expectedErr.test(err)) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
};

var testPasswordLength = testFunc(function*(test) {
  var client = getClient();
  yield throws(test, function*() {
    yield client.register('bobbb@foo.com', 'abcdef');
  }, /Password must be at least 7 characters long\./);
});

var testRegister = testFunc(function*(test) {
  var client = getClient();
  var email = getUniqueEmail();

  var testInvalidParam = gen(function*(paramRewriteFunc, expectedErr) {
    var _call = client._call;
    client._call2 = _call;
    client._call = gen(function*(method, params) {
      if (method === 'register') {
        paramRewriteFunc(params);
      }
      return (yield client._call2(method, params));    
    });
    yield throws(test, function*() {
        yield client.register(email, PASSWORD);
    }, expectedErr);
    client._call = _call;
  });

  yield testInvalidParam(function(params) {
    params.authToken = convert.bytesToBase64(crypto.randomBytes(1));
  }, 'INVALID_AUTH_TOKEN');
  yield testInvalidParam(function(params) {
    params.randomSalt = convert.bytesToBase64(crypto.randomBytes(1));
  }, 'INVALID_RANDOM_SALT');
  
  var session = yield client.register(email, PASSWORD);
  test.ok((yield client.checkSession(session)));

  yield throws(test, function*() {
    var session1 = _.clone(session);
    session1.email = "foo";
    yield client.checkSession(session1);
  }, 'INVALID_EMAIL');

  yield throws(test, function*() {
    var session1 = _.clone(session);
    session1.encryptedAESKey = "foo";
    yield client.checkSession(session1);
  }, 'INVALID_USER_DATA');

  // Registering with the same email twice should fail.
  yield throws(test, function*() {
    yield client.register(email, PASSWORD);
  }, 'EMAIL_ALREADY_REGISTERED');

});

var testLogin = testFunc(function*(test) {
  var client = yield getLoggedInClient();
  var session = client.session;
  var email = session.email;

  // Logging in with the wrong password should fail.
  yield throws(test, function*() {
    yield client.login(email, 'password2');
  }, 'INVALID_EMAIL_OR_PASSWORD');

  var doLogin = gen(function*() {
    var session = yield client.login(email, PASSWORD);
    test.ok((yield client.checkSession(session)));
    return session;
  });

  // Calling 'login' after 'register' should return a different
  // session key.
  var session2 = yield doLogin();

  test.notDeepEqual(session, session2);
  // The original session key returned from 'register' should remain valid.
  test.ok((yield client.checkSession(session2)));

  // Successive calls to 'login' should return different session
  // keys.
  var session3 = yield doLogin();
  test.notDeepEqual(session2, session3);

  yield client.logout();

  // The session key from the last 'login' call should remain valid.
  test.ok((yield client.checkSession(session2)));

  // Logging out again should fail through a client side error
  // because there's no session data in the local client state.
	yield throws(test, function*() {
	  yield client.logout();
	}, /Not logged in\./);

  client.session = session3;
  // Logging out with a bad session key should fail.
	yield throws(test, function*() {
	  yield client.logout();
	}, 'INVALID_SESSION_KEY');
  client.session = null;

  yield throws(test, function*() {
	  yield client.checkSession(session3);
  }, 'INVALID_SESSION_KEY');

  // Non logged out session should continue to be active
	test.ok((yield client.checkSession(session2)));
});

var testVerifyUserDataSignature = testFunc(function*(test) {
  var client = yield getLoggedInClient();

  // stub the client's _call method to make it behave as if the server
  // returned an invalidly signed encrypted encryption key.
  var _call = client._call;
  client._call2 = _call;
  var testValue = gen(function*(invalidValue) {
      client._call = gen(function*(method, params) {
        if (method === 'login') {
          return {userData: invalidValue, sessionKey: 'bar'};
        }
        return (yield client._call2(method, params));
      });

      yield throws(test, function*() {
        yield client.login(client.session.email, PASSWORD);
      }, /The server returned invalid user data\./);
    });

  yield testValue('foo');
  yield testValue('{ciphertext:"foo",iv:"bar",signature:"baz"}');

  client._call = _call;
});

var testRequiresAuth = testFunc(function*(test) {
  var client = getClient();

  // TODO audit this list
  var methods = ['logout', 'createWallet'];
  for (var i in methods) {
    yield throws(test, function*() {
      yield client._call(methods[i], {});
    }, 'SESSION_KEY_REQUIRED');
  }
});

var testCreateWallet = testFunc(function*(test) {
  var client = yield getLoggedInClient();
  var clientBackupPublicKey = getClientBackupPublicKey();

  // This test fails on the client side because the client
  // should fail to decrypted the encrypted encryption key locally
  // before even communicating with the server.
  yield throws(test, function*() {
    yield client.createWallet(
      'foo', clientBackupPublicKey);
  }, 'INVALID_PASSWORD');

  var testError = gen(function*(params, err) {
    yield throws(test, function*() {
      yield client._call('createWallet', params);
    }, err);
  });

  var params = {
    walletKey: '',
    serializedClientMainPublicKey: '',
    serializedClientBackupPublicKey: '',
    userData: ''};
  
  yield testError(params, 'INVALID_WALLET_KEY');

  var validPubkey = BIP32key.fromMasterKey('asdf').getPub().serialize();
  var walletKey = crypto.randomBytes(32).toString('base64');
  
  params.walletKey = crypto.randomBytes(32).toString('base64');
  // This test ensures that if the client does indeed send the server
  // a bad auth token, the server catches the error.
  var testInvalidPublicKey = gen(function*(pubkey) {
    var params1 = _.clone(params);
    params1.serializedClientMainPublicKey = pubkey;
    yield testError(params1, 'INVALID_PUBLIC_KEY');

    var params2 = _.clone(params);
    params2.serializedClientBackupPublicKey = pubkey;
    yield testError(params2, 'INVALID_PUBLIC_KEY');
  });

  yield testInvalidPublicKey('asdf');

  // private keys should fail
  yield testInvalidPublicKey(BIP32key.fromMasterKey('asdf').serialize());

  // identical public keys should fail
  params.serializedClientMainPublicKey = validPubkey;
  params.serializedClientBackupPublicKey = validPubkey;
  yield testError(params, 'INVALID_PUBLIC_KEY');

  params.serializedClientBackupPublicKey =
    BIP32key.fromMasterKey('asdf1234').getPub().serialize();
  
  // Test that users can only create a single wallet (this
  // limitation could be removed in the future).
  var result = yield client.createWallet(
    PASSWORD, clientBackupPublicKey);
  var walletInfo = client.session.walletInfo;
  yield throws(test, function*() {
    yield client.createWallet(
      PASSWORD, clientBackupPublicKey);
  }, 'USER_WALLET_ALREADY_EXISTS');

  // Test that the walletInfo that's returned on login matches the walletInfo
  // that's returned from createWallet.
  var email = client.session.email;
  yield client.logout();
  yield client.login(email, PASSWORD);
  var walletInfo2 = client.session.walletInfo;
  test.deepEqual(walletInfo, walletInfo2);

  // Verify that the server's public key matches the BIP32 public key
  // spec.
  var serializedServerPublicKey = result.serializedServerPublicKey;
  var serverPublicKey = BIP32key.deserialize(
    serializedServerPublicKey);
  test.equal(serverPublicKey.type, 'pub');

  // Verify that the encrypted user private key is returned from the
  // server and that decrypting it yields the expected private key.
  var info = client.session.walletInfo;
  var secretHash = yield client.getSecretHash(PASSWORD);
  var encryptionKey = client.getEncryptionKey(secretHash);
  var userData = JSON.parse(info.userData);
  var serializedClientMainKeyFromServer =
    sjcl.codec.utf8String.fromBits(
      btcutil.aesDecrypt(
        userData.encryptedClientMainKey,
        encryptionKey));

  test.equal(result.clientMainKey.serialize(),
    serializedClientMainKeyFromServer);
  test.equal(info.signature, result.signature);
  test.equal(info.serializedClientBackupPublicKey,
    clientBackupPublicKey.serialize());
  test.equal(info.serializedServerPublicKey, result.serializedServerPublicKey);

  // Check the wallet's signature.
  var combinedKey =
    info.id +
    info.serializedClientMainPublicKey +
    info.serializedClientBackupPublicKey +
    info.serializedServerPublicKey +
    JSON.stringify(userData.encryptedClientMainKey);

  var signatureKey = client.session.signatureKey;
  var expectedSignature = btcutil.hmac256(
    combinedKey, signatureKey);
  test.equal(info.signature, expectedSignature);

  // Try to set an invalid signature.
  yield throws(test, function*() {
    yield client._call('setWalletSignature',
      {walletID: 'foo', signature: 'bar'});
  }, 'INVALID_SIGNATURE');

  // Try to set a signature for an invalid wallet.
  yield throws(test, function*() {
    yield client._call(
      'setWalletSignature',
      {walletID: 'foo', signature: expectedSignature});
  }, 'INVALID_WALLET_ID');

  // Try to set the same wallet's signature twice.
  yield throws(test, function*() {
    yield client._call(
      'setWalletSignature',
      {walletID: result.walletID,
       signature: expectedSignature});
  }, 'SIGNATURE_ALREADY_WRITTEN');

});

// Test that if a wallet is created but setWalletSignature isn't called (or if it fails)
// the server discards the wallet. This avoids complicating the client with having
// to handle the case where the wallet isn't signed. It's easier to just force the client
// to create a new wallet.
var testSetSignatureFailure = testFunc(function*(test) {
  var client = yield getLoggedInClient();
  var clientBackupPublicKey = getClientBackupPublicKey();
  var _call = client._call;
  client._call2 = _call;
  client._call = gen(function*(method, params) {
    if (method == 'setWalletSignature') {
      return;
    }
    return (yield client._call2(method, params));
  });
  var result = yield client.createWallet(PASSWORD, clientBackupPublicKey);
  var email = client.session.email;
  client._call = _call;

  yield client.logout();
  var result = yield client.login(email, PASSWORD);
  test.ok(!result.walletID);
});

// Test that the server encrypts the server's private key with the wallet's key before
// storing it in the database.
var testServerPrivateKeyEncryption = testFunc(function*(test) {
  var client = yield getLoggedInClient();
  var clientBackupPublicKey = getClientBackupPublicKey();
  var result = yield client.createWallet(
    PASSWORD, clientBackupPublicKey);
  var serializedServerPublicKey = result.serializedServerPublicKey;
  var serverPublicKey = BIP32key.deserialize(
    serializedServerPublicKey);  
  
  // We go straight into the server db to ensure that the server private key
  // could be decrypted with the wallet key.
  var rawWallet =
    yield serverdb.Wallet.find(
      {where: {serializedServerPublicKey: serializedServerPublicKey}});
  test.ok(rawWallet);

  var serverPrivateKeyEncryptedWithWalletKey =
    rawWallet.serverPrivateKeyEncryptedWithWalletKey;

  var serializedClientMainPublicKey =
    result.clientMainKey.getPub().serialize();
  var secretHash = yield client.getSecretHash(PASSWORD);
  var walletKey =
    Client.getWalletKey(
      serializedClientMainPublicKey,
      secretHash);

  var serializedServerPrivateKey = sjcl.codec.utf8String.fromBits(
    btcutil.aesDecrypt(
      rawWallet.serverPrivateKeyEncryptedWithWalletKey,
      sjcl.codec.base64.toBits(walletKey)));

  // Test that the decrypted private key is indeed the private key
  // corresponding to the server's public key.
  var serverPrivateKey = BIP32key.deserialize(serializedServerPrivateKey);
  test.equal(serverPrivateKey.getPub().serialize(),
             rawWallet.serializedServerPublicKey);
});

var getClientBackupPublicKey = function() {
  var backupSeed = crypto.randomBytes(32);
  var clientBackupKey = BIP32key.fromMasterKey(backupSeed);
  var clientBackupPublicKey = clientBackupKey.getPub();
  return clientBackupPublicKey;
};

// Test that the client handles server errors properly after calling
// createWallet.
var testCreateWalletInvalidServerResponse = testFunc(function*(test) {
  var client = yield getLoggedInClient();

  client._call2 = client._call;

  var clientBackupPublicKey = getClientBackupPublicKey();

  var doTest = gen(function*(result, expectedError) {
    client._call = gen(function*(method, params) {
      if (method == 'createWallet') {
        return {serializedServerPublicKey: result};
      }
      return (yield client._call2(method, params));
    });

    yield throws(test, function*() {
      yield client.createWallet(PASSWORD, clientBackupPublicKey);
    },
    expectedError);
  });

  yield doTest('foo', /The server returned an invalid key\./);
  yield doTest(BIP32key.fromMasterKey('foo').serialize(),
         /The server key should be public\./);
  yield doTest(clientBackupPublicKey.serialize(),
         /The server key should be different from the backup client key./);
});

// Create a new wallet.
var setupWallet = gen(function*(client) {
  var clientBackupPublicKey = getClientBackupPublicKey();
  var result = yield client.createWallet(PASSWORD, clientBackupPublicKey);
  var serverPublicKey = BIP32key.deserialize(
    result.serializedServerPublicKey);
  var walletInfo = {
    clientMainPublicKey: result.clientMainKey.getPub(),
    clientBackupPublicKey: clientBackupPublicKey,
    serverPublicKey: serverPublicKey,
    id: result.walletID,
  };
  var childIndex = 0;
  var addresses = (yield client.createAddresses(1));
  return {
    walletID: result.walletID,
    address: addresses[0],
    clientMainKey: result.clientMainKey,
    clientBackupPublicKey: clientBackupPublicKey,
    serverPublicKey: serverPublicKey,
  };
});

var testCreateAddresses = testFunc(function*(test) {
  var client = yield getLoggedInClient();
  var setupWalletResult = yield setupWallet(client);
  var address = setupWalletResult.address;


  // test that the client can't create invalid addresses.
  var testAddress = btcutil.getDeterministicP2SHAddress(
    2,
    [setupWalletResult.clientMainKey.getPub(),
     setupWalletResult.clientBackupPublicKey,
     setupWalletResult.serverPublicKey],
    2);
  yield throws(test, function*() {
    yield client._call(
    'storeAddresses', {
      walletID: setupWalletResult.walletID,
      addresses: [
        {childIndex: 1,
         address: testAddress,
         signature: 'asdf'}]});
  }, 'INVALID_ADDRESS_STRING_AND_CHILD_NUM');

  var result = yield client.getAddresses();
  var resultAddresses = result.addresses;
  test.equal(resultAddresses.length, 1);
  var resultAddress = resultAddresses[0];
  test.equal(resultAddress.childIndex, 0);
  test.deepEqual(resultAddress, address);

  var addressString = address.address;
  var signature = btcutil.hmac256(
    0+':'+addressString+':'+setupWalletResult.walletID,
    client.session.signatureKey,
    'base64');
  test.equal(resultAddress.signature, signature);

  // test that invalid signatures throw an exeption
  var _call = client._call;
  client._call = gen(function*(method, params) {
    return {
      addresses: [{childIndex: 0, addressString: addressString, signature: 'foo'}]
    };;
  });
  yield throws(test, function*() {
    yield client.getAddresses();
  }, /Invalid address signature\./);
  client._call = _call;

  // test creating a second address and verifying it gets returned
  var addressString2 = (yield client.createAddresses(1))[0].address;

  var getAddressesResult2 = yield client.getAddresses();
  var resultAddresses = getAddressesResult2.addresses;
  test.equal(resultAddresses.length, 2);
  test.equal(resultAddress.address, addressString);
  test.equal(resultAddress.childIndex, 0);
  test.equal(resultAddress.signature, signature);

  test.equal(resultAddresses[1].address, addressString2);
  test.equal(resultAddresses[1].childIndex, 1);
  var signature2 = btcutil.hmac256(
    1+':'+addressString2+':'+setupWalletResult.walletID,
    client.session.signatureKey,
    'base64');
  test.equal(resultAddresses[1].signature, signature2);

  var addresses = yield client.createAddresses(3);
  test.equal(client.session.walletInfo.lastAddressIndex, 4);
  var email = client.session.email;
  yield client.logout();
  yield client.login(email, PASSWORD);
  test.equal(client.session.walletInfo.lastAddressIndex, 4);

  var _call = client._call;
  yield throws(test, function*() {
    yield client._call('storeAddresses',
      {walletID: setupWalletResult.walletID,
       addresses: [{
         childIndex: 4,
         addressString: 'asdf',
         redeemScript: 'asdf',
         signature: 'asdf'}]});
  }, 'ADDRESS_ALREADY_CREATED');
});

var testPostTransaction = testFunc(function*(test) {
  // NOTE: if the db schema changes and you start seeing weird errors,
  // uncomment the next 2 lines, re-rerun the test, and then comment them out again.
  // 
//  yield createHardcodedData();
  //return;

  // This test uses hardcoded data in case we want to test real addresses
  // on the blockchain, though it currently doesn't in fact do that because
  // the getUnspent call is stubbed at the end of the test to avoid
  // flakiness.
  var res = yield getHardcodedData();
  var walletInfo = getHardcodedDataWalletInfo(res.client, res.data);
  var client = res.client;

  var testErr = gen(function*(
      walletID, walletKey, inputsStr, destinationAddress,
      amount, errRegex) {
    yield throws(test, function*() {
      yield client._call(
        'postTransaction',
        {walletID: walletID,
         walletKey: walletKey,
         inputs: inputsStr,
         destinationAddress: destinationAddress,
         amount: amount});
    }, errRegex);
  });
  var authToken = yield client.getAuthToken(PASSWORD);
  var walletID = walletInfo.id;
  var destinationAddress = '1FGT4JmdmfeoYjpjJNHka6h4vmBA5unZpe'; 
  var amount = 12700;
  var inputSig = '3046022100f344e558b4279f1f221de47b1909688cf8645bb1fc80fce258a78ddc41c70a4b022100869655ec9b21df18c6c80756019d5ae4c7c905d34d256227d1abc3f36583ba0201';
  var txid = 'ab526146dc7d4d0da6f9023a3739a9ca63498deb666edad316343d43640ecb8c';
  var walletKey = yield client.getWalletKey(PASSWORD);
  var inputs = [{
    signature: inputSig,
    index: 0, txid:
    txid,
    address: walletInfo.address
  }];

  yield testErr(
    'foo',
    walletKey,
    inputs,
    destinationAddress,
    amount,
    'INVALID_WALLET_ID');

  yield testErr(
    walletID,
    'foo',
    inputs,
    destinationAddress,
    amount,
    'INVALID_WALLET_KEY');

  yield testErr(
    walletID,
    crypto.randomBytes(32).toString('base64'),
    inputs,
    destinationAddress,
    amount,
    'INVALID_WALLET_KEY');

  yield testErr(
    walletID,
    walletKey,
    inputs,
    'foo',
    amount,
    /INVALID_DESTINATION_ADDRESS/);

  yield testErr(
    walletID,
    walletKey,
    inputs,
    destinationAddress,
    -1,
    'INVALID_PARAM: instance.amount is not 0');

  var testInputError = gen(function*(inputs, errRegex) {
    yield testErr(
      walletID,
      walletKey,
      inputs,
      destinationAddress,
      amount,
      errRegex);
  });

  yield testInputError(
    [],
    /INVALID_PARAM: instance\.inputs does not meet minimum length of 1/);
  yield testInputError(
    {},
    /INVALID_PARAM: instance\.inputs is not of a type\(s\) array/);
  yield testInputError(
    [{}],
    /INVALID_PARAM: instance\.inputs\[0\]\.signature is required/);
  yield testInputError(
    [{signature: 1}],
    /INVALID_PARAM: instance.inputs\[0\]\.signature is not of a type\(s\) string/);
  yield testInputError(
    [{signature: 'foo'}],
    /INVALID_PARAM: instance\.inputs\[0\]\.index is required/);
  yield testInputError(
    [{signature: 'foo', index: 'bar'}],
    /INVALID_PARAM: instance\.inputs\[0\]\.index is not of a type\(s\) integer/);
  yield testInputError(
    [{signature: 'foo', index: 0}],
    /INVALID_PARAM: instance\.inputs\[0\]\.txid is required/);
  yield testInputError(
    [{signature: 'foo', index: 0, txid: 1}],
    /INVALID_PARAM: instance\.inputs\[0\]\.txid is not of a type\(s\) string/);
  yield testInputError(
    [{signature: 'foo', index: 0, txid: 'foo'}],
    /INVALID_PARAM: instance\.inputs\[0\]\.txid does not meet minimum length of 64/);
  yield testInputError(
    [{signature: 'foo', index: 0, txid: txid}],
    /INVALID_PARAM: instance\.inputs\[0\]\.address is required/);
  yield testInputError(
    [{signature: 'foo', index: 0, txid: txid, address: 'bar'}],
    /INVALID_PARAM: instance\.inputs\[0\]\.address is not of a type\(s\) object/);
  yield testInputError(
    [{signature: 'foo', index: 0, txid: txid, address: {}}],
    /INVALID_PARAM: instance\.inputs\[0\]\.address.address is required/);
  yield testInputError(
    [{signature: 'foo', index: 0, txid: txid, address: {address: 'foo'}}],
    /INVALID_PARAM: instance\.inputs\[0\]\.address\.childIndex/);
  yield testInputError(
    [{signature: 'foo', index: 0, txid: txid, address: {address: 'foo', childIndex: 0}}],
    /INVALID_INPUT_ADDRESS/);

  // only pre-registered addresses should work
  var eckey = new ECKey();
  var addressString = eckey.getBitcoinAddress(5).toString();
  var inputs =
    [{signature: inputSig,
     index: 0,
     txid: txid,
     address: {
       address: addressString,
       childIndex: 0,
     }}];

  yield testInputError(
    inputs,
    /INVALID_INPUT_ADDRESS/);


  inputs[0].address = walletInfo.address;
  inputs[0].address.childIndex = 4;
  yield testInputError(
    inputs,
    /INPUT_ADDRESS_MISMATCH/);

  // this should finally pass with no exceptions
  inputs[0].address.childIndex = 0;
  inputs[0].txid = txid;
  yield client._call('postTransaction', 
      {walletID: walletID,
       walletKey: walletKey,
       inputs: inputs,
       destinationAddress: destinationAddress,
       amount: amount}
    );


  // Finally, test the client.postTransaction implementation. But first,
  // stub out the getUnspent call.
  var call = client._call;
  client._call2 = call;
  client._call = gen(function*(method, params) {
    if (method == 'getUnspent') {
      return {
        totalAmount: amount,
        outputs: [{
          address: walletInfo.address,
          txid: txid,
          index: 0,
        }]
      }
    }
    return yield client._call2(method, params);

  });

  yield client.postTransaction(PASSWORD, walletInfo, '1FGT4JmdmfeoYjpjJNHka6h4vmBA5unZpe', amount);

  // TODO add some more testing logic to make sure the transaction gets posted to the
  // blockchain (which the server doesn't do at the moment).
});

// Dump the database's data into a file. Useful for testing hard coded addresses
// on the blockchain.
var testDataFile = './test/testdata.json';
var createHardcodedData = gen(function*() {
  var client = yield getLoggedInClient();
  yield setupWallet(client);

  var classNames = ['User', 'Wallet', 'Address'];
  var promises = classNames.map(function(className) {
    return serverdb[className].findAll();
  });
  var res = yield Promise.all(promises);
  var data = {};
  for (var i in classNames) {
    var className = classNames[i];
    data[className] = res[i];
  }
  fs.writeFileSync(testDataFile, JSON.stringify(data));
  return data;
});

var loadHardcodedData = gen(function*() {
  var data;
  try {
    var fileContents = fs.readFileSync(testDataFile, {encoding: 'utf8'});
    data = JSON.parse(fileContents);
  } catch (e) {
    return createHardcodedData();
  }

  for (var className in data) {
    yield serverdb[className].bulkCreate(data[className]);
  }

  return data;
});

var getHardcodedData = gen(function*() {
  var data = yield loadHardcodedData();
  var email = data.User[0].email;
  var client = getClient();
  yield client.login(email, PASSWORD);
  return {data: data, client: client};
});

// Create a walletInfo object from the first Wallet row in the hardcoded data file.
var getHardcodedDataWalletInfo = function(client, data) {
  var wallet = data.Wallet[0];
  var addressData = data.Address[0];
  return {
    serializedClientMainPublicKey: wallet.serializedClientMainPublicKey,
    serializedClientBackupPublicKey: wallet.serializedClientBackupPublicKey,
    serializedServerPublicKey: wallet.serializedServerPublicKey,
    clientMainPublicKey: BIP32key.deserialize(wallet.serializedClientMainPublicKey),
    clientBackupPublicKey: BIP32key.deserialize(wallet.serializedClientBackupPublicKey),
    serverPublicKey: BIP32key.deserialize(wallet.serializedServerPublicKey),
    encryptedClientMainKey: JSON.parse(wallet.userData).encryptedClientMainKey,
    id: wallet.externalID,
    address: {
      address: addressData.addressString,
      childIndex: addressData.childIndex,
      signature: addressData.signature,
    }
  };
}


// This isn't a real test but a function I used to benchmark creating P2SH addresses
// from public key triplets.
var testBenchmarkAddressCreation = testFunc(function*(test) {
  var clientMainKey = BIP32key.fromMasterKey(1234);
  var backupClientKey = BIP32key.fromMasterKey(2345);
  var serverKey = BIP32key.fromMasterKey(3456);

  var elapsed_time = function(note){
    var precision = 3; // 3 decimal places
    var elapsed = process.hrtime(start)[1] / 1000000; // divide by a million to get nano to milli
    console.log(process.hrtime(start)[0] + " s, " + elapsed.toFixed(precision) + " ms - " + note); // print message + time
  }
  var start = process.hrtime(); // reset the timer


  var addresses = [];
  for (var i = 0; i < 10; i++) {
    var addressString = btcutil.getDeterministicP2SHAddress(
      i, [clientMainKey, backupClientKey, serverKey], 2);
  }
  elapsed_time();

  for (var i = 0; i < 10; i++) {
    var addressString = btcutil.getDeterministicP2SHAddress(
      i, [clientMainKey, backupClientKey, serverKey], 2);
    addresses.push(addressString);
  }

  var encryptionKey = crypto.randomBytes(64).toString();

  start = process.hrtime();
  for (var i = 0; i < addresses.length; i++) {
    var sig = btcutil.hmac256(addresses[i], encryptionKey);
  }
  elapsed_time();

  start = process.hrtime();
  for (var i = 0; i < addresses.length; i++) {
    var sig = Crypto.HMAC(Crypto.SHA256, addresses[i], encryptionKey);
  }
  elapsed_time();
});


var exports = {};
//exports.testPasswordLength = testPasswordLength;
//exports.testRegister = testRegister;
//exports.testLogin = testLogin;
//exports.testVerifyUserDataSignature = testVerifyUserDataSignature;
//exports.testCreateWallet = testCreateWallet;
//exports.testSetSignatureFailure = testSetSignatureFailure;
exports.testServerPrivateKeyEncryption = testServerPrivateKeyEncryption;
// exports.testCreateWalletInvalidServerResponse = testCreateWalletInvalidServerResponse;
// exports.testCreateAddresses = testCreateAddresses;
// exports.testPostTransaction = testPostTransaction;

exports.setUp = setUp;
exports.tearDown = tearDown;

module.exports = exports;
