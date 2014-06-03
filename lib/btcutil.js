var assert = require('assert');
var crypto = require('crypto');
var Script = require('bitcoinjs-lib').Script;
var Address = require('bitcoinjs-lib').Address;
var convert = require('bitcoinjs-lib').convert;
var Promise = require('Promise');
var https = require('https');
var sjcl = require('sjcl');
var suspend = require('suspend');
var resume = suspend.resume;


var SIGNATURE_LENGTH = 32;
var log = console.log;

var checkPassword = function(password) {
  if (password.length < 7) {
    throw new Error('Password must be at least 7 characters long.');
  }
}

var aesEncrypt = function(plaintext, encryptionKey, iv) {
  var cipher = new sjcl.cipher.aes(encryptionKey);
  iv = iv || sjcl.random.randomWords(4);
  var ciphertext = sjcl.mode.ccm.encrypt(cipher, plaintext, iv);
  var ivBytes = sjcl.codec.bytes.fromBits(iv);
  var ciphertextBytes = sjcl.codec.bytes.fromBits(ciphertext);
  return convert.bytesToBase64(ivBytes.concat(ciphertextBytes));
}

var aesDecrypt = function(encryptionResult, encryptionKey) {
  var bytes = convert.base64ToBytes(encryptionResult);
  var iv = sjcl.codec.bytes.toBits(bytes.slice(0, 16));
  var ciphertext = sjcl.codec.bytes.toBits(bytes.slice(16, bytes.length));
  var cipher = new sjcl.cipher.aes(encryptionKey);
  return sjcl.mode.ccm.decrypt(cipher, ciphertext, iv);
}

var getCipherResult = function(cipher, partialOutput, outputEncoding) {
  if (typeof(partialOutput) === 'string') {
    return partialOutput + cipher.final(outputEncoding);
  }
  return Buffer.concat([partialOutput, cipher.final(outputEncoding)]);  
};

var hmac256 = function(data, key) {
  var signature = (new sjcl.misc.hmac(key, sjcl.hash.sha256)).encrypt(data);
  return sjcl.codec.base64.fromBits(signature);
}

var getDeterministicP2SHScript = function(idx, bip32Keys, numSigs) {
  var encodedKeys = bip32Keys.map(function(key) {
    assert(key.type === 'pub');
    var derivedKey = key.ckd(idx);
    var keyAtIdx = derivedKey.getKey();
    log(keyAtIdx.export('hex'));
    return keyAtIdx.export('bytes');
  });
  return Script.createMultiSigOutputScript(numSigs, encodedKeys);
}

var getDeterministicP2SHAddress = function(idx, bip32Keys, numSigs) {
  log('xxx');
  var script = getDeterministicP2SHScript(
    idx,
    bip32Keys,
    numSigs);
  var scriptHash = script.toScriptHash();
  var address = new Address(scriptHash, 5);
  log(address.toString());
  return address.toString();  
}

// A simple wrapper for the built in https.get method that returns a Promise
// and could therefore be yielded by a suspend.js generator.
var httpsGet = function(url) {
  return new Promise(function(resolve, reject) {
    https.get(url, function(res) {
      var buffers = [];
      res.on('data', function(data) {
        buffers.push(data);
      });
      res.on('end', function() {
        var data = Buffer.concat(buffers);
        if (res.statusCode === 200) {
          resolve(data);
        } else {
          var err = new Error(data.toString());
          err.code = res.statusCode;
          reject(err);
        }
      });
    }).on('error', function(err) {
      reject(err);
    });
  });
};

var httpsGetJSON = function(url) {
  return httpsGet(url).then(function(res) {
    return JSON.parse(res);
  });
};

// see https://groups.google.com/forum/#!topic/keyczar-discuss/VXHsoJSLKhM
var secureStrEqual = function(str1, str2) {
  str1 = convert.stringToBytes(str1);
  str2 = convert.stringToBytes(str2)
  return sjcl.bitArray.equal(str1, str2);
}

var gen = function(generator) {
  return function() {
    var args = Array.prototype.slice.call(arguments);
    var that = this;
    return new Promise(function(resolve, reject) {
      suspend.run(function*() {
          var func = suspend.async(generator);
          args.push(resume());
          resolve((yield func.apply(that, args)));
        },
        function(err) {
          reject(err);
        });
      });
  }
};

var getRandomBytes = function(numBytes) {
  return sjcl.codec.bytes.fromBits(sjcl.random.randomWords(Math.ceil(numBytes/4))).slice(0, numBytes);
}

exports.SIGNATURE_LENGTH = SIGNATURE_LENGTH;

exports.checkPassword = checkPassword;
exports.aesEncrypt = aesEncrypt;
exports.aesDecrypt = aesDecrypt;
exports.getDeterministicP2SHScript = getDeterministicP2SHScript;
exports.getDeterministicP2SHAddress = getDeterministicP2SHAddress;
exports.httpsGet = httpsGet;
exports.httpsGetJSON = httpsGetJSON;
exports.hmac256 = hmac256;
exports.secureStrEqual = secureStrEqual;
exports.gen = gen;
exports.getRandomBytes = getRandomBytes;
