"use strict"

var Sequelize = require('sequelize');
var crypto = require('crypto');
var config = require('./config');
var suspend = require('suspend');
var btcutil = require('../btcutil.js');
var gen = btcutil.gen;

var log = console.log;

var sequelize = new Sequelize('HDMNode', 'root', '', {
  dialect: 'mysql',
});

var ID_TYPE = Sequelize.INTEGER;
var ID_FIELD = {type: ID_TYPE, primaryKey: true, autoIncrement: true};
var FK_FIELD = {type: ID_TYPE, allowNull: false};
var UNIQUE_STRING_TYPE = {type: Sequelize.STRING, unique: true, allowNull: false};

var User = sequelize.define('User', {
  // TODO revisit id generation
  id: ID_FIELD,
  email: UNIQUE_STRING_TYPE,

  // The hash of the user's auth token, which is used to log into the service.
  authTokenHash: {type: Sequelize.STRING, allowNull: false},

  // The salt that's used to hash the auth token before storing it in
  // authTokenHash.  
  serverAuthTokenSalt: {type: Sequelize.STRING, allowNull: false},

  // An arbitrary string the client may store on the server for the user.
  // The server returns it to the client on login.
  userData: {type: Sequelize.STRING, allowNull: true},
  clientRandomSalt: {type: Sequelize.TEXT, allowNull: false},

  // The id of the user's main wallet. If the user has registered but
  // hasn't created a wallet yet, this field is null.
  externalWalletID: {type: Sequelize.STRING},
});

// Every time a user logs in a new Session is created and its key
// is stored client side. The key has to be passed together with
// any API call that requires a user session.
var Session = sequelize.define('Session', {
  id: ID_FIELD,
  key: {type: Sequelize.STRING}, // TODO add index
  userID: FK_FIELD,
});
var Wallet = sequelize.define('Wallet', {
  id: ID_FIELD,
  userID: FK_FIELD,
  externalID: {type: Sequelize.STRING, allowNull: false},

  // We encrypt the server private key before storing it in the database so that
  // if someone breaks into the database and steals the data they won't
  // have access to any server private keys. The server private key alone is
  // insufficient to steal any coins but it's a good practice to protect it
  // in case the attacker obtains one of the user's keys as well.
  // The encryption key (the 'wallet key') comes from the client. The server
  // doesn't care about how the wallet key is derived. It just needs to be
  // consistent between requests.
  serverPrivateKeyEncryptedWithWalletKey: {type: Sequelize.TEXT, allowNull: false}, // TODO add index

  // The following fields are the public keys used to initialize the wallet.
  serializedServerPublicKey: {type: Sequelize.STRING, allowNull: false},
  serializedClientMainPublicKey: {type: Sequelize.STRING, allowNull: false},
  serializedClientBackupPublicKey: {type: Sequelize.STRING, allowNull: false},

  // An arbitrary string the client may store for the wallet on the server side.
  userData: {type: Sequelize.TEXT, allowNull: true},

  // After the client creates the wallet the client signs the wallet's public
  // keys with the client's secret and passes the signature to the server.
  // On future sessions, the signature allows the client to validate
  // that the server has sent the client valid information about the wallet.
  // Without this validation, the server could lie to the client about the agreed
  // upon public keys, tricking the client into generating addresses that
  // don't belong to the user's wallet.
  signature: {type: Sequelize.STRING},

  // The index of the last generated address.
  lastAddressIndex: {type: Sequelize.INTEGER, defaultValue: -1},
});

// Note: We cache BIP32 derived addresses because it takes ~4 seconds to
// create 100 keys on a modern powerbook and each address is composed of 3
// keys. This is too slow to respond in real time to queries such as "get all
// addresses for this wallet."
var Address = sequelize.define('Address', {
  id: ID_FIELD,

  // The bitcoin address string
  addressString: Sequelize.STRING, // TODO add index
  childIndex: Sequelize.INTEGER, // TODO add index
  walletID: FK_FIELD, // TODO add index
  signature: {type: Sequelize.STRING, allowNull: false},
});

var _initialized = false;

var init = gen(function*() {
  try {
    yield sequelize.sync({force: false});
  } catch (e) {
    console.error(e);
  }
  _initialized = true;
});

// this function is only to be used in unit testing
var destroy = gen(function*() {
  if (_initialized) {
    try {
      yield sequelize.drop();
    } catch (e) {
      console.error(e);
    }
    _initialized = false;
  }
});

var initialized = function() {
  return _initialized;
}

exports.init = init;
exports.destroy = destroy;
exports.initialized = initialized;
exports.User = User;
exports.Session = Session;
exports.Wallet = Wallet;
exports.Address = Address;

