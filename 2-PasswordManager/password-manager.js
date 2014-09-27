"use strict";


/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setup_cipher = lib.setup_cipher,
    enc_gcm = lib.enc_gcm,
    dec_gcm = lib.dec_gcm,
    bitarray_slice = lib.bitarray_slice,
    bitarray_to_string = lib.bitarray_to_string,
    string_to_bitarray = lib.string_to_bitarray,
    bitarray_to_hex = lib.bitarray_to_hex,
    hex_to_bitarray = lib.hex_to_bitarray,
    bitarray_to_base64 = lib.bitarray_to_base64,
    base64_to_bitarray = lib.base64_to_bitarray,
    byte_array_to_hex = lib.byte_array_to_hex,
    hex_to_byte_array = lib.hex_to_byte_array,
    string_to_padded_byte_array = lib.string_to_padded_byte_array,
    string_to_padded_bitarray = lib.string_to_padded_bitarray,
    string_from_padded_byte_array = lib.string_from_padded_byte_array,
    string_from_padded_bitarray = lib.string_from_padded_bitarray,
    random_bitarray = lib.random_bitarray,
    bitarray_equal = lib.bitarray_equal,
    bitarray_len = lib.bitarray_len,
    bitarray_concat = lib.bitarray_concat,
    dict_num_keys = lib.dict_num_keys;


/********* Implementation ********/


var keychain = function() {
  // Class-private instance variables.
  var priv = {
    secrets: { kvs: {},
        masterKey: null,
        domainKey: null,
        passwordKey: null,
        recordMacKey: null
         },
    data: { 
        PasswordIndex:0, 
        MACIndex:1,
        domainKeyMessage: "DomainKeyMessage",
        passwordKeyMessage: "PasswordKeyMessage",
        recordMacKeyMessage: "RecordMacKeyMessage",
        masterKeyValidationMessage: "MasterKeyValidatorMessage",
        count:0
        }
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;
  
  // Flag to indicate whether password manager is "ready" or not
  var ready = false;

  var keychain = {};

  /** 
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {
    priv.data.version = "CS 255 Password Manager v1.0";
    priv.secrets.kvs = {};
    //Deriving the MasterKey
    priv.secrets.kvs.masterKeySalt = random_bitarray(256);
    priv.secrets.masterKey = KDF(password, priv.secrets.kvs.masterKeySalt);
    //Deriving the domainKey
    priv.secrets.domainKey = keychain.generateKey(priv.data.domainKeyMessage);
    //Deriving the passwordKey
    priv.secrets.passwordKey = bitarray_slice(keychain.generateKey(priv.data.passwordKeyMessage), 0, 128);
    //Deriving the recordMacKey
    priv.secrets.recordMacKey = keychain.generateKey(priv.data.recordMacKeyMessage);
    //Forming the MasterKeyValidator
    priv.secrets.kvs.masterKeyValidator = HMAC(priv.secrets.masterKey, priv.data.masterKeyValidationMessage);
    //We are ready!
    ready = true;
  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trusted_data_check
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (e.g., the result of a 
    * call to the save function). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trusted_data_check: string
    * Return Type: boolean
    */
  keychain.load = function(password, repr, trusted_data_check) {
    priv.secrets.kvs = JSON.parse(repr);
   
    //Derive and validate MasterKey
    priv.secrets.masterKey = KDF(password,priv.secrets.kvs.masterKeySalt);
    if(bitarray_equal(priv.secrets.kvs.masterKeyValidator, HMAC(priv.secrets.masterKey, priv.data.masterKeyValidationMessage)))
    {
        //Trusted storage check
        if(trusted_data_check !== undefined)
        {
            var dbMacKey = keychain.generateKey(trusted_data_check);
            var dbMacInDisk = priv.secrets.kvs.DbMac;
            // setting it to a fixed value of 0 before calculating HMAC of KVS
            priv.secrets.kvs.DbMac = 0;
            var valToMAC = JSON.stringify(priv.secrets.kvs);
            if(!bitarray_equal(HMAC(dbMacKey, valToMAC), dbMacInDisk))
            {
                throw "tampering detected while load!";
            }
            priv.data.count = trusted_data_check;
        }
        //Deriving passwordKey and recordMacKey
        priv.secrets.domainKey = keychain.generateKey(priv.data.domainKeyMessage);
        priv.secrets.passwordKey = bitarray_slice(keychain.generateKey(priv.data.passwordKeyMessage), 0, 128);
        priv.secrets.recordMacKey = keychain.generateKey(priv.data.recordMacKeyMessage);
        ready = true;
    }
    else
    {
        ready = false;
    }
    return ready;
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is the counter
    * used to preserve integrity. If the password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */

   // dump() returns the counter value as the trusted storage data (EXTRA-CREDIT)

  keychain.dump = function() {
    if(ready === false)
    {
        return null;
    }
    var retVal = {};
    // always setting it to a fixed value of 0 before calculating HMAC of KVS
    priv.secrets.kvs.DbMac = 0;
    var valToMac = JSON.stringify(priv.secrets.kvs);
    //Generate key for MACing the DB
    var dbMacKey = keychain.generateKey(priv.data.count);
    //MAC of the JSON encoded DB
    priv.secrets.kvs.DbMac = HMAC(dbMacKey, valToMac);
    retVal[0] = JSON.stringify(priv.secrets.kvs);
    retVal[1] = priv.data.count;
    return retVal;
  }

  keychain.generateKey = function(msg)
  {
      return HMAC(priv.secrets.masterKey, msg);
  }
  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: string
    */
  keychain.get = function(name) {
    if(ready === false)
    {
        return "Key not initialized.";
    }
    //If no record for the domain, then return null
    var hashOfDomain = HMAC(priv.secrets.domainKey, name);
    if(priv.secrets.kvs[hashOfDomain] === undefined)
    {
        return null;
    }
    else
    {
        //Checking record MAC
        var recordMAC = priv.secrets.kvs[hashOfDomain][priv.data.MACIndex];
        var dataToMAC=bitarray_concat(hashOfDomain, priv.secrets.kvs[hashOfDomain][priv.data.PasswordIndex]);
        if(!bitarray_equal(recordMAC, HMAC(priv.secrets.recordMacKey,dataToMAC)))
        {
            throw "record tampered!"
        }
        //Retrieving password
        var cipher=setup_cipher(priv.secrets.passwordKey);
        return string_from_padded_bitarray(dec_gcm(cipher, priv.secrets.kvs[hashOfDomain][priv.data.PasswordIndex]), MAX_PW_LEN_BYTES);
    }
  }

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  keychain.set = function(name, value) {
    if(ready === false)
    {
        return "Key not initialized.";
    }
    var hashOfDomain = HMAC(priv.secrets.domainKey, name);
    //If record doesn't exist, create one.
    if (priv.secrets.kvs[hashOfDomain] === undefined)
    {
        //Creating new object as the value for the key.
        priv.secrets.kvs[hashOfDomain] = {};
        //Generate encrypted password
        var cipher = setup_cipher(priv.secrets.passwordKey);
        priv.secrets.kvs[hashOfDomain][priv.data.PasswordIndex]= enc_gcm(cipher, string_to_padded_bitarray(value, MAX_PW_LEN_BYTES));
        //Generate record MAC
        var dataToMAC = bitarray_concat(hashOfDomain, priv.secrets.kvs[hashOfDomain][priv.data.PasswordIndex]);
        priv.secrets.kvs[hashOfDomain][priv.data.MACIndex] = HMAC(priv.secrets.recordMacKey,dataToMAC);
    }
    //If record exists, update it.
    else
    {
        //Set new encrypted password
        var cipher = setup_cipher(priv.secrets.passwordKey);
        priv.secrets.kvs[hashOfDomain][priv.data.PasswordIndex] = enc_gcm(cipher, string_to_padded_bitarray(value, MAX_PW_LEN_BYTES));
        //Generate record MAC
        var dataToMAC = bitarray_concat(hashOfDomain,priv.secrets.kvs[hashOfDomain][priv.data.PasswordIndex]);
        priv.secrets.kvs[hashOfDomain][priv.data.MACIndex] = HMAC(priv.secrets.recordMacKey,dataToMAC);
    }
    priv.data.count++;
  }

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: boolean
  */
  keychain.remove = function(name) {
    if(ready === false)
    {
        return "Key not initialized.";
    }
    var hashOfDomain = HMAC(priv.secrets.domainKey, name);
    //If record not found, return false.
    if (priv.secrets.kvs[hashOfDomain] === undefined)
    {
        return false;
    }
    //If record found, then delete it and return true.
    priv.secrets.kvs[hashOfDomain] = undefined;
    priv.data.count++;
    return true;
  }

  return keychain;
}

module.exports.keychain = keychain;
