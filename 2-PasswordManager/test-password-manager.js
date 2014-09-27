"use strict";

function assert(condition, message) {
  if (!condition) {
    console.trace();
    throw message || "Assertion failed!";
  }
}

var password_manager = require("./password-manager");
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

/********* Unit Tests ********/

function TestFunctionsWithoutInitializations()
{
    console.log("Testing get,set,dump and remove without initialization");
    var keychain = password_manager.keychain();
    try
    {
        keychain.get("service1");
    }
    catch(e)
    {
        assert(e==="Key not initialized.","Key not initialized exception expected");
    }
    try
    {
        keychain.set("service1","value1")
    }
    catch(e)
    {
        assert(e==="Key not initialized.","Key not initialized exception expected");
    }
    try
    {
        keychain.remove("service1")
    }
    catch(e)
    {
        assert(e==="Key not initialized.","Key not initialized exception expected");
    }
    assert(keychain.dump()===null,"null expected");
}

function TestPasswordVariations()
{
    console.log("Testing password variations");
    var password = "password123!!";
    var keychain = password_manager.keychain();
    console.log("\tInitializing keychain");
    keychain.init(password);
    var kvs = { "passLen64": "0123456789012345678901234567890123456789012345678901234567890123", 
            "passLen0": "",
            "passLen63": "012345678901234567890123456789012345678901234567890123456789012" };
    console.log("\tAdding keys+values to password manager");
    for (var k in kvs)
    {
      keychain.set(k, kvs[k]);
    }

    console.log("\tRetreiving existing keys+values");
    for (var k in kvs) {
      assert(keychain.get(k) === kvs[k], "Get failed for key " + k);
    }
}

function TestSetAndGet()
{
    console.log("Testing get and set");
    var password = "password123!!";
    var keychain = password_manager.keychain();
    console.log("\tInitializing keychain");
    keychain.init(password);
    var kvs = { "service1": "value1", 
            "service2": "value2",
            "service3": "value3" };
    console.log("\tAdding keys+values to password manager");
    for (var k in kvs)
    {
      keychain.set(k, kvs[k]);
    }

    console.log("\tRetreiving existing keys+values");
    for (var k in kvs) {
      assert(keychain.get(k) === kvs[k], "Get failed for key " + k);
    }
    console.log("\tRetreiving non-existing key+value");
    assert(keychain.get("service4") === null);
}

function TestUpdate()
{
    console.log("Testing Update");
    var password = "password123!!";
    var keychain = password_manager.keychain();
    console.log("\tInitializing keychain");
    keychain.init(password);
    var kvs = { "service1": "value1", 
            "service2": "value2",
            "service3": "value3" };

    console.log("\tAdding keys+values to password manager");
    for (var k in kvs)
    {
      keychain.set(k, kvs[k]);
    }

    console.log("\tRetreiving old value");
    var keyToUpdate="service3";
    assert(keychain.get(keyToUpdate)===kvs[keyToUpdate], "Get failed for key "+keyToUpdate);

    console.log("\tUpdating to new value");
    kvs[keyToUpdate]="updateValue3";
    keychain.set(keyToUpdate,kvs[keyToUpdate]);

    console.log("\tRetreiving new value");
    assert(keychain.get(keyToUpdate)===kvs[keyToUpdate], "Update failed for key "+keyToUpdate);
}

function TestRemove()
{
    console.log("Testing remove");
    var password = "password123!!";
    var keychain = password_manager.keychain();
    console.log("\tInitializing keychain");
    keychain.init(password);
    var kvs = { "service1": "value1", 
            "service2": "value2",
            "service3": "value3" };
    console.log("\tAdding keys+values to password manager");
    for (var k in kvs)
    {
      keychain.set(k, kvs[k]);
    }
    assert(keychain.remove("service1"),"Cant remove existing value");
    assert(!keychain.remove("service4"),"Removed on-existing value!");
    assert(keychain.get("service4") === null,"Expected null");
    assert(keychain.get("service1") === null,"Expected null");
}

function TestSwapAttack()
{
    console.log("Swap Attack");
    var password = "password123!!";
    var keychain = password_manager.keychain();
    console.log("\tInitializing keychain");
    keychain.init(password);
    var kvs = { "service1": "value1", 
            "service2": "value2",
            "service3": "value3" };

    console.log("\tAdding keys+values to password manager");
    for (var k in kvs)
    {
      keychain.set(k, kvs[k]);
    }

    console.log("\tSaving database");
    var swapAttackData = keychain.dump();
    var kvsFromDisk=JSON.parse(swapAttackData[0]);
    var keyList={};
    var i=0;
    for(var k in kvsFromDisk)
    {
        keyList[i++]=k;
    }
    var tmp=kvsFromDisk[keyList[2]][0];
    kvsFromDisk[keyList[2]][0]=kvsFromDisk[keyList[3]][0];
    kvsFromDisk[keyList[3]][0]=tmp;
    swapAttackData[0]=JSON.stringify(kvsFromDisk);

    console.log("\tLoading database");
    var contents = swapAttackData[0];
    var cksum = swapAttackData[1];
    var swapAttack_keychain = password_manager.keychain();
    swapAttack_keychain.init(password);
    //cksum not passed in to verify swap attack defence.
    assert(swapAttack_keychain.load(password, contents),"Load failed");
    console.log("\tChecking contents of new database");
    for (var k in kvs)
    {
        try
        {
            var value=swapAttack_keychain.get(k);
            if(k==="service3")
            {
                assert(value===kvs[k],"expected to get value for service3");
            }
        }
        catch(e)
        {
            assert("record tampered!" === e,"Record tampering expected for k: "+k);
        }
    }
}

function TestSaveAndLoad()
{
    console.log("Testing save & load");
    var password = "password123!!";
    var keychain = password_manager.keychain();
    console.log("\tInitializing keychain");
    keychain.init(password);
    var kvs = { "service1": "value1", 
            "service2": "value2",
            "service3": "value3" };
    console.log("\tAdding keys+values to password manager");
    for (var k in kvs)
    {
      keychain.set(k, kvs[k]);
    }
    console.log("\tSaving database");
    var data = keychain.dump();
    var contents = data[0];
    var cksum = data[1];

    console.log("\tLoading database");
    var new_keychain = password_manager.keychain();
    console.log("\tTesting wrong password");
    assert(!new_keychain.load("WrongPassword", contents, cksum),"Load failed to fail when given wrong password");

    console.log("\tCheckSum not provided");
    assert(new_keychain.load(password, contents),"Load failed");
    console.log("\t\tChecking contents of new database");
    for (var k in kvs)
    {
      assert(keychain.get(k) === new_keychain.get(k));
    }

    console.log("\tWrong CheckSum provided");
    new_keychain = password_manager.keychain();
    try
    {
        new_keychain.load(password, contents,random_bitarray(256));
    }
    catch(e)
    {
        assert(e==="tampering detected while load!","Expected tampering");
    }

    console.log("\tCorrect checkSum provided");
    new_keychain = password_manager.keychain();
    assert(new_keychain.load(password, contents,cksum),"Load failed");
    console.log("\t\tChecking contents of new database");
    for (var k in kvs)
    {
      assert(keychain.get(k) === new_keychain.get(k));
    }

    console.log("\tSaving empty database");
    var empty_keychain = password_manager.keychain();
    empty_keychain.init(password);
    var emptyData = empty_keychain.dump();
    console.log("\tLoading empty database");
    var new_empty_keychain = password_manager.keychain();
    assert(new_empty_keychain.load(password,emptyData[0],emptyData[1]),"Failed to load empty database");
}

function TestRollbackAttack()
{
    console.log("Testing rollback attack");
    var password = "password123!!";
    var keychain = password_manager.keychain();
    console.log("\tInitializing keychain");
    keychain.init(password);
    var kvs = { "service1": "value1", 
            "service2": "value2",
            "service3": "value3" };

    console.log("\tAdding keys+values to password manager");
    for (var k in kvs)
    {
      keychain.set(k, kvs[k]);
    }

    console.log("\tSaving old version database");
    var data = keychain.dump();
    var contents = data[0];
    var cksum = data[1];

    console.log("\tGathering old version data");
    var kvsFromDisk=JSON.parse(contents);
    var keyList={};
    var i=0;
    for(var k in kvsFromDisk)
    {
        keyList[i++]=k;
    }
    var oldVersion=kvsFromDisk[keyList[2]];

    console.log("\tUpdating to new value");
    var keyToUpdate="service1";
    kvs[keyToUpdate]="updateValue1";
    keychain.set(keyToUpdate,kvs[keyToUpdate]);

    console.log("\tSaving new version database");
    var data = keychain.dump();
    var contents = data[0];
    var cksum = data[1];

    console.log("\tRolling back to old version");
    var kvsFromDisk=JSON.parse(contents);
    var keyList={};
    var i=0;
    for(var k in kvsFromDisk)
    {
        keyList[i++]=k;
    }

    kvsFromDisk[keyList[2]]=oldVersion;
    contents=JSON.stringify(kvsFromDisk);

    console.log("\tLoading database");
    var new_keychain = password_manager.keychain();
    try
    {
        new_keychain.load(password, contents,cksum);
    }
    catch(e)
    {
        assert(e==="tampering detected while load!","Expected tampering");
    }
}

TestFunctionsWithoutInitializations();
TestSetAndGet();
TestPasswordVariations();
TestUpdate();
TestRemove();
TestSaveAndLoad();
TestSwapAttack();
TestRollbackAttack();

console.log("All tests passed!");