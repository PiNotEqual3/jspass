/*
generate key
 var key = openpgp.generate_key_pair(1, 1024, "Mr. Tester <test@test.de>")
 //$('#message').val(openpgp.write_encrypted_message(openpgp.read_publicKey(key.publicKeyArmored), $('#message').val()));
 var msg = openpgp.write_encrypted_message(openpgp.read_publicKey(key.publicKeyArmored), 'test message');

 openpgp.read_privateKey(key.privateKeyArmored);
 var priv_key = openpgp.read_privateKey(key.privateKeyArmored);


 var keymat = null;
 var sesskey = null;
 // Find the private (sub)key for the session key of the message
 for (var i = 0; i< msg[0].sessionKeys.length; i++) {
 if (priv_key[0].privateKeyPacket.publicKey.getKeyId() == msg[0].sessionKeys[i].keyId.bytes) {
 keymat = { key: priv_key[0], keymaterial: priv_key[0].privateKeyPacket};
 sesskey = msg[0].sessionKeys[i];
 break;
 }
 for (var j = 0; j < priv_key[0].subKeys.length; j++) {
 if (priv_key[0].subKeys[j].publicKey.getKeyId() == msg[0].sessionKeys[i].keyId.bytes) {
 keymat = { key: priv_key[0], keymaterial: priv_key[0].subKeys[j]};
 sesskey = msg[0].sessionKeys[i];
 break;
 }
 }
 }
 if (keymat != null) {
 if (!keymat.keymaterial.decryptSecretMPIs($('#decpassword').val())) {
 console.log("Password for secrect key was incorrect!");
 return;
 }
 console.log(msg[0].decrypt(keymat, sesskey));
 } else {
 console.log("No private key found!");
 }


 */

// Error Message function for openpgp
function showMessages(text)
{
    console.log(text);
}

function encrypt() {
  if (window.crypto.getRandomValues) {
    //require("./openpgp.min.js");
    openpgp.init();



  } else {
    $("#mybutton").val("browser not supported");
    window.alert("Error: Browser not supported\nReason: We need a cryptographically secure PRNG to be implemented (i.e. the window.crypto method)\nSolution: Use Chrome >= 11, Safari >= 3.1 or Firefox >= 21");   
    return false;
  }
}
$('#encrypt-btn').click( encrypt );
$('#decrypt-btn').click( function(){
    openpgp.init();


} );

function generate_keys()
{
    //generate key
    var key = openpgp.generate_key_pair(1, 1024, "Mr. Tester <test@test.de>");
    $('#pub_key').val( key.publicKeyArmored );
    $('#priv_key').val( key.privateKeyArmored );
}

function get_key()
{
    // read keys
    var key = {};
    key.publicKeyArmored = $('#pub_key').val();
    key.privateKeyArmored = $('#priv_key').val();
    return key;
}

pgptest();
function pgptest()
{
    openpgp.init();

    generate_keys();

    // read keys
    var key = get_key();

    // encrypt
    var msg_crypted = openpgp.write_encrypted_message(openpgp.read_publicKey(key.publicKeyArmored), 'test message');
    var priv_key = openpgp.read_privateKey(key.privateKeyArmored);

    //console.log(msg_crypted);
    //console.log(key.privateKeyArmored);

    // decrypt
    var msg = openpgp.read_message(msg_crypted);
    var keymat = null;
    var sesskey = null;
    // Find the private (sub)key for the session key of the message
    for (var i = 0; i< msg[0].sessionKeys.length; i++) {
        if (priv_key[0].privateKeyPacket.publicKey.getKeyId() == msg[0].sessionKeys[i].keyId.bytes) {
            keymat = { key: priv_key[0], keymaterial: priv_key[0].privateKeyPacket};
            sesskey = msg[0].sessionKeys[i];
            break;
        }
        for (var j = 0; j < priv_key[0].subKeys.length; j++) {
            if (priv_key[0].subKeys[j].publicKey.getKeyId() == msg[0].sessionKeys[i].keyId.bytes) {
                keymat = { key: priv_key[0], keymaterial: priv_key[0].subKeys[j]};
                sesskey = msg[0].sessionKeys[i];
                break;
            }
        }
    }
    if (keymat != null) {
        if (!keymat.keymaterial.decryptSecretMPIs($('#decpassword').val())) {
            console.log("Password for secrect key was incorrect!");
            return;
        }
        console.log(msg[0].decrypt(keymat, sesskey));
    } else {
        console.log("No private key found!");
    }
}

function require(script) {
    $.ajax({
        url: script,
        dataType: "script",
        async: false,           // <-- this is the key
        success: function () {
            // all good...
        },
        error: function () {
            throw new Error("Could not load script " + script);
        }
    });
}
