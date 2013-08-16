/*



 */

// Error Message function for openpgp
function showMessages(text)
{
    console.log(text);
}

function init()
{
    if (window.crypto.getRandomValues) {
        //require("./openpgp.min.js");
        openpgp.init();

    } else {
        $("#mybutton").val("browser not supported");
        window.alert("Error: Browser not supported\nReason: We need a cryptographically secure PRNG to be implemented (i.e. the window.crypto method)\nSolution: Use Chrome >= 11, Safari >= 3.1 or Firefox >= 21");
        return false;
    }
}

function encrypt(message) {
    // read keys
    var key = get_key();

    // encrypt
    var msg_crypted = openpgp.write_encrypted_message(openpgp.read_publicKey(key.publicKeyArmored), message);

    return msg_crypted;
}
$('#encrypt-btn').click( function(){
    var msg_crypted = encrypt($('#message').val());
    $('#message').val(msg_crypted);
});

function decrypt(msg_crypted)
{
    // read keys
    var key = get_key();
    var priv_key = openpgp.read_privateKey(key.privateKeyArmored);

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
        return msg[0].decrypt(keymat, sesskey);
    } else {
        console.log("No private key found!");
    }
}
$('#decrypt-btn').click( function()
{
    var message = decrypt( $('#message').val() );
    $('#message').val( message );
});

function generate_keys(user)
{
    //generate key
    var key = openpgp.generate_key_pair(1, 1024, user);
    $('#pub_key').val( key.publicKeyArmored );
    $('#priv_key').val( key.privateKeyArmored );
}
$('#gen_keys').click( function()
{
    generate_keys( $('#name').val() + " <" + $('#email').val() + ">" );
});

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
    init();

    generate_keys("Mr. Tester <test@test.de>");

    // read keys
    var key = get_key();

    var msg_crypted = encrypt('test message');

    var priv_key = openpgp.read_privateKey(key.privateKeyArmored);

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
