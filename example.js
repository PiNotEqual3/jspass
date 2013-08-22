/*

ToDo
 - password protect private key
 - store/load key in browser
 - store/load data
 - Tree Storage Container (EncryptedTree)
 - Search in EncryptedTree
 - add public keys to Tree Storage Node (friends)

 */
/*
Users = [
    {
         name: 'Bob',
         public_key: ''
    },{
         name: 'Alice',
         public_key: ''
    }
]

EncryptedTreeNode = {
    data_blocks: [],
    sub_nodes: [],
    //allow: ['user01', 'user02']
}

EncryptedBlock = {
    name: 'name',
    description: 'details for search',
    data: 'encrypted stuff',
    access: [
        {
            user: 'user01',
            key: encrypt('user01', 'private-key-for-this-message')
        },
        {
            user: 'user02',
            key: encrypt('user02', 'private-key-for-this-message')
        }
    ]
};
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


/**
 * test for pgp functions
 */
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

/**
 * JS File Download.
 *
 * @param text
 * @param filename
 */
function textfile_download(text, filename)
{
    var blob = new Blob([text], {type: "text/plain;charset=utf-8"});
    saveAs(blob, filename);
}
$('#priv_key_store_file').click(function(){
    var key = $('#priv_key').val();
    if (key)
    {
        textfile_download(key, 'privat_key.asc');
    }

    return false;
});

/**
 * JS File Upload.
 * requires browser with FileReader support
 *
 * @param evt
 * @param callback
 */
function textfile_upload_handler(evt, callback)
{
    if (FileReader)
    {
        var reader = new FileReader();
        reader.onload = (function(theFile) {
            return function(e) {
                //console.log(theFile.name);
                var r = e.target.result;
                var data = r.substr(r.indexOf('base64') + 7);
                callback(atob(data));
            };
        })( evt.target.files[0] );
        // read file
        reader.readAsDataURL( evt.target.files[0] );
    }
    else
    {
        alert('FileReader not supported!');
    }
}
$('#priv_key_load_file').change(function(event){
    textfile_upload_handler(event, function(file_content){
        $('#priv_key').val(file_content);
    });
});