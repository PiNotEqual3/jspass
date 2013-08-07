/*
generate key
 key = openpgp.generate_key_pair(1, 1024, "Mr. Tester <test@test.de>")
 $('#message').val(openpgp.write_encrypted_message(openpgp.read_publicKey(key.publicKeyArmored), $('#message').val()));

 openpgp.read_privateKey(key.privateKeyArmored);
 key_private = openpgp.read_privateKey(key.privateKeyArmored);
 console.log(openpgp.read_message($('#message').val()));

 */

function encrypt() {
  if (window.crypto.getRandomValues) {
    //require("./openpgp.min.js");
    openpgp.init();
    var pub_key = openpgp.read_publicKey($('#pubkey').text());
    $('#message').val(openpgp.write_encrypted_message(pub_key,$('#message').val()));
  } else {
    $("#mybutton").val("browser not supported");
    window.alert("Error: Browser not supported\nReason: We need a cryptographically secure PRNG to be implemented (i.e. the window.crypto method)\nSolution: Use Chrome >= 11, Safari >= 3.1 or Firefox >= 21");   
    return false;
  }
}
$('#encrypt-btn').click( encrypt );
$('#decrypt-btn').click( function(){
    openpgp.init();
    var pub_key = openpgp.read_publicKey($('#pubkey').text());
    $('#message').val(openpgp.read_message($('#message').val()));
} );


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
