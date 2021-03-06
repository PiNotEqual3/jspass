'use strict';

/*

ToDo
 - store/load encrypted messages (as file)
 - key ring
 var keys = openpgp.generate_key_pair
 openpgp.keyring.importPrivateKey(keys.privateKeyArmored);
 openpgp.keyring.importPublicKey(keys.publicKeyArmored);
 openpgp.keyring.store();
 openpgp.keyring.init();
 - add public keys to Tree Storage Node (friends)
 - Tree Storage Container (EncryptedTree)

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

/*
// get user from private key
p = openpgp.read_privateKey(g_key_pair.privateKeyArmored);
p[0].userIds[0].text
// get user from public key
p = openpgp.read_publicKey(g_key_pair.publicKeyArmored);
*/

// Error Message function for openpgp
function showMessages(text)
{
    console.log(text);
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

// //////////////////////////////// angular
/*
Views:
- Keys: Priv/Pub Key, genieren, laden/speichern
- Tree View: Labels
- List View: Such Feld, Liste mit CryptedBoxes
- DecrypedView: decryped content (TextBox)
- Friends Public Key List

*/

angular.module('crypt', [])
    .config(function(){
        if (window.crypto.getRandomValues) {
            //require("./openpgp.min.js");
            openpgp.init();

        } else {
            window.alert("Error: Browser not supported\nReason: We need a cryptographically secure PRNG to be implemented (i.e. the window.crypto method)\nSolution: Use Chrome >= 11, Safari >= 3.1 or Firefox >= 21");
            return false;
        }
    })
    .value('pgp', {
        keyPair: null,
        password: '',
        generateKeyPair: function(user, password){
            //generate key
            this.keyPair = openpgp.generate_key_pair(1, 1024, user, password);
            this.password = password;
            return {
                publicKeyArmored: this.keyPair.publicKeyArmored,
                privateKeyArmored: this.keyPair.privateKeyArmored
            };
        },
        encrypt: function(message)
        {
            if (!this.keyPair) console.log('pgp.encrypt(): No keypair given!');
            if (!message) console.log('pgp.encrypt(): Message is empty!');

            // encrypt
            var msg_crypted = openpgp.write_encrypted_message(
                openpgp.read_publicKey(this.keyPair.publicKeyArmored), message);

            return msg_crypted;
        },
        decrypt: function(msg_crypted, password)
        {
            var key = this.keyPair;
            if (!key) console.log('pgp.decrypt(): No keypair given!');
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
                if (!keymat.keymaterial.decryptSecretMPIs(password)){
                    console.log("Password for secrect key was incorrect!");
                    return;
                }
                return msg[0].decrypt(keymat, sesskey);
            } else {
                console.log("No private key found!");
            }
        }
    });

/**
 * Storage for data.
 * Currently only localStorage but could be extended to public or private servers.
 */
angular.module('storage', [])
    .value('storage', {
        // General storage function
        set: function(name, data)
        {
            this.local.set(name, data);
        },
        get: function(name)
        {
            return this.local.get(name);
        },
        // localStorage
        local: {
            set: function(name, data)
            {
                window.localStorage.setItem(name, JSON.stringify(data));
            },
            get: function(name)
            {
                return JSON.parse( window.localStorage.getItem(name) );
            }
        }
    }
);

/**
 * Main App Module
 */
var jsPass = angular.module('jsPass', ['crypt', 'storage'])
    .run(function(pgp, storage){
        var key_pair = storage.get('key_pair');
        if (!key_pair)
        {
            key_pair = pgp.generateKeyPair('master');
            storage.set('key_pair', key_pair);
        }
        pgp.keyPair = key_pair;
    }
);

/**
 * html blur event for angularjs
 */
jsPass.directive('ngBlur', function() {
    return function( scope, elem, attrs ) {
        elem.bind('blur', function() {
            scope.$apply(attrs.ngBlur);
        });
    };
});

/**
 * List of users for encrypted content
 */
jsPass.factory('Users', function() {
    var users = [];

    return {
        add: function(name, public_key)
        {
            users.push({
                name: name,
                public_key: public_key
            });
        },
        remove: function(user)
        {
            // TODO
        }
    };
});

/**
 * Container for encrypted content
 */
jsPass.factory('CryptContainer', function() {
    var items = [];

    return {
        fill: function(new_items) {
            if (angular.isArray(new_items))
            {
                items = new_items;
            }
        },
        getAll: function() {
            return items;
        },
        count: function() {
            return items.length;
        },
        add: function(name) {
            var key = items.indexOf(name);
            if (key > -1)
            {
                items.push({
                    name: name
                });
                return true;
            }
            else
            {
                return false;
            }
        },
        find: function(name)
        {
            var found = -1;
            angular.forEach(items, function(item, key) {
                if (item.name == name)
                {
                    found = key;
                }
            });
            return found;
        },
        get: function(name)
        {
            var key = this.find(name);
            if (key > -1)
            {
                return items[key];
            }
            else
            {
                return false;
            }
        },
        set: function(item)
        {
            var key = this.find(item.name);
            if (key > -1)
            {
                items[key] = item;
            }
            else
            {
                return false;
            }
        },
        remove: function(name)
        {
            var key = this.find(name);
            if (key > -1)
            {
                return items.splice(key, 1);
            }
            else
            {
                return false;
            }
        }
    };
});

/**
 * View controller for encryped content
 */
function DecrypedView($scope, pgp, storage, CryptContainer) {
    //var key_pair = pgp.generateKeyPair('master');
    $scope.content = '';
    $scope.selected = null;

    // Get encrypted values from storage
    CryptContainer.fill(storage.get('items'));

    // Show encrypted values in view
    $scope.get = function()
    {
        return CryptContainer.getAll();
    };
    // Update view
    $scope.$watch( CryptContainer.count, function () {
        $scope.items = CryptContainer.getAll();
    });

    // Add item
    $scope.add_item = function()
    {
        CryptContainer.add( $scope.new_item );
    };

    $scope.load = function(item)
    {
        $scope.selected = item;
        if (item.data)
        {
            $scope.content = pgp.decrypt( item.data, $scope.password );
        }
        else
        {
            $scope.content = '';
        }
    };
    $scope.store = function()
    {
        if ($scope.selected)
        {
            $scope.selected.data = pgp.encrypt( $scope.content );
            CryptContainer.set( $scope.selected );
            storage.set('items', $scope.items);
        };
    };
    $scope.remove = function(name)
    {
        CryptContainer.remove(name);
    }
};

/**
 * View Controller for private and public key
 */
function KeysView($scope, pgp, storage)
{
    $scope.show = function(mode)
    {
        $scope.view = mode;
        if (mode == 'private_key')
        {
            $scope.key_title = 'Private Key';
            $scope.key = pgp.keyPair.privateKeyArmored;
        }
        else if (mode == 'public_key')
        {
            $scope.key_title = 'Public Key';
            $scope.key = pgp.keyPair.publicKeyArmored;
        }
    };
    $scope.user = function()
    {
        var user = $scope.name;
        if ($scope.email)
        {
            user += ' <' + $scope.email + '>';
        }
        return user;
    };

    $scope.generate_key = function()
    {
        if ($scope.generate_key_form.$valid)
        {
            var key_pair = pgp.generateKeyPair( $scope.user(), $scope.password );
            $scope.store_key();
            $scope.show('private_key');
        }
    };
    $scope.upload_key = function(element) {
        var file = element.files[0];
        var reader = new FileReader();
        reader.onload = function(loadEvent) {
            $scope.$apply(function () {
                var r = loadEvent.target.result;
                var data = r.substr(r.indexOf('base64') + 7);
                var file_content = (atob(data));

                $scope.key = file_content;
                $scope.store_key();
            });
        };
        reader.readAsDataURL(file);
    };

    $scope.key_download = function()
    {
        var blob = new Blob([$scope.key], {type: "text/plain;charset=utf-8"});
        saveAs(blob, $scope.view + '.asc');
        return false;
    }

    $scope.store_key = function()
    {
        if ($scope.view == 'public_key')
        {
            pgp.keyPair.publicKeyArmored = $scope.key;
        }
        else if ($scope.view == 'private_key')
        {
            pgp.keyPair.privateKeyArmored = $scope.key;
        }
        storage.set('key_pair', pgp.keyPair);
    }
}