/*
 *  RANTOK NODE
 *
 * Copyright (C) 2018 Sergio José Muñoz López <semulopez@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

if (process.argv.length != 6) {
  console.log('Usage: rantok-node [hostname] [port] [dns-hostname] [dns-port]');
  process.exit();
}

const Datastore = require('nedb'); // DataBase
const inquirer = require('inquirer'); // CommandLine
const net = require('net'); // Network Connection
const crypto = require('crypto'); // Hash Function
const NodeRSA = require('node-rsa'); // RSA KEYS Function
const uuid = require('uuid'); // Unique ID Generator (SECURED)

const MAX_JUMPS = 7;
const CIPHER_ALG = 'aes256';

var db = new Datastore();
var public_db = {};

var hostname = String(process.argv[2]);
var port = Number(process.argv[3]);

var dns_hostname = String(process.argv[4]);
var dns_port = Number(process.argv[5]);

var verbose = false;

// CommandLine Menu Description
var actions_set = [{
  type: 'list',
  name: 'Action',
  message: 'Get, Put, Exit:',
  choices: [ 'get', 'put', 'exit' ],
  default: 'get'
}];
var get_set = [{
  type: 'input',
  name: 'dest_hostname',
  message: 'Destitation hostname:',
  validate: function( value ) {
    if (value.length) {
      return true;
    } else {
      return 'Please enter a hostname.';
    }
  }
},{
  type: 'input',
  name: 'dest_port',
  message: 'Destitation port:',
  validate: function( value ) {
    if (value.length) {
      return true;
    } else {
      return 'Please enter a port.';
    }
  }
},{
  type: 'input',
  name: 'key',
  message: 'Name of the [key] to obtain the [value]:',
  validate: function( value ) {
    if (value.length) {
      return true;
    } else {
      return 'Please enter a key.';
    }
  }
}];
var put_set = [{
  type: 'input',
  name: 'dest_hostname',
  message: 'Destitation hostname:',
  validate: function( value ) {
    if (value.length) {
      return true;
    } else {
      return 'Please enter a hostname.';
    }
  }
},{
  type: 'input',
  name: 'dest_port',
  message: 'Destitation port:',
  validate: function( value ) {
    if (value.length) {
      return true;
    } else {
      return 'Please enter a port.';
    }
  }
},{
  type: 'input',
  name: 'key',
  message: 'Insert the [key]:',
  validate: function( value ) {
    if (value.length) {
      return true;
    } else {
      return 'Please enter a key.';
    }
  }
},{
  type: 'input',
  name: 'value',
  message: 'insert the [value]:',
  validate: function( value ) {
    if (value.length) {
      return true;
    } else {
      return 'Please enter a value.';
    }
  }
}];

var _uuid = uuid.v4();

// RSA Object with 1024 bits size
var key = new NodeRSA({b: 1024});;

// RANTOK Nodes collection
var rt_nodes={};

// Start Main Function
_startNode();


// Main Function
function _startNode() {
  console.log('[rantok-node] Starting rantok node on '+hostname+':'+port+'...');

  process.stdout.write('[rantok-node] Generating asymmetrics keys...');
  key.generateKeyPair();
  console.log('OK');

  //  console.log('keys:\n'+key.exportKey('pkcs8-public-pem')+'\n'+key.exportKey('pkcs1-private-pem'));

  process.stdout.write('[rantok-node] Discovering nodes from '+dns_hostname+':'+dns_port+'...');
  _discoverNodes();

}

function _actions() {

  inquirer.prompt(actions_set).then(function(answer) {

    switch (answer.Action) {
    case 'get':
        inquirer.prompt(get_set).then((answer) => {
          process.stdout.write('[rantok-node] Sending request...');
          answer.type='get';
          _send(answer);
        });
      break;
    case 'put':
        inquirer.prompt(put_set).then((answer) => {
          process.stdout.write('[rantok-node] Sending request...');
          answer.type='put';
          _send(answer);
        });
      break;
    case 'exit':
    // Unregister Node on DNS and exit
        _unregDns(0);
      break;
    default:

    }

  });

}

function _shareSymKeyAndSend(dst, message, jmp) {

  var symKey = uuid.v4();

  var rt_node = new net.Socket();
  try {

    rt_node.connect(dst.port, dst.ip, function() {

      //rt_node.write(JSON.stringify({type: 'com', value: dst.key.encrypt(Buffer.from(JSON.stringify({uuid: _uuid, symKey: symKey})))}));

     var dest_key = new NodeRSA(dst.publicKey);

     try {
       rt_node.write(dest_key.encrypt(Buffer.from(JSON.stringify({type: 'com', value:{uuid: _uuid, symKey: symKey}}))));

       rt_node.on('data', (status) => {
         var cipher = crypto.createCipher(CIPHER_ALG,symKey);
        try {
           rt_node.write(JSON.stringify({type: 'pkg', uuid: _uuid, value: cipher.update(JSON.stringify(message),'utf8','hex')+cipher.final('hex')}));
        } catch (e) {

        }

         if(jmp<0){
           console.log(status.toString('utf8'));
           _actions();
         }

         rt_node.destroy();
       })
     } catch (e) {

       rt_node.destroy();

     }

    });

  } catch (e) {

    if(jmp<0){
      console.log('[rantok-node] Not responding...Try again?');
      _actions();
    }

  }

}
// Mapped Random Number Generator
function getRandomInt(min, max) {
    // TODO: Use better random library
    return Math.floor(Math.random() * (max - min)) + min;
}

// Reduce Set Choose - Jump Algorithm
function _rscNode() {

    /*var rsc_rt_nodes = {};// = JSON.parse(JSON.stringify(rt_nodes));

    if(Object.keys(rt_nodes).length-1 > 0){
      var number = getRandomInt(0, Object.keys(rt_nodes).length-1);

      for (var i = 0; i < number; i++) {
        var randNum = getRandomInt(0, Object.keys(rsc_rt_nodes).length-1);
          if(Object.keys(rsc_rt_nodes).length > 1)
            rsc_rt_nodes[Object.keys(rt_nodes)[randNum]] = rt_nodes[Object.keys(rt_nodes)[randNum]];
      }
    } else {
      return rt_nodes[Object.keys(rsc_rt_nodes)[0]];
    }
  */
  var random = getRandomInt(0, Object.keys(rt_nodes).length-1);

  return rt_nodes[Object.keys(rt_nodes)[random]];


}

function _send(answer,jmp) {

  if(answer.dest_hostname === hostname&&Number(answer.dest_port) === port){
    console.log('FAIL');
    console.error('[rantok-node] Can\'t request itself!!');
    _actions();
  }else {

    var values = JSON.parse(JSON.stringify(answer));

    delete values.dest_hostname;
    delete values.dest_port;

    var message = {request: values, uuid: _uuid, random: uuid.v4()};

    var hash = crypto.createHash('sha256');

    hash.update(JSON.stringify(message));

    db.find({ip: answer.dest_hostname, port: Number(answer.dest_port)}, function(err, node) {
      if(node.length>0){

        //console.log(node, ' ', JSON.stringify(node));

        var node_key = new NodeRSA(rt_nodes[node[0].uuid].publicKey);

        message.hash = hash.digest('hex');

        message = node_key.encrypt(Buffer.from(JSON.stringify(message)));

        var rscDest = _rscNode();

        var number = getRandomInt(2, MAX_JUMPS);

        //// DEBUG:
        message = {message: message, dst: node[0].uuid, jmp: number, id: uuid.v4()};

        _shareSymKeyAndSend(rscDest, message, jmp || -1);
      } else {
        console.log('FAIL');
        console.error('[rantok-node] Destination not exist.');
        _actions();
      }
    });

  }
}

// Unregister from DNS and Exit the Node
function _unregDns(code) {
  var rt_dns = new net.Socket();
  rt_dns.connect(dns_port, dns_hostname, function() {
    rt_dns.write(JSON.stringify({type: 'delete', uuid:_uuid}));
    process.exit (code);
  });
}

function _finishStartNode(){

  console.log('OK');

  console.log('[rantok-node] '+((Object.keys(rt_nodes).length>0)?Object.keys(rt_nodes).length:0)+' nodes found!');

  process.stdout.write('[rantok-node] Starting listener...');
  _startListening();
  console.log('OK');

  if(Object.keys(rt_nodes).length>0){
      process.stdout.write('[rantok-node] Handshaking with the other nodes...');
      for (var node in rt_nodes) {
        if (!rt_nodes[node].publicKey)
          _handShake(node);
      }
  }else
    _actions();

    process.stdin.resume();

    process.on ('exit', code => {

      _unregDns(code);

    });

    // Catch CTRL+C
    process.on ('SIGINT', () => {
      _unregDns(0);
    });

    process.on ('uncaughtException', err => {
      console.dir (err, { depth: null });
      _unregDns (1);
    });

}

function _handShake(node) {

  var rt_node = new net.Socket();
  rt_node.connect(rt_nodes[node].port, rt_nodes[node].hostname, function() {
  	//console.log('Send PKey to ', JSON.stringify(rt_nodes[node]));
    rt_node.write(JSON.stringify({type: 'handshake', value: {uuid: _uuid, ip:hostname, port:port, publicKey: key.exportKey('public')}}));
  });

  rt_node.on('data', function(data) {
    data = JSON.parse(data.toString('utf8'));
  	//console.log('Received public key: ' + data.publicKey);
    rt_nodes[node].publicKey = data.publicKey;
    if(node===Object.keys(rt_nodes)[Object.keys(rt_nodes).length-1]){
      console.log('OK');
      rt_node.destroy();
      _actions();
    }
  });

}

function _discoverNodes() {
  db = new Datastore();
  var rt_dns = new net.Socket();
  rt_dns.connect(dns_port, dns_hostname, function() {
  	rt_dns.write(JSON.stringify({type: 'get', ip:hostname, port:Number(port), uuid:_uuid}));
  });

  rt_dns.on('data', function(data) {
    data = JSON.parse(data.toString('utf8'))
    for (var node in data) {
      delete data._id;
      rt_nodes[data[node].uuid] = {ip:data[node].ip, port:Number(data[node].port), publicKey: false, symKey: false};
      db.insert(data, function(err, data){});
    }
      _finishStartNode();
  });

}

function _processPackage(pkg) {

    //// DEBUG:
    console.log('PGK: '+pkg.id, '-', pkg.jmp);

  if (pkg.jmp>1) {

    var rscDest = _rscNode();

    //// DEBUG:
    message = {message: pkg.message, dst: pkg.dst, jmp: pkg.jmp-1, id: pkg.id};

    //rt_node.write(JSON.stringify({type: 'pkg', uuid: _uuid, value: crypto.createCipher(CIPHER_ALG, symKey).update(JSON.stringify(message), 'utf-8', 'hex')}));

    _shareSymKeyAndSend(rscDest, message, pkg.jmp);

  } else {

    if(pkg.dst === _uuid){

      var data = pkg.message;

      data = JSON.parse(key.decrypt(Buffer.from(data)).toString('utf8'));

      //console.log('ORIGINAL:' + JSON.stringify(data));

      var data_hash = data.hash;

      delete data.hash;

      var hash = crypto.createHash('sha256');

      hash.update(JSON.stringify(data));

      if (hash.digest('hex') != data_hash) {
        console.error('HASH ERROR!!');
      }else {
        var dst = data.uuid;
        data = data.request;
        switch (data.type) {
          case 'get':
          var res={dest_hostname: rt_nodes[dst].ip, dest_port:rt_nodes[dst].port, type: 'response', key: data.key, value: public_db[data.key]};
          _send(res, 1);
            break;
          case 'put':
            public_db[data.key] = data.value;
            break;
          case 'response':
            console.log('\n[rantok-node] (',rt_nodes[dst].ip+':'+rt_nodes[dst].port+'/'+data.key,') => ',data.value);
            console.log('\n\n');
            break;
          default:
            break;
        }
      }

    } else{
      //console.log(rt_nodes[pkg.dst]);

      _shareSymKeyAndSend(rt_nodes[pkg.dst], pkg, pkg.jmp);
    }

  }

}

function _startListening() {
  var rt_listener = net.createServer(function(socket) {

  	socket.on('data', function(data){

      try {
        data = JSON.parse(data.toString('utf8'));
        //console.log('Plain-text');
      } catch (e) {
          try {
            data = key.decrypt(data).toString('utf8');
            data = JSON.parse(data);
          } catch (e) {
            console.error(e);
            console.log(data.toString('utf8'));
          }
          //console.log('Public-key')
        }

      switch (data.type) {
        case 'handshake':
          delete data.type;
          rt_nodes[data.value.uuid] = data.value;
          db.insert(data.value, function(err, data){});
          socket.write(JSON.stringify({publicKey: key.exportKey('public')}));
          break;
        case 'com':
          rt_nodes[data.value.uuid].symKey = data.value.symKey;
          socket.write('OK');
          break;
        case 'pkg':
          var decipher = crypto.createDecipher(CIPHER_ALG,rt_nodes[data.uuid].symKey);
          data.value = decipher.update(data.value,'hex','utf8')+decipher.final('utf8');
          data.value = JSON.parse(data.value);
          _processPackage(data.value);
          break;

        default:
          break;
      }

      });

      socket.on('end', socket.end);

    });

  rt_listener.listen(port, hostname);
}
