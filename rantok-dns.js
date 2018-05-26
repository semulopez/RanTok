/*
 *    RANTOK DNS
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

if (process.argv.length != 4) {
  console.log('Usage: rantok-dns [hostname] [port]');
  process.exit();
}

var net = require('net');
var Datastore = require('nedb');
var rt_nodes = new Datastore(/*{ filename: 'rantok-nodes.db', autoload: true }*/);

var hostname = String(process.argv[2]);
var port = Number(process.argv[3]);

process.stdout.write('[rantok-dns] Starting...');
var server = net.createServer(function(socket) {
  process.stdout.write('[rantok-dns] New connection: ');

	socket.on('data', function(data){
    try {

      data = JSON.parse(data.toString('utf8'));

    } catch (e) {
      console.log(e);
    }

    switch (data.type) {
      case 'get':
          rt_nodes.find({}, function(err, nodes) {
            socket.write(JSON.stringify(nodes));
            rt_nodes.insert(data, function(err, data) {
                console.log('<rantok-node uuid:\''+data.uuid+'\' ip:'+data.ip+' port:'+data.port+'>...ADD');
            });
          });
        break;
      case 'delete':
          rt_nodes.remove({ uuid: data.uuid }, {}, function (err, numRemoved) {
            console.error('<rantok-node uuid:\''+data.uuid+'\'>...DEL');
          });
        break;
      default:

    }

  });

  socket.on('end', socket.end);

});

server.listen(port, hostname);
console.log('OK');
