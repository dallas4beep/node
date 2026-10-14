'use strict';
const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');
const { opensslCli } = require('../common/crypto');
if (!opensslCli)
  common.skip('missing OpenSSL CLI');

const assert = require('assert');
const { spawn } = require('child_process');
const net = require('net');
const tls = require('tls');
const fixtures = require('../common/fixtures');
const destroy = process.argv[2] === 'destroy';
if (!destroy) {
  const child = spawn(process.execPath, [__filename, 'destroy'], {
    stdio: 'inherit',
  });
  child.on('exit', common.mustCall((code) => assert.strictEqual(code, 0)));
}

// TLS 1.3 control records have the same outer type as application records.
// Deliver data, KeyUpdate and more data together, and check callback ordering.
const before = 'before-key-update\n';
const after = 'after-key-update\n';
let received = '';
let holding = false;
let client;

const onUpdate = destroy ? common.mustNotCall() : common.mustCall(() => {
  assert.strictEqual(received, before);
});
const server = tls.createServer({
  key: fixtures.readKey('agent1-key.pem'),
  cert: fixtures.readKey('agent1-cert.pem'),
  minVersion: 'TLSv1.3',
}, common.mustCall((socket) => {
  holding = true;
  socket.on('data', common.mustCallAtLeast((data) => {
    received += data;
    if (received === before) {
      if (destroy) {
        socket._destroySSL();
        socket.destroy();
        server.close();
        proxy.close();
        return;
      }
      socket.write('ack');
    }
    if (received === before + after) {
      socket.end();
      server.close();
      proxy.close();
    }
  }));
  socket.on('close', common.mustCall(() => {
    assert.strictEqual(received, destroy ? before : before + after);
  }));
  socket.on('error', common.mustNotCall());
  client.stdin.write(before);
}));
server.on('keylog', (line) => {
  if (/^CLIENT_TRAFFIC_SECRET_(?:N|1) /.test(line.toString())) onUpdate();
});

const proxy = net.createServer(common.mustCall((socket) => {
  const upstream = net.connect({
    port: server.address().port,
    allowHalfOpen: true,
  });
  upstream.pipe(socket);
  socket.on('end', () => upstream.end());
  socket.on('close', () => upstream.destroy());
  const held = [];
  let pending = Buffer.alloc(0);
  let records = 0;
  socket.on('data', common.mustCallAtLeast((data) => {
    if (!holding) {
      upstream.write(data);
      return;
    }
    held.push(data);
    pending = Buffer.concat([pending, data]);
    while (pending.length >= 5) {
      const length = pending.readUInt16BE(3);
      if (pending.length < 5 + length) break;
      assert.strictEqual(pending[0], 23);
      pending = pending.subarray(5 + length);
      records++;
      if (records === 1) client.stdin.write('k\n');
      if (records === 2) client.stdin.write(after);
      if (records === 3) {
        holding = false;
        upstream.write(Buffer.concat(held));
        return;
      }
    }
  }));
}));

server.listen(0, common.mustCall(() => {
  proxy.listen(0, common.mustCall(() => {
    client = spawn(opensslCli, [
      's_client', '-tls1_3', '-connect', `127.0.0.1:${proxy.address().port}`,
      '-CAfile', fixtures.path('keys', 'ca1-cert.pem'), '-servername', 'agent1',
    ]);
    client.stdout.resume();
    client.stderr.resume();
    client.on('error', common.mustNotCall());
    client.on('exit', common.mustCall((code) => {
      if (destroy) {
        assert(code === 0 || code === 1);
      } else {
        assert.strictEqual(code, 0);
      }
    }));
  }));
}));
