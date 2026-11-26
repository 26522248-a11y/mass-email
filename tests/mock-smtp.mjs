import net from 'node:net';

/** Minimal SMTP sink for tests. Rejects addresses listed in `reject`. */
export function startMockSmtp({ reject = ['bad@example.com'] } = {}) {
  const messages = [];
  const connections = [];
  const server = net.createServer((socket) => {
    const state = { from: null, rcpts: [], data: null, buf: '', inData: false };
    connections.push(socket);
    socket.write('220 mock.test ESMTP\r\n');
    socket.on('data', (chunk) => {
      state.buf += chunk.toString('utf8');
      let idx;
      while ((idx = state.buf.indexOf('\r\n')) !== -1) {
        const line = state.buf.slice(0, idx);
        state.buf = state.buf.slice(idx + 2);
        if (state.inData) {
          if (line === '.') {
            state.inData = false;
            messages.push({ from: state.from, rcpts: [...state.rcpts], raw: state.data, receivedAt: Date.now() });
            state.data = null; state.rcpts = [];
            socket.write('250 2.0.0 queued\r\n');
          } else {
            state.data += (state.data ? '\r\n' : '') + line.replace(/^\.\./, '.');
          }
          continue;
        }
        const upper = line.toUpperCase();
        if (upper.startsWith('EHLO')) socket.write('250-mock.test\r\n250-SIZE 10485760\r\n250-8BITMIME\r\n250-PIPELINING\r\n250 AUTH PLAIN LOGIN\r\n');
        else if (upper.startsWith('HELO')) socket.write('250 mock.test\r\n');
        else if (upper.startsWith('AUTH')) socket.write('235 2.7.0 ok\r\n');
        else if (upper.startsWith('MAIL FROM')) { state.from = /<([^>]*)>/.exec(line)?.[1] ?? ''; socket.write('250 2.1.0 ok\r\n'); }
        else if (upper.startsWith('RCPT TO')) {
          const to = /<([^>]*)>/.exec(line)?.[1]?.toLowerCase() ?? '';
          if (reject.includes(to)) socket.write('550 5.1.1 no such user\r\n');
          else { state.rcpts.push(to); socket.write('250 2.1.5 ok\r\n'); }
        } else if (upper === 'DATA') { state.inData = true; state.data = ''; socket.write('354 end with .\r\n'); }
        else if (upper === 'RSET') { state.rcpts = []; socket.write('250 ok\r\n'); }
        else if (upper === 'QUIT') { socket.write('221 bye\r\n'); socket.end(); }
        else socket.write('250 ok\r\n');
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({
      port: server.address().port,
      messages,
      close: () => new Promise((r) => { for (const s of connections) s.destroy(); server.close(r); }),
    }));
  });
}
