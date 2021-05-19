/* eslint-disable @typescript-eslint/no-explicit-any */
import Fastify from 'fastify';
import FastifyJWT from '../src/';

const secret = `
-----BEGIN PRIVATE KEY-----
MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAq7BFUpkGp3+LQmlQ
Yx2eqzDV+xeG8kx/sQFV18S5JhzGeIJNA72wSeukEPojtqUyX2J0CciPBh7eqclQ
2zpAswIDAQABAkAgisq4+zRdrzkwH1ITV1vpytnkO/NiHcnePQiOW0VUybPyHoGM
/jf75C5xET7ZQpBe5kx5VHsPZj0CBb3b+wSRAiEA2mPWCBytosIU/ODRfq6EiV04
lt6waE7I2uSPqIC20LcCIQDJQYIHQII+3YaPqyhGgqMexuuuGx+lDKD6/Fu/JwPb
5QIhAKthiYcYKlL9h8bjDsQhZDUACPasjzdsDEdq8inDyLOFAiEAmCr/tZwA3qeA
ZoBzI10DGPIuoKXBd3nk/eBxPkaxlEECIQCNymjsoI7GldtujVnr1qT+3yedLfHK
srDVjIT3LsvTqw==
-----END PRIVATE KEY-----
`.trim();

function getConfiguredApp() {
  const app = Fastify({ logger: !true });
  app.register(FastifyJWT, {
    secret,
    algorithm: 'RS256',
    audience: 'fidget-spinners.com',
    issuer: 'fidget-spinners-auth',
    token: {},
  });

  return app;
}

describe('fastify-jwt', () => {
  test('works', async () => {
    const app = getConfiguredApp();
    app.get('/', {
      authorize: true,
      handler: (req, res) => {
        console.log(req.token);
        res.send(req.token?.message + ' ' + req.token?.sub);
      },
    });

    await app.ready();
    const res = await app.inject({ path: '/', method: 'GET' }).then(res => res.json<any>());
    expect(res.message).toBe('Unauthorized');

    const message = 'hey there';
    const userId = 123;
    const res2 = await app
      .inject({
        path: '/',
        method: 'GET',
        headers: { authorization: `Bearer ${await app.jwt.sign({ message, userId })}` },
      })
      .then(res => res.body);
    expect(res2).toBe(message + ' ' + userId);
  });
});
