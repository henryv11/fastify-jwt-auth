import {
  FastifyInstance,
  FastifyPluginCallback,
  FastifyRequest,
  preValidationHookHandler,
  RouteOptions,
  RouteShorthandOptions,
} from 'fastify';
import fp from 'fastify-plugin';
import jwt from 'jsonwebtoken';

const fastifyJwtAuth: FastifyPluginCallback<{
  algorithm: jwt.Algorithm;
  getToken?: (req: FastifyRequest) => Promise<string | undefined>;
  secret: jwt.Secret | Promise<jwt.Secret>;
  signOptions?: jwt.SignOptions;
  strategy?: (
    req: FastifyRequest,
    tokenResult: { token: NonNullable<FastifyRequest['token']> } | { error: string },
    conf: (RouteOptions | RouteShorthandOptions)['authorize'],
  ) => Promise<void>;
  tokenDescription?: string;
  tokenExample?: string;
  tokenHeaderPath?: string;
  validateTokenPayload?: (token: unknown) => token is NonNullable<FastifyRequest['token']>;
  verifyOptions?: jwt.VerifyOptions;
  issuer?: string | string[];
  audience?: string | string[];
  jwtid?: string;
}> = async function (
  app,
  {
    algorithm,
    getToken = (req: FastifyRequest) =>
      Promise.resolve((req.headers[tokenHeaderPath] as string | undefined)?.split(' ')[1]),
    secret: _secret,
    signOptions,
    strategy = req =>
      req.token ? Promise.resolve<void>(void 0) : Promise.reject(new UnauthorizedError({ response: req.tokenError })),
    tokenDescription = 'JSON Web Token in format "Bearer [token]',
    tokenExample = 'Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0IiwiaWF0IjoxNjAxODE0Mzc4fQ.Cqo8aBPhJN-hVN9wpAYNnIbLZ8M8ORMAMj_6ZIQTGV_g1hx3dti5Qjelgup2eh2dEnbP3aNmLqHKA7vYrJZjBQ',
    tokenHeaderPath = 'authorization',
    validateTokenPayload = () => true,
    verifyOptions,
    issuer,
    audience,
    jwtid,
  },
) {
  const secret = await _secret;

  const sign: FastifyInstance['jwt']['sign'] = function sign(payload, opts = sign.options) {
    return new Promise((resolve, reject) =>
      jwt.sign(payload, secret, opts, (err, token) => (err ? reject(err) : resolve(token as string))),
    );
  };

  const decode: FastifyInstance['jwt']['decode'] = function decode(token, opts = decode.options) {
    if (!token) throw new Error('missing token');
    return new Promise((resolve, reject) =>
      jwt.verify(token, secret, opts, (err, decoded) => {
        if (err) return reject(err);
        if (!decoded || !validateTokenPayload(decoded)) return reject(new Error('invalid token payload'));
        return resolve(decoded);
      }),
    );
  };

  sign.options = Object.freeze<jwt.SignOptions>({
    algorithm,
    ...signOptions,
    ...((jwtid || signOptions?.jwtid) && { jwtid: jwtid || signOptions?.jwtid }),
    ...((audience || signOptions?.audience) && { audience: audience || signOptions?.audience }),
    ...((issuer || signOptions?.issuer) && {
      issuer: (issuer && Array.isArray(issuer) ? issuer[0] : issuer) || signOptions?.issuer,
    }),
  });

  decode.options = Object.freeze<jwt.VerifyOptions>({
    jwtid,
    ...verifyOptions,
    algorithms: new Array().concat(algorithm, verifyOptions?.algorithms).filter(Boolean),
    issuer: new Array().concat(issuer, verifyOptions?.issuer).filter(Boolean),
    audience: new Array().concat(audience, verifyOptions?.audience).filter(Boolean),
  });

  app.decorate('jwt', Object.freeze<FastifyInstance['jwt']>({ sign, decode }));
  app.decorateRequest('token', null);
  app.decorateRequest('tokenError', '');
  app.decorateRequest('getToken', async function (this: FastifyRequest) {
    if (this.token) return { token: this.token };
    if (this.tokenError) return { error: this.tokenError };
    const token = await getToken(this);
    try {
      this.token = await app.jwt.decode(token);
      return { token: this.token };
    } catch (err) {
      this.tokenError = err.message;
      return { error: this.tokenError };
    }
  });

  app.addHook('onRoute', routeOptions => {
    if (!routeOptions.authorize) return;
    routeOptions.schema = {
      ...routeOptions.schema,
      headers: {
        ...(routeOptions.schema?.headers as any),
        type: 'object',
        required: [...((routeOptions.schema?.headers as any)?.required || []), tokenHeaderPath],
        properties: {
          ...(routeOptions.schema?.headers as any)?.properties,
          [tokenHeaderPath]: {
            type: 'string',
            example: tokenExample,
            description: tokenDescription,
          },
        },
      },
    };
    routeOptions.preValidation = new Array<preValidationHookHandler>().concat(async function (req) {
      await strategy(req, await req.getToken(), routeOptions.authorize);
    }, routeOptions.preValidation || []);
  });
};

export default fp(fastifyJwtAuth, { name: 'fastify-jwt-auth' });

class UnauthorizedError extends Error {
  public code = 401;
  public type = 'Unauthorized';
  constructor(public data: Record<string, unknown>) {
    super('Unauthorized');
    Error.captureStackTrace(this);
  }
}

declare module 'fastify' {
  interface FastifyRequest {
    token: null | ({ iat: number } & Partial<Record<string | number, string | number>>);
    tokenError: string | '';
    getToken: () => Promise<{ token: NonNullable<FastifyRequest['token']> } | { error: string }>;
  }
  interface RouteOptions {
    authorize?: Record<string, unknown> | boolean;
  }
  interface RouteShorthandOptions {
    authorize?: Record<string, unknown> | boolean;
  }
  interface FastifyInstance {
    jwt: Readonly<{
      sign: ((
        payload: Omit<NonNullable<FastifyRequest['token']>, 'iat'>,
        opts?: jwt.SignOptions,
      ) => Promise<string>) & {
        options: Readonly<jwt.SignOptions>;
      };
      decode: ((
        token: string | undefined | null | false,
        opts?: jwt.VerifyOptions,
      ) => Promise<NonNullable<FastifyRequest['token']>>) & { options: Readonly<jwt.VerifyOptions> };
    }>;
  }
}
