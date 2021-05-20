/* eslint-disable @typescript-eslint/no-explicit-any */
import {
  FastifyInstance,
  FastifyPluginCallback,
  FastifyRequest,
  preValidationHookHandler,
  RouteOptions,
  RouteShorthandOptions,
} from 'fastify';
import fp from 'fastify-plugin';
import { Algorithm, Secret, sign, SignOptions, verify, VerifyOptions } from 'jsonwebtoken';

const fastifyJwtAuth: FastifyPluginCallback<{
  secret: Secret;
  algorithm: Algorithm;
  audience?: string;
  issuer?: string;
  token?: {
    description?: string;
    example?: string;
    get?: (req: FastifyRequest) => Promise<string | undefined>;
    headerPath?: string;
    validatePayload?: (token: unknown) => token is Exclude<FastifyRequest['token'], null>;
  };
  strategy?: (req: FastifyRequest, conf: (RouteOptions | RouteShorthandOptions)['authorize']) => Promise<void>;
}> = function (
  app,
  {
    secret,
    algorithm,
    audience,
    token,
    issuer,
    strategy = req =>
      req.token ? Promise.resolve<void>(void 0) : Promise.reject(new UnauthorizedError({ response: req.tokenError })),
  },
  done,
) {
  const tokenConfig = {
    headerPath: 'authorization',
    description: 'JSON Web Token in format "Bearer [token]',
    validatePayload: () => true,
    example:
      'Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0IiwiaWF0IjoxNjAxODE0Mzc4fQ.Cqo8aBPhJN-hVN9wpAYNnIbLZ8M8ORMAMj_6ZIQTGV_g1hx3dti5Qjelgup2eh2dEnbP3aNmLqHKA7vYrJZjBQ',
    get: (req: FastifyRequest) =>
      Promise.resolve((req.headers[tokenConfig.headerPath] as string | undefined)?.split(' ')[1]),
    ...token,
  };
  const jwt = Object.freeze<FastifyInstance['jwt']>({
    sign: ({ sub, subject, userId, email, ...payload }, opts) =>
      new Promise((res, rej) =>
        sign(
          payload,
          secret,
          {
            ...opts,
            algorithm,
            ...(audience && { audience }),
            ...(issuer && { issuer }),
            subject: String(sub || subject || userId || email),
          },
          (err, token) => (err ? rej(err) : res(token as string)),
        ),
      ),

    decode: (token, opts) =>
      !token
        ? Promise.reject(new Error('missing token'))
        : new Promise((res, rej) =>
            verify(
              token,
              secret,
              {
                ...opts,
                algorithms: castArray(opts?.algorithms).concat(algorithm).filter(isNonNullable),
                audience: castArray(opts?.audience).concat(audience).filter(isNonNullable),
                issuer: castArray(opts?.issuer).concat(issuer).filter(isNonNullable),
              },
              (err, decoded) => {
                if (err) return rej(err);
                if (!decoded || !tokenConfig.validatePayload(decoded)) return rej(new Error('invalid token payload'));
                return res(decoded);
              },
            ),
          ),
  });

  app.decorate('jwt', jwt);
  app.decorateRequest('token', null);
  app.decorateRequest('tokenError', '');

  app.addHook('onRequest', (req, _, done) =>
    tokenConfig
      .get(req)
      .then(token =>
        jwt
          .decode(token)
          .then(decoded => (req.token = decoded))
          .catch(err => (req.tokenError = err.message))
          .finally(done),
      )
      .catch(err => done(err)),
  );

  app.addHook('onRoute', routeOptions => {
    if (!routeOptions.authorize) return;
    routeOptions.schema = {
      ...routeOptions.schema,
      headers: {
        ...(routeOptions.schema?.headers as any),
        type: 'object',
        required: [...((routeOptions.schema?.headers as any)?.required || []), tokenConfig.headerPath],
        properties: {
          ...(routeOptions.schema?.headers as any)?.properties,
          [tokenConfig.headerPath]: {
            type: 'string',
            example: tokenConfig.example,
            description: tokenConfig.description,
          },
        },
      },
    };
    routeOptions.preValidation = new Array<preValidationHookHandler>().concat(
      (req, _, done) =>
        strategy(req, routeOptions.authorize)
          .then(() => done())
          .catch(err => done(err)),
      routeOptions.preValidation || [],
    );
  });

  done();
};

export default fp(fastifyJwtAuth);

class UnauthorizedError extends Error {
  public code = 401;
  public type = 'Unauthorized';
  constructor(public data: Record<string, unknown>) {
    super('Unauthorized');
    Error.captureStackTrace(this);
  }
}

function castArray<T>(value: T): (T extends (infer U)[] ? U : T)[] {
  return (Array.isArray(value) ? value : [value]) as any;
}

function isNonNullable<T>(value: T): value is NonNullable<T> {
  return value != null;
}

declare module 'fastify' {
  interface FastifyRequest {
    token: null | ({ iat: number } & Partial<Record<string | number, string | number>>);
    tokenError: string | '';
  }
  interface RouteOptions {
    authorize?: Record<string, unknown> | boolean;
  }
  interface RouteShorthandOptions {
    authorize?: Record<string, unknown> | boolean;
  }
  interface FastifyInstance {
    jwt: Readonly<{
      sign: (payload: Omit<Exclude<FastifyRequest['token'], null>, 'iat'>, opts?: SignOptions) => Promise<string>;
      decode: (
        token: string | undefined | null | false,
        opts?: VerifyOptions,
      ) => Promise<Exclude<FastifyRequest['token'], null>>;
    }>;
  }
}
