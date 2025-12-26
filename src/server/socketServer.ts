import compression from 'compression';
import winston from 'express-winston';
import { logger } from '../shared/logger.js';
import { serveStatic, trim } from './socketServer/assets.js';
import { html } from './socketServer/html.js';
import { metricMiddleware, metricRoute } from './socketServer/metrics.js';
import { favicon, redirect } from './socketServer/middleware.js';
import { policies } from './socketServer/security.js';
import { listen } from './socketServer/socket.js';
import { loadSSL } from './socketServer/ssl.js';
import type { SSL, SSLBuffer, Server } from '../shared/interfaces.js';
import type { Express } from 'express';
import type SocketIO from 'socket.io';

export async function server(
  app: Express,
  { base, port, host, title, allowIframe, secret_token }: Server,
  ssl?: SSL,
): Promise<SocketIO.Server> {
  const basePath = trim(base);
  logger().info('Starting server', {
    ssl,
    port,
    base,
    title,
  });
  if(secret_token !== undefined) {
    app.use((req, res, next) => {
      // 1. Define your secret token (MUST match what is in NPM)
      const WETTY_TOKEN = secret_token; 

      // 2. Read the header from the incoming request
      // Nginx Proxy Manager sends headers as lowercase 'x-wetty-token'
      const clientToken = req.headers['x-wetty-token']; 
      // 3. Allow access to 'web_modules' or 'assets' if needed? 
      //    Likely NO, we want to block the whole interface.

      // 4. Validate
      if (clientToken === WETTY_TOKEN) {
          return next(); // Proceed to load Wetty
      }
      // 5. Reject if mismatch
      // Using the imported logger to record the attempt
      logger().info('Blocked direct/unauthorized access attempt', { ip: req.ip });

      // Send 403 Forbidden
      res.status(403).send('Forbidden: Access allowed only via Proxy');
    });
  }
  const client = html(basePath, title);
  app
    .disable('x-powered-by')
    .use(metricMiddleware(basePath))
    .use(`${basePath}/metrics`, metricRoute)
    .use(`${basePath}/client`, serveStatic('client'))
    .use(
      winston.logger({
        winstonInstance: logger(),
        expressFormat: true,
        level: 'http',
      }),
    )
    .use(compression())
    .use(await favicon(basePath))
    .use(redirect)
    .use(policies(allowIframe))
    .get(basePath, client)
    .get(`${basePath}/ssh/:user`, client);

  const sslBuffer: SSLBuffer = await loadSSL(ssl);

  return listen(app, host, port, basePath, sslBuffer);
}
