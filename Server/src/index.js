import { checkQuota } from './utils/rateLimits.js';
import { RequestHandler } from './handlers/requestHandler.js';
import { ResponseHandler } from './handlers/responseHandler.js';

export default {
  async fetch(request, env) {
    const quota = await checkQuota(request, env);
    if (!quota.allowed) return quota.response;

    const url = new URL(request.url);
    const requestHandler = new RequestHandler(env);
    const responseHandler = new ResponseHandler();

    if (request.method === "OPTIONS") {
      return responseHandler.cors();
    }

    const routes = {
      'POST /session/create': () => requestHandler.handleCreateSession(request),
      'POST /session/exchange': () => requestHandler.handleKeyExchange(request),
      'POST /message/send': () => requestHandler.handleSendMessage(request),
      'GET /session/status': () => requestHandler.handleSessionStatus(request),
      'POST /session/delete': () => requestHandler.handleDeleteSession(request),
      'GET /algorithms': () => requestHandler.handleGetAlgorithms(request),
      'GET /signatures': () => requestHandler.handleGetSignatures(request),
    };

    const routeKey = `${request.method} ${url.pathname}`;
    const handler = routes[routeKey];

    if (handler) {
      try {
        return await handler();
      } catch (error) {
        return responseHandler.serverError(error);
      }
    }

    return responseHandler.error("Endpoint not found", 404);
  }
};