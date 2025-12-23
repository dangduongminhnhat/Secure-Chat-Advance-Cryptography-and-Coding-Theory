// ============================================
// File: src/handlers/responseHandler.js
// ============================================
export class ResponseHandler {
  constructor() {
    this.corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Session-Token',
      'Content-Type': 'application/json'
    };
  }

  // Success response
  success(data, status = 200) {
    return new Response(
      JSON.stringify({
        success: true,
        ...data
      }),
      {
        status,
        headers: this.corsHeaders
      }
    );
  }

  // Error response
  error(message, status = 400) {
    return new Response(
      JSON.stringify({
        success: false,
        error: message
      }),
      {
        status,
        headers: this.corsHeaders
      }
    );
  }

  // CORS preflight response
  cors() {
    return new Response(null, {
      headers: this.corsHeaders
    });
  }

  // Session not found error
  sessionNotFound() {
    return this.error('Session not found or expired', 404);
  }

  // Unauthorized error
  unauthorized(message = 'Unauthorized') {
    return this.error(message, 401);
  }

  // Internal server error
  serverError(error) {
    console.error('Server error:', error);
    return this.error(String(error), 500);
  }
}