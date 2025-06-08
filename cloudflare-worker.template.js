/**
 * Cloudflare Worker for AbuseIPDB API Proxy
 * 
 * This worker acts as a proxy for the AbuseIPDB API, which:
 * 1. Protects your API key from client exposure
 * 2. Handles CORS for browser requests
 * 3. Returns the complete AbuseIPDB API response
 * 4. Uses HMAC-based authentication for security with build-time generated keys
 * 
 * Deploy this to your Cloudflare Workers account and update the 
 * AbuseIPDBService.cs file with your worker URL.
 */

// Import build-time generated constants (will be injected during build)
// __BUILD_CONSTANTS_INJECTION_POINT__

// Configuration - API key will be injected during GitHub Actions build
const ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY_WILL_BE_INJECTED_HERE";
const ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check";

// Authentication key - this will be replaced with generated key during build
// If build constants are available, use them; otherwise fallback to default
let AUTH_KEY;
let BUILD_INFO = {};

try {
  // Try to use build-time generated constants
  if (typeof GENERATED_AUTH_KEY !== 'undefined') {
    AUTH_KEY = GENERATED_AUTH_KEY;
    BUILD_INFO = {
      buildId: BUILD_ID || 'unknown',
      buildTimestamp: BUILD_TIMESTAMP || 'unknown',
      keySource: 'generated'
    };
    console.log(`Using generated auth key - Build: ${BUILD_INFO.buildId} (${BUILD_INFO.buildTimestamp})`);
  } else {
    throw new Error('Generated constants not available');
  }
} catch (error) {
  // Fallback to hardcoded key for development
  AUTH_KEY = "albatross-abuseipdb-client";
  BUILD_INFO = {
    buildId: 'dev',
    buildTimestamp: new Date().toISOString(),
    keySource: 'fallback'
  };
  console.log('Using fallback auth key for development');
}

// Create a mapping of known allowed origins
const ALLOWED_ORIGINS = [
  "https://albatross.devnomadic.com",
  // Production Cloudflare Pages
  "https://albatross.pages.dev",
  // Albatross preview deployments on Cloudflare Pages (specific pattern)
  "https://albatross-5kt.pages.dev",
  // Wildcard patterns for albatross-5kt subdomain deployments
  "*.albatross-5kt.pages.dev",
  "*.albatross.pages.dev",
  // Preview worker domain
  "https://abuseipdb-preview.devnomadic.workers.dev"
  // Note: localhost removed for security - only production origins allowed
];

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  // Handle CORS preflight requests
  if (request.method === "OPTIONS") {
    return handleCORS(request);
  }

  // Get the request origin
  const origin = request.headers.get('Origin') || '';
  
  // Debug CORS
  console.log('Request CORS info:', {
    origin,
    isAllowed: isAllowedOrigin(origin),
    userAgent: request.headers.get('User-Agent'),
    referer: request.headers.get('Referer')
  });
  
  // Enforce browser-only access with proper Origin header validation
  // This ensures the worker can only be called from legitimate browser requests
  const userAgent = request.headers.get('User-Agent') || '';
  const referer = request.headers.get('Referer') || '';
  
  // Check if this is a legitimate browser request
  const isBrowserRequest = origin && (
    userAgent.includes('Mozilla') || 
    userAgent.includes('Chrome') || 
    userAgent.includes('Safari') || 
    userAgent.includes('Firefox') || 
    userAgent.includes('Edge')
  );
  
  // Additional validation: browser requests should have Origin header from allowed origins
  const hasValidOrigin = origin && isAllowedOrigin(origin);
  
  // Block requests that don't appear to be from a legitimate browser/SPA
  if (!isBrowserRequest || !hasValidOrigin) {
    console.log('Blocked non-browser request:', {
      origin,
      userAgent: userAgent.substring(0, 50),
      referer: referer.substring(0, 50),
      isBrowserRequest,
      hasValidOrigin
    });
    
    return new Response(
      JSON.stringify({ 
        error: "Access denied: Browser requests from allowed origins only",
        buildInfo: BUILD_INFO,
        details: "This API can only be accessed from the official web application"
      }),
      {
        status: 403,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders(origin)
        }
      }
    );
  }
  
  // Get the Worker-Token (HMAC token)
  const workerToken = request.headers.get('Worker-Token') || '';
  
  // Debug: Log the full request URL for verification
  console.log('Full request URL:', request.url);
  console.log('URL search params:', new URL(request.url).searchParams.toString());
  console.log('Build info:', BUILD_INFO);
  
  // Convert URL to lowercase for consistent HMAC generation
  const normalizedUrl = request.url.toLowerCase();
  console.log('Normalized URL for HMAC:', normalizedUrl);
  
  // Validate the HMAC token
  if (!workerToken || !(await validateHmacToken(workerToken, normalizedUrl))) {
    return new Response(
      JSON.stringify({ 
        error: "Unauthorized: Invalid authentication token",
        buildInfo: BUILD_INFO
      }),
      {
        status: 401,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders(origin)
        }
      }
    );
  }

  // Check if the origin is allowed (if an Origin header is present)
  if (origin && !isAllowedOrigin(origin)) {
    return new Response(
      JSON.stringify({ 
        error: "Unauthorized: Origin not allowed",
        buildInfo: BUILD_INFO
      }),
      {
        status: 403,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders(origin)
        }
      }
    );
  }

  // Get URL parameters (use normalized lowercase URL for parsing)
  const url = new URL(normalizedUrl);
  const ipAddress = url.searchParams.get('ipaddress'); // lowercase parameter name
  const maxAgeInDays = url.searchParams.get('maxageindays') || 30; // lowercase parameter name
  const verbose = url.searchParams.get('verbose') === 'true';
  
  // Debug: Log the parsed parameters
  console.log('Parsed parameters:', { ipAddress, maxAgeInDays, verbose });
  
  // Validate required parameters
  if (!ipAddress) {
    return new Response(
      JSON.stringify({ 
        error: "Missing required parameter: ipaddress",
        buildInfo: BUILD_INFO
      }),
      {
        status: 400,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders(origin)
        }
      }
    );
  }

  try {
    // Make request to AbuseIPDB API
    const abuseIPDBResponse = await fetch(ABUSEIPDB_API_URL, {
      method: 'GET',
      headers: {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json',
      },
      // Build query parameters
      // Note: Using the original case for the AbuseIPDB API (they expect camelCase)
      cf: {
        // Cloudflare-specific options
        cacheTtl: 300, // Cache for 5 minutes
        cacheEverything: true
      }
    });

    // Check if the AbuseIPDB API request was successful
    if (!abuseIPDBResponse.ok) {
      console.error('AbuseIPDB API error:', abuseIPDBResponse.status, abuseIPDBResponse.statusText);
      return new Response(
        JSON.stringify({ 
          error: `AbuseIPDB API error: ${abuseIPDBResponse.status} ${abuseIPDBResponse.statusText}`,
          buildInfo: BUILD_INFO
        }),
        {
          status: abuseIPDBResponse.status,
          headers: {
            'Content-Type': 'application/json',
            ...corsHeaders(origin)
          }
        }
      );
    }

    // Get the response data
    const responseData = await abuseIPDBResponse.json();
    
    // Add build information to the response
    responseData.workerInfo = {
      buildInfo: BUILD_INFO,
      timestamp: new Date().toISOString(),
      requestId: generateRequestId()
    };

    // Return the response with CORS headers
    return new Response(JSON.stringify(responseData), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders(origin)
      }
    });

  } catch (error) {
    console.error('Worker error:', error);
    return new Response(
      JSON.stringify({ 
        error: 'Internal server error',
        buildInfo: BUILD_INFO,
        details: error.message
      }),
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders(origin)
        }
      }
    );
  }
}

/**
 * Validates HMAC token using the same algorithm as the C# client
 */
async function validateHmacToken(receivedToken, requestUrl) {
  try {
    if (!AUTH_KEY || !requestUrl) {
      console.error('Missing AUTH_KEY or requestUrl for HMAC validation');
      return false;
    }

    // Use the request URL as the message (same as C# implementation)
    const message = requestUrl;
    
    // Convert the auth key to bytes
    const keyBytes = new TextEncoder().encode(AUTH_KEY);
    const messageBytes = new TextEncoder().encode(message);
    
    // Import the key for HMAC
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    // Generate HMAC
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageBytes);
    
    // Convert to base64 (same format as C#)
    const expectedToken = arrayBufferToBase64(signature);
    
    // Debug logging
    console.log('HMAC validation:', {
      message: message.substring(0, 100) + '...',
      expectedToken: expectedToken.substring(0, 20) + '...',
      receivedToken: receivedToken.substring(0, 20) + '...',
      authKeySource: BUILD_INFO.keySource
    });
    
    // Compare tokens
    return expectedToken === receivedToken;
    
  } catch (error) {
    console.error('HMAC validation error:', error);
    return false;
  }
}

/**
 * Convert ArrayBuffer to base64 string
 */
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Check if origin is allowed
 */
function isAllowedOrigin(origin) {
  if (!origin) return false;
  
  // No localhost allowed in production - only specific allowed origins
  
  // Check against allowed origins
  return ALLOWED_ORIGINS.some(allowedOrigin => {
    // Remove protocol for comparison if present
    const cleanOrigin = origin.replace(/^https?:\/\//, '');
    const cleanAllowed = allowedOrigin.replace(/^https?:\/\//, '');
    
    // Handle wildcard domains (starting with * or .)
    if (cleanAllowed.startsWith('*.')) {
      const domain = cleanAllowed.substring(2); // Remove "*."
      return cleanOrigin.endsWith('.' + domain) || cleanOrigin === domain;
    }
    if (cleanAllowed.startsWith('.')) {
      return cleanOrigin.endsWith(cleanAllowed);
    }
    
    // Exact match (with or without protocol)
    return cleanOrigin === cleanAllowed || origin === allowedOrigin;
  });
}

/**
 * Generate CORS headers
 */
function corsHeaders(origin) {
  const headers = {
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Worker-Token, Authorization, X-Requested-With, Accept, Origin, User-Agent',
    'Access-Control-Max-Age': '86400',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Type',
  };
  
  // Only allow specific origins for browser requests
  if (origin) {
    if (isAllowedOrigin(origin)) {
      // Allowed origin - use specific origin and allow credentials
      headers['Access-Control-Allow-Origin'] = origin;
      headers['Access-Control-Allow-Credentials'] = 'true';
    } else {
      // Unknown origin - don't allow
      headers['Access-Control-Allow-Origin'] = 'null';
      headers['Access-Control-Allow-Credentials'] = 'false';
    }
  } else {
    // No origin header - this shouldn't happen for browser requests
    // We'll block these in the main handler
    headers['Access-Control-Allow-Origin'] = 'null';
  }
  
  return headers;
}

/**
 * Handle CORS preflight requests
 */
function handleCORS(request) {
  const origin = request.headers.get('Origin') || '';
  
  // Debug logging for CORS preflight
  console.log('CORS preflight request:', {
    origin,
    method: request.method,
    isAllowed: isAllowedOrigin(origin),
    requestHeaders: request.headers.get('Access-Control-Request-Headers'),
    requestMethod: request.headers.get('Access-Control-Request-Method')
  });
  
  const headers = corsHeaders(origin);
  
  return new Response(null, {
    status: 204,
    headers
  });
}

/**
 * Generate a unique request ID for tracking
 */
function generateRequestId() {
  return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
}
