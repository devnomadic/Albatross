/**
 * Cloudflare Worker for Integrated IP Analysis
 * 
 * This worker provides comprehensive IP analysis by combining multiple data sources:
 * 1. AbuseIPDB API - IP abuse reputation checking
 * 2. Cloudflare Radar API - ASN and network information lookup
 * 
 * Features:
 * - Protects API keys from client exposure
 * - Handles CORS for browser requests
 * - Fetches both APIs in parallel for optimal performance
 * - Returns combined data in a single JSON response
 * - Uses HMAC-based authentication for security with build-time generated keys
 * - Provides fallback data when one API fails
 * 
 * Deploy this to your Cloudflare Workers account and update the 
 * AbuseIPDBService.cs file with your worker URL.
 * 
 * Response Format:
 * {
 *   "data": { ... AbuseIPDB data ... },
 *   "asnInfo": {
 *     "success": true/false,
 *     "data": [ ... Cloudflare Radar ASN data ... ],
 *     "error": null/string
 *   },
 *   "workerInfo": { ... metadata ... }
 * }
 */

// Import build-time generated constants (will be injected during build)
// __BUILD_CONSTANTS_INJECTION_POINT__

// Configuration - API keys will be injected during GitHub Actions build
const ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY_WILL_BE_INJECTED_HERE";
const ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check";

// Cloudflare Radar API configuration
const CLOUDFLARE_RADAR_API_URL = "https://api.cloudflare.com/client/v4/radar/entities/asns/ip";
const CLOUDFLARE_API_TOKEN = "YOUR_CLOUDFLARE_API_TOKEN_WILL_BE_INJECTED_HERE";

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
  "https://abuseipdb-preview.devnomadic.workers.dev",
  // Local development
  "https://localhost:5044",
  "http://localhost:5044"
];

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  // Handle CORS preflight requests
  if (request.method === "OPTIONS") {
    return handleCORS(request);
  }

  // All requests go through the combined handler
  return handleCombinedRequest(request);
}

async function handleCombinedRequest(request) {

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
    // Fetch both APIs in parallel for better performance
    const [abuseIPDBResponse, radarResponse] = await Promise.allSettled([
      // AbuseIPDB API request
      fetch(`${ABUSEIPDB_API_URL}?ipAddress=${encodeURIComponent(ipAddress)}&maxAgeInDays=${maxAgeInDays}&verbose=${verbose}`, {
        method: 'GET',
        headers: {
          'Key': ABUSEIPDB_API_KEY,
          'Accept': 'application/json',
          'User-Agent': 'Albatross-Worker/1.0'
        },
        cf: {
          cacheTtl: 300, // Cache for 5 minutes
          cacheEverything: true
        }
      }),
      
      // Cloudflare Radar API request
      fetch(`${CLOUDFLARE_RADAR_API_URL}?ip=${encodeURIComponent(ipAddress)}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${CLOUDFLARE_API_TOKEN}`,
          'Content-Type': 'application/json',
          'User-Agent': 'Albatross-Worker/1.0'
        },
        cf: {
          cacheTtl: 3600, // Cache for 1 hour (ASN info doesn't change frequently)
          cacheEverything: true
        }
      })
    ]);

    // Process AbuseIPDB response
    let abuseIPDBData = null;
    let abuseIPDBError = null;
    
    if (abuseIPDBResponse.status === 'fulfilled' && abuseIPDBResponse.value.ok) {
      try {
        abuseIPDBData = await abuseIPDBResponse.value.json();
        console.log('AbuseIPDB API response successful');
      } catch (error) {
        console.error('Error parsing AbuseIPDB response:', error);
        abuseIPDBError = 'Failed to parse AbuseIPDB response';
      }
    } else {
      const status = abuseIPDBResponse.status === 'fulfilled' ? abuseIPDBResponse.value.status : 'rejected';
      const statusText = abuseIPDBResponse.status === 'fulfilled' ? abuseIPDBResponse.value.statusText : abuseIPDBResponse.reason?.message || 'Network error';
      console.error('AbuseIPDB API error:', status, statusText);
      abuseIPDBError = `AbuseIPDB API error: ${status} ${statusText}`;
    }

    // Process Cloudflare Radar response
    let radarData = null;
    let radarError = null;
    
    if (radarResponse.status === 'fulfilled' && radarResponse.value.ok) {
      try {
        radarData = await radarResponse.value.json();
        console.log('Cloudflare Radar API response successful:', {
          success: radarData.success,
          resultCount: radarData.result?.length || 0
        });
      } catch (error) {
        console.error('Error parsing Radar response:', error);
        radarError = 'Failed to parse Cloudflare Radar response';
      }
    } else {
      const status = radarResponse.status === 'fulfilled' ? radarResponse.value.status : 'rejected';
      const statusText = radarResponse.status === 'fulfilled' ? radarResponse.value.statusText : radarResponse.reason?.message || 'Network error';
      console.error('Cloudflare Radar API error:', status, statusText);
      radarError = `Cloudflare Radar API error: ${status} ${statusText}`;
    }

    // Combine the responses into a single response object
    const combinedResponse = {
      // AbuseIPDB data (maintain original structure for compatibility)
      data: abuseIPDBData?.data || null,
      
      // Add Cloudflare Radar ASN information
      asnInfo: {
        success: radarData?.success || false,
        data: radarData?.result || null,
        error: radarError
      },
      
      // Metadata and errors
      abuseIPDBError: abuseIPDBError,
      workerInfo: {
        buildInfo: BUILD_INFO,
        timestamp: new Date().toISOString(),
        requestId: generateRequestId(),
        sources: {
          abuseipdb: abuseIPDBError ? 'error' : 'success',
          radar: radarError ? 'error' : 'success'
        }
      }
    };

    // Determine overall response status
    const hasAbuseIPDBData = abuseIPDBData && !abuseIPDBError;
    const hasRadarData = radarData && radarData.success && !radarError;
    
    // Return successful response if at least one API succeeded
    if (hasAbuseIPDBData || hasRadarData) {
      console.log('Combined API response successful:', {
        abuseipdb: hasAbuseIPDBData ? 'success' : 'failed',
        radar: hasRadarData ? 'success' : 'failed'
      });
      
      return new Response(JSON.stringify(combinedResponse), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders(origin)
        }
      });
    } else {
      // Both APIs failed
      console.error('Both APIs failed');
      return new Response(JSON.stringify(combinedResponse), {
        status: 502,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders(origin)
        }
      });
    }

  } catch (error) {
    console.error('Combined worker error:', error);
    return new Response(
      JSON.stringify({ 
        error: 'Internal server error',
        buildInfo: BUILD_INFO,
        details: error.message,
        asnInfo: {
          success: false,
          error: 'Internal server error'
        }
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
