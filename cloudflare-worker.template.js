/**
 * Cloudflare Worker for Integrated IP Analysis
 * 
 * This worker provides comprehensive IP analysis by combining multiple data sources:
 * 1. AbuseIPDB API - IP abuse reputation checking
 * 2. Cloudflare Radar API - ASN and network information lookup
 * 3. Cloudflare Workers AI - AI-powered reputation analysis using Llama 3.1 70B
 * 
 * Features:
 * - Protects API keys from client exposure
 * - Handles CORS for browser requests
 * - Fetches multiple APIs in parallel for optimal performance
 * - Generates AI-powered risk assessments and recommendations
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
 *   "aiReputation": {
 *     "success": true/false,
 *     "error": null/string,
 *     "analysis": {
 *       "riskLevel": "low|medium|high|critical",
 *       "trustScore": <0-100>,
 *       "summary": "<AI-generated assessment>",
 *       "recommendations": ["<action 1>", "<action 2>"]
 *     },
 *     "model": "@cf/meta/llama-3.1-70b-instruct",
 *     "timestamp": "<ISO timestamp>"
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

// ES Module export for Cloudflare Workers (required for AI binding)
export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight requests
    if (request.method === "OPTIONS") {
      return handleCORS(request);
    }

    // All requests go through the combined handler
    return handleCombinedRequest(request, env);
  }
};

/**
 * Generate AI-based IP reputation analysis using Cloudflare Workers AI
 * @param {object} env - Worker environment with AI binding
 * @param {string} ipAddress - The IP address to analyze
 * @param {object} abuseData - AbuseIPDB data for context
 * @param {object} asnData - ASN data for context
 * @returns {Promise<object>} AI reputation analysis
 */
async function generateAIReputation(env, ipAddress, abuseData, asnData) {
  try {
    // Check if AI binding is available
    if (!env || !env.AI) {
      console.log('AI binding not available in environment');
      return {
        success: false,
        error: 'AI service not available',
        analysis: null
      };
    }

    // Build context from available data
    const abuseScore = abuseData?.data?.abuseConfidenceScore || 0;
    const totalReports = abuseData?.data?.totalReports || 0;
    const countryCode = abuseData?.data?.countryCode || 'Unknown';
    const isp = abuseData?.data?.isp || 'Unknown';
    const usageType = abuseData?.data?.usageType || 'Unknown';
    const asnName = asnData?.result?.[0]?.asn?.name || 'Unknown';
    const asnNumber = asnData?.result?.[0]?.asn?.asn || 'Unknown';
    const numDistinctUsers = abuseData?.data?.numDistinctUsers || 0;
    const reports = abuseData?.data?.reports || [];

    // Extract sample abuse event details
    let eventSummary = '';
    if (reports.length > 0) {
      const recentReports = reports.slice(0, 5);
      const categories = recentReports.flatMap(r => r.categories || []);
      const uniqueCategories = [...new Set(categories)];
      const comments = recentReports.map(r => r.comment).filter(c => c && c.trim());
      
      eventSummary = `\n\nAbuse Events (${totalReports} reports from ${numDistinctUsers} users):`;
      if (uniqueCategories.length > 0) {
        eventSummary += `\nEvent Types: ${uniqueCategories.join(', ')}`;
      }
      if (comments.length > 0) {
        eventSummary += `\nSample Reports:\n${comments.slice(0, 3).map((c, i) => `  ${i + 1}. ${c.substring(0, 100)}${c.length > 100 ? '...' : ''}`).join('\n')}`;
      }
    }

    // Create a prompt for the AI to analyze the IP reputation
    const prompt = `You are a cybersecurity expert analyzing IP address reputation. Based on the following real-time data, provide a concise risk assessment and reputation summary.

IP Address: ${ipAddress}
Country: ${countryCode}
ISP: ${isp}
Usage Type: ${usageType}
ASN: ${asnNumber} (${asnName})
Abuse Confidence Score: ${abuseScore}% (0-100 scale, higher is worse)
Total Abuse Reports: ${totalReports}${eventSummary}

Provide a JSON response with the following structure:
{
  "riskLevel": "low|medium|high|critical",
  "trustScore": <number 0-100, higher is better>,
  "summary": "<2-3 sentence overall risk assessment>",
  "eventsSummary": "<1-2 sentence summary of abuse event patterns, or null if no events>",
  "recommendations": ["<action 1>", "<action 2>"]
}

Focus on actionable insights based on the abuse score, report count, network information, and abuse event patterns. Keep summaries concise and professional.`;

    console.log('Calling Workers AI with Llama 3.1 70B for IP reputation analysis...');

    // Call Cloudflare Workers AI using Llama 3.1 70B Instruct model
    const response = await env.AI.run('@cf/meta/llama-3.1-70b-instruct', {
      messages: [
        {
          role: 'system',
          content: 'You are a cybersecurity expert. Respond only with valid JSON, no markdown formatting or code blocks.'
        },
        {
          role: 'user',
          content: prompt
        }
      ],
      max_tokens: 500,
      temperature: 0.3, // Lower temperature for more consistent, factual responses
    });

    console.log('AI response received:', response);

    // Parse the AI response
    let analysis = null;
    if (response && response.response) {
      try {
        // The response.response contains the AI's text output
        const aiText = response.response.trim();
        
        // Try to extract JSON from the response (handle cases where AI might add extra text)
        let jsonText = aiText;
        if (aiText.includes('{')) {
          const startIdx = aiText.indexOf('{');
          const endIdx = aiText.lastIndexOf('}');
          if (startIdx >= 0 && endIdx > startIdx) {
            jsonText = aiText.substring(startIdx, endIdx + 1);
          }
        }
        
        analysis = JSON.parse(jsonText);
        console.log('AI analysis parsed successfully:', analysis);
      } catch (parseError) {
        console.error('Error parsing AI response:', parseError);
        // Fallback to basic analysis if JSON parsing fails
        const eventsFallback = reports.length > 0 
          ? `Reported ${totalReports} times for ${[...new Set(reports.flatMap(r => r.categories || []))].slice(0, 3).join(', ')}.`
          : null;
        
        analysis = {
          riskLevel: abuseScore > 75 ? 'critical' : abuseScore > 50 ? 'high' : abuseScore > 25 ? 'medium' : 'low',
          trustScore: Math.max(0, 100 - abuseScore),
          summary: `IP from ${countryCode} with ${abuseScore}% abuse confidence score and ${totalReports} reports.`,
          eventsSummary: eventsFallback,
          recommendations: ['Review the abuse reports for details', 'Consider blocking if risk level is high']
        };
      }
    }

    return {
      success: true,
      error: null,
      analysis: analysis,
      model: '@cf/meta/llama-3.1-70b-instruct',
      timestamp: new Date().toISOString()
    };

  } catch (error) {
    console.error('AI reputation generation error:', error);
    return {
      success: false,
      error: error.message || 'Failed to generate AI reputation',
      analysis: null
    };
  }
}

async function handleCombinedRequest(request, env) {

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
  
  // Extract and validate timestamp before HMAC validation
  const urlForTimestamp = new URL(normalizedUrl);
  const timestamp = urlForTimestamp.searchParams.get('timestamp');
  
  if (!timestamp) {
    return new Response(
      JSON.stringify({ 
        error: "Unauthorized: Missing timestamp parameter",
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
  
  if (!isTimestampValid(timestamp)) {
    return new Response(
      JSON.stringify({ 
        error: "Unauthorized: Invalid or expired timestamp",
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

    // Generate AI-based reputation analysis using the collected data
    console.log('Generating AI reputation analysis...');
    const aiReputation = await generateAIReputation(env, ipAddress, abuseIPDBData, radarData);
    console.log('AI reputation analysis result:', {
      success: aiReputation.success,
      error: aiReputation.error
    });

    // Combine the responses into a single response object
    const combinedResponse = {
      
      // Add AI reputation analysis
      aiReputation: aiReputation,
      
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
          radar: radarError ? 'error' : 'success',
          ai: aiReputation.success ? 'success' : 'error'
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
      
      // Use custom replacer to enforce property order
      const orderedKeys = ['aiReputation', 'data', 'asnInfo', 'abuseIPDBError', 'workerInfo'];
      return new Response(JSON.stringify(combinedResponse, (key, value) => {
        if (value && typeof value === 'object' && !Array.isArray(value)) {
          return orderedKeys.reduce((obj, k) => {
            if (k in value) obj[k] = value[k];
            return obj;
          }, {});
        }
        return value;
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders(origin)
        }
      });
    } else {
      // Both APIs failed
      console.error('Both APIs failed');
      
      // Use custom replacer to enforce property order
      const orderedKeys = ['aiReputation', 'data', 'asnInfo', 'abuseIPDBError', 'workerInfo'];
      return new Response(JSON.stringify(combinedResponse, (key, value) => {
        if (value && typeof value === 'object' && !Array.isArray(value)) {
          return orderedKeys.reduce((obj, k) => {
            if (k in value) obj[k] = value[k];
            return obj;
          }, {});
        }
        return value;
      }), {
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
      validationStatus: 'In progress',
      keySourceAvailable: typeof BUILD_INFO.keySource !== 'undefined'
    });
    
    // Compare tokens
    return expectedToken === receivedToken;
    
  } catch (error) {
    console.error('HMAC validation error:', error);
    return false;
  }
}

/**
 * Validates that the timestamp is within a 2-minute window of the current UTC time
 * @param {string} timestamp - The timestamp in yyyyMMddHHmm format
 * @returns {boolean} - True if the timestamp is valid and within the window
 */
function isTimestampValid(timestamp) {
  try {
    if (!timestamp || timestamp.length !== 12) {
      console.log('Invalid timestamp format:', timestamp);
      return false;
    }
    
    // Parse the timestamp (yyyyMMddHHmm format)
    const year = parseInt(timestamp.substring(0, 4));
    const month = parseInt(timestamp.substring(4, 6)) - 1; // JavaScript months are 0-based
    const day = parseInt(timestamp.substring(6, 8));
    const hour = parseInt(timestamp.substring(8, 10));
    const minute = parseInt(timestamp.substring(10, 12));
    
    // Create the timestamp date
    const timestampDate = new Date(Date.UTC(year, month, day, hour, minute));
    
    // Get current UTC time
    const now = new Date();
    
    // Calculate the difference in milliseconds
    const diffMs = Math.abs(now.getTime() - timestampDate.getTime());
    
    // Convert to minutes
    const diffMinutes = diffMs / (1000 * 60);
    
    // Allow up to 2 minutes difference
    const isValid = diffMinutes <= 2;
    
    console.log('Timestamp validation:', {
      timestamp,
      parsedDate: timestampDate.toISOString(),
      currentDate: now.toISOString(),
      diffMinutes: diffMinutes.toFixed(2),
      isValid
    });
    
    return isValid;
    
  } catch (error) {
    console.error('Error validating timestamp:', error);
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
