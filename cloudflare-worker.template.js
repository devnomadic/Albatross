/**
 * Cloudflare Worker for Integrated IP Analysis
 * 
 * This worker provides comprehensive IP analysis by combining multiple data sources:
 * 1. AbuseIPDB API - IP abuse reputation checking
 * 2. Cloudflare Radar API - ASN and network information lookup
 * 3. Cloudflare Workers AI - AI-powered reputation analysis (default: gpt-oss-120b, overridable via aimodel param)
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
 *     "model": "@cf/openai/gpt-oss-120b",
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

// Workers AI model configuration - default model plus allowed overrides via the 'aimodel' query parameter
const DEFAULT_AI_MODEL = "@cf/openai/gpt-oss-120b";
const ALLOWED_AI_MODELS = [
  "@cf/openai/gpt-oss-120b",
  "@cf/openai/gpt-oss-20b",
  "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
  "@cf/meta/llama-4-scout-17b-16e-instruct",
  "@cf/moonshotai/kimi-k2.6",
  "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b"
];

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
 * @param {string} [aiModel] - Workers AI model identifier to use (defaults to DEFAULT_AI_MODEL)
 * @returns {Promise<object>} AI reputation analysis
 */
async function generateAIReputation(env, ipAddress, abuseData, asnData, aiModel) {
  const model = aiModel && ALLOWED_AI_MODELS.includes(aiModel) ? aiModel : DEFAULT_AI_MODEL;
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

    // Heuristic device/service type flags (used as context for the AI to refine)
    const heuristicFlags = detectIpIntelligence(abuseData);

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

Preliminary automated device/service type flags (heuristic, may be incomplete or wrong):
mobile=${heuristicFlags.is_mobile}, vpn=${heuristicFlags.is_vpn}, tor=${heuristicFlags.is_tor}, proxy=${heuristicFlags.is_proxy}, datacenter=${heuristicFlags.is_datacenter}, botnet/C2=${heuristicFlags.is_botnet}
(is_tor is based only on reverse-DNS hostname patterns and will miss exit nodes with generic hostnames.)

Provide a JSON response with the following structure:
{
  "riskLevel": "low|medium|high|critical",
  "trustScore": <number 0-100, higher is better>,
  "summary": "<2-3 sentence overall risk assessment>",
  "eventsSummary": "<2-3 sentence summary of abuse event patterns & targeted services or null if no events>",
  "asnReputation": "<2-3 sentence assessment of the ASN/network operator's reputation, e.g. whether it is a well-known hosting/cloud provider, residential ISP, VPN/proxy network, or an ASN commonly associated with abuse based on the usage type and abuse data, or null if there is insufficient data>",
  "intelligenceGuess": {
    "is_mobile": <true|false>,
    "is_vpn": <true|false>,
    "is_tor": <true|false>,
    "is_proxy": <true|false>,
    "is_datacenter": <true|false>,
    "is_botnet": <true|false>,
    "notes": "<1 sentence explaining your reasoning, especially where you overrode a preliminary flag, or null if you agree with all preliminary flags>"
  },
  "recommendations": ["<action 1>", "<action 2>"]
}

Focus on actionable insights based on the abuse score, report count, network information, ASN reputation, and abuse event patterns. For intelligenceGuess, use your knowledge of well-known ASNs, ISPs, hosting providers, and VPN/proxy/Tor exit-node ranges to confirm or correct the preliminary flags (the is_tor flag only checked hostname patterns, so it may be a false negative), and refine is_botnet based on whether the abuse events/comments genuinely indicate compromised-host or bot-driven (as opposed to a single manual attacker) behavior. Keep summaries concise and professional.`;

    console.log('Calling Workers AI with model', model, 'for IP reputation analysis...');

    // Call Cloudflare Workers AI using the selected model
    const response = await env.AI.run(model, {
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
      max_tokens: 900, // Increased to accommodate asnReputation + intelligenceGuess fields without truncating JSON
      temperature: 0.3, // Lower temperature for more consistent, factual responses
    });

    console.log('AI response received:', response);

    // Parse the AI response
    // Different model families use different response shapes:
    // - Llama-style models return { response: "<text>" }
    // - OpenAI-compatible models (e.g. gpt-oss-*) return { choices: [{ message: { content: "<text>" } }] }
    const aiText = response?.response ?? response?.choices?.[0]?.message?.content ?? null;

    let analysis = null;
    if (aiText) {
      try {
        // The extracted text contains the AI's raw output
        const trimmedText = aiText.trim();
        
        // Try to extract JSON from the response (handle cases where AI might add extra text)
        let jsonText = trimmedText;
        if (trimmedText.includes('{')) {
          const startIdx = trimmedText.indexOf('{');
          const endIdx = trimmedText.lastIndexOf('}');
          if (startIdx >= 0 && endIdx > startIdx) {
            jsonText = trimmedText.substring(startIdx, endIdx + 1);
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
          asnReputation: asnName !== 'Unknown' ? `ASN ${asnNumber} (${asnName}), usage type: ${usageType}.` : null,
          intelligenceGuess: { ...heuristicFlags, notes: 'AI response could not be parsed; showing heuristic-only flags.' },
          recommendations: ['Review the abuse reports for details', 'Consider blocking if risk level is high']
        };
      }
    } else {
      console.error('AI response did not contain a recognizable text field for model', model, response);
      // Fallback to basic analysis if no text output was found
      const eventsFallback = reports.length > 0 
        ? `Reported ${totalReports} times for ${[...new Set(reports.flatMap(r => r.categories || []))].slice(0, 3).join(', ')}.`
        : null;
      
      analysis = {
        riskLevel: abuseScore > 75 ? 'critical' : abuseScore > 50 ? 'high' : abuseScore > 25 ? 'medium' : 'low',
        trustScore: Math.max(0, 100 - abuseScore),
        summary: `IP from ${countryCode} with ${abuseScore}% abuse confidence score and ${totalReports} reports.`,
        eventsSummary: eventsFallback,
        asnReputation: asnName !== 'Unknown' ? `ASN ${asnNumber} (${asnName}), usage type: ${usageType}.` : null,
        intelligenceGuess: { ...heuristicFlags, notes: 'AI analysis unavailable; showing heuristic-only flags.' },
        recommendations: ['Review the abuse reports for details', 'Consider blocking if risk level is high']
      };
    }

    return {
      success: true,
      error: null,
      analysis: analysis,
      model: model,
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

/**
 * Derive best-effort IP device/service type flags from AbuseIPDB data.
 * These are heuristics based on AbuseIPDB's usageType classification and
 * report categories - they are not authoritative real-time lookups.
 *
 * Notes on scope:
 * - is_tor is a best-effort heuristic based on reverse-DNS hostname patterns
 *   (e.g. "tor-exit", "torproject") - it will miss Tor exit nodes whose
 *   hostname doesn't advertise itself as such; no live exit-node list is used.
 * - is_botnet is a best-effort heuristic (see below) based only on AbuseIPDB
 *   report categories/comments - it is not a real threat-intel feed lookup
 *   (e.g. abuse.ch ThreatFox, AlienVault OTX), so it can miss active C2 hosts
 *   that haven't yet been reported to AbuseIPDB, or over-flag noisy scanners.
 *
 * @param {object} abuseData - Parsed AbuseIPDB API response
 * @returns {object} Flags object: { is_mobile, is_vpn, is_tor, is_proxy, is_datacenter, is_botnet }
 */
function detectIpIntelligence(abuseData) {
  const usageType = (abuseData?.data?.usageType || '').toLowerCase();
  const reports = abuseData?.data?.reports || [];
  const categories = new Set(reports.flatMap(r => r.categories || []));
  const comments = reports.map(r => r.comment || '');
  const numDistinctUsers = abuseData?.data?.numDistinctUsers || 0;
  const hostnames = (abuseData?.data?.hostnames || []).join(' ').toLowerCase();

  // AbuseIPDB category 13 = "VPN IP", category 9 = "Open Proxy"
  const is_vpn = categories.has(13) || usageType.includes('vpn');
  const is_proxy = categories.has(9) || usageType.includes('proxy');
  const is_datacenter = /data center|datacenter|hosting|colocation/.test(usageType);
  const is_mobile = usageType.includes('mobile');
  const TOR_HOSTNAME_REGEX = /tor-?exit|tor-?relay|torservers|torproject|\btor\b/i;
  const is_tor = TOR_HOSTNAME_REGEX.test(hostnames);

  // Botnet / C2 heuristic, based only on AbuseIPDB categories, comments & report volume:
  // - Category 20 = "Exploited Host" is AbuseIPDB's own signal that the host is known compromised
  // - Categories 4 (DDoS Attack), 14 (Port Scan), 18 (Brute-Force), 22 (SSH), 23 (IoT Targeted) are
  //   typical of scripted/automated attack tooling; 3+ of these together suggests bot-driven traffic
  //   rather than a single manual actor
  // - Report comments mentioning known botnet/malware/C2 terminology are a direct signal
  // - Volume: a high number of distinct reporters (numDistinctUsers) indicates broad, indiscriminate
  //   scanning/attack activity typical of a bot rather than one attacker targeting a specific victim.
  //   When combined with 2+ automated-attack categories, this lowers the bar from 3+ categories alone,
  //   since widespread reporting adds independent corroborating evidence of automated behavior.
  const hasExploitedHostCategory = categories.has(20);
  const AUTOMATED_ATTACK_CATEGORIES = [4, 14, 18, 22, 23];
  const automatedAttackCategoryCount = AUTOMATED_ATTACK_CATEGORIES.filter(c => categories.has(c)).length;
  const BOTNET_KEYWORD_REGEX = /\b(botnet|mirai|zombie|c2|c&c|command[- ]and[- ]control|malware|trojan)\b/i;
  const hasBotnetKeyword = comments.some(c => BOTNET_KEYWORD_REGEX.test(c));
  const HIGH_VOLUME_DISTINCT_USERS_THRESHOLD = 5;
  const hasHighVolumeWithAttackPattern = automatedAttackCategoryCount >= 2 && numDistinctUsers >= HIGH_VOLUME_DISTINCT_USERS_THRESHOLD;
  const is_botnet = hasExploitedHostCategory || hasBotnetKeyword || automatedAttackCategoryCount >= 3 || hasHighVolumeWithAttackPattern;

  return {
    is_mobile,
    is_vpn,
    is_tor,
    is_proxy,
    is_datacenter,
    is_botnet
  };
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
  
  // Check if this is a request to the dedicated API hostname (bypass authentication for API clients)
  const requestUrl = new URL(request.url);
  const hostname = requestUrl.hostname.toLowerCase();
  const isApiHostname = hostname === 'albatross-api.devnomadic.com' || hostname === 'albatross-apipreview.devnomadic.com';
  
  console.log('API hostname check:', {
    hostname,
    isApiHostname
  });
  
  // Enforce browser-only access with proper Origin header validation
  // This ensures the worker can only be called from legitimate browser requests
  // Skip this check for dedicated API hostnames (to support curl, Postman, etc.)
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
  // Skip this check for dedicated API hostnames
  if (!isApiHostname && (!isBrowserRequest || !hasValidOrigin)) {
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
  // Skip timestamp and HMAC validation for dedicated API hostnames
  if (!isApiHostname) {
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
  }

  // Get URL parameters (use normalized lowercase URL for parsing)
  const url = new URL(isApiHostname ? request.url.toLowerCase() : normalizedUrl);
  const ipAddress = url.searchParams.get('ipaddress'); // lowercase parameter name
  const rawMaxAgeInDays = parseInt(url.searchParams.get('maxageindays'), 10);
  // Enforce AbuseIPDB's supported maxAgeInDays range of 1-365 (default 30 when missing/invalid)
  const maxAgeInDays = Number.isNaN(rawMaxAgeInDays) ? 30 : Math.min(365, Math.max(1, rawMaxAgeInDays));
  const verbose = url.searchParams.get('verbose') === 'true';
  const enableAI = url.searchParams.get('enableai') === 'true'; // AI toggle parameter
  const cloudProvider = url.searchParams.get('cloudprovider') || null; // Cloud provider search: aws, azure, gcp, oracle, all, or none
  const aiModel = url.searchParams.get('aimodel') || null; // Optional Workers AI model override

  // Validate cloudProvider against allowed values if provided
  const allowedCloudProviders = ['none', 'all', 'azure', 'aws', 'gcp', 'oracle'];
  if (cloudProvider && !allowedCloudProviders.includes(cloudProvider.toLowerCase())) {
    return new Response(
      JSON.stringify({
        error: "Invalid parameter: cloudprovider must be one of 'none', 'all', 'azure', 'aws', 'gcp', or 'oracle'",
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

  // Validate aiModel against the allow-list if provided
  if (aiModel && !ALLOWED_AI_MODELS.includes(aiModel)) {
    return new Response(
      JSON.stringify({
        error: `Invalid parameter: aimodel must be one of ${ALLOWED_AI_MODELS.join(', ')}`,
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
  
  // Debug: Log the parsed parameters
  console.log('Parsed parameters:', { ipAddress, maxAgeInDays, verbose, enableAI, cloudProvider, aiModel });
  
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
    // Build array of API calls to execute in parallel
    const apiCalls = [
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
    ];
    
    // Add cloud manifest search if requested
    let cloudManifestPromise = null;
    if (cloudProvider) {
      cloudManifestPromise = searchCloudManifests(ipAddress, cloudProvider, env);
    }
    
    // Fetch both APIs in parallel for better performance
    const [abuseIPDBResponse, radarResponse] = await Promise.allSettled(apiCalls);
    
    // Wait for cloud manifest search if it was initiated
    let cloudMatches = null;
    if (cloudManifestPromise) {
      cloudMatches = await cloudManifestPromise;
    }

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

    // Generate AI-based reputation analysis using the collected data (only if enabled)
    let aiReputation = null;
    if (enableAI) {
      console.log('Generating AI reputation analysis...');
      aiReputation = await generateAIReputation(env, ipAddress, abuseIPDBData, radarData, aiModel);
      console.log('AI reputation analysis result:', {
        success: aiReputation.success,
        error: aiReputation.error
      });
    } else {
      console.log('AI reputation analysis disabled by client request');
      aiReputation = {
        success: false,
        error: 'AI analysis disabled',
        analysis: null
      };
    }

    // Combine the responses into a single response object
    const combinedResponse = {
      
      // Add AI reputation analysis
      aiReputation: aiReputation,
      
      // AbuseIPDB data (maintain original structure for compatibility)
      data: abuseIPDBData?.data || null,
      
      // Best-effort IP device/service type detection (heuristic, derived from AbuseIPDB data)
      ipIntelligence: detectIpIntelligence(abuseIPDBData),
      
      // Add Cloudflare Radar ASN information
      asnInfo: {
        success: radarData?.success || false,
        data: radarData?.result || null,
        error: radarError
      },
      
      // Add cloud manifest search results (if requested)
      ...(cloudMatches && { cloudMatches }),
      
      // Metadata and errors
      abuseIPDBError: abuseIPDBError,
      workerInfo: {
        buildInfo: BUILD_INFO,
        timestamp: new Date().toISOString(),
        requestId: generateRequestId(),
        sources: {
          abuseipdb: abuseIPDBError ? 'error' : 'success',
          radar: radarError ? 'error' : 'success',
          ai: enableAI ? (aiReputation.success ? 'success' : 'error') : 'disabled',
          cloudManifests: cloudMatches ? (cloudMatches && cloudMatches.error ? 'error' : 'success') : 'not-requested'
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
 * Search cloud provider IP manifests for matches
 */
async function searchCloudManifests(ipAddress, provider, env) {
  try {
    const results = {
      azure: [],
      aws: [],
      gcp: [],
      oracle: []
    };
    
    // Determine which providers to search
    const validProviders = ['azure', 'aws', 'gcp', 'oracle'];
    const normalizedProvider = (provider || '').toString().toLowerCase();

    let providersToSearch;
    if (!normalizedProvider || normalizedProvider === 'all') {
      // Default to all known providers if "all" or no provider specified
      providersToSearch = validProviders;
    } else if (validProviders.includes(normalizedProvider)) {
      providersToSearch = [normalizedProvider];
    } else {
      const errorMessage = `Invalid provider: ${provider}. Valid providers are: ${validProviders.join(', ')} or 'all'.`;
      console.error(errorMessage);
      return {
        azure: [],
        aws: [],
        gcp: [],
        oracle: [],
        summary: {
          totalMatches: 0,
          providers: 0,
          matchedProviders: []
        },
        error: errorMessage
      };
    }
    
    // Determine the base URL based on environment
    // Preview worker uses preview Pages deployment, production uses production site
    const isPreview = env.ENVIRONMENT === 'preview' || (typeof ENVIRONMENT !== 'undefined' && ENVIRONMENT === 'preview');
    const baseUrl = isPreview 
      ? 'https://bug-fix-worker-ai-bindings.albatross-5kt.pages.dev'
      : 'https://albatross.devnomadic.com';
    
    // Search each provider's manifest
    for (const providerName of providersToSearch) {
      try {
        // Fetch manifest from origin (wwwroot/ip-manifests/)
        // Use lowercase filenames (azure.json, aws.json, etc.)
        const fileName = providerName.toLowerCase();
        const manifestUrl = `${baseUrl}/ip-manifests/${fileName}.json`;
        console.log(`Fetching manifest: ${manifestUrl}`);
        
        const response = await fetch(manifestUrl, {
          cf: {
            cacheTtl: 3600, // Cache for 1 hour
            cacheEverything: true
          }
        });
        
        if (!response.ok) {
          console.error(`Failed to fetch ${providerName} manifest:`, response.status, response.statusText);
          continue;
        }
        
        const manifestData = await response.json();
        console.log(`Successfully loaded ${providerName} manifest, searching for ${ipAddress}`);
        
        // Search based on provider format
        if (providerName === 'azure') {
          results.azure = searchAzureManifest(ipAddress, manifestData);
          console.log(`Azure search complete: ${results.azure.length} matches`);
        } else if (providerName === 'aws') {
          results.aws = searchAwsManifest(ipAddress, manifestData);
          console.log(`AWS search complete: ${results.aws.length} matches`);
        } else if (providerName === 'gcp') {
          results.gcp = searchGcpManifest(ipAddress, manifestData);
          console.log(`GCP search complete: ${results.gcp.length} matches`);
        } else if (providerName === 'oracle') {
          results.oracle = searchOracleManifest(ipAddress, manifestData);
          console.log(`Oracle search complete: ${results.oracle.length} matches`);
        }
      } catch (error) {
        console.error(`Error searching ${providerName} manifest:`, error);
      }
    }
    
    // Build summary
    const allMatches = [...results.azure, ...results.aws, ...results.gcp, ...results.oracle];
    const matchedProviders = [];
    if (results.azure.length > 0) matchedProviders.push('Azure');
    if (results.aws.length > 0) matchedProviders.push('AWS');
    if (results.gcp.length > 0) matchedProviders.push('GCP');
    if (results.oracle.length > 0) matchedProviders.push('Oracle');
    
    return {
      ...results,
      summary: {
        totalMatches: allMatches.length,
        providers: matchedProviders.length,
        matchedProviders: matchedProviders
      }
    };
  } catch (error) {
    console.error('Error searching cloud manifests:', error);
    return {
      azure: [],
      aws: [],
      gcp: [],
      oracle: [],
      summary: {
        totalMatches: 0,
        providers: 0,
        matchedProviders: []
      },
      error: error.message
    };
  }
}

/**
 * Search Azure manifest
 */
function searchAzureManifest(ipAddress, manifestData) {
  const matches = [];
  
  if (!manifestData.values) {
    console.error('Azure manifest has no values array');
    return matches;
  }
  
  console.log(`Searching Azure manifest for ${ipAddress}, found ${manifestData.values.length} value entries`);
  let checkedPrefixes = 0;
  
  for (const value of manifestData.values) {
    if (!value.properties || !value.properties.addressPrefixes) continue;
    
    for (const cidr of value.properties.addressPrefixes) {
      checkedPrefixes++;
      if (isIpInRange(ipAddress, cidr)) {
        console.log(`✓ Azure match found: ${ipAddress} in ${cidr}`);
        matches.push({
          provider: 'Azure',
          region: value.properties.region || 'Unknown',
          service: value.properties.systemService || value.name || 'Unknown',
          cidrRange: cidr,
          platform: value.properties.platform || 'Azure'
        });
      }
    }
  }
  
  console.log(`Azure search complete: checked ${checkedPrefixes} prefixes, found ${matches.length} matches`);
  return matches;
}

/**
 * Search AWS manifest
 */
function searchAwsManifest(ipAddress, manifestData) {
  const matches = [];
  
  if (manifestData.prefixes) {
    for (const prefix of manifestData.prefixes) {
      if (isIpInRange(ipAddress, prefix.ip_prefix)) {
        matches.push({
          provider: 'AWS',
          region: prefix.region || 'Unknown',
          service: prefix.service || 'Unknown',
          cidrRange: prefix.ip_prefix,
          networkBorderGroup: prefix.network_border_group
        });
      }
    }
  }
  
  if (manifestData.ipv6_prefixes) {
    for (const prefix of manifestData.ipv6_prefixes) {
      if (isIpInRange(ipAddress, prefix.ipv6_prefix)) {
        matches.push({
          provider: 'AWS',
          region: prefix.region || 'Unknown',
          service: prefix.service || 'Unknown',
          cidrRange: prefix.ipv6_prefix,
          networkBorderGroup: prefix.network_border_group
        });
      }
    }
  }
  
  return matches;
}

/**
 * Search GCP manifest
 */
function searchGcpManifest(ipAddress, manifestData) {
  const matches = [];
  
  if (!manifestData.prefixes) return matches;
  
  for (const prefix of manifestData.prefixes) {
    const cidr = prefix.ipv4Prefix || prefix.ipv6Prefix;
    if (cidr && isIpInRange(ipAddress, cidr)) {
      matches.push({
        provider: 'GCP',
        region: prefix.scope || 'Unknown',
        service: prefix.service || 'Unknown',
        cidrRange: cidr
      });
    }
  }
  
  return matches;
}

/**
 * Search Oracle manifest
 */
function searchOracleManifest(ipAddress, manifestData) {
  const matches = [];
  
  if (!manifestData.regions) return matches;
  
  for (const region of manifestData.regions) {
    if (!region.cidrs) continue;
    
    for (const cidr of region.cidrs) {
      if (isIpInRange(ipAddress, cidr.cidr)) {
        matches.push({
          provider: 'Oracle',
          region: region.region || 'Unknown',
          service: cidr.tags ? cidr.tags.join(', ') : 'Unknown',
          cidrRange: cidr.cidr
        });
      }
    }
  }
  
  return matches;
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
 * Check if an IP address is within a CIDR range
 * Supports both IPv4 and IPv6
 */
function isIpInRange(ip, cidrRange) {
  try {
    // Parse CIDR notation (e.g., "192.168.1.0/24" or "2001:db8::/32")
    const parts = cidrRange.split('/');
    if (parts.length !== 2) {
      console.error('Invalid CIDR format:', cidrRange);
      return false;
    }
    
    const rangeIp = parts[0];
    const prefix = parseInt(parts[1], 10);
    
    if (isNaN(prefix)) {
      console.error('Invalid prefix length:', parts[1], 'in', cidrRange);
      return false;
    }
    
    // Detect IP version
    const isIPv6 = ip.includes(':');
    const isRangeIPv6 = rangeIp.includes(':');
    
    // Validate prefix length based on IP version
    if (isRangeIPv6) {
      // IPv6: prefix must be 0-128
      if (prefix < 0 || prefix > 128) {
        console.error('Invalid IPv6 prefix length:', prefix, '(must be 0-128) in', cidrRange);
        return false;
      }
    } else {
      // IPv4: prefix must be 0-32
      if (prefix < 0 || prefix > 32) {
        console.error('Invalid IPv4 prefix length:', prefix, '(must be 0-32) in', cidrRange);
        return false;
      }
    }
    
    // IP versions must match
    if (isIPv6 !== isRangeIPv6) {
      return false;
    }
    
    if (isIPv6) {
      // IPv6 handling
      return isIPv6InRange(ip, rangeIp, prefix);
    } else {
      // IPv4 handling
      return isIPv4InRange(ip, rangeIp, prefix);
    }
  } catch (error) {
    console.error('Error checking IP range:', error, { ip, cidrRange });
    return false;
  }
}

/**
 * Check if IPv4 address is in CIDR range
 */
function isIPv4InRange(ip, rangeIp, prefixLength) {
  // Convert IP addresses to 32-bit integers
  const ipNum = ipv4ToNumber(ip);
  const rangeNum = ipv4ToNumber(rangeIp);
  
  // Create subnet mask
  const mask = (0xFFFFFFFF << (32 - prefixLength)) >>> 0;
  
  // Compare network portions
  return (ipNum & mask) === (rangeNum & mask);
}

/**
 * Convert IPv4 address to 32-bit number
 */
function ipv4ToNumber(ip) {
  const parts = ip.split('.');

  // IPv4 must have exactly 4 octets
  if (parts.length !== 4) {
    throw new Error(`Invalid IPv4 address (expected 4 octets): "${ip}"`);
  }

  const nums = parts.map((part) => Number(part));

  // Each octet must be an integer between 0 and 255
  for (let i = 0; i < nums.length; i++) {
    const value = nums[i];
    if (!Number.isFinite(value) || !Number.isInteger(value) || value < 0 || value > 255) {
      throw new Error(`Invalid IPv4 octet "${parts[i]}" in address "${ip}"`);
    }
  }

  return ((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]) >>> 0;
}

/**
 * Check if IPv6 address is in CIDR range
 */
function isIPv6InRange(ip, rangeIp, prefixLength) {
  // Expand both IPs to full notation
  const ipExpanded = expandIPv6(ip);
  const rangeExpanded = expandIPv6(rangeIp);
  
  // Convert to bit arrays
  const ipBits = ipv6ToBits(ipExpanded);
  const rangeBits = ipv6ToBits(rangeExpanded);
  
  // Compare first prefixLength bits
  for (let i = 0; i < prefixLength; i++) {
    if (ipBits[i] !== rangeBits[i]) {
      return false;
    }
  }
  
  return true;
}

/**
 * Expand IPv6 address to full notation
 */
function expandIPv6(ip) {
  // Handle :: compression
  if (ip.includes('::')) {
    // Validate that there is at most one '::' occurrence
    const doubleColonMatches = ip.match(/::/g);
    if (doubleColonMatches && doubleColonMatches.length > 1) {
      // Invalid IPv6 with multiple '::' - return original to avoid runtime errors
      return ip;
    }

    const sides = ip.split('::');
    const leftParts = sides[0] ? sides[0].split(':') : [];
    const rightParts = sides[1] ? sides[1].split(':') : [];
    const missingParts = 8 - leftParts.length - rightParts.length;

    // If missingParts is negative, the address is malformed; avoid creating
    // an array with negative length and just return the original string.
    if (missingParts < 0) {
      return ip;
    }
    const middleParts = new Array(missingParts).fill('0000');
    const allParts = [...leftParts, ...middleParts, ...rightParts];
    return allParts.map(p => p.padStart(4, '0')).join(':');
  }
  
  // Just pad existing parts
  return ip.split(':').map(p => p.padStart(4, '0')).join(':');
}

/**
 * Convert IPv6 address to bit array
 */
function ipv6ToBits(ip) {
  const parts = ip.split(':');
  let bits = '';
  
  for (const part of parts) {
    const num = parseInt(part, 16);
    bits += num.toString(2).padStart(16, '0');
  }
  
  return bits;
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
