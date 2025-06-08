#!/usr/bin/env node

// Test script to verify authentication key synchronization
// between C# service and Cloudflare Worker

const fs = require('fs');
const path = require('path');

console.log('🔐 Testing Authentication Key Synchronization');
console.log('='.repeat(50));

try {
    // Read the generated C# constants
    const csharpConstants = fs.readFileSync(path.join(__dirname, 'Generated', 'BuildConstants.cs'), 'utf8');
    
    // Read the generated JavaScript constants
    const jsConstants = fs.readFileSync(path.join(__dirname, 'Generated', 'build-constants.js'), 'utf8');
    
    // Read the processed Cloudflare Worker
    const workerContent = fs.readFileSync(path.join(__dirname, 'cloudflare-worker.js'), 'utf8');
    
    // Extract auth key from C# constants using regex
    const csharpKeyMatch = csharpConstants.match(/AuthKeyBase64 = "([^"]+)"/);
    const csharpKey = csharpKeyMatch ? csharpKeyMatch[1] : null;
    
    // Extract auth key from JavaScript constants
    const jsKeyMatch = jsConstants.match(/GENERATED_AUTH_KEY_B64 = "([^"]+)"/);
    const jsKey = jsKeyMatch ? jsKeyMatch[1] : null;
    
    // Extract auth key from worker
    const workerKeyMatch = workerContent.match(/GENERATED_AUTH_KEY_B64 = "([^"]+)"/);
    const workerKey = workerKeyMatch ? workerKeyMatch[1] : null;
    
    // Extract build information
    const buildIdMatch = csharpConstants.match(/BuildId = "([^"]+)"/);
    const buildId = buildIdMatch ? buildIdMatch[1] : 'unknown';
    
    const timestampMatch = csharpConstants.match(/BuildTimestamp = "([^"]+)"/);
    const timestamp = timestampMatch ? timestampMatch[1] : 'unknown';
    
    console.log(`📅 Build ID: ${buildId}`);
    console.log(`🕐 Build Timestamp: ${timestamp}`);
    console.log();
    
    console.log('🔑 Authentication Key Verification:');
    console.log(`   C# Service Key:     ${csharpKey ? csharpKey.substring(0, 16) + '...' : 'NOT FOUND'}`);
    console.log(`   JS Constants Key:   ${jsKey ? jsKey.substring(0, 16) + '...' : 'NOT FOUND'}`);
    console.log(`   Worker Key:         ${workerKey ? workerKey.substring(0, 16) + '...' : 'NOT FOUND'}`);
    console.log();
    
    // Verify synchronization
    const keysMatch = csharpKey && jsKey && workerKey && 
                     csharpKey === jsKey && jsKey === workerKey;
    
    if (keysMatch) {
        console.log('✅ SUCCESS: All authentication keys are synchronized!');
        console.log('   - C# service will use the same key as the Cloudflare Worker');
        console.log('   - Build-time key generation is working correctly');
        console.log('   - Security enhancement is active');
    } else {
        console.log('❌ ERROR: Authentication keys are NOT synchronized!');
        console.log('   - This could cause authentication failures');
        console.log('   - Please rebuild the project');
        process.exit(1);
    }
    
    // Additional security verification
    if (csharpKey && csharpKey.length >= 32) {
        console.log('🔒 Security verification passed (key length adequate)');
    } else {
        console.log('⚠️  WARNING: Generated key may be too short');
    }
    
    // Check if this is a unique key (not the old hardcoded one)
    const oldHardcodedKey = "YWxiYXRyb3NzLWFidXNlaXBkYi1jbGllbnQ=";
    if (csharpKey !== oldHardcodedKey) {
        console.log('🆕 Confirmed: Using dynamically generated key (not hardcoded)');
    } else {
        console.log('⚠️  WARNING: Still using old hardcoded key');
    }
    
    console.log();
    console.log('🎯 Ready for deployment!');
    
} catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error('💡 Try running: dotnet build');
    process.exit(1);
}
