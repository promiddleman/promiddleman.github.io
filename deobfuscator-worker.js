/**
 * Python Deobfuscator Pro - Web Worker
 * Handles intensive deobfuscation in background thread
 */

// Import required scripts
self.importScripts(
  'https://cdnjs.cloudflare.com/ajax/libs/pako/2.1.0/pako.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/js-beautify/1.14.7/beautify.min.js',
  'deobfuscator.js'
);

// Process incoming messages
self.onmessage = function(e) {
  const { code, options, action } = e.data;
  
  // Different actions the worker can perform
  switch (action) {
    case 'deobfuscate':
      handleDeobfuscation(code, options);
      break;
      
    case 'analyze':
      analyzeCode(code);
      break;
      
    default:
      self.postMessage({ error: 'Unknown action' });
  }
};

/**
 * Main deobfuscation handler
 * @param {string} code - Code to deobfuscate
 * @param {object} options - Deobfuscation options
 */
function handleDeobfuscation(code, options) {
  try {
    // Send initial status
    self.postMessage({ status: 'starting', message: 'Initializing deobfuscator...' });
    
    // Create deobfuscator instance
    const deobfuscator = new PythonDeobfuscator(options);
    
    // Analyze code first
    const patterns = detectPatterns(code);
    self.postMessage({ 
      status: 'analyzing', 
      message: 'Analyzing obfuscation patterns...',
      patterns
    });
    
    // Start deobfuscation
    self.postMessage({ status: 'processing', message: 'Processing code...' });
    const startTime = performance.now();
    
    // Run deobfuscation
    const result = deobfuscator.deobfuscate(code);
    const endTime = performance.now();
    
    // Calculate some metrics
    const sizeReduction = ((code.length - result.code.length) / code.length * 100).toFixed(2);
    const complexity = calculateComplexity(code, result.code);
    
    // Add additional metrics
    const enhancedStats = {
      ...result.stats,
      sizeReduction: sizeReduction,
      originalSize: code.length,
      resultSize: result.code.length,
      timeMs: endTime - startTime,
      complexity
    };
    
    // Send complete result
    self.postMessage({
      status: 'complete',
      code: result.code,
      stats: enhancedStats,
      patterns
    });
    
  } catch (error) {
    self.postMessage({
      status: 'error',
      message: error.message || 'Unknown error during deobfuscation',
      stack: error.stack
    });
  }
}

/**
 * Analyze code for patterns
 * @param {string} code - Code to analyze
 */
function analyzeCode(code) {
  try {
    const patterns = detectPatterns(code);
    self.postMessage({
      status: 'analysis_complete',
      patterns
    });
  } catch (error) {
    self.postMessage({
      status: 'error',
      message: error.message || 'Unknown error during analysis'
    });
  }
}

/**
 * Detect obfuscation patterns in code
 * @param {string} code - Code to analyze
 * @returns {Array} - Array of detected patterns
 */
function detectPatterns(code) {
  const patterns = [];
  
  // Common obfuscation techniques to check for
  const checks = [
    {
      name: 'marshal',
      regex: /marshal\.loads|__import__\s*\(\s*['"](marshal)['"]\)/i,
      examples: [
        /exec\s*\(\s*marshal\.loads\s*\(\s*(.*?)\s*\)\s*\)/,
        /__import__\s*\(\s*['"](marshal)['"]\s*\)\.loads/
      ]
    },
    {
      name: 'base64',
      regex: /base64\.(?:b64decode|standard_b64decode)|__import__\s*\(\s*['"](base64)['"]\)/i,
      examples: [
        /exec\s*\(\s*base64\.(?:b64decode|standard_b64decode)\s*\(\s*(.*?)\s*\)/,
        /__import__\s*\(\s*['"](base64)['"]\s*\)\.(?:b64decode|standard_b64decode)/
      ]
    },
    {
      name: 'zlib',
      regex: /zlib\.decompress|__import__\s*\(\s*['"](zlib)['"]\)/i,
      examples: [
        /exec\s*\(\s*zlib\.decompress\s*\(\s*(.*?)\s*\)\s*\)/,
        /__import__\s*\(\s*['"](zlib)['"]\s*\)\.decompress/
      ]
    },
    {
      name: 'hex',
      regex: /bytes\.fromhex|bytearray\.fromhex/i,
      examples: [
        /bytes\.fromhex\s*\(\s*['"](.*?)['"]/,
        /bytearray\.fromhex\s*\(\s*['"](.*?)['"]/
      ]
    },
    {
      name: 'eval',
      regex: /eval\s*\(/i,
      examples: [
        /eval\s*\(\s*(?:compile\s*\(\s*)?(['"](.*?)['"])/,
        /eval\s*\(\s*["'](.*?)["']\s*\)/
      ]
    },
    {
      name: 'lambda',
      regex: /lambda\s+[^:]+\s*:/i,
      examples: [
        /\(\s*lambda\s+([^:]+)\s*:\s*(.*?)\s*\)\s*\(\s*(.*?)\s*\)/,
        /lambda\s+([^:]+)\s*:\s*([^(]+)\s*\(\s*(.*?)\s*\)/
      ]
    },
    {
      name: 'pyc',
      regex: /^\x42\x0D\x0D\x0A|^\x33[\x0D-\xF9]/,  // Magic numbers for PYC
      examples: []
    },
    {
      name: 'lzma',
      regex: /lzma\.decompress|__import__\s*\(\s*['"](lzma)['"]\)/i,
      examples: [
        /lzma\.decompress\s*\(\s*(.*?)\s*\)/,
        /__import__\s*\(\s*['"](lzma)['"]\s*\)\.decompress/
      ]
    }
  ];
  
  // Check for each pattern
  for (const check of checks) {
    if (check.regex.test(code)) {
      const examples = [];
      
      // Find examples of usage
      for (const exampleRegex of check.examples) {
        const match = code.match(exampleRegex);
        if (match) {
          examples.push(match[0]);
          // Limit to first example for brevity
          break;
        }
      }
      
      patterns.push({
        name: check.name,
        examples: examples
      });
    }
  }
  
  // Special checks for obfuscation indicators
  
  // Check for large hexadecimal strings (often used in obfuscation)
  if (/\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i.test(code)) {
    patterns.push({
      name: 'hex_strings',
      examples: [code.match(/(['"])(?:\\x[0-9a-f]{2}){3,}.*?\1/i)?.[0] || '']
    });
  }
  
  // Check for exec function (common in obfuscated code)
  if (/exec\s*\(/i.test(code)) {
    patterns.push({
      name: 'exec',
      examples: [code.match(/exec\s*\([^)]{1,40}(?:\)[^)]*)?/i)?.[0] || '']
    });
  }
  
  return patterns;
}

/**
 * Calculate complexity score based on code characteristics
 * @param {string} originalCode - Original code
 * @param {string} resultCode - Deobfuscated code
 * @returns {number} - Complexity score (1-10)
 */
function calculateComplexity(originalCode, resultCode) {
  let score = 0;
  
  // 1. Nesting level of obfuscation (harder = more layers)
  const nestingLevel = (originalCode.match(/exec\s*\(/g) || []).length;
  score += Math.min(3, nestingLevel);
  
  // 2. Ratio of original to result size
  const sizeRatio = originalCode.length / Math.max(1, resultCode.length);
  score += Math.min(3, Math.floor(sizeRatio));
  
  // 3. Number of different techniques
  const techniques = [
    /marshal\.loads/i, /base64\./i, /zlib\./i, /lzma\./i,
    /bytes\.fromhex/i, /eval\s*\(/i, /lambda\s+[^:]+:/i
  ];
  
  const techniqueCount = techniques.filter(t => t.test(originalCode)).length;
  score += Math.min(3, techniqueCount);
  
  // 4. Presence of control flow obfuscation
  if (/if\s+(?:ord|chr|len)\s*\([^)]+\)\s*[<=>]/i.test(originalCode)) {
    score += 1;
  }
  
  // Final score, capped at 10
  return Math.min(10, Math.max(1, score));
}

// Notify that the worker is ready
self.postMessage({ status: 'ready' });
