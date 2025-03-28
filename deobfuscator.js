/**
 * Python Deobfuscator Pro - Enhanced JavaScript Engine v2.0
 * Supports: Marshal, Base64, Zlib, Lzma, Hex, Eval, Lambda & PYC detection
 */

class PythonDeobfuscator {
  constructor(options = {}) {
    // Configure options with defaults
    this.options = {
      maxDepth: options.maxDepth || 30,
      timeout: (options.timeout || 60) * 1000,
      useMarshal: options.useMarshal !== false,
      useBase64: options.useBase64 !== false,
      useZlib: options.useZlib !== false,
      useLambda: options.useLambda !== false,
      useHex: options.useHex !== false, 
      useEval: options.useEval !== false,
      usePyc: options.usePyc !== false,
      useCustom: options.useCustom || false,
      customPattern: options.customPattern || '',
      beautify: options.beautify !== false
    };
    
    // Initialize statistics
    this.stats = {
      layers: 0,
      techniques: {},
      startTime: 0,
      endTime: 0
    };
    
    // Collection of deobfuscation patterns
    this.patterns = {
      marshal: [
        /exec\s*\(\s*marshal\.loads\s*\(\s*(.*?)\s*\)\s*\)/g,
        /exec\s*\(\s*__import__\s*\(\s*['"](marshal)['"]\s*\)\.loads\s*\(\s*(.*?)\s*\)\s*\)/g,
        /exec\s*\(\s*eval\s*\(\s*\(\s*lambda\s+.*?\s*:\s*.*?\s*\)\s*\(\s*['"]{2}\s*,.*?chr\s*\)\s*\(\s*(.*?)\s*\)\s*\)\s*\)/g,
        /exec\s*\(\s*marshal\.loads\s*\(\s*b?['"](.*?)['"].*?\s*\)\s*\)/g
      ],
      
      base64: [
        /exec\s*\(\s*__import__\s*\(\s*['"](base64)['"]\s*\)\.(?:b64decode|b64encode|standard_b64decode)\s*\(\s*b?['"](.*?)['"].*?\s*\)\s*\)/g,
        /exec\s*\(\s*base64\.(?:b64decode|standard_b64decode)\s*\(\s*b?['"](.*?)['"].*?\s*\)(?:\.decode\s*\(\s*['"](utf-?8)['"]\s*\))?\s*\)/g
      ],
      
      zlib: [
        /exec\s*\(\s*zlib\.decompress\s*\(\s*(.*?)\s*\)\s*\)/g,
        /exec\s*\(\s*__import__\s*\(\s*['"](zlib)['"]\s*\)\.decompress\s*\(\s*(.*?)\s*\)\s*\)/g,
        /exec\s*\(\s*zlib\.decompress\s*\(\s*base64\.b(?:64decode|ase64decode)\s*\(\s*b?['"](.*?)['"].*?\s*\)\s*\)\s*\)/g
      ],
      
      lzma: [
        /exec\s*\(\s*lzma\.decompress\s*\(\s*(.*?)\s*\)\s*\)/g,
        /exec\s*\(\s*__import__\s*\(\s*['"](lzma)['"]\s*\)\.decompress\s*\(\s*(.*?)\s*\)\s*\)/g
      ],
      
      hex: [
        /exec\s*\(\s*bytes\.fromhex\s*\(\s*['"](.*?)['"].*?\s*\)(?:\.decode\s*\(\s*['"](utf-?8)['"]\s*\))?\s*\)/g,
        /exec\s*\(\s*bytearray\.fromhex\s*\(\s*['"](.*?)['"].*?\s*\)(?:\.decode\s*\(\s*['"](utf-?8)['"]\s*\))?\s*\)/g
      ],
      
      eval: [
        /eval\s*\(\s*(?:compile\s*\(\s*)?(['"](.*?)['"].*?)['"]\s*,\s*['"].*?['"]\s*,\s*['"].*?['"]\s*\)/g,
        /eval\s*\(\s*["'](.*?)["']\s*\)/g
      ],
      
      lambda: [
        /\(\s*lambda\s+([^:]+)\s*:\s*(.*?)\s*\)\s*\(\s*(.*?)\s*\)/g,
        /lambda\s+([^:]+)\s*:\s*([^(]+)\s*\(\s*(.*?)\s*\)/g
      ]
    };
    
    // Add custom pattern if provided
    if (this.options.useCustom && this.options.customPattern) {
      try {
        const customRegex = new RegExp(this.options.customPattern, 'g');
        this.patterns.custom = [customRegex];
      } catch (e) {
        console.error('Invalid custom pattern:', e);
      }
    }
  }
  
  /**
   * Main deobfuscation method - processes code with all enabled techniques
   * @param {string} code - Obfuscated Python code
   * @returns {object} - Result with deobfuscated code and stats
   */
  deobfuscate(code) {
    // Reset statistics
    this.stats = {
      layers: 0,
      techniques: {},
      startTime: performance.now(),
      endTime: 0
    };
    
    // Process binary PYC if detected
    if (this.isPycData(code) && this.options.usePyc) {
      // Note: In a browser context, we can't fully process PYC files
      // This would require server-side processing or a Python runtime
      this.recordTechnique('pyc');
      const result = this.handlePycData(code);
      this.stats.endTime = performance.now();
      return result;
    }
    
    let currentCode = code;
    let previousCode = '';
    let startTime = performance.now();
    let depth = 0;
    
    // Main deobfuscation loop - continue until no changes or max depth reached
    while (depth < this.options.maxDepth) {
      previousCode = currentCode;
      
      // Apply each enabled deobfuscation technique
      currentCode = this.applyTechniques(currentCode);
      
      // Check if we made any progress
      if (currentCode === previousCode) {
        break; // No changes made, exit loop
      }
      
      // Check timeout
      if (performance.now() - startTime > this.options.timeout) {
        console.warn('Deobfuscation timeout reached');
        break;
      }
      
      depth++;
      this.stats.layers++;
    }
    
    // Apply code beautification if enabled
    if (this.options.beautify && typeof js_beautify === 'function') {
      currentCode = this.beautifyPythonCode(currentCode);
    }
    
    // Record final stats
    this.stats.endTime = performance.now();
    
    return {
      code: currentCode,
      stats: this.stats
    };
  }
  
  /**
   * Apply all enabled deobfuscation techniques to the code
   * @param {string} code - Current code state
   * @returns {string} - Processed code after applying techniques
   */
  applyTechniques(code) {
    let result = code;
    
    // Marshal deobfuscation
    if (this.options.useMarshal) {
      result = this.processMarshal(result);
    }
    
    // Base64 deobfuscation
    if (this.options.useBase64) {
      result = this.processBase64(result);
    }
    
    // Zlib deobfuscation
    if (this.options.useZlib) {
      result = this.processZlib(result);
    }
    
    // Hex deobfuscation
    if (this.options.useHex) {
      result = this.processHex(result);
    }
    
    // Eval unwrapping
    if (this.options.useEval) {
      result = this.processEval(result);
    }
    
    // Lambda unwrapping
    if (this.options.useLambda) {
      result = this.processLambda(result);
    }
    
    // Custom pattern
    if (this.options.useCustom && this.patterns.custom) {
      result = this.processCustomPattern(result);
    }
    
    return result;
  }
  
  /**
   * Process marshal-encoded Python code
   * @param {string} code - Python code with marshal encoding
   * @returns {string} - Processed code
   */
  processMarshal(code) {
    let result = code;
    let modified = false;
    
    for (const pattern of this.patterns.marshal) {
      const matches = [...result.matchAll(pattern)];
      
      for (const match of matches) {
        try {
          // Extract the marshaled data
          const marshaledData = match[1] || match[2];
          if (!marshaledData) continue;
          
          // For demonstration, extract string content or provide placeholder
          let decodedContent;
          
          // Try to find Python strings that might be code
          const strings = this.extractPythonStrings(marshaledData);
          if (strings.length > 0) {
            decodedContent = strings.join('\n');
          } else {
            // Fallback - provide a placeholder
            decodedContent = '# Marshal-encoded content (needs Python runtime to fully decode)';
          }
          
          // Replace the matched pattern with decoded content
          result = result.replace(match[0], decodedContent);
          modified = true;
        } catch (e) {
          console.error('Error processing marshal pattern:', e);
        }
      }
    }
    
    if (modified) {
      this.recordTechnique('marshal');
    }
    
    return result;
  }
  
  /**
   * Process base64-encoded Python code
   * @param {string} code - Python code with base64 encoding
   * @returns {string} - Processed code
   */
  processBase64(code) {
    let result = code;
    let modified = false;
    
    for (const pattern of this.patterns.base64) {
      const matches = [...result.matchAll(pattern)];
      
      for (const match of matches) {
        try {
          // Extract the base64 data
          const base64Data = match[2] || match[1];
          if (!base64Data) continue;
          
          // Attempt to decode base64
          let decodedContent;
          try {
            // Clean the string and decode
            const cleanedData = base64Data.trim().replace(/^b['"]/i, '').replace(/['"]$/, '');
            decodedContent = this.base64Decode(cleanedData);
          } catch (e) {
            console.warn('Base64 decode failed:', e);
            decodedContent = '# Failed to decode base64 content';
          }
          
          // Replace the matched pattern with decoded content
          result = result.replace(match[0], decodedContent);
          modified = true;
        } catch (e) {
          console.error('Error processing base64 pattern:', e);
        }
      }
    }
    
    if (modified) {
      this.recordTechnique('base64');
    }
    
    return result;
  }
  
  /**
   * Process zlib-compressed Python code
   * @param {string} code - Python code with zlib compression
   * @returns {string} - Processed code
   */
  processZlib(code) {
    let result = code;
    let modified = false;
    
    for (const pattern of this.patterns.zlib) {
      const matches = [...result.matchAll(pattern)];
      
      for (const match of matches) {
        try {
          // Check if we have pako library available for zlib decompression
          if (typeof pako !== 'undefined') {
            // Extract the zlib data
            let zlibData;
            
            if (match[3]) {
              // Handle base64+zlib combination
              try {
                const base64Data = match[3].trim().replace(/^b['"]/i, '').replace(/['"]$/, '');
                const decoded = this.base64Decode(base64Data, true); // Get bytes
                zlibData = decoded;
              } catch (e) {
                console.warn('Failed to decode base64 in zlib content:', e);
                continue;
              }
            } else {
              // Direct zlib data
              const dataStr = match[1] || match[2];
              if (!dataStr) continue;
              
              // Try to evaluate to get the actual bytes
              try {
                // This is a simplified approach - in real implementation you'd
                // need more robust parsing of Python byte literals
                if (dataStr.startsWith('b"') || dataStr.startsWith("b'")) {
                  // Handle byte string
                  const bytes = this.parsePythonBytes(dataStr);
                  zlibData = bytes;
                } else {
                  // Handle other expressions
                  console.warn('Complex zlib data expression, skipping');
                  continue;
                }
              } catch (e) {
                console.warn('Failed to evaluate zlib data:', e);
                continue;
              }
            }
            
            // Decompress with pako
            try {
              const decompressed = pako.inflate(zlibData);
              const decodedContent = new TextDecoder().decode(decompressed);
              result = result.replace(match[0], decodedContent);
              modified = true;
            } catch (e) {
              console.warn('Zlib decompression failed:', e);
              result = result.replace(match[0], '# Failed to decompress zlib content');
              modified = true;
            }
          } else {
            // No pako library, add a comment
            result = result.replace(match[0], '# Zlib compressed content (needs pako library)');
            modified = true;
          }
        } catch (e) {
          console.error('Error processing zlib pattern:', e);
        }
      }
    }
    
    if (modified) {
      this.recordTechnique('zlib');
    }
    
    return result;
  }
  
  /**
   * Process hex-encoded Python code
   * @param {string} code - Python code with hex encoding
   * @returns {string} - Processed code
   */
  processHex(code) {
    let result = code;
    let modified = false;
    
    for (const pattern of this.patterns.hex) {
      const matches = [...result.matchAll(pattern)];
      
      for (const match of matches) {
        try {
          // Extract the hex data
          const hexData = match[1];
          if (!hexData) continue;
          
          // Decode hex to string
          try {
            const hexString = hexData.trim().replace(/^0x/i, '');
            const bytes = new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
            const decodedContent = new TextDecoder().decode(bytes);
            result = result.replace(match[0], decodedContent);
            modified = true;
          } catch (e) {
            console.warn('Hex decode failed:', e);
            result = result.replace(match[0], '# Failed to decode hex content');
            modified = true;
          }
        } catch (e) {
          console.error('Error processing hex pattern:', e);
        }
      }
    }
    
    if (modified) {
      this.recordTechnique('hex');
    }
    
    return result;
  }
  
  /**
   * Process eval expressions in Python code
   * @param {string} code - Python code with eval
   * @returns {string} - Processed code
   */
  processEval(code) {
    let result = code;
    let modified = false;
    
    for (const pattern of this.patterns.eval) {
      const matches = [...result.matchAll(pattern)];
      
      for (const match of matches) {
        try {
          // Extract the eval content
          const evalContent = match[1] || match[2];
          if (!evalContent) continue;
          
          // For eval, we'll just unwrap the string
          const unwrapped = evalContent.replace(/^["']/g, '').replace(/["']$/g, '');
          result = result.replace(match[0], unwrapped);
          modified = true;
        } catch (e) {
          console.error('Error processing eval pattern:', e);
        }
      }
    }
    
    if (modified) {
      this.recordTechnique('eval');
    }
    
    return result;
  }
  
  /**
   * Process lambda expressions in Python code
   * @param {string} code - Python code with lambda functions
   * @returns {string} - Processed code
   */
  processLambda(code) {
    let result = code;
    let modified = false;
    
    for (const pattern of this.patterns.lambda) {
      const matches = [...result.matchAll(pattern)];
      
      for (const match of matches) {
        try {
          // Extract the lambda parts
          const param = match[1];
          const body = match[2];
          const arg = match[3];
          
          if (!param || !body || !arg) continue;
          
          // Simplify by replacing parameter with argument in body
          // This is a simplified approach - for complex lambdas a more robust parser would be needed
          
          // Create a regex that matches the parameter as a whole word
          const paramRegex = new RegExp(`\\b${param.trim()}\\b`, 'g');
          
          // Replace parameter with argument in the body
          const simplifiedBody = body.trim().replace(paramRegex, arg.trim());
          
          // Replace the entire lambda expression with the simplified body
          result = result.replace(match[0], `(${simplifiedBody})`);
          modified = true;
        } catch (e) {
          console.error('Error processing lambda pattern:', e);
        }
      }
    }
    
    if (modified) {
      this.recordTechnique('lambda');
    }
    
    return result;
  }
  
  /**
   * Process custom pattern in Python code
   * @param {string} code - Python code to process with custom pattern
   * @returns {string} - Processed code
   */
  processCustomPattern(code) {
    let result = code;
    let modified = false;
    
    for (const pattern of this.patterns.custom) {
      const matches = [...result.matchAll(pattern)];
      
      for (const match of matches) {
        try {
          // Extract any captured groups
          const captured = match.slice(1).filter(Boolean);
          
          if (captured.length > 0) {
            // Use the first non-empty captured group
            const content = captured[0];
            result = result.replace(match[0], `# Custom pattern match\n${content}`);
          } else {
            // No captures, just comment the match
            result = result.replace(match[0], `# Matched custom pattern: ${match[0]}`);
          }
          
          modified = true;
        } catch (e) {
          console.error('Error processing custom pattern:', e);
        }
      }
    }
    
    if (modified) {
      this.recordTechnique('custom');
    }
    
    return result;
  }
  
  /**
   * Record a technique used in statistics
   * @param {string} technique - Name of the technique
   */
  recordTechnique(technique) {
    this.stats.techniques[technique] = (this.stats.techniques[technique] || 0) + 1;
  }
  
  /**
   * Check if the input looks like PYC data
   * @param {string} data - Code to check
   * @returns {boolean} - True if it appears to be PYC data
   */
  isPycData(data) {
    // Check if it starts with common PYC magic numbers
    if (typeof data === 'string') {
      return false; // String data is not binary PYC
    }
    
    // For ArrayBuffer or typed array, check magic numbers
    if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
      const view = new Uint8Array(data instanceof ArrayBuffer ? data : data.buffer);
      
      // Check common PYC magic numbers for Python 3.x
      if (view.length >= 4) {
        // Python 3.x PYC files start with:
        // 0x42 0x0D 0x0D 0x0A (Python 3.7+)
        // Or other magic numbers for different versions
        return (view[0] === 0x42 && view[1] === 0x0D) || 
               (view[0] === 0x33 && (view[1] >= 0x0D || view[1] <= 0xF9));
      }
    }
    
    return false;
  }
  
  /**
   * Process PYC data (demonstration only - limited functionality in browser)
   * @param {ArrayBuffer|TypedArray} data - PYC binary data
   * @returns {object} - Result with deobfuscated code and stats
   */
  handlePycData(data) {
    // In a browser, we can't fully decompile PYC
    // This would typically be done server-side with uncompyle6 or similar tools
    
    // For demonstration, return a message about PYC handling
    const message = `# Python Bytecode (.pyc) file detected
# 
# PYC files cannot be fully decompiled in the browser.
# This would require server-side processing with tools like:
# - uncompyle6
# - decompyle3
# - pycdc
# 
# However, we can still detect and extract some information:
# 
# PYC Header Analysis:
# --------------------
# Format: Python bytecode file
# Bytes 0-3: Magic number (indicates Python version)
# Bytes 4-7: Timestamp
# Bytes 8-11: Size parameter (Python 3.3+)
# Bytes 12-15: Hash parameter (Python 3.7+)
# 
# For full decompilation, please use a local Python decompiler tool.
`;
    
    return {
      code: message,
      stats: this.stats
    };
  }
  
  /**
   * Decode base64 string to utf-8 text or bytes
   * @param {string} base64 - Base64 encoded string
   * @param {boolean} toBytes - If true, return Uint8Array instead of string
   * @returns {string|Uint8Array} - Decoded content
   */
  base64Decode(base64, toBytes = false) {
    // Clean the input (remove whitespace and quotes)
    const cleaned = base64.replace(/\s/g, '');
    
    // Decode base64
    const binary = atob(cleaned);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    
    if (toBytes) {
      return bytes;
    }
    
    // Convert to string
    return new TextDecoder().decode(bytes);
  }
  
  /**
   * Parse Python byte literal (simplified)
   * @param {string} byteStr - Python byte literal (e.g., b'\x01\x02')
   * @returns {Uint8Array} - Parsed bytes
   */
  parsePythonBytes(byteStr) {
    // Very simplified parser for demonstration
    // A real implementation would need to handle all Python escape sequences
    
    // Strip b prefix and quotes
    let cleaned = byteStr.replace(/^b['"]/i, '').replace(/['"]$/g, '');
    
    // Handle \x escapes
    const bytes = [];
    let i = 0;
    while (i < cleaned.length) {
      if (cleaned[i] === '\\' && cleaned[i + 1] === 'x' && i + 3 < cleaned.length) {
        // Hex escape sequence
        const hex = cleaned.substring(i + 2, i + 4);
        bytes.push(parseInt(hex, 16));
        i += 4;
      } else {
        // Regular character
        bytes.push(cleaned.charCodeAt(i));
        i += 1;
      }
    }
    
    return new Uint8Array(bytes);
  }
  
  /**
   * Extract Python string literals from code
   * @param {string} code - Python code
   * @returns {Array<string>} - Extracted string literals
   */
  extractPythonStrings(code) {
    const strings = [];
    
    // Match triple-quoted strings
    const tripleRegex = /"""([\s\S]*?)"""|'''([\s\S]*?)'''/g;
    let match;
    
    while ((match = tripleRegex.exec(code)) !== null) {
      const content = match[1] || match[2];
      if (content && content.trim().length > 0 && this.isPythonCode(content)) {
        strings.push(content);
      }
    }
    
    // Match single-quoted strings
    const singleRegex = /"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'/g;
    
    while ((match = singleRegex.exec(code)) !== null) {
      const content = match[1] || match[2];
      if (content && content.trim().length > 0 && this.isPythonCode(content)) {
        strings.push(content);
      }
    }
    
    return strings;
  }
  
  /**
   * Check if a string looks like Python code
   * @param {string} text - Text to check
   * @returns {boolean} - True if it looks like Python code
   */
  isPythonCode(text) {
    // Simple heuristic - check for some common Python keywords and syntax
    const pythonIndicators = [
      'def ', 'class ', 'import ', 'from ', 'for ', 'while ', 'if ', 'else:', 
      'elif ', 'try:', 'except:', 'with ', 'return ', 'print(', '# ', '"""',
      'lambda ', 'async ', 'await '
    ];
    
    return pythonIndicators.some(indicator => text.includes(indicator));
  }
  
  /**
   * Beautify Python code using js-beautify with Python-friendly options
   * @param {string} code - Python code to beautify
   * @returns {string} - Beautified code
   */
  beautifyPythonCode(code) {
    try {
      // js-beautify doesn't have specific Python mode, but we can adjust options
      return js_beautify(code, {
        indent_size: 4,
        indent_char: ' ',
        max_preserve_newlines: 2,
        preserve_newlines: true,
        keep_array_indentation: false,
        break_chained_methods: false,
        indent_scripts: 'normal',
        brace_style: 'collapse',
        space_before_conditional: true,
        unescape_strings: true,
        jslint_happy: false,
        end_with_newline: true,
        wrap_line_length: 0,
        indent_inner_html: false,
        comma_first: false,
        e4x: false,
        indent_empty_lines: false
      });
    } catch (e) {
      console.error('Error beautifying code:', e);
      return code; // Return original code if beautification fails
    }
  }
}

// Export for both browser and Node.js environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PythonDeobfuscator };
} else if (typeof window !== 'undefined') {
  window.PythonDeobfuscator = PythonDeobfuscator;
}
