const fs = require('fs');

const content = fs.readFileSync('c:\\Users\\sheks\\Desktop\\InteractiveWithYou\\html\\channel-points.html', 'utf8');

// A very naive unused function checker: find function declarations, check if they occur elsewhere
const funcs = [];
let match;
const funcRegex = /(?:function\s+([a-zA-Z0-9_]+)\s*\(|const\s+([a-zA-Z0-9_]+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[a-zA-Z0-9_]+)\s*=>)/g;
while ((match = funcRegex.exec(content)) !== null) {
    const name = match[1] || match[2];
    if (name) funcs.push(name);
}

console.log(`Found ${funcs.length} functions.`);
const unused = [];
for (const f of funcs) {
    // Escape string for regex
    const regex = new RegExp(`\\b${f}\\b`, 'g');
    const matches = content.match(regex);
    // matches includes the definition itself. If it's 1, it's unused.
    if (matches && matches.length === 1) {
        // Double check it's not exported or a callback passed somewhere directly (our regex might be too strict)
        unused.push(f);
    }
}

console.log('Potentially unused functions:', unused.join(', '));
