const fs = require('fs');
const { execSync } = require('child_process');

const regex = /\b[a-z][a-z0-9_]*\.(?:[a-z0-9_]+\.)+[A-Z][A-Za-z0-9_]*\b/g;

function checkFile(file) {
    if (!fs.existsSync(file)) return 0;
    const content = fs.readFileSync(file, 'utf8');
    
    const spans = [];
    let state = 'CODE';
    let start = 0;
    let i = 0;
    
    while (i < content.length) {
        const char = content[i];
        const next = content[i + 1];
        const next2 = content[i + 2];
        
        if (state === 'CODE') {
            if (char === '"' && next === '"' && next2 === '"') {
                if (i > start) spans.push({ text: content.slice(start, i), type: 'CODE', start });
                start = i;
                state = 'TEXT_BLOCK';
                i += 3;
            } else if (char === '"') {
                if (i > start) spans.push({ text: content.slice(start, i), type: 'CODE', start });
                start = i;
                state = 'STRING';
                i++;
            } else if (char === "'") {
                if (i > start) spans.push({ text: content.slice(start, i), type: 'CODE', start });
                start = i;
                state = 'CHAR';
                i++;
            } else if (char === '/' && next === '/') {
                if (i > start) spans.push({ text: content.slice(start, i), type: 'CODE', start });
                start = i;
                state = 'LINE_COMMENT';
                i += 2;
            } else if (char === '/' && next === '*') {
                if (i > start) spans.push({ text: content.slice(start, i), type: 'CODE', start });
                start = i;
                state = 'BLOCK_COMMENT';
                i += 2;
            } else {
                i++;
            }
        } else if (state === 'TEXT_BLOCK') {
            if (char === '\\') {
                i += 2;
            } else if (char === '"' && next === '"' && next2 === '"') {
                i += 3;
                spans.push({ text: content.slice(start, i), type: 'TEXT_BLOCK', start });
                start = i;
                state = 'CODE';
            } else {
                i++;
            }
        } else if (state === 'STRING') {
            if (char === '\\') {
                i += 2;
            } else if (char === '"') {
                i++;
                spans.push({ text: content.slice(start, i), type: 'STRING', start });
                start = i;
                state = 'CODE';
            } else {
                i++;
            }
        } else if (state === 'CHAR') {
            if (char === '\\') {
                i += 2;
            } else if (char === "'") {
                i++;
                spans.push({ text: content.slice(start, i), type: 'CHAR', start });
                start = i;
                state = 'CODE';
            } else {
                i++;
            }
        } else if (state === 'LINE_COMMENT') {
            if (char === '\n') {
                i++;
                spans.push({ text: content.slice(start, i), type: 'LINE_COMMENT', start });
                start = i;
                state = 'CODE';
            } else {
                i++;
            }
        } else if (state === 'BLOCK_COMMENT') {
            if (char === '*' && next === '/') {
                i += 2;
                spans.push({ text: content.slice(start, i), type: 'BLOCK_COMMENT', start });
                start = i;
                state = 'CODE';
            } else {
                i++;
            }
        }
    }
    if (i > start) {
        spans.push({ text: content.slice(start, i), type: state, start });
    }
    
    let fileViolations = 0;
    
    for (const span of spans) {
        if (span.type !== 'CODE') continue;
        
        let match;
        regex.lastIndex = 0;
        while ((match = regex.exec(span.text)) !== null) {
            const absoluteIndex = span.start + match.index;
            const beforeMatch = content.slice(0, absoluteIndex);
            
            const offset = match.index;
            const before = span.text.slice(Math.max(0, offset - 20), offset).trim();
            if (before.includes('import') || before.includes('package')) {
                continue;
            }
            
            const linesBefore = beforeMatch.split('\n');
            const lineNumber = linesBefore.length;
            const lineContent = content.split('\n')[lineNumber - 1].trim();
            
            console.error(`[STYLE ERROR] Fully qualified package reference found in ${file}:${lineNumber} -> ${match[0]}`);
            console.error(`  > ${lineContent}`);
            fileViolations++;
        }
    }
    
    return fileViolations;
}

try {
    let files = [];
    if (process.argv.includes('--all')) {
        const stdout = execSync('git ls-files', { encoding: 'utf8' });
        files = stdout.split('\n').map(f => f.trim()).filter(f => f.endsWith('.java'));
    } else {
        const stdout = execSync('git diff --cached --name-only --diff-filter=ACM', { encoding: 'utf8' });
        files = stdout.split('\n').map(f => f.trim()).filter(f => f.endsWith('.java'));
    }

    let totalViolations = 0;

    for (const file of files) {
        totalViolations += checkFile(file);
    }

    if (totalViolations > 0) {
        console.error(`\n[COMMIT BLOCKED] Found ${totalViolations} fully qualified package reference(s).`);
        console.error(`Please use import statements and simple class names instead.`);
        process.exit(1);
    }
    console.log('Java style check passed successfully.');
    process.exit(0);
} catch (err) {
    console.error('Failed to run Java style check:', err.message);
    process.exit(1);
}
