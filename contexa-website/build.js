/**
 * Contexa Website Build Script
 * Inlines shared includes (header, footer, sidebar) into all HTML pages
 * and converts internal links to relative paths.
 * Supports both fresh builds (data-include placeholders) and rebuilds
 * (replaces previously inlined content with latest version).
 *
 * Usage: node build.js
 */
const fs = require('fs');
const path = require('path');

const SITE_DIR = __dirname;
const INCLUDES_DIR = path.join(SITE_DIR, 'includes');
const CACHE_BUST = '?v=' + Date.now();

// Load include templates
const header = fs.readFileSync(path.join(INCLUDES_DIR, 'header.html'), 'utf-8');
const footer = fs.readFileSync(path.join(INCLUDES_DIR, 'footer.html'), 'utf-8');
const sidebar = fs.readFileSync(path.join(INCLUDES_DIR, 'docs-sidebar.html'), 'utf-8');

/**
 * Recursively find all HTML files excluding includes/
 */
function findHtmlFiles(dir) {
  let results = [];
  const items = fs.readdirSync(dir);
  for (const item of items) {
    const fullPath = path.join(dir, item);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      if (item !== 'includes' && item !== 'node_modules' && item !== '.git') {
        results = results.concat(findHtmlFiles(fullPath));
      }
    } else if (item.endsWith('.html')) {
      results.push(fullPath);
    }
  }
  return results;
}

/**
 * Calculate relative path from a file to the site root
 */
function getRelativeRoot(filePath) {
  const relFromRoot = path.relative(SITE_DIR, path.dirname(filePath));
  if (!relFromRoot) return './';
  const depth = relFromRoot.split(path.sep).length;
  return '../'.repeat(depth);
}

/**
 * Convert absolute internal links (/path) to relative (relRoot + path)
 */
function adjustLinks(html, relRoot) {
  return html.replace(/(href|src|action)="\/([^"]*?)"/g, function(match, attr, p) {
    return attr + '="' + relRoot + p + '"';
  });
}

/**
 * Process a single HTML file
 */
function processFile(filePath) {
  let content = fs.readFileSync(filePath, 'utf-8');
  const relRoot = getRelativeRoot(filePath);

  // Adjust links in include templates for this file's depth
  const adjustedHeader = adjustLinks(header, relRoot);
  const adjustedFooter = adjustLinks(footer, relRoot);
  const adjustedSidebar = adjustLinks(sidebar, relRoot);

  // 1. Replace data-include placeholders (fresh build)
  content = content.replace(
    /<div\s+data-include="\/includes\/header\.html"\s*><\/div>/,
    adjustedHeader
  );
  content = content.replace(
    /<div\s+data-include="\/includes\/footer\.html"\s*><\/div>/,
    adjustedFooter
  );
  content = content.replace(
    /<div\s+data-include="\/includes\/docs-sidebar\.html"\s*><\/div>/,
    adjustedSidebar
  );

  // 2. Remove leftover <style> blocks from previous sidebar builds
  content = content.replace(
    /<style>\s*\.sidebar-links[\s\S]*?<\/style>\s*/g,
    ''
  );

  // 3. Replace previously inlined sidebar (rebuild)
  content = content.replace(
    /<nav class="docs-sidebar"[^>]*>[\s\S]*?<\/nav>\s*(?:<!--\s*Mobile sidebar overlay\s*-->\s*<div class="sidebar-overlay"><\/div>\s*)?(?:<!--\s*Mobile sidebar toggle button\s*-->\s*<button class="sidebar-toggle"[\s\S]*?<\/button>)?/,
    adjustedSidebar
  );

  // 3. Replace previously inlined header (rebuild)
  //    Matches <header>...</header> followed by any number of mobile-nav blocks
  content = content.replace(
    /<header class="site-header"[^>]*>[\s\S]*?<\/header>(?:\s*<!--\s*Mobile Navigation\s*-->\s*<div class="mobile-nav"[\s\S]*?<\/div>\s*<\/div>)*/,
    adjustedHeader
  );

  // 4. Replace previously inlined footer (rebuild)
  content = content.replace(
    /<footer class="site-footer"[^>]*>[\s\S]*?<\/footer>/,
    adjustedFooter
  );

  // Remove include.js script tag (no longer needed after inlining)
  content = content.replace(
    /\s*<script\s+src="[^"]*include\.js[^"]*"[^>]*><\/script>/g,
    ''
  );

  // Inject docs-search.js and docs-toc.js for pages that have docs content
  if (content.includes('docs-content') && !content.includes('docs-search.js')) {
    content = content.replace(
      /(<script\s+src="[^"]*code-highlight\.js[^"]*"><\/script>)/,
      '$1\n  <script src="' + relRoot + 'assets/js/docs-search.js"></script>' +
      '\n  <script src="' + relRoot + 'assets/js/docs-toc.js"></script>'
    );
  }

  // Convert remaining absolute internal links to relative paths
  // (covers <head> CSS/JS and any body links not in header/footer/sidebar)
  content = adjustLinks(content, relRoot);

  // Wrap api-tables with scroll container for horizontal scrolling
  // First remove existing wrappers (for rebuild idempotency)
  content = content.replace(/<div class="table-scroll">(<table[\s\S]*?<\/table>)<\/div>/g, '$1');
  // Then wrap each api-table
  content = content.replace(/<table class="api-table">([\s\S]*?)<\/table>/g,
    '<div class="table-scroll"><table class="api-table">$1</table></div>');

  // Cache busting: update or add version query to local CSS/JS references
  content = content.replace(
    /(href="[^"]*\.css)(\?v=[^"]*)?(")/g,
    '$1' + CACHE_BUST + '$3'
  );
  content = content.replace(
    /(src="[^"]*\.js)(\?v=[^"]*)?(")/g,
    '$1' + CACHE_BUST + '$3'
  );

  fs.writeFileSync(filePath, content, 'utf-8');
}

// Main execution
const files = findHtmlFiles(SITE_DIR);
let processed = 0;
let errors = 0;

for (const file of files) {
  try {
    processFile(file);
    processed++;
  } catch (err) {
    console.error('ERROR processing ' + path.relative(SITE_DIR, file) + ': ' + err.message);
    errors++;
  }
}

console.log('Build complete: ' + processed + ' files processed, ' + errors + ' errors');

// Verify: check for any remaining data-include references
let remaining = 0;
for (const file of files) {
  const content = fs.readFileSync(file, 'utf-8');
  const matches = content.match(/data-include="/g);
  if (matches) {
    console.warn('WARNING: ' + path.relative(SITE_DIR, file) + ' still has ' + matches.length + ' unresolved includes');
    remaining += matches.length;
  }
}

if (remaining === 0) {
  console.log('Verification passed: all includes resolved');
} else {
  console.warn('Verification: ' + remaining + ' unresolved includes remain');
}
