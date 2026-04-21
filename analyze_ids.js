const fs = require('fs');
const path = require('path');

const filesToAnalyze = [
  'index.html',
  'html/alerts.html',
  'html/channel-points.html',
  'html/commands.html',
  'html/comunity.html',
  'html/config.html',
  'html/contacto.html',
  'html/functions.html',
  'html/home.html',
  'html/overlay.html',
  'html/payments.html',
  'html/plan-admin.html'
];

const basePath = 'c:/Users/sheks/Desktop/InteractiveWithYou';

for (const file of filesToAnalyze) {
  const fullPath = path.join(basePath, file);
  if (!fs.existsSync(fullPath)) continue;
  
  const content = fs.readFileSync(fullPath, 'utf8');
  console.log(`\n--- Analyzing ${file} ---`);
  
  // Extract HTML IDs
  const idRegex = /\bid=["']([^"']+)["']/g;
  const ids = new Set();
  let match;
  while ((match = idRegex.exec(content)) !== null) {
    ids.add(match[1]);
  }
  
  // Extract getElementById calls
  const getElRegex = /getElementById\(['"]([^"']+)['"]\)/g;
  const queriedIds = new Set();
  while ((match = getElRegex.exec(content)) !== null) {
    queriedIds.add(match[1]);
  }
  
  // Find getElementById calls for IDs that don't exist in the HTML
  const missingIds = [];
  for (const qid of queriedIds) {
    if (!ids.has(qid)) {
      missingIds.push(qid);
    }
  }
  
  if (missingIds.length > 0) {
    console.log(`Missing IDs referenced in JS: ${missingIds.join(', ')}`);
  } else {
    console.log(`No missing IDs referenced in JS.`);
  }
}
