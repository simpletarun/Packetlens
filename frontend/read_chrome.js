const fs = require('fs');
const s = fs.readFileSync('tests/map-chrome.test.tsx','utf8');
const lines = s.split(/\r?\n/);
for(let i=90;i<Math.min(180,lines.length);i++) {
  console.log((i+1)+': '+lines[i]);
}
