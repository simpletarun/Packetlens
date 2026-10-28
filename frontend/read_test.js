const fs = require('fs');
const s = fs.readFileSync('tests/map-data.test.ts','utf8');
const lines = s.split(/\r?\n/);
for(let i=0;i<Math.min(200,lines.length);i++) {
  console.log((i+1)+': '+lines[i]);
}
