const https = require('https');

module.exports = url => new Promise((resolve, reject) => {
  https.get(url, res => { let b = ''; res.on('data', c => b += c); res.on('end', () => resolve(b)); })
    .on('error', reject);
});
