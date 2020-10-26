const fs = require('fs-extra');

console.log('build.js: Removing output directory');
if (fs.existsSync('./dist')) {
  fs.removeSync('./dist', {
    recursive: true
  });
}