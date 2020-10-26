const fs = require('fs-extra');

let path = './dist/test'
console.log(`Removing ${path}`);
fs.rmdirSync(path, { recursive: true });

path = './package.json';
let to = './dist/package.json';
console.log(`Copying: ${path} to ${to}`)
fs.copyFileSync(path, to);

path = './README.md';
to = './dist/README.md';
console.log(`Copying: ${path} to ${to}`)
fs.copyFileSync(path, to);

fs.copySync('./dist/src', './dist');

fs.rmdirSync('./dist/src', { recursive: true });
