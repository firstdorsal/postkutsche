#!/bin/bash
cat README_basic.md > README.md
jsdoc2md index.js >> README.md
jsdoc index.js -t ~/Documents/docdash-orange --readme ./README_basic.md
rsync -a ./out/ root@firstdorsal.eu:/opt/server/nodejs/public/doc/${PWD##*/} --delete
rm -r ./out
git commit README.md -m "🤖 makedoc";
git push