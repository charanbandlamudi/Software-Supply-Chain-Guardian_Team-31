const _ = require('lodash');
const mkdirp = require('mkdirp');
mkdirp.sync('/tmp/out');
console.log(_.merge({}, { a: 1 }));
