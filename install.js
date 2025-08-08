'use strict'

const fs = require('node:fs')
const path = require('node:path')
const selfsigned = require('selfsigned')

const nodeVersion = Number(process.versions.node.split('.')[0])
const pems =
  // Due to new version of openssl, we need to use a larger key size
  // for node 24 and above, otherwise the default key size is sufficient
  nodeVersion > 22
    ? selfsigned.generate({}, { keySize: 2048 })
    : selfsigned.generate()

fs.writeFileSync(path.join(__dirname, 'key.pem'), pems.private)
fs.writeFileSync(path.join(__dirname, 'cert.pem'), pems.cert)
