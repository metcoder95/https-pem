'use strict'

const fs = require('node:fs')
const path = require('node:path')
const selfsigned = require('selfsigned')

const pems = selfsigned.generate()

fs.writeFileSync(path.join(__dirname, 'key.pem'), pems.private)
fs.writeFileSync(path.join(__dirname, 'cert.pem'), pems.cert)
