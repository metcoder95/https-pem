'use strict'

const path = require('node:path')
const fs = require('node:fs')

let selfsigned
const keyPath = path.join(__dirname, 'key.pem')
const certPath = path.join(__dirname, 'cert.pem')

// In case npm scripts are disabled, we still want to provide the key and cert
exports.key = fs.existsSync(keyPath) ? fs.readFileSync(keyPath) : null
exports.cert = fs.existsSync(certPath) ? fs.readFileSync(certPath) : null
exports.generate = generate
exports.default = exports

function generate ({ attr, opts } = { attr: [], opts: null }, done) {
  if (done == null) {
    const promise = new Promise((resolve, reject) => {
      generate({ attr, opts }, (err, pems) => {
        if (err) return reject(err)
        resolve({ key: pems.private, cert: pems.cert })
      })
    })

    return promise
  }

  if (!selfsigned) selfsigned = require('selfsigned')

  selfsigned.generate(attr, opts, done)
}
