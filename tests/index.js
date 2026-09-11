'use strict'

const https = require('node:https')
const { once } = require('node:events')
const { test } = require('node:test')
const { X509Certificate } = require('node:crypto')

const { Agent } = require('undici')
const selfsigned = require('selfsigned')
const forge = require('node-forge')

const client = new Agent({
  connect: {
    rejectUnauthorized: false
  }
})

test('https-pem (default)', async t => {
  const pem = require('..')
  const server = https.createServer(pem, function (req, res) {
    res.end('foo')
  })

  server.listen()
  await once(server, 'listening')
  t.after(() => server.close())

  const response = await client.request({
    origin: `https://localhost:${server.address().port}`,
    path: '/',
    method: 'GET'
  })

  t.plan(2)
  t.assert.strictEqual(response.statusCode, 200)
  t.assert.strictEqual(await response.body.text(), 'foo')
})

test('https-pem (generate)', async t => {
  const pem = require('..')
  const pems = await pem.generate({
    attr: [{ name: 'commonName', value: 'localhost' }],
    opts: { keySize: 5120 }
  })

  const server = https.createServer(pems, function (req, res) {
    res.end('foo')
  })

  server.listen()
  await once(server, 'listening')
  t.after(() => server.close())

  const response = await client.request({
    origin: `https://localhost:${server.address().port}`,
    path: '/',
    method: 'GET'
  })

  t.plan(2)
  t.assert.strictEqual(response.statusCode, 200)
  t.assert.strictEqual(await response.body.text(), 'foo')
})

// `selfsigned` clears the sign bit of the 9 random bytes it draws for the
// serial number without re-minimising the DER INTEGER, and node-forge strips
// only one of the redundant leading zero bytes. These 9 bytes are one of the
// roughly 1 in 65536 draws that come out as `00 00 01 ...` and leave a
// positive INTEGER with illegal padding, which OpenSSL refuses to load.
const ILLEGAL_PADDING_SEED = '\x80\x00\x01\x02\x03\x04\x05\x06\x07'

// Turns the next `attempts` serial numbers into the pathological one above.
// Returns a getter for how many of them were actually drawn, so a test can
// tell whether it exercised the bad path at all.
function forceIllegalSerialNumber (t, attempts = 1) {
  const getBytesSync = forge.random.getBytesSync
  let remaining = attempts

  forge.random.getBytesSync = function (count) {
    // 9 bytes are only ever drawn for the serial number
    if (count === 9 && remaining > 0) {
      remaining--
      return ILLEGAL_PADDING_SEED
    }

    return getBytesSync.call(this, count)
  }
  t.after(() => { forge.random.getBytesSync = getBytesSync })

  return () => attempts - remaining
}

test('selfsigned on its own produces a certificate OpenSSL rejects', async t => {
  const drawn = forceIllegalSerialNumber(t)

  const { cert } = await new Promise((resolve, reject) => {
    selfsigned.generate(undefined, { keySize: 1024 }, (err, pems) => {
      if (err) return reject(err)
      resolve(pems)
    })
  })
  t.assert.strictEqual(drawn(), 1, 'the serial number seed was not drawn')

  let err
  try {
    new X509Certificate(cert) // eslint-disable-line no-new
  } catch (e) {
    err = e
  }

  if (err === undefined) {
    // Nothing left to work around: `generate.js` can go away and `index.js`
    // can call `selfsigned.generate()` directly again.
    t.diagnostic('selfsigned no longer emits non-minimal serial numbers')
    return
  }

  t.assert.strictEqual(err.code, 'ERR_OSSL_ASN1_ILLEGAL_PADDING')
})

test('https-pem (generate) draws a new serial number when OpenSSL rejects one', async t => {
  const pem = require('..')
  const drawn = forceIllegalSerialNumber(t)

  const { key, cert } = await pem.generate({ opts: { keySize: 1024 } })
  t.assert.strictEqual(drawn(), 1, 'the serial number seed was not drawn')

  t.assert.ok(key)
  // A minimally encoded positive INTEGER never starts with a zero byte
  const parsed = new X509Certificate(cert)
  t.assert.doesNotMatch(parsed.serialNumber, /^00/)
})

test('https-pem (generate) survives consecutive rejected serial numbers', async t => {
  const pem = require('..')
  const drawn = forceIllegalSerialNumber(t, 2)

  const { cert } = await pem.generate({ opts: { keySize: 1024 } })
  t.assert.strictEqual(drawn(), 2, 'not every serial number seed was drawn')

  new X509Certificate(cert) // eslint-disable-line no-new
})

test('https-pem (generate) gives up instead of returning an unusable pair', async t => {
  const pem = require('..')
  forceIllegalSerialNumber(t, Infinity)

  await t.assert.rejects(
    pem.generate({ opts: { keySize: 1024 } }),
    err => {
      t.assert.match(err.message, /could not generate a certificate OpenSSL can load/)
      t.assert.strictEqual(err.cause.code, 'ERR_OSSL_ASN1_ILLEGAL_PADDING')
      return true
    }
  )
})

test('https-pem (default) ships a certificate OpenSSL can load', t => {
  const pem = require('..')

  t.assert.ok(pem.key)
  const cert = new X509Certificate(pem.cert)
  t.assert.doesNotMatch(cert.serialNumber, /^00/)
})

test('https-pem (generate) serves over TLS past a rejected serial number', async t => {
  const pem = require('..')
  forceIllegalSerialNumber(t)

  const pems = await pem.generate({
    attr: [{ name: 'commonName', value: 'localhost' }],
    opts: { keySize: 2048 }
  })

  const server = https.createServer(pems, function (req, res) {
    res.end('foo')
  })

  server.listen()
  await once(server, 'listening')
  t.after(() => server.close())

  const response = await client.request({
    origin: `https://localhost:${server.address().port}`,
    path: '/',
    method: 'GET'
  })

  t.plan(2)
  t.assert.strictEqual(response.statusCode, 200)
  t.assert.strictEqual(await response.body.text(), 'foo')
})
