'use strict'

const { X509Certificate } = require('node:crypto')
const selfsigned = require('selfsigned')

// `selfsigned` derives the certificate serial number from 9 random bytes and
// runs them through its own `toPositiveHex()`, which clears the sign bit but
// does not re-minimise the resulting DER INTEGER. Roughly 1 in 65536 draws end
// up with two redundant leading zero bytes, and node-forge's encoder strips
// only one of them (see the "should all leading bytes be stripped vs just one?"
// TODO in its `asn1.js`), so the serial goes out as a positive INTEGER with
// illegal padding.
//
// node-forge's own parser accepts that encoding, so the
// `verifyCertificateChain()` check `selfsigned` runs before returning passes
// and the pair looks fine. OpenSSL rejects it, so the certificate only blows
// up later, as ERR_OSSL_ASN1_ILLEGAL_PADDING from the middle of a TLS
// handshake. That made every consumer building a server from a freshly
// generated pair intermittently fail (nodejs/undici#5245).
//
// Each serial number is drawn independently, so generating again is enough to
// get past it: three attempts bring the odds down to about 1 in 2.8e14. All of
// this can go away once `selfsigned` emits minimally encoded serial numbers.
const ATTEMPTS = 3

// Returns the error OpenSSL refused the certificate with, or `null` if it
// loads. node-forge parsing it successfully says nothing about OpenSSL.
function loadError (cert) {
  try {
    new X509Certificate(cert) // eslint-disable-line no-new
    return null
  } catch (err) {
    return err
  }
}

function unusable (cause) {
  return new Error(
    `could not generate a certificate OpenSSL can load in ${ATTEMPTS} attempts`,
    { cause }
  )
}

function generateSync (attrs, opts) {
  let lastError

  for (let i = 0; i < ATTEMPTS; i++) {
    const pems = selfsigned.generate(attrs, opts)
    const err = loadError(pems.cert)

    if (err === null) return pems

    lastError = err
  }

  throw unusable(lastError)
}

function generate (attrs, opts, done) {
  let remaining = ATTEMPTS

  selfsigned.generate(attrs, opts, function onPems (err, pems) {
    if (err) return done(err)

    const loadErr = loadError(pems.cert)

    if (loadErr === null) return done(null, pems)
    if (--remaining > 0) return selfsigned.generate(attrs, opts, onPems)

    done(unusable(loadErr))
  })
}

module.exports = { generate, generateSync }
