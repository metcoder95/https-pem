'use strict'

const https = require('node:https')
const { once } = require('node:events')
const { test } = require('node:test')

const { Agent } = require('undici')

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
