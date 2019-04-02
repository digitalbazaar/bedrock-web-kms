module.exports = {
  env: {
    browser: true
  },
  extends: ['digitalbazaar', 'digitalbazaar/jsdoc'],
  globals: {
    crypto: true,
    localStorage: true,
    window: true,
    TextDecoder: true,
    TextEncoder: true,
    Uint8Array: true
  }
}
