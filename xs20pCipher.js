/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {Ed25519KeyPair} from 'crypto-ld';
// TODO: replace with forge once available?
import {secretbox} from 'tweetnacl';

export const JWE_ENC = 'XS20P';

/**
 * Generates a content encryption key (CEK). The 256-bit key is intended to be
 * used as a SecretBox (aka XSalsa20-Poly1305) key.
 *
 * @return {Promise<Uint8Array>} resolves to the generated key.
 */
export async function generateKey() {
  // generate content encryption key
  return crypto.getRandomValues(new Uint8Array(secretbox.keyLength));
}

/**
 * Encrypts some data. The data will be encrypted using the given 256-bit
 * SecretBox (aka XSalsa20-Poly1305) content encryption key (CEK).
 *
 * @param {Uint8Array} data the data to encrypt.
 * @param {Uint8Array} additionalData optional additional authentication data.
 * @param {Uint8Array} the content encryption key to use.
 *
 * @return {Promise<Object>} resolves to `{ciphertext, iv, tag}`.
 */
export async function encrypt({data, additionalData, cek}) {
  if(!(data instanceof Uint8Array)) {
    throw new TypeError('"data" must be a Uint8Array.');
  }
  if(!(cek instanceof Uint8Array)) {
    throw new TypeError('"cek" must be a Uint8Array.');
  }

  const iv = crypto.getRandomValues(new Uint8Array(secretbox.nonceLength));

  // encrypt data
  const encrypted = secretbox(data, iv, cek);

  // split ciphertext and tag
  const tagBytes = secretbox.overheadLength;
  const ciphertext = encrypted.subarray(0, encrypted.length - tagBytes);
  const tag = encrypted.subarray(encrypted.length - tagBytes);

  return {
    ciphertext,
    iv,
    tag
  };
}

/**
 * Decrypts some encrypted data. The data must have been encrypted using
 * the given SecretBox (aka XSalsa20-Poly1305) content encryption key (CEK).
 *
 * @param {Uint8Array} ciphertext the data to decrypt.
 * @param {Uint8Array} iv the initialization vector (aka nonce).
 * @param {Uint8Array} tag the authentication tag.
 * @param {Uint8Array} additionalData optional additional authentication data.
 * @param {Uint8Array} cek the content encryption key to use.
 *
 * @return {Promise<Uint8Array>} the decrypted data.
 */
export async function decrypt({ciphertext, iv, tag, additionalData, cek}) {
  if(!(iv instanceof Uint8Array)) {
    throw new Error('Invalid or missing "iv".');
  }
  if(!(ciphertext instanceof Uint8Array)) {
    throw new Error('Invalid or missing "ciphertext".');
  }
  if(!(tag instanceof Uint8Array)) {
    throw new Error('Invalid or missing "tag".');
  }
  if(!(cek instanceof Uint8Array)) {
    throw new TypeError('"cek" must be a Uint8Array.');
  }

  // decrypt `ciphertext`
  const encrypted = new Uint8Array(ciphertext.length + tag.length);
  encrypted.set(ciphertext);
  encrypted.set(tag, ciphertext.length);
  return secretbox.open(encrypted, iv, cek);
}
