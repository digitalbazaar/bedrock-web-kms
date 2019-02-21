/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import * as base64url from 'base64-universal';
import * as fipsCipher from './fipsCipher.js';
import * as recommendedCipher from './recommendedCipher.js';

const VERSIONS = ['recommended', 'fips'];

export class AccountMasterKey {
  /**
   * Creates a new instance of an AccountMasterKey. This function should never
   * be called directly. Use one of these methods to create an AccountMasterKey
   * instance:
   *
   * `AccountMasterKey.fromPassword`
   * `AccountMasterKey.fromBiometric`
   * `AccountMasterKey.fromFido`
   *
   * @param {Object} signer an API for creating digital signatures using the
   *   master authentication key.
   * @param {KmsService} kmsService the kmsService to use to perform key
   *   operations.
   * @param {String} kmsPlugin the ID of the KMS plugin to use.
   *
   * @return {AccountMasterKey}.
   */
  constructor({signer, kmsService, kmsPlugin}) {
    this.signer = signer;
    this.kmsService = kmsService;
    this.kmsPlugin = kmsPlugin;
  }

  /**
   * Generates a key. The key can be a key encryption key (KEK) or an HMAC
   * key. It can be generated using a FIPS-compliant algorithm or the latest
   * recommended algorithm.
   *
   * @param {String} type the type of key to create (`hmac` or `kek`).
   * @param {String} version `fips` to use FIPS-compliant ciphers,
   *   `recommended` to use the latest recommended ciphers.
   *
   * @return {Promise<String>} resolves to the identifier for the new key.
   */
  generateKey({type, version = 'recommended'}) {
    _assertVersion(version);

    // for the time being, fips and recommended are the same; there is no
    // other standardized key wrapping algorithm
    if(type === 'hmac') {
      type = 'HS256';
    } else if(type === 'kek') {
      type = 'AES-KW';
    } else {
      throw new Error(`Unknown key type "${type}".`);
    }

    const {kmsService, kmsPlugin: plugin, signer} = this;
    return kmsService.generateKey({plugin, type, signer});
  }

  /**
   * Encrypts some data. The data can be encrypted using a FIPS-compliant
   * cipher or the latest recommended cipher. If a wrapped content encryption
   * key (CEK) is given, it will be first unwrapped using a key encryption key
   * (KEK) identified by `kekId` via a KMS service. If a CEK is not given, a
   * random one will be generated and wrapped by the KEK.
   *
   * @param {Uint8Array|String} data the data to encrypt.
   * @param {String} kekId the ID of the wrapping key to use.
   * @param {String} wrappedCek an optional base64url-encoded CEK.
   * @param {String} version `fips` to use FIPS-compliant ciphers, `recommended`
   *   to use the latest recommended ciphers.
   *
   * @return {Promise<Object>} resolves to a JWE.
   */
  async encrypt({data, kekId, wrappedCek, version = 'recommended'}) {
    _assertVersion(version);
    data = _strToUint8Array(data);
    const {kmsService, kmsPlugin: plugin, signer} = this;

    // if a wrapped CEK was given, unwrap and reuse it, otherwise generate one
    let cek;
    if(wrappedCek) {
      if(typeof wrappedCek !== 'string') {
        throw new TypeError('"wrappedCek" must be a string.');
      }
      // unwrap CEK via KmsService
      cek = await kmsService.unwrap({plugin, wrappedKey, kekId, signer});
    } else if(version === 'fips') {
      // generate a FIPS-compliant CEK
      cek = await fipsCipher.generateKey();
    } else {
      // generate a recommended CEK
      cek = await recommendedCipher.generateKey();
    }

    if(!wrappedCek) {
      // TODO: allow key wrapping for other known keys if `ECDH-ES+A256KW` is
      // supported for asymmetric key wrap
      wrappedCek = await kmsService.wrapKey({plugin, key: cek, keyId, signer});
    }

    // create shared protected header as additional authenticated data (aad)
    const protected = base64url(JSON.stringify({enc}));
    const additionalData = _strToUint8Array(protected);

    // encrypt data
    const cipher = (version === 'fips') ? fipsCipher : recommendedCipher;
    const {enc, ciphertext, iv, tag} = cipher.encrypt(
      {data, additionalData, cek});

    // represent encrypted data as JWE
    const header = {
      // TODO: add `ECDH-ES+A256KW` support for asymmetric key wrap
      alg: 'A256KW',
      enc,
      kid: kekId
    };
    const jwe = {
      protected,
      recipients: [{
        header,
        encrypted_key: wrappedCek
      },
      iv: base64url.encode(iv),
      ciphertext: base64url.encode(ciphertext),
      tag: base64url.encode(tag)
    };
    return jwe;
  }

  /**
   * Encrypts an object. The object will be serialized to JSON and passed
   * to `encrypt`. See `encrypt` for other parameters.
   *
   * @param {Object} obj the object to encrypt.
   *
   * @return {Promise<Object>} resolves to a JWE.
   */
  async encryptObject({obj, ...rest}) {
    return this.encrypt({data: JSON.stringify(obj), ...rest});
  }

  /**
   * Decrypts a JWE. The only JWEs currently supported use an `alg` of `A256KW`
   * and `enc` of `A256GCM` or `C20P`. These parameters refer to data that has
   * been encrypted using a 256-bit AES-GCM or ChaCha20Poly1305 content
   * encryption key CEK that has been wrapped using a 256-bit AES-KW key
   * encryption key KEK.
   *
   * @param {Object} jwe the JWE to decrypt.
   * @param {String} kekId the ID of the KEK to use to decrypt.
   *
   * @return {Promise<Uint8Array>} resolves to the decrypted data.
   */
  async decrypt({jwe, kekId}) {
    if(!(jwe && typeof jwe === 'object')) {
      throw new TypeError('"jwe" must be an object.');
    }
    if(typeof jwe.protected !== 'string')) {
      throw new TypeError('"jwe.protected" is missing or not a string.');
    }

    // validate encrypted data params
    if(typeof jwe.iv !== 'string') {
      throw new Error('Invalid or missing "iv".');
    }
    if(typeof jwe.ciphertext !== 'string') {
      throw new Error('Invalid or missing "ciphertext".');
    }
    if(typeof jwe.tag !== 'string') {
      throw new Error('Invalid or missing "tag".');
    }

    // find header for kekId
    if(!Array.isArray(jwe.recipients)) {
      throw new TypeError('"jwe.recipients" must be an array.');
    }
    const {header, encrypted_key: wrappedKey} = jwe.recipients.find(
      e => e.header && e.header.kid === kekId);

    // validate header
    if(!(header && typeof header === 'object' &&
      typeof header.kid === 'string' && header.alg === 'A256KW' &&
      (header.enc === 'A256GCM' || header.enc === 'C20P'))) {
      throw new Error('Invalid or unsupported JWE header.');
    }
    if(typeof wrappedKey !== 'string') {
      throw new Error('Invalid or missing "encrypted_key".');
    }

    const {enc} = header;
    const cipher = (header.enc === 'A256GCM') ? fipsCipher : recommendedCipher;
    const {kmsService, kmsPlugin: plugin, signer} = this;

    // unwrap CEK via KmsService
    const kekId = header.kid;
    const cek = await kmsService.unwrap({plugin, wrappedKey, kekId, signer});

    const additionalData = _strToUint8Array(jwe.protected);
    return cipher.decrypt({enc, ciphertext, iv, tag, additionalData, cek});
  }

  /**
   * Decrypts a JWE that must contain an encrypted object. This method will
   * call `decrypt` and then `JSON.parse` the resulting decrypted UTF-8 data.
   *
   * @param {Object} jwe the JWE to decrypt.
   * @param {String} kekId the ID of the KEK to use to decrypt.
   *
   * @return {Promise<Object>} resolves to the decrypted object.
   */
  async decryptObject({jwe, kekId}) {
    const data = await this.decrypt({jwe});
    return JSON.parse(new TextDecoder().decode(data));
  }

  // TODO: move HMAC-based indexing to data hub and implement `fromPassword`

  /**
   * Blinds the given String or Uint8Array of data using an HMAC key that is
   * derived from the master HMAC key.
   *
   * @param data the String or Uint8Array of data to blind.
   *
   * @return a Promise that resolves to a base64url-encoded HMAC signature.
   */
  async blind({data}) {
    data = _strToUint8Array(data);
    const signature = new Uint8Array(
      await crypto.subtle.sign('HMAC', this.hmac, data));
    return base64url.encode(signature);
  }

  /**
   * Generates a the master key from a password.
   *
   * @param {String} password the password to use.
   *
   * @return {Promise<AccountMasterKey>} the new AccountMasterKey instance.
   */
  async fromPassword({password, salt}) {
    // TODO: need to handle from a bcrypt token and from a password+salt?
  }

  async fromBiometric() {
    throw new Error('Not implemented.');
  }
}

function _strToUint8Array(data) {
  if(typeof data === 'string') {
    // convert data to Uint8Array
    return new TextEncoder().encode(data);
  }
  if(!(data instanceof Uint8Array)) {
    throw new TypeError('"data" be a string or Uint8Array.');
  }
  return data;
}

function _assertVersion(version) {
  if(typeof version !== 'string') {
    throw new TypeError('"version" must be a string.');
  }
  if(!VERSIONS.contains(version)) {
    throw new Error(`Unsupported version "${version}"`);
  }
}
