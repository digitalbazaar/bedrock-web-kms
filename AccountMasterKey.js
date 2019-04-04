/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import cryptoLd from 'crypto-ld';
const {Ed25519KeyPair} = cryptoLd;
import {Kek} from './Kek.js';
import {Hmac} from './Hmac.js';
import {SeedCache} from './SeedCache.js';

const VERSIONS = ['recommended', 'fips'];
const _seedCache = new SeedCache();

export class AccountMasterKey {
  /**
   * Creates a new instance of an AccountMasterKey. This function should never
   * be called directly. Use one of these methods to create an AccountMasterKey
   * instance.
   *
   * @example
   * AccountMasterKey.fromSecret();
   * AccountMasterKey.fromCache();
   * AccountMasterKey.fromBiometric();
   * AccountMasterKey.fromFido();
   *
   * @param {Object} options - The options to use.
   * @param {string} options.accountId - The ID of the account associated with
   *   this master key.
   * @param {Object} options.signer - An API for creating digital signatures
   *   using the master authentication key.
   * @param {Object} options.kmsService - The kmsService to use to perform
   *   key operations.
   * @param {string} options.kmsPlugin - The ID of the KMS plugin to use.
   *
   * @returns {AccountMasterKey} Key information.
   */
  constructor({accountId, signer, kmsService, kmsPlugin}) {
    this.accountId = accountId;
    this.signer = signer;
    this.kmsService = kmsService;
    this.kmsPlugin = kmsPlugin;
  }

  /**
   * Generates a key. The key can be a key encryption key (KEK) or an HMAC
   * key. It can be generated using a FIPS-compliant algorithm or the latest
   * recommended algorithm.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.type - The type of key to create (`hmac` or `kek`).
   * @param {string} [options.version=recommended] - `fips` to
   *   use FIPS-compliant ciphers, `recommended` to use the latest recommended
   *   ciphers.
   *
   * @returns {Promise<Object>} A Kek or Hmac instance.
   */
  async generateKey({type, version = 'recommended'}) {
    _assertVersion(version);

    // for the time being, fips and recommended are the same; there is no
    // other standardized key wrapping algorithm
    let Class;
    if(type === 'hmac') {
      type = 'Sha256HmacKey2019';
      Class = Hmac;
    } else if(type === 'kek') {
      type = 'AesKeyWrappingKey2019';
      Class = Kek;
    } else {
      throw new Error(`Unknown key type "${type}".`);
    }

    const {kmsService, kmsPlugin: plugin, signer} = this;
    const id = await kmsService.generateKey({plugin, type, signer});
    return new Class({id, kmsService, signer});
  }

  /**
   * Gets a KEK API for wrapping and unwrapping cryptographic keys. The key ID
   * is presumed to be scoped to the KMS service and plugin assigned
   * to this account master key instance.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.id - The ID of the KEK.
   *
   * @returns {Promise<Object>} The new Kek instance.
   */
  async getKek({id}) {
    const {kmsService, signer} = this;
    // FIXME: call kmsService.getKeyDescription()? ...get key `type`?
    return new Kek({id, kmsService, signer});
  }

  /**
   * Gets an HMAC API for signing and verifying cryptographic keys. The key ID
   * is presumed to be scoped to the KMS service and plugin assigned
   * to this account master key instance.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.id - The ID of the HMAC key.
   *
   * @returns {Promise<Object>} The new Hmac instance.
   */
  async getHmac({id}) {
    const {kmsService, signer} = this;
    // FIXME: call kmsService.getKeyDescription()? ...get key `type`?
    return new Hmac({id, kmsService, signer});
  }

  /**
   * Generates a master key from a secret.
   *
   * @param {Object} options - The options to use.
   * @param {string|Uint8Array} options.secret - The secret to use, such as a
   *   bcrypt hash.
   * @param {string} options.accountId - The ID of the account associated
   *   with this master key.
   * @param {Object} options.kmsService - The kmsService to use to
   *   perform key operations.
   * @param {string} options.kmsPlugin - The ID of the KMS plugin to use.
   * @param {boolean} [options.cache=true] - Use `true` to cache the key,
   *   `false` not to; a cached key must be cleared via `clearCache` or it will
   *   persist until the user clears their local website storage.
   *
   * @returns {Promise<AccountMasterKey>} The new AccountMasterKey instance.
   */
  static async fromSecret(
    {secret, accountId, kmsService, kmsPlugin, cache = true}) {
    if(typeof secret === 'string') {
      secret = _strToUint8Array(secret);
    } else if(!(secret instanceof Uint8Array)) {
      throw new TypeError('"secret" must be a Uint8Array or a string.');
    }

    // prefix secret and compute a SHA-256 hash as the seed for the key
    const prefix = _strToUint8Array(`bedrock-web-kms:${accountId}:`);
    const data = new Uint8Array(prefix.length + secret.length);
    data.set(prefix);
    data.set(secret, prefix.length);
    const seed = new Uint8Array(await crypto.subtle.digest('SHA-256', data));

    // cache seed if requested
    if(cache) {
      await _seedCache.set({accountId, seed});
    }

    const signer = await _signerFromSeed({seed});
    return new AccountMasterKey({accountId, signer, kmsService, kmsPlugin});
  }

  /**
   * Loads a master key from local website cache if available. This method will
   * only work if the master key for the given account has been previously
   * cached. To clear this master key to prevent future loading, call
   * `clearCache` with the account ID.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.accountId - The ID of the account associated with
   *   this master key.
   * @param {Object} options.kmsService - The kmsService to use to perform key
   *   operations.
   * @param {string} options.kmsPlugin - The ID of the KMS plugin to use.
   *
   * @returns {Promise<AccountMasterKey>} The new AccountMasterKey instance
   *   or `null` if no cached key for `accountId` could be loaded.
   */
  static async fromCache({accountId, kmsService, kmsPlugin}) {
    if(typeof localStorage === 'undefined') {
      return null;
    }

    const seed = await _seedCache.get({accountId});
    if(!seed) {
      return null;
    }

    const signer = await _signerFromSeed({seed});
    return new AccountMasterKey({accountId, signer, kmsService, kmsPlugin});
  }

  static async fromBiometric() {
    throw new Error('Not implemented.');
  }

  static async fromFido() {
    throw new Error('Not implemented.');
  }

  /**
   * Clears this key from any caches. This must be called for keys created
   * via `fromSecret` with `cache` set to `true` in order to ensure the key
   * cannot be loaded via `fromCache`.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.accountId - The ID of the account associated
   *   with this master key.
   *
   * @returns {Promise<undefined>} On completion.
   */
  static async clearCache({accountId}) {
    await _seedCache.remove({accountId});
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
  if(!VERSIONS.includes(version)) {
    throw new Error(`Unsupported version "${version}"`);
  }
}

async function _signerFromSeed({seed}) {
  // generate Ed25519 key from seed
  const keyPair = await Ed25519KeyPair.generate({seed});

  // create signer and specify ID for key using fingerprint
  const signer = keyPair.signer();
  signer.id = `urn:bedrock-web-kms:key:${keyPair.fingerprint()}`;
  return signer;
}
