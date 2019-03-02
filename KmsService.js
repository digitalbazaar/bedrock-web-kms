/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';
import * as base64url from 'base64url-universal';
import {createAuthzHeader, createSignatureString} from 'http-signature-header';

export class KmsService {
  constructor({
    urls = {
      base: '/kms',
      operations: '/kms/operations'
    }
  } = {}) {
    this.config = {urls};
  }

  /**
   * Generates a new cryptographic key.
   *
   * @param {String} plugin the KMS plugin to use.
   * @param {String} type the key type (e.g. 'AES-KW', 'HS256').
   * @param {String} id an identifier to use for the key.
   * @param {Object} an API with an `id` property and a `sign` function for
   *   authentication purposes.
   *
   * @return {Promise<String>} the ID for the key.
   */
  async generateKey({plugin, type, id, signer}) {
    _assert(plugin, 'plugin', 'string');
    _assert(type, 'type', 'string');
    _assert(id, 'id', 'string');
    _assert(signer, 'signer', 'object');
    return this._postOperation({
      method: 'generateKey',
      parameters: {type, id},
      plugin,
      signer
    });
  }

  /**
   * Wraps a cryptographic key using a key encryption key (KEK).
   *
   * @param {String} plugin the KMS plugin to use.
   * @param {Uint8Array|String} key the key material as a Uint8Array
   *   or a base64url-encoded string.
   * @param {String} kekId the ID of the wrapping key to use.
   * @param {Object} an API with a `sign` function for authentication purposes.
   *
   * @return {Promise<String>} the base64url-encoded wrapped key bytes.
   */
  async wrapKey({plugin, key, kekId, signer}) {
    _assert(plugin, 'plugin', 'string');
    _assert(key, 'key', ['Uint8Array', 'string']);
    _assert(kekId, 'kekId', 'string');
    _assert(signer, 'signer', 'object');
    if(key instanceof Uint8Array) {
      key = base64url.encode(key);
    }
    return this._postOperation({
      method: 'wrapKey',
      parameters: {encodedKey: key, kekId},
      plugin,
      signer
    });
  }

  /**
   * Unwraps a cryptographic key using a key encryption key (KEK).
   *
   * @param {String} plugin the KMS plugin to use.
   * @param {String} wrappedKey the wrapped key material as a base64url-encoded
   *   string.
   * @param {String} kekId the ID of the unwrapping key to use.
   * @param {Object} an API with a `sign` function for authentication purposes.
   *
   * @return {Promise<String>} the base64url-encoded wrapped key bytes.
   */
  async unwrapKey({plugin, wrappedKey, kekId, signer}) {
    _assert(plugin, 'plugin', 'string');
    _assert(wrappedKey, 'wrappedKey', 'string');
    _assert(kekId, 'kekId', 'string');
    _assert(signer, 'signer', 'object');
    return this._postOperation({
      method: 'unwrapKey',
      parameters: {wrappedKey, kekId},
      plugin,
      signer
    });
  }

  /**
   * Signs some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {String} plugin the KMS plugin to use.
   * @param {String} keyId the ID of the signing key to use.
   * @param {Uint8Array|String} data the data to sign as a Uint8Array
   *   or a base64url-encoded string.
   * @param {Object} an API with a `sign` function for authentication purposes;
   *   this is not used to sign the data itself.
   *
   * @return {Promise<String>} the base64url-encoded signature.
   */
  async sign({plugin, keyId, data, signer}) {
    _assert(plugin, 'plugin', 'string');
    _assert(keyId, 'keyId', 'string');
    _assert(data, 'data', ['Uint8Array', 'string']);
    _assert(signer, 'signer', 'object');
    if(data instanceof Uint8Array) {
      data = base64url.encode(data);
    }
    return this._postOperation({
      method: 'sign',
      parameters: {keyId, data},
      plugin,
      signer
    });
  }

  /**
   * Verifies some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {String} plugin the KMS plugin to use.
   * @param {String} keyId the ID of the signing key to use.
   * @param {Uint8Array|String} data the data to sign as a Uint8Array
   *   or a base64url-encoded string.
   * @param {String} signature the base64url-encoded signature to verify.
   * @param {Object} an API with a `sign` function for authentication purposes.
   *
   * @return {Promise<Boolean>} `true` if verified, `false` if not.
   */
  async verify({plugin, keyId, data, signature, signer}) {
    _assert(plugin, 'plugin', 'string');
    _assert(keyId, 'keyId', 'string');
    _assert(data, 'data', ['Uint8Array', 'string']);
    _assert(signature, 'signature', 'string');
    _assert(signer, 'signer', 'object');
    if(data instanceof Uint8Array) {
      data = base64url.encode(data);
    }
    return this._postOperation({
      method: 'verify',
      parameters: {keyId, data, signature},
      plugin,
      signer
    });
  }

  /**
   * Posts an operation to the KMS service.
   *
   * @param {String} method the method to run (e.g. `generateKey`, `wrapKey`).
   * @param {Object} parameters the parameter for the method.
   * @param {String} plugin the KMS plugin to use.
   * @param {Object} an API with a `sign` function for authentication purposes.
   *
   * @return {Promise<Boolean>} true on success, false on failure.
   */
  async _postOperation({method, parameters, plugin, signer}) {
    const response = await this._signedAxios({
      url: this.config.urls.operations,
      method: 'POST',
      data: {
        method,
        parameters,
        plugin
      },
      signer
    });
    return response.data;
  }

  async _signedAxios({signer, ...requestOptions}) {
    if(!('headers' in requestOptions)) {
      requestOptions.headers = {};
    }
    if(requestOptions.url.startsWith('/')) {
      requestOptions.url = `${window.location.origin}${requestOptions.url}`;
    }
    requestOptions.headers.host = new URL(requestOptions.url).host;
    await this._signHttp({signer, requestOptions});
    return axios(requestOptions);
  }

  async _signHttp({signer, requestOptions}) {
    // set expiration 10 minutes into the future
    const expires = new Date(Date.now() + 600000).toUTCString();
    requestOptions.headers.Expires = expires;

    // sign header
    const includeHeaders = ['expires', 'host', '(request-target)'];
    const plaintext = createSignatureString({includeHeaders, requestOptions});
    const data = new TextEncoder().encode(plaintext);
    const signature = base64url.encode(await signer.sign({data}));

    const authzHeader = createAuthzHeader({
      includeHeaders,
      keyId: signer.id,
      signature
    });

    requestOptions.headers.Authorization = authzHeader;
  }
}

async function _assert(variable, name, types) {
  if(!Array.isArray(types)) {
    types = [types];
  }
  const type = variable instanceof Uint8Array ? 'Uint8Array' : typeof variable;
  if(!types.includes(type)) {
    throw new TypeError(
      `"${name}" must be ${types.length > 1 ? 'a' : 'one of'} ` +
      `${types.join(', ')}.`);
  }
}
