/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';
import base64url from 'base64url-universal';
import {CapabilityInvocation} from 'ocapld';
import jsigs from 'jsonld-signatures';
import uuid from 'uuid-random';

const {SECURITY_CONTEXT_V2_URL, sign, suites} = jsigs;
const {Ed25519Signature2018} = suites;

export class KmsService {
  constructor({
    urls = {
      base: '/kms'
    }
  } = {}) {
    this.config = {urls};
  }

  /**
   * Generates a new cryptographic key.
   *
   * @param {String} plugin the KMS plugin to use.
   * @param {String} type the key type (e.g. 'AesKeyWrappingKey2019').
   * @param {Object} an API with an `id` property and a `sign` function for
   *   authentication purposes.
   *
   * @return {Promise<String>} the ID for the key.
   */
  async generateKey({plugin, type, signer}) {
    _assert(plugin, 'plugin', 'string');
    _assert(type, 'type', 'string');
    _assert(signer, 'signer', 'object');
    const baseUrl = `${window.location.origin}${this.config.urls.base}`;
    const id = `${baseUrl}/${plugin}/${uuid()}`;

    const {id: newId} = await this._postOperation({
      url: id,
      operation: {
        type: 'GenerateKeyOperation',
        invocationTarget: {id, type, controller: signer.id}
      },
      signer
    });
    return newId;
  }

  /**
   * Wraps a cryptographic key using a key encryption key (KEK).
   *
   * @param {Uint8Array} key the key material as a Uint8Array.
   * @param {String} kekId the ID of the wrapping key to use.
   * @param {Object} an API with a `sign` function for authentication purposes.
   *
   * @return {Promise<String>} the base64url-encoded wrapped key bytes.
   */
  async wrapKey({key, kekId, signer}) {
    _assert(key, 'key', 'Uint8Array');
    _assert(kekId, 'kekId', 'string');
    _assert(signer, 'signer', 'object');
    const unwrappedKey = base64url.encode(key);
    const {wrappedKey} = await this._postOperation({
      url: kekId,
      operation: {
        type: 'WrapKeyOperation',
        invocationTarget: kekId,
        unwrappedKey
      },
      signer
    });
    return wrappedKey;
  }

  /**
   * Unwraps a cryptographic key using a key encryption key (KEK).
   *
   * @param {String} wrappedKey the wrapped key material as a base64url-encoded
   *   string.
   * @param {String} kekId the ID of the unwrapping key to use.
   * @param {Object} an API with a `sign` function for authentication purposes.
   *
   * @return {Promise<Uint8Array>} the key bytes.
   */
  async unwrapKey({wrappedKey, kekId, signer}) {
    _assert(wrappedKey, 'wrappedKey', 'string');
    _assert(kekId, 'kekId', 'string');
    _assert(signer, 'signer', 'object');
    const {unwrappedKey} = await this._postOperation({
      url: kekId,
      operation: {
        type: 'UnwrapKeyOperation',
        invocationTarget: kekId,
        wrappedKey
      },
      signer
    });
    return base64url.decode(unwrappedKey);
  }

  /**
   * Signs some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {String} keyId the ID of the signing key to use.
   * @param {Uint8Array} data the data to sign as a Uint8Array.
   * @param {Object} an API with a `sign` function for authentication purposes;
   *   this is not used to sign the data itself.
   *
   * @return {Promise<String>} the base64url-encoded signature.
   */
  async sign({keyId, data, signer}) {
    _assert(keyId, 'keyId', 'string');
    _assert(data, 'data', 'Uint8Array');
    _assert(signer, 'signer', 'object');
    data = base64url.encode(data);
    const {signatureValue} = await this._postOperation({
      url: keyId,
      operation: {
        type: 'SignOperation',
        invocationTarget: keyId,
        verifyData: data
      },
      signer
    });
    return signatureValue;
  }

  /**
   * Verifies some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {String} keyId the ID of the signing key to use.
   * @param {Uint8Array} data the data to sign as a Uint8Array.
   * @param {String} signature the base64url-encoded signature to verify.
   * @param {Object} an API with a `sign` function for authentication purposes.
   *
   * @return {Promise<Boolean>} `true` if verified, `false` if not.
   */
  async verify({keyId, data, signature, signer}) {
    _assert(keyId, 'keyId', 'string');
    _assert(data, 'data', 'Uint8Array');
    _assert(signature, 'signature', 'string');
    _assert(signer, 'signer', 'object');
    const verifyData = base64url.encode(data);
    const {verified} = await this._postOperation({
      url: keyId,
      operation: {
        type: 'VerifyOperation',
        invocationTarget: keyId,
        verifyData,
        signatureValue: signature
      },
      signer
    });
    return verified;
  }

  /**
   * Posts an operation to the KMS service.
   *
   * @param {String} url the URL to post to (i.e. the key identifier).
   * @param {Object} operation the operation to run.
   * @param {Object} an API with a `sign` function for authentication purposes.
   *
   * @return {Promise<Any>} resolves to the result of the operation.
   */
  async _postOperation({url, operation, signer}) {
    // TODO: ensure `signer` uses an Ed25519 key

    // attach capability invocation to operation
    operation = {'@context': SECURITY_CONTEXT_V2_URL, ...operation};
    const data = await sign(operation, {
      suite: new Ed25519Signature2018({
        signer,
        verificationMethod: signer.id
      }),
      purpose: new CapabilityInvocation({capability: url})
    });

    // send operation
    const response = await axios({
      url,
      method: 'POST',
      data
    });
    return response.data;
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
