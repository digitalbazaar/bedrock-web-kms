/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

export class Kek {
  /**
   * Creates a new instance of a key encryption key.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.id - The ID of this key.
   * @param {Object} options.signer - An API for creating digital signatures
   *   using an authentication key for a KMS service.
   * @param {Object} options.kmsService - The kmsService to use to perform key
   *   operations.
   *
   * @returns {Kek} The new Kek instance.
   */
  constructor({id, signer, kmsService}) {
    this.id = id;
    // TODO: support other algorithms
    this.algorithm = 'A256KW';
    this.signer = signer;
    this.kmsService = kmsService;
  }

  /**
   * Wraps a cryptographic key.
   *
   * @param {Object} options - The options to use.
   * @param {Uint8Array} options.key - The key material as a Uint8Array.
   *
   * @returns {Promise<string>} The base64url-encoded wrapped key bytes.
   */
  async wrap({key}) {
    const {id: kekId, kmsService, signer} = this;
    return kmsService.wrapKey({key, kekId, signer});
  }

  /**
   * Unwraps a cryptographic key.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.wrappedKey - The wrapped key material as a
   *   base64url-encoded string.
   *
   * @returns {Promise<Uint8Array>} The key bytes.
   */
  async unwrap({wrappedKey}) {
    const {id: kekId, kmsService, signer} = this;
    return kmsService.unwrapKey({wrappedKey, kekId, signer});
  }
}
