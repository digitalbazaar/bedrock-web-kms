/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

export class Kek {
  /**
   * Creates a new instance of a key encryption key.
   *
   * @param {String} id the ID of this key.
   * @param {Object} signer an API for creating digital signatures using an
   *   authentication key for a KMS service.
   * @param {KmsService} kmsService the kmsService to use to perform key
   *   operations.
   * @param {String} kmsPlugin the ID of the KMS plugin to use.
   *
   * @return {Kek}.
   */
  constructor({id, signer, kmsService, kmsPlugin}) {
    this.id = id;
    // TODO: support other algorithms
    this.algorithm = 'A256KW';
    this.signer = signer;
    this.kmsService = kmsService;
    this.kmsPlugin = kmsPlugin;
  }

  /**
   * Wraps a cryptographic key.
   *
   * @param {Uint8Array} key the key material as a Uint8Array.
   *
   * @return {Promise<String>} the base64url-encoded wrapped key bytes.
   */
  async wrap({key}) {
    const {id: kekId, kmsService, kmsPlugin: plugin, signer} = this;
    return kmsService.wrapKey({plugin, key, kekId, signer});
  }

  /**
   * Unwraps a cryptographic key.
   *
   * @param {String} wrappedKey the wrapped key material as a base64url-encoded
   *   string.
   *
   * @return {Promise<Uint8Array>} the key bytes.
   */
  async unwrap({wrappedKey}) {
    const {id: kekId, kmsService, kmsPlugin: plugin, signer} = this;
    return kmsService.unwrapKey({plugin, wrappedKey, kekId, signer});
  }
}
