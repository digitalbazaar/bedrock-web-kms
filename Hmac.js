/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

export class Hmac {
  /**
   * Creates a new instance of an HMAC.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.id - The ID of the hmac key.
   * @param {Object} options.signer - An API for creating digital signatures
   *   using an authentication key for a KMS service.
   * @param {Object} options.kmsService - The kmsService to use to
   *   perform key operations.
   *
   * @returns {Hmac} The new Hmac instance.
   */
  constructor({id, signer, kmsService}) {
    this.id = id;
    // TODO: support other algorithms
    this.algorithm = 'HS256';
    this.signer = signer;
    this.kmsService = kmsService;
  }

  /**
   * Signs some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {Object} options - The options to use.
   * @param {Uint8Array} options.data - The data to sign as a Uint8Array.
   *
   * @returns {Promise<string>} The base64url-encoded signature.
   */
  async sign({data}) {
    const {id: keyId, kmsService, signer} = this;
    return kmsService.sign({keyId, data, signer});
  }

  /**
   * Verifies some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {Object} options - The options to use.
   * @param {Uint8Array} options.data - The data to sign as a Uint8Array.
   * @param {string} options.signature - The base64url-encoded signature
   *   to verify.
   *
   * @returns {Promise<boolean>} `true` if verified, `false` if not.
   */
  async verify({data, signature}) {
    const {id: keyId, kmsService, signer} = this;
    return kmsService.verify({keyId, data, signature, signer});
  }
}
