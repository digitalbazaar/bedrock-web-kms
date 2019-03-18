/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import base64url from 'base64url-universal';

const SEED_CACHE_KEY = 'bedrock-web-kms-seed-cache';

export class SeedCache {
  constructor() {}

  async set({accountId, seed}) {
    if(typeof localStorage === 'undefined') {
      return false;
    }

    const cache = this._getCache();

    try {
      cache[accountId] = base64url.encode(seed);
      return this._updateCache(cache);
    } catch(e) {}

    return false;
  }

  async get({accountId}) {
    if(typeof localStorage === 'undefined') {
      return null;
    }

    const cache = this._getCache();

    try {
      const encodedSeed = cache[accountId];
      if(encodedSeed) {
        return base64url.decode(encodedSeed);
      }
    } catch(e) {}

    return null;
  }

  async remove({accountId}) {
    if(typeof localStorage === 'undefined') {
      return false;
    }

    const cache = this._getCache();

    try {
      delete cache[accountId];
      return this._updateCache(cache);
    } catch(e) {}

    return false;
  }

  _updateCache(cache) {
    try {
      localStorage.setItem(SEED_CACHE_KEY, JSON.stringify(cache));
      return true;
    } catch(e) {}
    return false;
  }

  _getCache() {
    let cache;
    try {
      cache = JSON.parse(localStorage.getItem(SEED_CACHE_KEY)) || {};
    } catch(e) {
      cache = {};
    }
    return cache;
  }
}
