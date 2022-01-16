/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.syncope.core.provisioning.java.cache;

import org.apache.syncope.core.provisioning.api.cache.VirAttrCache;
import org.apache.syncope.core.provisioning.api.cache.VirAttrCacheKey;
import org.apache.syncope.core.provisioning.api.cache.VirAttrCacheValue;

/**
 * Empty virtual attribute value cache implementation.
 */
public class DisabledVirAttrCache implements VirAttrCache {

    @Override
    public void setCacheSpec(final String cacheSpec) {
        // nothing to do
    }

    @Override
    public void expire(final VirAttrCacheKey key) {
        // nothing to do
    }

    @Override
    public VirAttrCacheValue get(final VirAttrCacheKey key) {
        return null;
    }

    @Override
    public VirAttrCacheValue put(final VirAttrCacheKey key, final VirAttrCacheValue value) {
        return value;
    }
}
