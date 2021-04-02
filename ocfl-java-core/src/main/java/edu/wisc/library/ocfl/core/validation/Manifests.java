/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 University of Wisconsin Board of Regents
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package edu.wisc.library.ocfl.core.validation;

import edu.wisc.library.ocfl.api.util.Enforce;
import edu.wisc.library.ocfl.core.validation.model.SimpleInventory;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Helper class that wrangles inventory manifests, particularly when an object contains versions that use
 * different digest algorithms
 */
class Manifests {

    private final Map<String, Map<String, String>> manifests;

    public Manifests(SimpleInventory inventory) {
        Enforce.notBlank(inventory.getDigestAlgorithm(), "digestAlgorithm cannot be blank");
        Enforce.notNull(inventory.getManifest(), "manifest cannot be null");

        this.manifests = new HashMap<>();
        this.manifests.put(inventory.getDigestAlgorithm(), inventory.getInvertedManifest());
    }

    /**
     * Adds a new inventory's manifest. The new manifest will only be added if there is not an existing manifest
     * with the same algorithm
     *
     * @param inventory the inventory containing the manifest to add
     */
    public void addManifest(SimpleInventory inventory) {
        Enforce.notBlank(inventory.getDigestAlgorithm(), "digestAlgorithm cannot be blank");
        Enforce.notNull(inventory.getManifest(), "manifest cannot be null");

        if (!manifests.containsKey(inventory.getDigestAlgorithm())) {
            this.manifests.put(inventory.getDigestAlgorithm(), inventory.getInvertedManifest());
        }
    }

    /**
     * @param digestAlgorithm the digest algorithm desired
     * @param contentPath the content path
     * @return the digest associated to the content path with the specified algorithm or null
     */
    public String getDigest(String digestAlgorithm, String contentPath) {
        return manifests.getOrDefault(digestAlgorithm, Collections.emptyMap()).get(contentPath);
    }

    /**
     * @param contentPath the content path
     * @return map of digest algorithms to digests that map to the apth
     */
    public Map<String, String> getDigests(String contentPath) {
        return manifests.entrySet().stream()
                .map(entry -> {
                    var digest = entry.getValue().get(contentPath);
                    if (digest != null) {
                        return Map.entry(entry.getKey(), digest);
                    }
                    return null;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    public boolean containsAlgorithm(String digestAlgorithm) {
        return manifests.containsKey(digestAlgorithm);
    }

    public boolean hasMultipleAlgorithms() {
        return manifests.size() > 1;
    }

}
