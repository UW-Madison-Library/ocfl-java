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

import edu.wisc.library.ocfl.api.model.VersionNum;
import edu.wisc.library.ocfl.api.util.Enforce;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;

/**
 * Helper class to make it easy to iterate over all of the content paths that should exist in a given object version
 */
class ContentPaths {

    private final Map<VersionNum, Set<String>> contentPaths;

    public ContentPaths(Collection<String> contentPaths) {
        Enforce.notNull(contentPaths, "contentPaths cannto be null");
        this.contentPaths = new HashMap<>();

        contentPaths.forEach(path -> {
            var end = path.indexOf('/');
            var version = VersionNum.fromString(path.substring(0, end));
            this.contentPaths.computeIfAbsent(version, k -> new HashSet<>()).add(path);
        });
    }

    /**
     * Returns an iterator that iterates over ever content path that should exist in the manifest of the specified
     * version
     *
     * @param versionNum the version to iterate on
     * @return the iterator
     */
    public Iterator<String> pathsForVersion(VersionNum versionNum) {
        return new Iterator<>() {
            VersionNum currentVersion = versionNum;
            Iterator<String> currentPaths = contentPaths.getOrDefault(currentVersion, Collections.emptySet()).iterator();

            @Override
            public boolean hasNext() {
                if (currentPaths.hasNext()) {
                    return true;
                } else if (currentVersion.getVersionNum() > 1) {
                    currentVersion = currentVersion.previousVersionNum();
                    currentPaths = contentPaths.getOrDefault(currentVersion, Collections.emptySet()).iterator();
                    return hasNext();
                }
                return false;
            }

            @Override
            public String next() {
                if (hasNext()) {
                    return currentPaths.next();
                }
                throw new NoSuchElementException("No more content paths");
            }
        };
    }

}
