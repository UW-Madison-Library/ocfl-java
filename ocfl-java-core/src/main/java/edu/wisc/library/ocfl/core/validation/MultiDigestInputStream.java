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

import at.favre.lib.bytes.Bytes;
import edu.wisc.library.ocfl.api.model.DigestAlgorithm;
import edu.wisc.library.ocfl.api.util.Enforce;

import java.io.FilterInputStream;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

// TODO
public class MultiDigestInputStream extends FilterInputStream {

    private final Map<DigestAlgorithm, DigestInputStream> streamMap;

    public static MultiDigestInputStream create(InputStream inputStream,
                                                Collection<DigestAlgorithm> digestAlgorithms) {
        Enforce.notNull(inputStream, "inputStream cannot be null");
        Enforce.notNull(digestAlgorithms, "digestAlgorithms cannot be null");

        var streamMap = new HashMap<DigestAlgorithm, DigestInputStream>();
        var wrapped = inputStream;

        for (var algorithm : digestAlgorithms) {
            var digestStream = new DigestInputStream(wrapped, algorithm.getMessageDigest());
            wrapped = digestStream;
            streamMap.put(algorithm, digestStream);
        }

        return new MultiDigestInputStream(wrapped, streamMap);
    }

    private MultiDigestInputStream(InputStream stream, Map<DigestAlgorithm, DigestInputStream> streamMap) {
        super(stream);
        this.streamMap = streamMap;
    }

    public Map<DigestAlgorithm, String> getResults() {
        var results = new HashMap<DigestAlgorithm, String>();

        streamMap.forEach((algorithm, stream) -> {
            results.put(algorithm, Bytes.wrap(stream.getMessageDigest().digest()).encodeHex());
        });

        return results;
    }

}
