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
import edu.wisc.library.ocfl.api.exception.OcflIOException;
import edu.wisc.library.ocfl.api.model.DigestAlgorithm;
import edu.wisc.library.ocfl.api.util.Enforce;
import edu.wisc.library.ocfl.core.ObjectPaths;
import edu.wisc.library.ocfl.core.validation.model.SimpleInventory;

import java.io.IOException;
import java.security.DigestInputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

// TODO rename?
public class Validator {

    private static final DigestAlgorithm[] POSSIBLE_INV_ALGORITHMS = new DigestAlgorithm[]{
            DigestAlgorithm.sha256, DigestAlgorithm.sha512
    };

    private final Storage storage;
    private final SimpleInventoryParser inventoryParser;
    private final SimpleInventoryValidator inventoryValidator;

    public Validator(Storage storage) {
        this.storage = Enforce.notNull(storage, "storage cannot be null");
        this.inventoryParser = new SimpleInventoryParser();
        this.inventoryValidator = new SimpleInventoryValidator();
    }

    public ValidationResults validateObject(String objectRootPath, boolean contentFixityCheck) {
        var results = new ValidationResults();

        // TODO validate namaste

        var inventoryPath = ObjectPaths.inventoryPath(objectRootPath);

        if (storage.fileNotExists(inventoryPath)) {
            return results.addIssue(ValidationCode.E063,
                    "Object root inventory not found at %s", inventoryPath);
        }

        var parseResult = parseInventory(inventoryPath, results, POSSIBLE_INV_ALGORITHMS);

        if (parseResult.inventory.isPresent()) {
            var rootInventory = parseResult.inventory.get();

            results.addAll(inventoryValidator.validateInventory(rootInventory, inventoryPath));
        }

        // TODO validate side car
        // TODO validate object root contents

        // TODO if root inv not valid, return

        // TODO validate version invs
        // TODO validate version roots
        // TODO validate content -- need to verify fixity paths exist too

        // TODO optionally check fixity

        return results;
    }

    public ValidationResults validateVersion(String versionRootPath, boolean contentFixityCheck) {
        return null;
    }

    private ParseResult parseInventory(String inventoryPath,
                                       ValidationResults results,
                                       DigestAlgorithm... digestAlgorithms) {
        try (var stream = storage.readFile(inventoryPath)) {
            var wrapped = stream;
            Map<DigestAlgorithm, DigestInputStream> digestStreams = null;

            if (digestAlgorithms != null && digestAlgorithms.length > 0) {
                digestStreams = new HashMap<>(digestAlgorithms.length);

                for (var algorithm : digestAlgorithms) {
                    var digestStream = new DigestInputStream(wrapped, algorithm.getMessageDigest());
                    digestStreams.put(algorithm, digestStream);
                    wrapped = digestStream;
                }
            }

            var parseResult = inventoryParser.parse(wrapped, inventoryPath);

            results.addAll(parseResult.getValidationResults());

            var result = new ParseResult(parseResult.getInventory());

            if (digestStreams != null) {
                digestStreams.forEach((algorithm, digestStream) -> {
                    result.withDigest(algorithm, Bytes.wrap(digestStream.getMessageDigest().digest()).encodeHex());
                });
            }

            return result;
        } catch (IOException e) {
            throw new OcflIOException(e);
        }
    }

    private static class ParseResult {
        final Optional<SimpleInventory> inventory;
        final Map<DigestAlgorithm, String> digests;

        ParseResult(Optional<SimpleInventory> inventory) {
            this.inventory = inventory;
            digests = new HashMap<>();
        }

        ParseResult withDigest(DigestAlgorithm algorithm, String value) {
            digests.put(algorithm, value);
            return this;
        }
    }

}
