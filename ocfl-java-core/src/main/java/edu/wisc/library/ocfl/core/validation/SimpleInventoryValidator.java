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
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.wisc.library.ocfl.api.DigestAlgorithmRegistry;
import edu.wisc.library.ocfl.api.exception.OcflIOException;
import edu.wisc.library.ocfl.api.model.DigestAlgorithm;
import edu.wisc.library.ocfl.api.model.InventoryType;
import edu.wisc.library.ocfl.api.model.VersionNum;
import edu.wisc.library.ocfl.core.validation.model.SimpleInventory;

import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.regex.Pattern;

// TODO rename?
public class SimpleInventoryValidator {

    private static final Pattern VALID_VERSION = Pattern.compile("^v\\d+$");

    private static final VersionNum VERSION_ZERO = VersionNum.fromInt(0);

    private static final Set<String> ALLOWED_CONTENT_DIGESTS = Set.of(
            DigestAlgorithm.sha256.getOcflName(),
            DigestAlgorithm.sha512.getOcflName()
        );

    private final ObjectMapper objectMapper;
    private final SimpleInventoryParser inventoryParser;

    public SimpleInventoryValidator() {
        objectMapper = new ObjectMapper();
        inventoryParser = new SimpleInventoryParser();
    }

    public InventoryValidationResults validateInventory(InputStream inventoryStream,
                                                        String inventoryPath,
                                                        DigestAlgorithm... digestAlgorithms) {
        var results = new ValidationResults();

        String digest = null;

        var parseResult = parseInventory(inventoryStream,
                inventoryPath,
                results,
                digestAlgorithms);

        if (parseResult.inventory != null) {
            validateInventory(parseResult.inventory, inventoryPath, results);

            if (parseResult.inventory.getDigestAlgorithm() != null) {
                digest = parseResult.digests.get(DigestAlgorithm.fromOcflName(parseResult.inventory.getDigestAlgorithm()));
            }
        }

        return new InventoryValidationResults(parseResult.inventory, digest, results);
    }

    private void validateInventory(SimpleInventory inventory, String inventoryPath, ValidationResults results) {
        results.addIssue(ifNotNull(inventory.getId(), () -> notBlank(inventory.getId(), ValidationCode.E036,
                        "Inventory id cannot be blank in %s", inventoryPath)))
                .addIssue(ifNotNull(inventory.getType(), () -> isTrue(inventory.getType().equals(InventoryType.OCFL_1_0.getId()),
                        ValidationCode.E038,
                        "Inventory type must equal '%s' in %s", InventoryType.OCFL_1_0.getId(), inventoryPath)))
                .addIssue(ifNotNull(inventory.getDigestAlgorithm(), () -> isTrue(ALLOWED_CONTENT_DIGESTS.contains(inventory.getDigestAlgorithm()),
                        ValidationCode.E025,
                        "Inventory digest algorithm must be one of %s in %s", ALLOWED_CONTENT_DIGESTS, inventoryPath)));

        if (inventory.getHead() != null) {
            parseAndValidateVersionNum(inventory.getHead(), inventoryPath, results);
        }

        if (inventory.getContentDirectory() != null) {
            var content = inventory.getContentDirectory();
            results.addIssue(isTrue(content.contains("/"), ValidationCode.E017,
                            "Inventory content directory cannot contain '/' in %s", inventoryPath))
                    .addIssue(isTrue(content.equals(".") || content.equals(".."), ValidationCode.E018,
                            "Inventory content directory cannot equal '.' or '..' in %s", inventoryPath));
        }

        validateInventoryVersionNumbers(inventory, inventoryPath, results);
        validateInventoryManifest(inventory, inventoryPath, results);
        validateInventoryVersions(inventory, inventoryPath, results);
        validateInventoryFixity(inventory, inventoryPath, results);
    }

    private void validateInventoryManifest(SimpleInventory inventory, String inventoryPath, ValidationResults results) {
        if (inventory.getManifest() != null) {
            var digests = new HashSet<String>(inventory.getManifest().size());
            // TODO validate hex chars only
            for (var digest : inventory.getManifest().keySet()) {
                var digestLower = digest.toLowerCase();

                if (digests.contains(digestLower)) {
                    results.addIssue(ValidationCode.E096,
                            "Inventory manifest cannot contain duplicates of digest %s in %s",
                            digestLower, inventoryPath);
                } else {
                    digests.add(digestLower);
                }
            }

            validateDigestPathsMap(inventory.getManifest(),
                    path -> results.addIssue(ValidationCode.E100,
                            "Inventory manifest cannot contain content paths that begin or end with '/' in %s. Found: %s",
                            inventoryPath, path),
                    path -> results.addIssue(ValidationCode.E101,
                            "Inventory manifest content paths must be unique in %s. Found: %s",
                            inventoryPath, path),
                    path -> results.addIssue(ValidationCode.E099,
                            "Inventory manifest cannot contain blank content path parts in %s. Found: %s",
                            inventoryPath, path),
                    path -> results.addIssue(ValidationCode.E099,
                            "Inventory manifest cannot contain content path parts equal to '.' or '..' in %s. Found: %s",
                            inventoryPath, path),
                    path -> results.addIssue(ValidationCode.E101,
                            "Inventory manifest content paths must be non-conflicting in %s. Found conflicting path: %s",
                            inventoryPath, path)
                    );
        }
    }

    private void validateInventoryVersions(SimpleInventory inventory, String inventoryPath, ValidationResults results) {
        if (inventory.getVersions() != null) {
            for (var entry : inventory.getVersions().entrySet()) {
                var versionNum = entry.getKey();
                var version = entry.getValue();

                if (version.getCreated() != null) {
                    try {
                        // TODO not sure if this covers all possible formats
                        OffsetDateTime.parse(version.getCreated());
                    } catch (DateTimeParseException e) {
                        results.addIssue(ValidationCode.E049,
                                "Inventory version %s created timestamp must be formatted in accordance to RFC3339 in %s. Found: %s",
                                versionNum, inventoryPath, version.getCreated());
                    }
                }

                if (version.getState() != null) {
                    var manifest = inventory.getManifest() == null ? Collections.emptyMap() : inventory.getManifest();

                    for (var digest : version.getState().keySet()) {
                        results.addIssue(isTrue(manifest.containsKey(digest), ValidationCode.E050,
                                "Inventory version %s contains digest %s that does not exist in the manifest in %s",
                                versionNum, digest, inventoryPath));
                    }

                    validateDigestPathsMap(version.getState(),
                            path -> results.addIssue(ValidationCode.E053,
                                    "Inventory version %s cannot contain paths that begin or end with '/' in %s. Found: %s",
                                    versionNum, inventoryPath, path),
                            path -> results.addIssue(ValidationCode.E095,
                                    "Inventory version %s paths must be unique in %s. Found: %s",
                                    versionNum, inventoryPath, path),
                            path -> results.addIssue(ValidationCode.E052,
                                    "Inventory version %s cannot contain blank path parts in %s. Found: %s",
                                    versionNum, inventoryPath, path),
                            path -> results.addIssue(ValidationCode.E052,
                                    "Inventory version %s cannot contain path parts equal to '.' or '..' in %s. Found: %s",
                                    versionNum, inventoryPath, path),
                            path -> results.addIssue(ValidationCode.E095,
                                    "Inventory version %s paths must be non-conflicting in %s. Found conflicting path: %s",
                                    versionNum, inventoryPath, path)
                            );
                }
            }
        }
    }

    private void validateInventoryVersionNumbers(SimpleInventory inventory, String inventoryPath, ValidationResults results) {
        if (inventory.getVersions() != null) {
            if (inventory.getHead() != null
                    && !inventory.getVersions().containsKey(inventory.getHead())) {
                results.addIssue(ValidationCode.E044,
                        "Inventory versions is missing an entry for version %s in %s", inventory.getHead(), inventoryPath);
            }

            if (inventory.getVersions().size() > 0) {
                // TODO confirm that this works for zero-padded versions
                var versions = new TreeSet<String>(Comparator.naturalOrder());
                versions.addAll(inventory.getVersions().keySet());

                var previousVersion = VersionNum.fromInt(0);
                Integer paddingWidth = null;
                boolean inconsistentPadding = false;

                for (var actual : versions) {
                    var parsed = parseAndValidateVersionNum(actual, inventoryPath, results);

                    if (parsed.isPresent()) {
                        var currentNum = parsed.get();

                        var next = previousVersion.nextVersionNum();

                        if (next.equals(currentNum)) {
                            if (paddingWidth == null) {
                                paddingWidth = currentNum.getZeroPaddingWidth();
                            } else if (!inconsistentPadding) {
                                inconsistentPadding = paddingWidth != currentNum.getZeroPaddingWidth();
                            }
                        } else {
                            var missing = next;
                            while (!missing.equals(currentNum)) {
                                results.addIssue(ValidationCode.E044,
                                        "Inventory versions is missing an entry for version %s in %s", missing, inventoryPath);
                                missing = missing.nextVersionNum();
                            }
                        }

                        previousVersion = currentNum;
                    }
                }

                results.addIssue(isTrue(!inconsistentPadding, ValidationCode.E013,
                        "Inventory versions contain inconsistently padded version numbers in %s", inventoryPath));

                var highestVersion = versions.last();

                if (highestVersion != null && inventory.getHead() != null) {
                    results.addIssue(isTrue(highestVersion.equals(inventory.getHead()), ValidationCode.E040,
                            "Inventory head must be the highest version number in %s", inventoryPath));
                }
            } else {
                results.addIssue(ValidationCode.E008,
                        "Inventory must contain at least one version %s", inventoryPath);
            }
        }
    }

    private void validateInventoryFixity(SimpleInventory inventory, String inventoryPath, ValidationResults results) {
        if (inventory.getFixity() != null) {
            var fixity = inventory.getFixity();

            for (var entry : fixity.entrySet()) {
                var algorithm = entry.getKey();
                var digestMap = entry.getValue();

                if (DigestAlgorithmRegistry.getAlgorithm(algorithm) == null) {
                    results.addIssue(ValidationCode.E027,
                            "Inventory fixity block contains unknown algorithm %s in %s",
                            algorithm, inventoryPath);
                }

                if (digestMap != null) {
                    var digests = new HashSet<String>(digestMap.size());
                    // TODO validate hex chars only
                    for (var digest : digestMap.keySet()) {
                        var digestLower = digest.toLowerCase();

                        if (digests.contains(digestLower)) {
                            results.addIssue(ValidationCode.E097,
                                    "Inventory fixity block cannot contain duplicates of digest %s in %s",
                                    digestLower, inventoryPath);
                        } else {
                            digests.add(digestLower);
                        }
                    }

                    validateDigestPathsMap(digestMap,
                            path -> results.addIssue(ValidationCode.E100,
                                    "Inventory fixity block cannot contain content paths that begin or end with '/' in %s. Found: %s",
                                    inventoryPath, path),
                            path -> results.addIssue(ValidationCode.E101,
                                    "Inventory fixity block content paths must be unique in %s. Found: %s",
                                    inventoryPath, path),
                            path -> results.addIssue(ValidationCode.E099,
                                    "Inventory fixity block cannot contain blank content path parts in %s. Found: %s",
                                    inventoryPath, path),
                            path -> results.addIssue(ValidationCode.E099,
                                    "Inventory fixity block cannot contain content path parts equal to '.' or '..' in %s. Found: %s",
                                    inventoryPath, path),
                            path -> results.addIssue(ValidationCode.E101,
                                    "Inventory fixity block content paths must be non-conflicting in %s. Found conflicting path: %s",
                                    inventoryPath, path)
                    );
                }
            }
        }
    }

    private void validateDigestPathsMap(Map<String, List<String>> map,
                                        Consumer<String> leadingTrailingSlashes,
                                        Consumer<String> nonUnique,
                                        Consumer<String> blankPart,
                                        Consumer<String> dotPart,
                                        Consumer<String> conflicting) {
        var files = new HashSet<String>();
        var dirs = new HashSet<String>();

        for (var paths : map.values()) {
            for (var path : paths) {
                if (path.startsWith("/") || path.endsWith("/")) {
                    leadingTrailingSlashes.accept(path);
                }

                if (files.contains(path)) {
                    nonUnique.accept(path);
                } else {
                    files.add(path);
                }

                var parts = path.split("/");

                var pathBuilder = new StringBuilder();

                for (int i = 0; i < parts.length; i++) {
                    var part = parts[i];

                    if (part.isEmpty()) {
                        blankPart.accept(path);
                    } else if (part.equals(".") || part.equals("..")) {
                        dotPart.accept(path);
                    }

                    if (i < parts.length - 1) {
                        pathBuilder.append("/").append(part);
                        dirs.add(pathBuilder.toString());
                    }
                }
            }
        }

        Set<String> iter;
        Set<String> check;

        if (files.size() > dirs.size()) {
            iter = dirs;
            check = files;
        } else {
            iter = files;
            check = dirs;
        }

        iter.forEach(path -> {
            if (check.contains(path)) {
                conflicting.accept(path);
            }
        });
    }

    private Optional<VersionNum> parseAndValidateVersionNum(String num, String inventoryPath, ValidationResults results) {
        Optional<VersionNum> versionNum = Optional.empty();

        if (isInvalidVersionNum(num)) {
            // TODO this is not the right code https://github.com/OCFL/spec/issues/532
            results.addIssue(ValidationCode.E011,
                    "Inventory contains invalid version number in %s. Found: %s", inventoryPath, num);
        } else {
            var parsed = VersionNum.fromString(num);

            if (parsed.equals(VERSION_ZERO)) {
                results.addIssue(ValidationCode.E009,
                        "Inventory version numbers must be greater than 0 in %s", inventoryPath);
            } else {
                versionNum = Optional.of(parsed);
            }
        }

        return versionNum;
    }

    private ParseInventoryResult parseInventory(InputStream inventoryStream,
                                                String inventoryPath,
                                                ValidationResults results,
                                                DigestAlgorithm... digestAlgorithms) {
        try {
            var wrapped = inventoryStream;
            Map<DigestAlgorithm, DigestInputStream> digestStreams = null;

            if (digestAlgorithms != null && digestAlgorithms.length > 0) {
                digestStreams = new HashMap<>(digestAlgorithms.length);

                for (var algorithm : digestAlgorithms) {
                    var digestStream = new DigestInputStream(wrapped, algorithm.getMessageDigest());
                    digestStreams.put(algorithm, digestStream);
                    wrapped = digestStream;
                }
            }

            var jsonTree = objectMapper.readTree(wrapped);
            var parseResult = inventoryParser.parse(jsonTree, inventoryPath);
            results.addAll(parseResult.getValidationResults());

            var result = new ParseInventoryResult(parseResult.getInventory());

            if (digestStreams != null) {
                digestStreams.forEach((algorithm, digestStream) -> {
                    result.withDigest(algorithm, Bytes.wrap(digestStream.getMessageDigest().digest()).encodeHex());
                });
            }

            return result;
        } catch (JsonParseException e) {
            results.addIssue(ValidationCode.E033, "Inventory at %s is an invalid JSON document", inventoryPath);
            return new ParseInventoryResult(null);
        } catch (IOException e) {
            throw new OcflIOException(e);
        }
    }

    private Optional<ValidationIssue> notBlank(String value, ValidationCode code, String messageTemplate, Object... args) {
        if (value == null || value.isBlank()) {
            return Optional.of(createIssue(code, messageTemplate, args));
        }
        return Optional.empty();
    }

    private Optional<ValidationIssue> notNull(Object value, ValidationCode code, String messageTemplate, Object... args) {
        if (value == null) {
            return Optional.of(createIssue(code, messageTemplate, args));
        }
        return Optional.empty();
    }

    private Optional<ValidationIssue> isTrue(boolean condition, ValidationCode code, String messageTemplate, Object... args) {
        if (!condition) {
            return Optional.of(createIssue(code, messageTemplate, args));
        }
        return Optional.empty();
    }

    private boolean isInvalidVersionNum(String num) {
        return num == null || !VALID_VERSION.matcher(num).matches();
    }

    private Optional<ValidationIssue> ifNotNull(Object value, Supplier<Optional<ValidationIssue>> condition) {
        if (value != null) {
            return condition.get();
        }
        return Optional.empty();
    }

    private ValidationIssue createIssue(ValidationCode code, String messageTemplate, Object... args) {
        var message = messageTemplate;

        if (args != null && args.length > 0) {
            message = String.format(messageTemplate, args);
        }

        return new ValidationIssue(code, message);
    }

    private static class ParseInventoryResult {

        final SimpleInventory inventory;
        final Map<DigestAlgorithm, String> digests;

        ParseInventoryResult(SimpleInventory inventory) {
            this.inventory = inventory;
            digests = new HashMap<>();
        }

        ParseInventoryResult withDigest(DigestAlgorithm algorithm, String value) {
            digests.put(algorithm, value);
            return this;
        }

    }

}
