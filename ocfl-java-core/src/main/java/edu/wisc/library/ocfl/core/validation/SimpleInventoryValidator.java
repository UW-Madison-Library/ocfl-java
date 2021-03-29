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

import edu.wisc.library.ocfl.api.DigestAlgorithmRegistry;
import edu.wisc.library.ocfl.api.model.DigestAlgorithm;
import edu.wisc.library.ocfl.api.model.InventoryType;
import edu.wisc.library.ocfl.api.model.VersionNum;
import edu.wisc.library.ocfl.api.util.Enforce;
import edu.wisc.library.ocfl.core.validation.model.SimpleInventory;

import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.BitSet;
import java.util.Collections;
import java.util.Comparator;
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

    private static final Map<String, Integer> DIGEST_LENGTHS = Map.of(
            DigestAlgorithm.md5.getOcflName(), 32,
            DigestAlgorithm.sha1.getOcflName(), 40,
            DigestAlgorithm.sha256.getOcflName(), 64,
            DigestAlgorithm.sha512.getOcflName(), 128,
            DigestAlgorithm.blake2b512.getOcflName(), 128,
            DigestAlgorithm.blake2b160.getOcflName(), 40,
            DigestAlgorithm.blake2b256.getOcflName(), 64,
            DigestAlgorithm.blake2b384.getOcflName(), 96,
            DigestAlgorithm.sha512_256.getOcflName(), 64
    );

    private final BitSet lowerHexChars;

    public SimpleInventoryValidator() {
        lowerHexChars = new BitSet();
        for (int i = '0'; i <= '9'; i++) {
            lowerHexChars.set(i);
        }
        for (int i = 'a'; i <= 'f'; i++) {
            lowerHexChars.set(i);
        }
    }

    public ValidationResults validateInventory(SimpleInventory inventory,
                                                        String inventoryPath) {
        Enforce.notNull(inventory, "inventory cannot be null");
        Enforce.notNull(inventoryPath, "inventoryPath cannot be null");

        var results = new ValidationResults();

        results.addIssue(notBlank(inventory.getId(), ValidationCode.E036, "Inventory id cannot be blank in %s", inventoryPath))
                .addIssue(notNull(inventory.getType(), ValidationCode.E036, "Inventory type cannot be null in %s", inventoryPath))
                .addIssue(ifNotNull(inventory.getType(), () -> isTrue(inventory.getType().equals(InventoryType.OCFL_1_0.getId()),
                        ValidationCode.E038,
                        "Inventory type must equal '%s' in %s", InventoryType.OCFL_1_0.getId(), inventoryPath)))
                .addIssue(notNull(inventory.getDigestAlgorithm(), ValidationCode.E036, "Inventory digest algorithm cannot be null in %s", inventoryPath))
                .addIssue(ifNotNull(inventory.getDigestAlgorithm(), () -> isTrue(ALLOWED_CONTENT_DIGESTS.contains(inventory.getDigestAlgorithm()),
                        ValidationCode.E025,
                        "Inventory digest algorithm must be one of %s in %s", ALLOWED_CONTENT_DIGESTS, inventoryPath)))
                .addIssue(notNull(inventory.getHead(), ValidationCode.E036, "Inventory head cannot be null in %s", inventoryPath));

        if (inventory.getHead() != null) {
            parseAndValidateVersionNum(inventory.getHead(), inventoryPath, results);
        }

        if (inventory.getContentDirectory() != null) {
            var content = inventory.getContentDirectory();
            results.addIssue(isFalse(content.contains("/"), ValidationCode.E017,
                    "Inventory content directory cannot contain '/' in %s", inventoryPath))
                    .addIssue(isFalse(content.equals(".") || content.equals(".."), ValidationCode.E018,
                            "Inventory content directory cannot equal '.' or '..' in %s", inventoryPath));
        }

        validateInventoryVersionNumbers(inventory, inventoryPath, results);
        validateInventoryManifest(inventory, inventoryPath, results);
        validateInventoryVersions(inventory, inventoryPath, results);
        validateInventoryFixity(inventory, inventoryPath, results);

        return results;
    }

    private void validateInventoryManifest(SimpleInventory inventory, String inventoryPath, ValidationResults results) {
        if (inventory.getManifest() != null) {
            var digests = new HashSet<String>(inventory.getManifest().size());
            for (var digest : inventory.getManifest().keySet()) {
                var digestLower = digest.toLowerCase();

                if (!isDigestValidHex(digestLower, inventory.getDigestAlgorithm())) {
                    results.addIssue(ValidationCode.E096,
                            "Inventory manifest digests must be valid in %s. Found: %s", inventoryPath, digest);
                }

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
        } else {
            results.addIssue(ValidationCode.E041,
                    "Inventory manifest cannot be null in %s",
                    inventoryPath);
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
                } else {
                    results.addIssue(ValidationCode.E048,
                            "Inventory version %s must contain a created timestamp in %s",
                            versionNum, inventoryPath);
                }

                if (version.getUser() != null) {
                    var user = version.getUser();
                    results.addIssue(notBlank(user.getName(), ValidationCode.E054,
                            "Inventory version %s user name cannot be blank in %s",
                            versionNum, inventoryPath));
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
                } else {
                    results.addIssue(ValidationCode.E048,
                            "Inventory version %s must contain a state in %s",
                            versionNum, inventoryPath);
                }
            }
        } else {
            results.addIssue(ValidationCode.E043,
                    "Inventory versions cannot be null in %s",
                    inventoryPath);
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

                results.addIssue(isFalse(inconsistentPadding, ValidationCode.E013,
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
                    for (var digest : digestMap.keySet()) {
                        var digestLower = digest.toLowerCase();

                        if (!isDigestValidHex(digestLower, algorithm)) {
                            results.addIssue(ValidationCode.E057,
                                    "Inventory fixity block digests must be valid in %s. Found: %s", inventoryPath, digest);
                        }

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
                        if (i > 0) {
                            pathBuilder.append("/");
                        }
                        pathBuilder.append(part);
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

    private Optional<ValidationIssue> isFalse(boolean condition, ValidationCode code, String messageTemplate, Object... args) {
        if (condition) {
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

    private boolean isDigestValidHex(String lowerDigest, String algorithm) {
        // can't validate something we don't have info on
        if (!(algorithm == null || !DIGEST_LENGTHS.containsKey(algorithm))) {
            var length = DIGEST_LENGTHS.get(algorithm);

            if (lowerDigest.length() != length) {
                return false;
            }

            for (int i = 0; i < lowerDigest.length(); i++) {
                if (!lowerHexChars.get(lowerDigest.charAt(i))) {
                    return false;
                }
            }
        }

        return true;
    }

    private ValidationIssue createIssue(ValidationCode code, String messageTemplate, Object... args) {
        var message = messageTemplate;

        if (args != null && args.length > 0) {
            message = String.format(messageTemplate, args);
        }

        return new ValidationIssue(code, message);
    }

}
