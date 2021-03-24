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
import edu.wisc.library.ocfl.api.DigestAlgorithmRegistry;
import edu.wisc.library.ocfl.api.OcflConstants;
import edu.wisc.library.ocfl.api.exception.OcflIOException;
import edu.wisc.library.ocfl.api.model.DigestAlgorithm;
import edu.wisc.library.ocfl.api.model.VersionNum;
import edu.wisc.library.ocfl.api.util.Enforce;
import edu.wisc.library.ocfl.core.ObjectPaths;
import edu.wisc.library.ocfl.core.util.FileUtil;
import edu.wisc.library.ocfl.core.validation.model.SimpleInventory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

// TODO rename?
public class Validator {

    private static final Logger LOG = LoggerFactory.getLogger(Validator.class);

    private static final DigestAlgorithm[] POSSIBLE_INV_ALGORITHMS = new DigestAlgorithm[]{
            DigestAlgorithm.sha256, DigestAlgorithm.sha512
    };

    private static final String OBJECT_NAMASTE_CONTENTS = OcflConstants.OBJECT_NAMASTE_1_0 + "\n";

    private static final Set<String> OBJECT_ROOT_FILES = Set.of(
            OcflConstants.OBJECT_NAMASTE_1_0,
            OcflConstants.INVENTORY_FILE
    );

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

        // TODO this is only true for OCFL 1.0
        var namasteFile = ObjectPaths.objectNamastePath(objectRootPath);
        validateNamaste(namasteFile, results);

        var inventoryPath = ObjectPaths.inventoryPath(objectRootPath);

        if (storage.fileExists(inventoryPath)) {
            var parseResult = parseInventory(inventoryPath, results, POSSIBLE_INV_ALGORITHMS);
            parseResult.inventory.ifPresent(inventory ->
                    validateObjectWithInventory(objectRootPath, inventoryPath, inventory,
                            parseResult.digests, parseResult.isValid, contentFixityCheck, results));
        } else {
            results.addIssue(ValidationCode.E063,
                    "Object root inventory not found at %s", inventoryPath);
        }

        return results;
    }

    private void validateObjectWithInventory(String objectRootPath,
                                             String inventoryPath,
                                             SimpleInventory rootInventory,
                                             Map<DigestAlgorithm, String> inventoryDigests,
                                             boolean inventoryIsValid,
                                             boolean contentFixityCheck,
                                             ValidationResults results) {
        var ignoreFiles = new HashSet<>(OBJECT_ROOT_FILES);

        var validationResults = inventoryValidator.validateInventory(rootInventory, inventoryPath);
        results.addAll(validationResults);

        validateSidecar(inventoryPath, rootInventory, inventoryDigests, results)
                .ifPresent(ignoreFiles::add);

        var seenVersions = validateObjectRootContents(objectRootPath, ignoreFiles, rootInventory, results);

        if (inventoryIsValid && !validationResults.hasErrors()) {
            rootInventory.getVersions().keySet().stream()
                    .filter(version -> !seenVersions.contains(version))
                    .forEach(version -> results.addIssue(ValidationCode.E010,
                                "Object root at %s is missing version directory %s", objectRootPath, version));

            var rootDigest = inventoryDigests.get(DigestAlgorithmRegistry.getAlgorithm(rootInventory.getDigestAlgorithm()));

            rootInventory.getVersions().keySet().forEach(versionStr -> {
                if (Objects.equals(rootInventory.getHead(), versionStr)) {
                    validateHeadVersion(objectRootPath, rootInventory, rootDigest, results);
                } else {
                    validateVersion(objectRootPath, versionStr, rootInventory, results);
                }
            });

            validateContentFiles(objectRootPath, rootInventory, results);

            if (contentFixityCheck) {
                fixityCheck(objectRootPath, rootInventory, results);
            }
        } else {
            LOG.debug("Skipping further validation of the object at {} because its inventory is invalid", objectRootPath);
        }
    }

    private void validateVersion(String objectRootPath,
                                 String versionStr,
                                 SimpleInventory rootInventory,
                                 ValidationResults results) {
        var versionPath = FileUtil.pathJoinFailEmpty(objectRootPath, versionStr);
        var inventoryPath = ObjectPaths.inventoryPath(versionPath);
        var contentDir = defaultedContentDir(rootInventory);

        var ignoreFiles = new HashSet<String>();
        ignoreFiles.add(contentDir);

        if (storage.fileExists(inventoryPath)) {
            ignoreFiles.add(OcflConstants.INVENTORY_FILE);

            var parseResult = parseInventory(inventoryPath, results, POSSIBLE_INV_ALGORITHMS);
            parseResult.inventory.ifPresent(inventory -> {
                var validationResults = inventoryValidator.validateInventory(inventory, inventoryPath);
                results.addAll(validationResults);

                validateSidecar(inventoryPath, inventory, parseResult.digests, results)
                        .ifPresent(ignoreFiles::add);

                // TODO suspect code
                results.addIssue(areEqual(rootInventory.getId(), inventory.getId(), ValidationCode.E037,
                        "Inventory ID is inconsistent between versions in %s", inventoryPath))
                        // TODO suspect code
                        .addIssue(areEqual(versionStr, inventory.getHead(), ValidationCode.E040,
                                "Inventory head must be %s in %s", versionStr, inventoryPath))
                        .addIssue(areEqual(contentDir, defaultedContentDir(inventory), ValidationCode.E019,
                                "Inventory content directory is inconsistent between versions in %s", inventoryPath));

                if (parseResult.isValid && !validationResults.hasErrors()) {
                    if (Objects.equals(rootInventory.getDigestAlgorithm(), inventory.getDigestAlgorithm())) {
                        validateVersionState(versionStr, rootInventory, inventory, inventoryPath, results);
                    } else {
                        // TODO the digest changed -- requires special handling
                    }
                }
            });
        } else {
            // TODO should be a warning if it does not exist
        }

        validateVersionDirContents(objectRootPath, versionStr, objectRootPath, ignoreFiles, results);
    }

    private void validateHeadVersion(String objectRootPath,
                                     SimpleInventory rootInventory,
                                     String rootDigest,
                                     ValidationResults results) {
        var versionStr = rootInventory.getHead();
        var versionPath = FileUtil.pathJoinFailEmpty(objectRootPath, versionStr);
        var inventoryPath = ObjectPaths.inventoryPath(versionPath);
        var contentDir = defaultedContentDir(rootInventory);

        var ignoreFiles = new HashSet<String>();
        ignoreFiles.add(contentDir);

        if (storage.fileExists(inventoryPath)) {
            ignoreFiles.add(OcflConstants.INVENTORY_FILE);
            ignoreFiles.add(OcflConstants.INVENTORY_SIDECAR_PREFIX + rootInventory.getDigestAlgorithm());

            var sidecarPath = inventoryPath + "." + rootInventory.getDigestAlgorithm();
            var actualDigest = validateInventorySidecar(sidecarPath,
                    DigestAlgorithmRegistry.getAlgorithm(rootInventory.getDigestAlgorithm()),
                    rootDigest, results);

            if (!rootDigest.equalsIgnoreCase(actualDigest)) {
                results.addIssue(ValidationCode.E064,
                        "The inventory at %s must be identical to the inventory in the object root", inventoryPath);
            }
        } else {
            // TODO should be a warning if it does not exist
        }

        validateVersionDirContents(objectRootPath, versionStr, objectRootPath, ignoreFiles, results);
    }

    private void validateVersionState(String versionStr,
                                      SimpleInventory rootInventory,
                                      SimpleInventory inventory,
                                      String inventoryPath,
                                      ValidationResults results) {
        var currentVersionNum = VersionNum.fromString(versionStr);
        while (true) {
            var currentVersionStr = currentVersionNum.toString();
            var rootVersion = rootInventory.getVersions().get(currentVersionStr);
            var childVersion = inventory.getVersions().get(currentVersionStr);

            if (childVersion == null) {
                results.addIssue(ValidationCode.E066,
                        "Inventory is missing version %s in %s", currentVersionStr, inventoryPath);
            } else {
                // TODO warnings on meta diffs
                if (!Objects.equals(rootVersion.getState(), childVersion.getState())) {
                    results.addIssue(ValidationCode.E066,
                            "Inventory version %s's state is inconsistent in %s when compared to the root inventory",
                            currentVersionStr, inventoryPath);
                }
            }

            if (currentVersionNum.equals(VersionNum.V1)) {
                break;
            } else {
                currentVersionNum = currentVersionNum.previousVersionNum();
            }
        }
    }

    private void validateContentFiles(String objectRootPath, SimpleInventory inventory, ValidationResults results) {
        var contentDir = defaultedContentDir(inventory);

        var manifestPaths = getManifestPaths(inventory);
        var fixityPaths = getFixityPaths(inventory);

        inventory.getVersions().keySet().forEach(versionNum -> {
            var versionContentDir = FileUtil.pathJoinFailEmpty(versionNum, contentDir);
            var versionContentPath = FileUtil.pathJoinFailEmpty(objectRootPath, versionContentDir);
            var listings = storage.listDirectory(versionContentPath, true);

            listings.forEach(listing -> {
                var fullPath = FileUtil.pathJoinFailEmpty(versionContentPath, listing.getRelativePath());
                var contentPath = FileUtil.pathJoinFailEmpty(versionContentDir, listing.getRelativePath());

                if (listing.isDirectory()) {
                    results.addIssue(ValidationCode.E024,
                            "Object contains an empty directory within version content at %s",
                            fullPath);
                } else {
                    if (!manifestPaths.remove(contentPath)) {
                        results.addIssue(ValidationCode.E023,
                                "Object contains a file with in version content at %s that is not referenced in the manifest",
                                fullPath);
                    }
                    fixityPaths.remove(contentPath);
                }
            });
        });

        manifestPaths.forEach(contentPath -> {
            results.addIssue(ValidationCode.E092,
                    "Inventory manifest contains content path %s but this file does not exist in %s",
                    contentPath, objectRootPath);
        });

        fixityPaths.forEach(contentPath -> {
            results.addIssue(ValidationCode.E093,
                    "Inventory fixity contains content path %s but this file does not exist in %s",
                    contentPath, objectRootPath);
        });
    }

    private void fixityCheck(String objectRootPath, SimpleInventory inventory, ValidationResults results) {
        var invertedFixityMap = invertFixity(inventory);
        var contentAlgorithm = DigestAlgorithmRegistry.getAlgorithm(inventory.getDigestAlgorithm());

        if (inventory.getManifest() != null) {
            for (var entry : inventory.getManifest().entrySet()) {
                var digest = entry.getKey();

                for (var contentPath : entry.getValue()) {
                    var storagePath = FileUtil.pathJoinFailEmpty(objectRootPath, contentPath);

                    var expectations = new HashMap<DigestAlgorithm, String>();
                    expectations.put(contentAlgorithm, digest);

                    var fixityDigests = invertedFixityMap.get(contentPath);
                    if (fixityDigests != null) {
                        expectations.putAll(fixityDigests);
                    }

                    try (var contentStream = new BufferedInputStream(storage.readFile(storagePath))) {
                        var wrapped = MultiDigestInputStream.create(contentStream, expectations.keySet());

                        while (wrapped.read() != -1) {
                            // read entire stream
                        }

                        var actualDigests = wrapped.getResults();

                        expectations.forEach((algorithm, expected) -> {
                            var actual = actualDigests.get(algorithm);
                            if (!expected.equalsIgnoreCase(actual)) {
                                var code = algorithm.equals(contentAlgorithm) ? ValidationCode.E092 : ValidationCode.E093;
                                results.addIssue(code,
                                        "File %s failed %s fixity check. Expected: %s; Actual: %s",
                                        storagePath, algorithm.getOcflName(), expected, actual);
                            }
                        });
                    } catch (Exception e) {
                        results.addIssue(ValidationCode.E092,
                                "Failed to validate fixity of %s: %s", storagePath, e.getMessage());
                    }
                }
            }
        }
    }

    private void validateVersionDirContents(String objectRootPath,
                                            String versionStr,
                                            String versionPath,
                                            Set<String> ignoreFiles,
                                            ValidationResults results) {
        var files = storage.listDirectory(versionPath, false);

        for (var file : files) {
            var fileName = file.getRelativePath();

            if (ignoreFiles.contains(fileName)) {
                continue;
            }

            if (file.isFile()) {
                results.addIssue(ValidationCode.E015,
                        "Version directory %s in %s contains an unexpected file %s",
                        objectRootPath, versionStr, fileName);
            }

            // TODO warn about dirs
        }
    }

    private void validateNamaste(String namasteFile, ValidationResults results) {
        try (var stream = storage.readFile(namasteFile)) {
            var contents = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            // TODO there are technically multiple different codes that could be used here
            if (!OBJECT_NAMASTE_CONTENTS.equals(contents)) {
                results.addIssue(ValidationCode.E002,
                        "OCFL object version declaration must be '%s' in %s",
                        OcflConstants.OBJECT_NAMASTE_1_0, namasteFile);
            }
        } catch (Exception e) {
            LOG.info("Expected file to exist: {}", namasteFile, e);
            results.addIssue(ValidationCode.E003, "OCFL object version declaration must exist at %s", namasteFile);
        }
    }

    private String validateInventorySidecar(String sidecarPath, DigestAlgorithm algorithm, String digest, ValidationResults results) {
        try (var stream = storage.readFile(sidecarPath)) {
            var parts = new String(stream.readAllBytes(), StandardCharsets.UTF_8).split("\\s+");

            if (parts.length != 2) {
                results.addIssue(ValidationCode.E061,
                        "Inventory sidecar file at %s is in an invalid format", sidecarPath);

            } else {
                if (!digest.equalsIgnoreCase(parts[0])) {
                    results.addIssue(ValidationCode.E060,
                            "Inventory at %s does not match expected %s digest. Expected: %s; Found: %s",
                            sidecarPath, algorithm.getOcflName(), digest, parts[0]);
                }

                return parts[0];
            }
        } catch (Exception e) {
            LOG.info("Expected file to exist: {}", sidecarPath, e);
            results.addIssue(ValidationCode.E058,
                    "Inventory sidecar missing at %s", sidecarPath);
        }

        return null;
    }

    private Set<String> validateObjectRootContents(String objectRootPath,
                                            Set<String> ignoreFiles,
                                            SimpleInventory inventory,
                                            ValidationResults results) {
        var files = storage.listDirectory(objectRootPath, false);
        var seenVersions = new HashSet<String>();

        for (var file : files) {
            var fileName = file.getRelativePath();

            if (ignoreFiles.contains(fileName)) {
                continue;
            }

            if (Objects.equals(OcflConstants.LOGS_DIR, fileName)) {
                if (file.isFile()) {
                    results.addIssue(ValidationCode.E001,
                            "Object logs directory at %s/logs must be a directory",
                            objectRootPath);
                }
            } else if (Objects.equals(OcflConstants.EXTENSIONS_DIR, fileName)) {
                if (file.isFile()) {
                    results.addIssue(ValidationCode.E001,
                            "Object extensions directory at %s/extensions must be a directory",
                            objectRootPath);
                }
                // TODO verify extensions contents -- warnings
            } else {
                var versionNum = parseVersionNum(fileName);
                if (versionNum != null && file.isFile()) {
                    results.addIssue(ValidationCode.E001,
                            "Object root %s contains version %s but it is a file and must be a directory",
                            objectRootPath);
                } else if (inventory.getVersions() != null && versionNum != null) {
                    if (!inventory.getVersions().containsKey(fileName)) {
                        results.addIssue(ValidationCode.E046,
                                "Object root %s contains version directory %s but the version does not exist in the root inventory",
                                objectRootPath, fileName);
                    } else {
                        seenVersions.add(fileName);
                    }
                } else {
                    results.addIssue(ValidationCode.E001,
                            "Object root %s contains an unexpected file %s",
                            objectRootPath, fileName);
                }
            }
        }

        return seenVersions;
    }

    private Optional<String> validateSidecar(String inventoryPath,
                                   SimpleInventory inventory,
                                   Map<DigestAlgorithm, String> digests,
                                   ValidationResults results) {
        if (inventory.getDigestAlgorithm() != null) {
            var algorithm = DigestAlgorithmRegistry.getAlgorithm(inventory.getDigestAlgorithm());
            var digest = digests.get(algorithm);

            if (digest != null) {
                var sidecarPath = inventoryPath + "." + inventory.getDigestAlgorithm();
                validateInventorySidecar(sidecarPath, algorithm, digest, results);
                return Optional.of(OcflConstants.INVENTORY_SIDECAR_PREFIX + inventory.getDigestAlgorithm());
            }
        }
        return Optional.empty();
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

            var result = new ParseResult(parseResult.getInventory(), parseResult.getValidationResults().hasErrors());

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

    private VersionNum parseVersionNum(String versionNum) {
        try {
            return VersionNum.fromString(versionNum);
        } catch (Exception e) {
            return null;
        }
    }

    private String defaultedContentDir(SimpleInventory inventory) {
        var content = inventory.getContentDirectory();
        if (content == null || content.isEmpty()) {
            return OcflConstants.DEFAULT_CONTENT_DIRECTORY;
        }
        return content;
    }

    private Set<String> getManifestPaths(SimpleInventory inventory) {
        if (inventory.getManifest() == null) {
            return new HashSet<>();
        }

        return inventory.getManifest().values().stream()
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());
    }

    private Set<String> getFixityPaths(SimpleInventory inventory) {
        if (inventory.getFixity() == null) {
            return new HashSet<>();
        }

        return inventory.getFixity().values()
                .stream().flatMap(e -> e.values().stream())
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());
    }

    private Map<String, Map<DigestAlgorithm, String>> invertFixity(SimpleInventory inventory) {
        if (inventory.getFixity() == null) {
            return new HashMap<>();
        }

        var inverted = new HashMap<String, Map<DigestAlgorithm, String>>();

        inventory.getFixity().forEach((algorithmStr, map) -> {
            var algorithm = DigestAlgorithmRegistry.getAlgorithm(algorithmStr);
            map.forEach((digest, paths) -> {
                paths.forEach(path -> {
                    inverted.computeIfAbsent(path, k -> new HashMap<>())
                            .put(algorithm, digest);
                });
            });
        });

        return inverted;
    }

    private Optional<ValidationIssue> areEqual(Object left, Object right, ValidationCode code, String messageTemplate, Object... args) {
        if (!Objects.equals(left, right)) {
            return Optional.of(createIssue(code, messageTemplate, args));
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

    private static class ParseResult {
        final Optional<SimpleInventory> inventory;
        final Map<DigestAlgorithm, String> digests;
        final boolean isValid;

        ParseResult(Optional<SimpleInventory> inventory, boolean isValid) {
            this.inventory = inventory;
            this.isValid = isValid;
            digests = new HashMap<>();
        }

        ParseResult withDigest(DigestAlgorithm algorithm, String value) {
            digests.put(algorithm, value);
            return this;
        }
    }

}
