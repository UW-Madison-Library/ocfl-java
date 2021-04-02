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
import edu.wisc.library.ocfl.api.OcflConstants;
import edu.wisc.library.ocfl.api.exception.NotFoundException;
import edu.wisc.library.ocfl.api.exception.OcflIOException;
import edu.wisc.library.ocfl.api.exception.OcflInputException;
import edu.wisc.library.ocfl.api.model.DigestAlgorithm;
import edu.wisc.library.ocfl.api.model.OcflVersion;
import edu.wisc.library.ocfl.api.model.ValidationCode;
import edu.wisc.library.ocfl.api.model.ValidationIssue;
import edu.wisc.library.ocfl.api.model.ValidationResults;
import edu.wisc.library.ocfl.api.model.VersionNum;
import edu.wisc.library.ocfl.api.util.Enforce;
import edu.wisc.library.ocfl.core.ObjectPaths;
import edu.wisc.library.ocfl.core.extension.storage.layout.FlatLayoutExtension;
import edu.wisc.library.ocfl.core.extension.storage.layout.HashedNTupleIdEncapsulationLayoutExtension;
import edu.wisc.library.ocfl.core.extension.storage.layout.HashedNTupleLayoutExtension;
import edu.wisc.library.ocfl.core.util.FileUtil;
import edu.wisc.library.ocfl.core.validation.model.SimpleInventory;
import edu.wisc.library.ocfl.core.validation.model.SimpleVersion;
import edu.wisc.library.ocfl.core.validation.storage.FileSystemStorage;
import edu.wisc.library.ocfl.core.validation.storage.Storage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

/**
 * Validates an object directory against the OCFL 1.0 spec
 */
public class Validator {

    private static final Logger LOG = LoggerFactory.getLogger(Validator.class);

    private static final DigestAlgorithm[] POSSIBLE_INV_ALGORITHMS = new DigestAlgorithm[]{
            DigestAlgorithm.sha256, DigestAlgorithm.sha512
    };

    private static final String OBJECT_NAMASTE_CONTENTS = OcflVersion.OCFL_1_0.getOcflObjectVersion() + "\n";

    private static final Set<String> OBJECT_ROOT_FILES = Set.of(
            OcflConstants.OBJECT_NAMASTE_1_0,
            OcflConstants.INVENTORY_FILE
    );

    private static final Set<String> REGISTERED_EXTENSIONS = Set.of(
            HashedNTupleLayoutExtension.EXTENSION_NAME,
            HashedNTupleIdEncapsulationLayoutExtension.EXTENSION_NAME,
            FlatLayoutExtension.EXTENSION_NAME,
            OcflConstants.MUTABLE_HEAD_EXT_NAME,
            OcflConstants.DIGEST_ALGORITHMS_EXT_NAME,
            // TODO technically the contents of this should be examined
            OcflConstants.INIT_EXT
    );

    private final Storage storage;
    private final SimpleInventoryParser inventoryParser;
    private final SimpleInventoryValidator inventoryValidator;

    /**
     * Validates that object at the specified location on disk
     *
     * @param objectRoot the path to the object root on disk
     * @param checkContentFixity true if the content file digests should be validated
     * @return the validation results
     */
    public static ValidationResults validateObject(Path objectRoot, boolean checkContentFixity) {
        return new Validator(new FileSystemStorage(objectRoot.getParent()))
                .validateObject(objectRoot.getFileName().toString(), checkContentFixity);
    }

    /**
     * Validates that the specified inventory file is internally valid
     *
     * @param inventoryPath the path to the inventory file
     * @return the validation results
     */
    public static ValidationResults validateInventory(Path inventoryPath) {
        return new Validator(new FileSystemStorage(inventoryPath.getParent()))
                .validateInventory(inventoryPath.getFileName().toString());
    }

    public Validator(Storage storage) {
        this.storage = Enforce.notNull(storage, "storage cannot be null");
        this.inventoryParser = new SimpleInventoryParser();
        this.inventoryValidator = new SimpleInventoryValidator();
    }

    /**
     * Validates the specified directory against the OCFL 1.0 spec.
     *
     * @param objectRootPath the path to the object to validate
     * @param contentFixityCheck true if the content file digests should be validated
     * @return the validation results
     */
    public ValidationResults validateObject(String objectRootPath, boolean contentFixityCheck) {
        Enforce.notBlank(objectRootPath, "objectRootPath cannot be blank");

        var results = new ValidationResultsBuilder();

        // TODO figure out how to handle links

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

        return results.build();
    }

    /**
     * Validates that an inventory is internally valid.
     *
     * @param inventoryPath the path to the inventory to validate
     * @return the validation results
     */
    public ValidationResults validateInventory(String inventoryPath) {
        Enforce.notBlank(inventoryPath, "inventoryPath cannot be blank");

        if (!storage.fileExists(inventoryPath)) {
            throw new OcflInputException("No inventory found at: " + inventoryPath);
        }

        var results = new ValidationResultsBuilder();
        var parseResults = parseInventory(inventoryPath, results, POSSIBLE_INV_ALGORITHMS);

        parseResults.inventory.ifPresent(inventory -> {
            var validationResults = inventoryValidator.validateInventory(inventory, inventoryPath);
            results.addAll(validationResults);
        });

        return results.build();
    }

    private void validateObjectWithInventory(String objectRootPath,
                                             String inventoryPath,
                                             SimpleInventory rootInventory,
                                             Map<DigestAlgorithm, String> inventoryDigests,
                                             boolean inventoryIsValid,
                                             boolean contentFixityCheck,
                                             ValidationResultsBuilder results) {
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

            var contentFiles = findAllContentFiles(objectRootPath, rootInventory, results);
            var manifests = new Manifests(rootInventory);

            // This MUST be done in reverse order
            seenVersions.forEach(versionStr -> {
                if (Objects.equals(rootInventory.getHead(), versionStr)) {
                    validateHeadVersion(objectRootPath, rootInventory, rootDigest, results);
                } else {
                    validateVersion(objectRootPath, versionStr, rootInventory, contentFiles, manifests, results);
                }
            });

            validateContentFiles(inventoryPath, rootInventory, contentFiles, manifests, results);

            if (contentFixityCheck) {
                // TODO digests from the non-root fixity blocks are not validated
                fixityCheck(objectRootPath, rootInventory, manifests, results);
            }
        } else {
            LOG.debug("Skipping further validation of the object at {} because its inventory is invalid", objectRootPath);
        }
    }

    private void validateVersion(String objectRootPath,
                                 String versionStr,
                                 SimpleInventory rootInventory,
                                 ContentPaths contentFiles,
                                 Manifests manifests,
                                 ValidationResultsBuilder results) {
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

                var versionContentDir = defaultedContentDir(inventory);

                // TODO suspect code
                results.addIssue(areEqual(rootInventory.getId(), inventory.getId(), ValidationCode.E037,
                        "Inventory id is inconsistent between versions in %s. Expected: %s; Found: %s",
                        inventoryPath, rootInventory.getId(), inventory.getId()))
                        // TODO suspect code
                        .addIssue(areEqual(versionStr, inventory.getHead(), ValidationCode.E040,
                                "Inventory head must be %s in %s", versionStr, inventoryPath))
                        .addIssue(areEqual(contentDir, versionContentDir, ValidationCode.E019,
                                "Inventory content directory is inconsistent between versions in %s. Expected: %s; Found: %s",
                                inventoryPath, contentDir, versionContentDir));

                if (parseResult.isValid && !validationResults.hasErrors()) {
                    if (!Objects.equals(rootInventory.getDigestAlgorithm(), inventory.getDigestAlgorithm())
                            && !manifests.containsAlgorithm(inventory.getDigestAlgorithm())) {
                        manifests.addManifest(inventory);
                    }

                    validateVersionIsConsistent(versionStr, rootInventory, inventory, inventoryPath, results);
                    validateContentFiles(inventoryPath, inventory, contentFiles, manifests, results);
                }
            });
        } else {
            results.addIssue(ValidationCode.W010, "Every version should contain an inventory. Missing: %s", inventoryPath);
        }

        validateVersionDirContents(objectRootPath, versionStr, versionPath, contentDir, ignoreFiles, results);
    }

    private void validateHeadVersion(String objectRootPath,
                                     SimpleInventory rootInventory,
                                     String rootDigest,
                                     ValidationResultsBuilder results) {
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
            var sidecarDigest = validateInventorySidecar(sidecarPath, results);
            var inventoryDigest = computeInventoryDigest(inventoryPath, DigestAlgorithmRegistry.getAlgorithm(rootInventory.getDigestAlgorithm()));

            if (!rootDigest.equalsIgnoreCase(inventoryDigest)) {
                results.addIssue(ValidationCode.E064,
                        "Inventory at %s must be identical to the inventory in the object root", inventoryPath);
            }

            if (sidecarDigest != null && !sidecarDigest.equalsIgnoreCase(inventoryDigest)) {
                results.addIssue(ValidationCode.E060,
                        "Inventory at %s does not match expected %s digest. Expected: %s; Found: %s",
                        inventoryPath, rootInventory.getDigestAlgorithm(), sidecarDigest, inventoryDigest);
            }
        } else {
            results.addIssue(ValidationCode.W010, "Every version should contain an inventory. Missing: %s", inventoryPath);
        }

        validateVersionDirContents(objectRootPath, versionStr, versionPath, contentDir, ignoreFiles, results);
    }

    private void validateVersionIsConsistent(String versionStr,
                                             SimpleInventory rootInventory,
                                             SimpleInventory inventory,
                                             String inventoryPath,
                                             ValidationResultsBuilder results) {
        var currentVersionNum = VersionNum.fromString(versionStr);
        var rootManifest = rootInventory.getManifest();
        var childManifest = inventory.getManifest();

        BiFunction<String, String, Boolean> stateComparator = (child, root) -> root.equalsIgnoreCase(child);

        if (!Objects.equals(rootInventory.getDigestAlgorithm(), inventory.getDigestAlgorithm())) {
            var translationMap = new HashMap<String, String>(inventory.getManifest().size());
            stateComparator = (child, root) -> {
                var mapped = translationMap.get(child);

                if (mapped != null) {
                    return root.equalsIgnoreCase(mapped);
                }

                var childPaths = childManifest.get(child);
                var rootPaths = rootManifest.get(root);

                for (var path : childPaths) {
                    if (rootPaths.contains(path)) {
                        translationMap.put(child, root);
                        return true;
                    }
                }

                return false;
            };
        }

        while (true) {
            var currentVersionStr = currentVersionNum.toString();
            var rootVersion = rootInventory.getVersions().get(currentVersionStr);
            var childVersion = inventory.getVersions().get(currentVersionStr);

            if (childVersion == null) {
                results.addIssue(ValidationCode.E066,
                        "Inventory is missing version %s in %s", currentVersionStr, inventoryPath);
            } else {
                validateVersionState(rootVersion, childVersion, currentVersionStr, inventoryPath, stateComparator, results);

                results.addIssue(areEqual(rootVersion.getCreated(), childVersion.getCreated(), ValidationCode.W011,
                                "The version created timestamp of version %s in %s is inconsistent with the root inventory",
                                currentVersionStr, inventoryPath))
                        .addIssue(areEqual(rootVersion.getMessage(), childVersion.getMessage(), ValidationCode.W011,
                                "The version message of version %s in %s is inconsistent with the root inventory",
                                currentVersionStr, inventoryPath))
                        .addIssue(areEqual(rootVersion.getUser(), childVersion.getUser(), ValidationCode.W011,
                                "The version user of version %s in %s is inconsistent with the root inventory",
                                currentVersionStr, inventoryPath));
            }

            if (currentVersionNum.equals(VersionNum.V1)) {
                break;
            } else {
                currentVersionNum = currentVersionNum.previousVersionNum();
            }
        }
    }

    private void validateVersionState(SimpleVersion rootVersion,
                                      SimpleVersion childVersion,
                                      String currentVersionStr,
                                      String inventoryPath,
                                      BiFunction<String, String, Boolean> stateComparator,
                                      ValidationResultsBuilder results) {
        var invertedRootState = new HashMap<>(rootVersion.getInvertedState());

        childVersion.getState().forEach((childDigest, childPaths) -> {
            childPaths.forEach(childPath -> {
                var rootDigest = invertedRootState.remove(childPath);
                if (rootDigest == null) {
                    results.addIssue(ValidationCode.E066,
                            "In %s version %s's state contains a path that does not exist in the root inventory: %s",
                            inventoryPath, currentVersionStr, childPath);
                } else if (!stateComparator.apply(childDigest, rootDigest)){
                    results.addIssue(ValidationCode.E066,
                            "In %s version %s's state contains a path that is inconsistent with the root inventory: %s",
                            inventoryPath, currentVersionStr, childPath);
                }
            });
        });

        invertedRootState.keySet().forEach(path -> {
            results.addIssue(ValidationCode.E066,
                    "In %s version %s's state is missing a path that exist in the root inventory: %s",
                    inventoryPath, currentVersionStr, path);
        });
    }

    private void validateContentFiles(String inventoryPath,
                                      SimpleInventory inventory,
                                      ContentPaths contentFiles,
                                      Manifests manifests,
                                      ValidationResultsBuilder results) {
        var invertedManifest = inventory.getInvertedManifestCopy();
        var fixityPaths = getFixityPaths(inventory);

        for (var it = contentFiles.pathsForVersion(VersionNum.fromString(inventory.getHead())); it.hasNext();) {
            var contentPath = it.next();
            var digest = invertedManifest.remove(contentPath);
            if (digest == null) {
                results.addIssue(ValidationCode.E023,
                        "Object contains a file in version content that is not referenced in the manifest of %s: %s",
                        inventoryPath, contentPath);
            } else {
                var expectedDigest = manifests.getDigest(inventory.getDigestAlgorithm(), contentPath);
                if (expectedDigest != null && !digest.equalsIgnoreCase(expectedDigest)) {
                    results.addIssue(ValidationCode.E092,
                            "Inventory manifest entry in %s for content path %s differs from later versions. Expected: %s; Found: %s",
                            inventoryPath, contentPath, expectedDigest, digest);
                }
            }
            fixityPaths.remove(contentPath);
        }

        invertedManifest.keySet().forEach(contentPath -> {
            results.addIssue(ValidationCode.E092,
                    "Inventory manifest in %s contains a content path that does not exist: %s",
                    inventoryPath, contentPath);
        });

        fixityPaths.forEach(contentPath -> {
            results.addIssue(ValidationCode.E093,
                    "Inventory fixity in %s contains a content path that does not exist: %s",
                    inventoryPath, contentPath);
        });
    }

    private ContentPaths findAllContentFiles(String objectRootPath, SimpleInventory inventory, ValidationResultsBuilder results) {
        var contentDir = defaultedContentDir(inventory);

        var files = new HashSet<String>(inventory.getManifest().size());

        inventory.getVersions().keySet().forEach(versionNum -> {
            var versionContentDir = FileUtil.pathJoinFailEmpty(versionNum, contentDir);
            var versionContentPath = FileUtil.pathJoinFailEmpty(objectRootPath, versionContentDir);
            var listings = storage.listDirectory(versionContentPath, true);

            listings.forEach(listing -> {
                var fullPath = FileUtil.pathJoinIgnoreEmpty(versionContentPath, listing.getRelativePath());
                var contentPath = FileUtil.pathJoinIgnoreEmpty(versionContentDir, listing.getRelativePath());

                if (listing.isDirectory() && !versionContentPath.equals(contentPath)) {
                    results.addIssue(ValidationCode.E024,
                            "Object contains an empty directory within version content at %s",
                            fullPath);
                } else {
                    files.add(contentPath);
                }
            });
        });

        return new ContentPaths(files);
    }

    private void fixityCheck(String objectRootPath, SimpleInventory inventory, Manifests manifests, ValidationResultsBuilder results) {
        var invertedFixityMap = invertFixity(inventory);
        var contentAlgorithm = DigestAlgorithmRegistry.getAlgorithm(inventory.getDigestAlgorithm());

        for (var entry : inventory.getManifest().entrySet()) {
            var digest = entry.getKey();

            for (var contentPath : entry.getValue()) {
                var storagePath = FileUtil.pathJoinFailEmpty(objectRootPath, contentPath);

                var expectations = new HashMap<DigestAlgorithm, String>();
                expectations.put(contentAlgorithm, digest);

                // This is necessary if there was an algorithm change over the course of an object's life
                if (manifests.hasMultipleAlgorithms()) {
                    manifests.getDigests(contentPath).entrySet().stream()
                            .filter(e -> !Objects.equals(e.getKey(), contentAlgorithm.getOcflName()))
                            .forEach(e -> {
                                var algorithm = DigestAlgorithmRegistry.getAlgorithm(e.getKey());
                                if (algorithm != null) {
                                    expectations.put(algorithm, e.getValue());
                                }
                            });
                }

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
                } catch (NotFoundException e) {
                    // Ignore this. We already reported missing files.
                } catch (Exception e) {
                    results.addIssue(ValidationCode.E092,
                            "Failed to validate fixity of %s: %s", storagePath, e.getMessage());
                }
            }
        }
    }

    private void validateVersionDirContents(String objectRootPath,
                                            String versionStr,
                                            String versionPath,
                                            String contentDirPath,
                                            Set<String> ignoreFiles,
                                            ValidationResultsBuilder results) {
        var files = storage.listDirectory(versionPath, false);

        if (storage.fileExists(contentDirPath) && storage.listDirectory(contentDirPath, false).isEmpty()) {
            results.addIssue(ValidationCode.W003,
                    "Version content directory exists at %s, but is empty.", contentDirPath);
        }

        for (var file : files) {
            var fileName = file.getRelativePath();

            if (ignoreFiles.contains(fileName)) {
                continue;
            }

            if (file.isFile()) {
                results.addIssue(ValidationCode.E015,
                        "Version directory %s in %s contains an unexpected file %s",
                        versionStr, objectRootPath, fileName);
            } else {
                results.addIssue(ValidationCode.W002,
                        "Version directory %s in %s contains an unexpected directory %s",
                        versionStr, objectRootPath, fileName);
            }
        }
    }

    private void validateNamaste(String namasteFile, ValidationResultsBuilder results) {
        try (var stream = storage.readFile(namasteFile)) {
            var contents = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            // TODO there are technically multiple different codes that could be used here
            if (!OBJECT_NAMASTE_CONTENTS.equals(contents)) {
                results.addIssue(ValidationCode.E007,
                        "OCFL object version declaration must be '%s' in %s",
                        OcflConstants.OBJECT_NAMASTE_1_0, namasteFile);
            }
        } catch (Exception e) {
            LOG.info("Expected file to exist: {}", namasteFile, e);
            results.addIssue(ValidationCode.E003, "OCFL object version declaration must exist at %s", namasteFile);
        }
    }

    private String validateInventorySidecar(String sidecarPath, ValidationResultsBuilder results) {
        try (var stream = storage.readFile(sidecarPath)) {
            var parts = new String(stream.readAllBytes(), StandardCharsets.UTF_8).split("\\s+");

            if (parts.length != 2) {
                results.addIssue(ValidationCode.E061,
                        "Inventory sidecar file at %s is in an invalid format", sidecarPath);

            } else {
                if (!OcflConstants.INVENTORY_FILE.equals(parts[1])) {
                    results.addIssue(ValidationCode.E061,
                            "Inventory sidecar file at %s is in an invalid format", sidecarPath);
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
                                                   ValidationResultsBuilder results) {
        var files = storage.listDirectory(objectRootPath, false);
        // It is essential that the order is reversed here so that we later validate versions in reverse order
        var seenVersions = new TreeSet<>(Comparator.<String>naturalOrder().reversed());

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
                } else {
                    validateExtensionContents(objectRootPath, results);
                }
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
                        if (versionNum.getZeroPaddingWidth() > 0) {
                            results.addIssue(ValidationCode.W001,
                                    "Object contains zero-padded version %s in %s",
                                    fileName, objectRootPath);
                        }
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

    private void validateExtensionContents(String objectRootPath, ValidationResultsBuilder results) {
        var dir = FileUtil.pathJoinFailEmpty(objectRootPath, OcflConstants.EXTENSIONS_DIR);
        var files = storage.listDirectory(dir, false);

        for (var file : files) {
            if (file.isFile()) {
                results.addIssue(ValidationCode.E067,
                        "Object extensions directory %s cannot contain file %s",
                        dir, file.getRelativePath());
            } else if (!REGISTERED_EXTENSIONS.contains(file.getRelativePath())) {
                results.addIssue(ValidationCode.W013,
                        "Object extensions directory %s contains unregistered extension %s",
                        dir, file.getRelativePath());
            }
        }
    }

    private Optional<String> validateSidecar(String inventoryPath,
                                             SimpleInventory inventory,
                                             Map<DigestAlgorithm, String> digests,
                                             ValidationResultsBuilder results) {
        if (inventory.getDigestAlgorithm() != null) {
            var algorithm = DigestAlgorithmRegistry.getAlgorithm(inventory.getDigestAlgorithm());
            var digest = digests.get(algorithm);

            if (digest != null) {
                var sidecarPath = inventoryPath + "." + inventory.getDigestAlgorithm();
                var expectedDigest = validateInventorySidecar(sidecarPath, results);
                if (expectedDigest != null && !digest.equalsIgnoreCase(expectedDigest)) {
                    results.addIssue(ValidationCode.E060,
                            "Inventory at %s does not match expected %s digest. Expected: %s; Found: %s",
                            inventoryPath, algorithm.getOcflName(), expectedDigest, digest);
                }
                return Optional.of(OcflConstants.INVENTORY_SIDECAR_PREFIX + inventory.getDigestAlgorithm());
            }
        }
        return Optional.empty();
    }

    private ParseResult parseInventory(String inventoryPath,
                                       ValidationResultsBuilder results,
                                       DigestAlgorithm... digestAlgorithms) {
        try (var stream = storage.readFile(inventoryPath)) {
            var wrapped = MultiDigestInputStream.create(stream, Arrays.asList(digestAlgorithms));

            var parseResult = inventoryParser.parse(wrapped, inventoryPath);

            results.addAll(parseResult.getValidationResults());

            var result = new ParseResult(parseResult.getInventory(), !parseResult.getValidationResults().hasErrors());
            wrapped.getResults().forEach(result::withDigest);

            return result;
        } catch (IOException e) {
            throw new OcflIOException(e);
        }
    }

    private String computeInventoryDigest(String inventoryPath, DigestAlgorithm algorithm) {
        try (var stream = storage.readFile(inventoryPath)) {
            var wrapped = MultiDigestInputStream.create(stream, List.of(algorithm));
            while (wrapped.read() > 0) {
                // consume stream
            }
            return wrapped.getResults().get(algorithm);
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
            if (algorithm != null) {
                map.forEach((digest, paths) -> {
                    paths.forEach(path -> {
                        inverted.computeIfAbsent(path, k -> new HashMap<>())
                                .put(algorithm, digest);
                    });
                });
            }
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
