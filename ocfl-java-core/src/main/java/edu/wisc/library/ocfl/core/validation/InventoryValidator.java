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

import edu.wisc.library.ocfl.api.OcflConstants;
import edu.wisc.library.ocfl.api.exception.InvalidInventoryException;
import edu.wisc.library.ocfl.api.model.VersionNum;
import edu.wisc.library.ocfl.api.util.Enforce;
import edu.wisc.library.ocfl.core.model.Inventory;
import edu.wisc.library.ocfl.core.model.User;
import edu.wisc.library.ocfl.core.model.Version;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Validates that an {@link Inventory} meets the minimum requirements to be serialized as valid OCFL inventory.
 */
public final class InventoryValidator {

    private static final VersionNum VERSION_ZERO = VersionNum.fromString("v0");
    private static final Pattern CONTENT_DIR_PATTERN = Pattern.compile(".*[/\\\\].*");

    private InventoryValidator() {

    }

    /**
     * Validates that an {@link Inventory} meets the minimum requirements to be serialized as valid OCFL inventory.
     * Only the HEAD version is validated.
     *
     * @param inventory the inventory to validate
     * @return the same inventory
     * @throws InvalidInventoryException when validation fails
     */
    public static Inventory validateShallow(Inventory inventory) {
        Enforce.notNull(inventory, "inventory cannot be null");

        notBlank(inventory.getId(), () -> "Object ID cannot be blank");
        notNull(inventory.getHead(), prefix(inventory, () -> "HEAD cannot be null"));
        isTrue(!inventory.getHead().equals(VERSION_ZERO), prefix(inventory, () -> "HEAD version must be greater than v0"));
        notNull(inventory.getType(), prefix(inventory, () -> "Type cannot be null"));
        validateDigestAlgorithm(inventory);
        validateContentDirectory(inventory);

        notNull(inventory.getManifest(), prefix(inventory, () -> "Manifest cannot be null"));
        validateHeaVersion(inventory);

        return inventory;
    }

    /**
     * Validates that the currentInventory is a valid next inventory state from the previousInventory. The must have
     * the same id, type, digestAlgorithm, and contentDirectory values. Additionally, the currentInventory must be
     * one version later than the previous, and all of the versions they have in common must be identical.
     *
     * @param currentInventory current inventory
     * @param previousInventory inventory immediately prior to the current inventory
     */
    public static void validateCompatibleInventories(Inventory currentInventory, Inventory previousInventory) {
        areEqual(currentInventory.getId(), previousInventory.getId(),
                () -> String.format("Object IDs are not the same. Existing: %s; New: %s",
                        previousInventory.getId(), currentInventory.getId()));
        areEqual(currentInventory.getType(), previousInventory.getType(),
                () -> String.format("Inventory types are not the same. Existing: %s; New: %s",
                        previousInventory.getType().getId(), currentInventory.getType().getId()));
        areEqual(currentInventory.getDigestAlgorithm(), previousInventory.getDigestAlgorithm(),
                () -> String.format("Inventory digest algorithms are not the same. Existing: %s; New: %s",
                        previousInventory.getDigestAlgorithm().getOcflName(), currentInventory.getDigestAlgorithm().getOcflName()));
        areEqual(currentInventory.getContentDirectory(), previousInventory.getContentDirectory(),
                () -> String.format("Inventory content directories are not the same. Existing: %s; New: %s",
                        previousInventory.getContentDirectory(), currentInventory.getContentDirectory()));
        if (!Objects.equals(currentInventory.getHead(), previousInventory.nextVersionNum())) {
            throw new InvalidInventoryException(String.format(
                    "The new HEAD inventory version must be the next sequential version number. Existing: %s; New: %s",
                    previousInventory.getHead(), currentInventory.getHead()));
        }
        validateVersionStates(currentInventory, previousInventory);
        validateManifests(currentInventory, previousInventory);
    }

    /**
     * Validates that the two inventories contain the same version states, excluding the version in the current
     * that is not in the previous.
     *
     * @param currentInventory current inventory
     * @param previousInventory inventory immediately prior to the current inventory
     */
    public static void validateVersionStates(Inventory currentInventory, Inventory previousInventory) {
        var current = previousInventory.getHead();
        var currentVersions = currentInventory.getVersions().keySet().stream()
                .collect(Collectors.toMap(Function.identity(), Function.identity()));
        var previousVersions = previousInventory.getVersions().keySet().stream()
                .collect(Collectors.toMap(Function.identity(), Function.identity()));

        while (true) {
            validateVersionNumber(currentInventory, currentVersions.get(current), previousVersions.get(current));
            var currentState = currentInventory.getVersion(current).getState();
            var previousState = previousInventory.getVersion(current).getState();
            if (!Objects.equals(currentState, previousState)) {
                throw new InvalidInventoryException(String.format("In object %s the inventories in version %s and %s define a different state for version %s.",
                        currentInventory.getId(), currentInventory.getHead(), previousInventory.getHead(), current));
            }
            if (VersionNum.V1.equals(current)) {
                break;
            }
            current = current.previousVersionNum();
        }
    }

    /**
     * Validates that the manifests in the two inventories are compatible
     *
     * @param currentInventory current inventory
     * @param previousInventory inventory immediately prior to the current inventory
     */
    private static void validateManifests(Inventory currentInventory, Inventory previousInventory) {
        var currentManifest = new HashMap<>(currentInventory.getManifest());
        var previousManifest = previousInventory.getManifest();

        previousManifest.forEach((digest, previousPaths) -> {
            var currentPaths = currentManifest.remove(digest);
            if (currentPaths == null) {
                throw inconsistentManifestEntry(currentInventory, previousInventory, digest);
            } else {
                var currentPathsCopy = new HashSet<>(currentPaths);
                previousPaths.forEach(previousPath -> {
                    var currentPath = currentPathsCopy.remove(previousPath);
                    if (!currentPath) {
                        throw inconsistentManifestEntry(currentInventory, previousInventory, digest);
                    }
                });

                if (!currentPathsCopy.isEmpty()) {
                    throw inconsistentManifestEntry(currentInventory, previousInventory, digest);
                }
            }
        });

        var currentVersionPrefix = currentInventory.getHead().toString() + "/";

        currentManifest.values().stream().flatMap(Collection::stream).forEach(currentPath -> {
            if (!currentPath.startsWith(currentVersionPrefix)) {
                throw new InvalidInventoryException(String.format("In object %s the manifest in version %s contains a content path it should not %s.",
                        currentInventory.getId(), currentInventory.getHead(), currentPath));
            }
        });
    }

    private static InvalidInventoryException inconsistentManifestEntry(Inventory currentInventory, Inventory previousInventory, String digest) {
        return new InvalidInventoryException(String.format("In object %s the manifests in version %s and %s are inconsistent for digest %s.",
                currentInventory.getId(), currentInventory.getHead(), previousInventory.getHead(), digest));
    }

    private static void validateHeaVersion(Inventory inventory) {
        var versionMap = inventory.getVersions();
        notEmpty(versionMap, prefix(inventory, () -> "Versions cannot be empty"));

        for (var i = 1; i <= versionMap.size(); i++) {
            var versionNum = new VersionNum(i);
            notNull(versionMap.get(versionNum), prefix(inventory, () -> String.format("Version %s is missing", versionNum)));
        }

        var expectedHead = new VersionNum(versionMap.size());
        isTrue(inventory.getHead().equals(expectedHead), prefix(inventory, () ->
                String.format("HEAD must be the latest version. Expected: %s; Was: %s", expectedHead, inventory.getHead())));

        validateVersion(inventory, versionMap.get(expectedHead), expectedHead);
    }

    private static void validateVersion(Inventory inventory, Version version, VersionNum versionNum) {
        notNull(version, prefix(inventory, () -> String.format("Version %s is missing",  versionNum)));
        notNull(version.getCreated(), prefix(inventory, () -> String.format("Version created timestamp in version %s cannot be null", versionNum)));
        validateUser(inventory, version.getUser(), versionNum);

        var state = version.getState();
        notNull(state, prefix(inventory, () -> String.format("Version state of version %s cannot be null",  versionNum)));

        var directories = new HashSet<String>();
        var files = new HashSet<String>();

        state.forEach((digest, logicalPaths) -> {
            notEmpty(logicalPaths, prefix(inventory, () -> String.format("Version state logical paths in version %s cannot be empty", versionNum)));
            notNull(inventory.getContentPath(digest),
                    prefix(inventory, () -> String.format("Version state entry %s => %s in version %s does not have a corresponding entry in the manifest block.",
                            digest, logicalPaths, versionNum)));

            logicalPaths.forEach(path -> {
                files.add(path);
                var parts = path.split("/");
                var pathBuilder = new StringBuilder();
                for (int i = 0; i < parts.length - 1; i++) {
                    var part = parts[i];
                    if (i > 0) {
                        pathBuilder.append("/");
                    }
                    pathBuilder.append(part);
                    directories.add(pathBuilder.toString());
                }
            });
        });

        Set<String> iter;
        Set<String> check;

        if (files.size() > directories.size()) {
            iter = directories;
            check = files;
        } else {
            iter = files;
            check = directories;
        }

        iter.forEach(path -> {
            if (check.contains(path)) {
                throw new InvalidInventoryException(prefix(inventory, () -> String.format("In version %s the logical path %s conflicts with another logical path.",
                        versionNum, path)).get());
            }
        });
    }

    private static void validateDigestAlgorithm(Inventory inventory) {
        var digestAlgorithm = inventory.getDigestAlgorithm();
        notNull(digestAlgorithm, prefix(inventory, () -> "Digest algorithm cannot be null"));
        isTrue(OcflConstants.ALLOWED_DIGEST_ALGORITHMS.contains(digestAlgorithm),
                prefix(inventory, () -> String.format("Digest algorithm must be one of: %s; Found: %s",
                        OcflConstants.ALLOWED_DIGEST_ALGORITHMS, digestAlgorithm)));
    }

    private static void validateContentDirectory(Inventory inventory) {
        var contentDirectory = inventory.getContentDirectory();
        if (contentDirectory != null) {
            notBlank(contentDirectory, prefix(inventory, () -> "Content directory cannot be blank"));
            isTrue(!CONTENT_DIR_PATTERN.matcher(contentDirectory).matches(),
                    prefix(inventory, () -> "Content directory cannot contain / or \\. Found: " + contentDirectory));
        }
    }

    private static void validateUser(Inventory inventory, User user, VersionNum versionNum) {
        if (user != null) {
            notBlank(user.getName(), prefix(inventory, () -> String.format("User name in version %s cannot be blank", versionNum)));
        }
    }

    private static void validateVersionNumber(Inventory inventory, VersionNum currentVersion, VersionNum previousVersion) {
        if (!Objects.equals(currentVersion.toString(), previousVersion.toString())) {
            throw new InvalidInventoryException(prefix(inventory, () -> String.format("Version number formatting differs: %s vs %s",
                    previousVersion, currentVersion)).get());
        }
    }

    private static Supplier<String> prefix(Inventory inventory, Supplier<String> message) {
        return () -> {
            return String.format("Inventory %s %s: %s", inventory.getId(), inventory.getHead(), message.get());
        };
    }

    private static void notNull(Object object, Supplier<String> messageSupplier) {
        if (object == null) {
            throw new InvalidInventoryException(messageSupplier.get());
        }
    }

    private static void notBlank(String value, Supplier<String> messageSupplier) {
        if (value == null || value.isBlank()) {
            throw new InvalidInventoryException(messageSupplier.get());
        }
    }

    private static void notEmpty(Collection<?> collection, Supplier<String> messageSupplier) {
        if (collection == null || collection.isEmpty()) {
            throw new InvalidInventoryException(messageSupplier.get());
        }
    }

    private static void notEmpty(Map<?, ?> map, Supplier<String> messageSupplier) {
        if (map == null || map.isEmpty()) {
            throw new InvalidInventoryException(messageSupplier.get());
        }
    }

    private static void isTrue(boolean test, Supplier<String> messageSupplier) {
        if (!test) {
            throw new InvalidInventoryException(messageSupplier.get());
        }
    }

    private static <T> void areEqual(T left, T right, Supplier<String> messageSupplier) {
        if (!Objects.equals(left, right)) {
            throw new InvalidInventoryException(messageSupplier.get());
        }
    }

}
