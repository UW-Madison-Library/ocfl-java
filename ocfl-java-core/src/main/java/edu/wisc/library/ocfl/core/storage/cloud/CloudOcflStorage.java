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

package edu.wisc.library.ocfl.core.storage.cloud;

import edu.wisc.library.ocfl.api.OcflConstants;
import edu.wisc.library.ocfl.api.OcflFileRetriever;
import edu.wisc.library.ocfl.api.exception.CorruptObjectException;
import edu.wisc.library.ocfl.api.exception.FixityCheckException;
import edu.wisc.library.ocfl.api.exception.NotFoundException;
import edu.wisc.library.ocfl.api.exception.ObjectOutOfSyncException;
import edu.wisc.library.ocfl.api.exception.OcflIOException;
import edu.wisc.library.ocfl.api.exception.OcflStateException;
import edu.wisc.library.ocfl.api.io.FixityCheckInputStream;
import edu.wisc.library.ocfl.api.model.DigestAlgorithm;
import edu.wisc.library.ocfl.api.model.ObjectVersionId;
import edu.wisc.library.ocfl.api.model.ValidationResults;
import edu.wisc.library.ocfl.api.model.VersionNum;
import edu.wisc.library.ocfl.api.util.Enforce;
import edu.wisc.library.ocfl.core.ObjectPaths;
import edu.wisc.library.ocfl.core.extension.OcflExtensionConfig;
import edu.wisc.library.ocfl.core.extension.storage.layout.OcflStorageLayoutExtension;
import edu.wisc.library.ocfl.core.inventory.SidecarMapper;
import edu.wisc.library.ocfl.core.model.Inventory;
import edu.wisc.library.ocfl.core.model.RevisionNum;
import edu.wisc.library.ocfl.core.path.constraint.LogicalPathConstraints;
import edu.wisc.library.ocfl.core.path.constraint.PathConstraintProcessor;
import edu.wisc.library.ocfl.core.storage.AbstractOcflStorage;
import edu.wisc.library.ocfl.core.storage.OcflStorage;
import edu.wisc.library.ocfl.core.util.FileUtil;
import edu.wisc.library.ocfl.core.util.NamasteTypeFile;
import edu.wisc.library.ocfl.core.util.UncheckedFiles;
import edu.wisc.library.ocfl.core.validation.Validator;
import edu.wisc.library.ocfl.core.validation.storage.CloudStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * {@link OcflStorage} implementation for integrating with cloud storage providers. {@link CloudClient} implementation
 * to integrate with different providers.
 */
public class CloudOcflStorage extends AbstractOcflStorage {

    private static final Logger LOG = LoggerFactory.getLogger(CloudOcflStorage.class);

    private static final String MEDIA_TYPE_TEXT = "text/plain; charset=UTF-8";
    private static final String MEDIA_TYPE_JSON = "application/json; charset=UTF-8";

    private final PathConstraintProcessor logicalPathConstraints;

    private final CloudClient cloudClient;

    private final CloudOcflStorageInitializer initializer;
    private OcflStorageLayoutExtension storageLayoutExtension;
    private final CloudOcflFileRetriever.Builder fileRetrieverBuilder;
    private final Validator validator;

    /**
     * Create a new builder.
     *
     * @return builder
     */
    public static CloudOcflStorageBuilder builder() {
        return new CloudOcflStorageBuilder();
    }

    /**
     * Creates a new CloudOcflStorage object.
     *
     * <p>{@link #initializeStorage} must be called before using this object.
     *
     * @see CloudOcflStorageBuilder
     *
     * @param cloudClient the client to use to interface with cloud storage such as S3
     * @param initializer initializes a new OCFL repo
     */
    public CloudOcflStorage(CloudClient cloudClient,
                            CloudOcflStorageInitializer initializer) {
        this.cloudClient = Enforce.notNull(cloudClient, "cloudClient cannot be null");
        this.initializer = Enforce.notNull(initializer, "initializer cannot be null");

        this.logicalPathConstraints = LogicalPathConstraints.constraintsWithBackslashCheck();
        this.fileRetrieverBuilder = CloudOcflFileRetriever.builder().cloudClient(this.cloudClient);
        this.validator = new Validator(new CloudStorage(cloudClient));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Inventory loadInventory(String objectId) {
        ensureOpen();

        LOG.debug("Load inventory for object <{}>", objectId);

        Inventory inventory = null;

        if (containsObject(objectId)) {
            var objectRootPath = objectRootPath(objectId);

            // currently just validates that no unsupported extensions are used
            loadObjectExtensions(objectRootPath);

            if (hasMutableHead(objectRootPath)) {
                inventory = downloadAndVerifyMutableInventory(objectId, objectRootPath);
                ensureRootObjectHasNotChanged(inventory);
            } else {
                inventory = downloadAndVerifyInventory(objectId, objectRootPath);
            }

            if (inventory != null && !Objects.equals(objectId, inventory.getId())) {
                throw new CorruptObjectException(String.format("Expected object at %s to have id %s. Found: %s",
                        objectRootPath, objectId, inventory.getId()));
            }
        }

        return inventory;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getInventoryBytes(String objectId, VersionNum versionNum) {
        ensureOpen();

        Enforce.notBlank(objectId, "objectId cannot be blank");
        Enforce.notNull(versionNum, "versionNum cannot be null");

        LOG.debug("Loading inventory bytes for object {} version {}", objectId, versionNum);

        var objectRootPath = objectRootPath(objectId);
        var versionPath = FileUtil.pathJoinFailEmpty(objectRootPath, versionNum.toString());

        var inventoryPath = ObjectPaths.inventoryPath(versionPath);

        try (var stream = cloudClient.downloadStream(inventoryPath)) {
            return stream.readAllBytes();
        } catch (KeyNotFoundException e) {
            var mutableHeadInventoryPath = ObjectPaths.mutableHeadInventoryPath(objectRootPath);

            try (var mutableStream = cloudClient.downloadStream(mutableHeadInventoryPath)) {
                var bytes = mutableStream.readAllBytes();
                var inv = inventoryMapper.readMutableHead("root", "bogus",
                        RevisionNum.R1, new ByteArrayInputStream(bytes));

                if (versionNum.equals(inv.getHead())) {
                    return bytes;
                }
            } catch (KeyNotFoundException e2) {
                // Ignore missing mutable head
            } catch (IOException e2) {
                throw new OcflIOException(e2);
            }
        } catch (IOException e) {
            throw new OcflIOException(e);
        }

        throw new NotFoundException(String.format("No inventory could be found for object %s version %s", objectId, versionNum));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Stream<String> listObjectIds() {
        LOG.debug("List object ids");

        return findOcflObjectRootDirs().map(objectRoot -> {
            var inventory = downloadInventory(objectRoot);
            return inventory.getId();
        });
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void storeNewVersion(Inventory inventory, Path stagingDir) {
        ensureOpen();

        LOG.debug("Store new version of object <{}> version <{}> revision <{}> from staging directory <{}>",
                inventory.getId(), inventory.getHead(), inventory.getRevisionNum(), stagingDir);

        if (inventory.hasMutableHead()) {
            storeNewMutableHeadVersion(inventory, stagingDir);
        } else {
            storeNewImmutableVersion(inventory, stagingDir);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, OcflFileRetriever> getObjectStreams(Inventory inventory, VersionNum versionNum) {
        ensureOpen();

        LOG.debug("Get file streams for object <{}> version <{}>", inventory.getId(), versionNum);

        var version = inventory.ensureVersion(versionNum);
        var algorithm = inventory.getDigestAlgorithm();

        var map = new HashMap<String, OcflFileRetriever>(version.getState().size());

        version.getState().forEach((digest, paths) -> {
            var srcPath = inventory.storagePath(digest);
            paths.forEach(path -> {
                map.put(path, fileRetrieverBuilder.build(srcPath, algorithm, digest));
            });
        });

        return map;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void reconstructObjectVersion(Inventory inventory, VersionNum versionNum, Path stagingDir) {
        ensureOpen();

        LOG.debug("Reconstruct object <{}> version <{}> in directory <{}>", inventory.getId(), versionNum, stagingDir);

        var version = inventory.ensureVersion(versionNum);
        var digestAlgorithm = inventory.getDigestAlgorithm();

        version.getState().forEach((id, files) -> {
            var srcPath = inventory.storagePath(id);

            for (var logicalPath : files) {
                logicalPathConstraints.apply(logicalPath);
                var destination = Paths.get(FileUtil.pathJoinFailEmpty(stagingDir.toString(), logicalPath));

                UncheckedFiles.createDirectories(destination.getParent());

                try (var stream = new FixityCheckInputStream(cloudClient.downloadStream(srcPath), digestAlgorithm, id)) {
                    Files.copy(stream, destination);
                    stream.checkFixity();
                } catch (FixityCheckException e) {
                    throw new FixityCheckException(
                            String.format("File %s in object %s failed its fixity check.", logicalPath, inventory.getId()), e);
                } catch (IOException e) {
                    throw new OcflIOException(e);
                }
            }
        });
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void purgeObject(String objectId) {
        ensureOpen();

        LOG.info("Purge object <{}>", objectId);

        cloudClient.deletePath(objectRootPath(objectId));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void rollbackToVersion(Inventory inventory, VersionNum versionNum) {
        ensureOpen();

        LOG.info("Rollback object <{}> to version {}", inventory.getId(), versionNum);

        var versionPath = objectVersionPath(inventory, versionNum);

        try {
            copyInventoryToRoot(versionPath, inventory);
        } catch (Exception e) {
            try {
                var previousVersionPath = objectVersionPath(inventory, inventory.getHead());
                copyInventoryToRoot(previousVersionPath, inventory);
            } catch (RuntimeException e1) {
                LOG.error("Failed to rollback inventory at {}. Object must be fixed manually.",
                        ObjectPaths.inventoryPath(inventory.getObjectRootPath()), e1);
            }
        }

        try {
            var currentVersion = inventory.getHead();

            while (currentVersion.compareTo(versionNum) > 0) {
                LOG.info("Purging object {} version {}", inventory.getId(), currentVersion);
                cloudClient.deletePath(objectVersionPath(inventory, currentVersion));
                currentVersion = currentVersion.previousVersionNum();
            }

            purgeMutableHead(inventory.getId());
        } catch (Exception e) {
            throw new CorruptObjectException(String.format("Object %s was corrupted while attempting to rollback to version %s. It must be manually remediated.",
                    inventory.getId(), versionNum), e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void commitMutableHead(Inventory oldInventory, Inventory newInventory, Path stagingDir) {
        ensureOpen();

        LOG.debug("Commit mutable HEAD on object <{}>", newInventory.getId());

        ensureRootObjectHasNotChanged(newInventory);

        if (cloudClient.listDirectory(ObjectPaths.mutableHeadVersionPath(newInventory.getObjectRootPath())).getObjects().isEmpty()) {
            throw new ObjectOutOfSyncException(
                    String.format("Cannot commit mutable HEAD of object %s because a mutable HEAD does not exist.", newInventory.getId()));
        }

        var versionPath = objectVersionPath(newInventory, newInventory.getHead());

        ensureVersionDoesNotExist(newInventory, versionPath);

        var objectKeys = copyMutableVersionToImmutableVersion(oldInventory, newInventory);

        try {
            storeInventoryInCloudWithRollback(newInventory, stagingDir, versionPath);

            try {
                purgeMutableHead(newInventory.getId());
            } catch (RuntimeException e) {
                LOG.error("Failed to cleanup mutable HEAD of object {} at {}. It must be deleted manually.",
                        newInventory.getId(), ObjectPaths.mutableHeadExtensionRoot(newInventory.getObjectRootPath()), e);
            }
        } catch (RuntimeException e) {
            cloudClient.safeDeleteObjects(objectKeys);
            throw e;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void purgeMutableHead(String objectId) {
        ensureOpen();

        LOG.info("Purge mutable HEAD on object <{}>", objectId);

        cloudClient.deletePath(ObjectPaths.mutableHeadExtensionRoot(objectRootPath(objectId)));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean containsObject(String objectId) {
        ensureOpen();

        var exists = false;

        // TODO this ONLY WORKs for OCFL v1.0
        try {
            cloudClient.head(ObjectPaths.objectNamastePath(objectRootPath(objectId)));
            exists = true;
        } catch (KeyNotFoundException e) {
            // Ignore; object does not exist
        }

        LOG.debug("OCFL repository contains object <{}>: {}", objectId, exists);

        return exists;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String objectRootPath(String objectId) {
        ensureOpen();

        var objectRootPath = storageLayoutExtension.mapObjectId(objectId);

        LOG.debug("Object root path for object <{}>: {}", objectId, objectRootPath);

        return objectRootPath;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void exportVersion(ObjectVersionId objectVersionId, Path outputPath) {
        ensureOpen();

        Enforce.notNull(objectVersionId.getVersionNum(), "versionNum cannot be null");

        var versionRootPath = FileUtil.pathJoinFailEmpty(objectRootPath(objectVersionId.getObjectId()),
                objectVersionId.getVersionNum().toString()) + "/";

        var objects = cloudClient.list(versionRootPath).getObjects();

        if (objects.isEmpty()) {
            throw new NotFoundException(String.format("Object %s version %s was not found.",
                    objectVersionId.getObjectId(), objectVersionId.getVersionNum()));
        }

        LOG.debug("Copying <{}> to <{}>", versionRootPath, outputPath);

        copyObjects(objects, outputPath);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void exportObject(String objectId, Path outputPath) {
        ensureOpen();

        var objectRootPath = objectRootPath(objectId) + "/";

        var objects = cloudClient.list(objectRootPath).getObjects();

        if (objects.isEmpty()) {
            throw new NotFoundException(String.format("Object %s was not found.", objectId));
        }

        LOG.debug("Copying <{}> to <{}>", objectRootPath, outputPath);

        copyObjects(objects, outputPath);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void importObject(String objectId, Path objectPath) {
        var objectRootPath = objectRootPath(objectId);

        if (!cloudClient.listDirectory(objectRootPath).getObjects().isEmpty()) {
            throw new ObjectOutOfSyncException(String.format("Cannot import object %s because the object already exists.",
                    objectId));
        }

        LOG.debug("Importing <{}> to <{}>", objectId, objectRootPath);

        storeFilesInCloud(objectPath, objectRootPath);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ValidationResults validateObject(String objectId, boolean contentFixityCheck) {
        ensureOpen();

        if (!containsObject(objectId)) {
            throw new NotFoundException(String.format("Object %s was not found.", objectId));
        }

        var objectRoot = objectRootPath(objectId);

        LOG.debug("Validating object <{}> at <{}>", objectId, objectRoot);

        return validator.validateObject(objectRoot, contentFixityCheck);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doInitialize(OcflExtensionConfig layoutConfig) {
        this.storageLayoutExtension = this.initializer.initializeStorage(ocflVersion, layoutConfig, supportEvaluator);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() {
        LOG.debug("Closing " + this.getClass().getName());
    }

    private void storeNewImmutableVersion(Inventory inventory, Path stagingDir) {
        var objectRootPath = inventory.getObjectRootPath();
        ensureNoMutableHead(inventory.getId(), objectRootPath);

        var versionPath = objectVersionPath(inventory, inventory.getHead());
        ensureVersionDoesNotExist(inventory, versionPath);

        String namasteFile = null;

        try {
            if (isFirstVersion(inventory)) {
                namasteFile = writeObjectNamasteFile(objectRootPath);
            }

            var objectKeys = storeContentInCloud(inventory, stagingDir);
            // TODO write a copy to the cache?

            try {
                verifyPriorInventory(inventory, ObjectPaths.inventorySidecarPath(objectRootPath, inventory));
                storeInventoryInCloudWithRollback(inventory, stagingDir, versionPath);
            } catch (RuntimeException e) {
                cloudClient.safeDeleteObjects(objectKeys);
                throw e;
            }
        } catch (RuntimeException e) {
            // TODO this could corrupt the object if another process is concurrently creating the same object
            if (namasteFile != null) {
                cloudClient.safeDeleteObjects(namasteFile);
            }
            throw e;
        }
    }

    private void storeNewMutableHeadVersion(Inventory inventory, Path stagingDir) {
        ensureRevisionDoesNotExist(inventory);

        var cleanupKeys = new ArrayList<String>(2);

        var isNewMutableHead = false;

        if (!cloudClient.listDirectory(ObjectPaths.mutableHeadExtensionRoot(inventory.getObjectRootPath())).getObjects().isEmpty()) {
            ensureRootObjectHasNotChanged(inventory);
        } else {
            cleanupKeys.add(copyRootInventorySidecarToMutableHead(inventory));
            isNewMutableHead = true;
        }

        try {
            cleanupKeys.add(createRevisionMarker(inventory));

            var objectKeys = storeContentInCloud(inventory, stagingDir);

            // TODO write a copy to the cache?

            try {
                verifyPriorInventoryMutable(inventory, isNewMutableHead);
                // TODO if this fails the inventory may be left in a bad state
                storeMutableHeadInventoryInCloud(inventory, stagingDir);
            } catch (RuntimeException e) {
                cloudClient.safeDeleteObjects(objectKeys);
                throw e;
            }
        } catch (RuntimeException e) {
            cloudClient.safeDeleteObjects(cleanupKeys);
            throw e;
        }

        deleteMutableHeadFilesNotInManifest(inventory);
    }

    private List<String> storeContentInCloud(Inventory inventory, Path sourcePath) {
        var contentPrefix = contentPrefix(inventory);
        var fileIds = inventory.getFileIdsForMatchingFiles(contentPrefix);
        var objectKeys = Collections.synchronizedList(new ArrayList<String>());

        try {
            fileIds.forEach(fileId -> {
                var contentPath = inventory.ensureContentPath(fileId);
                var contentPathNoVersion = contentPath.substring(contentPath.indexOf(inventory.resolveContentDirectory()));
                var file = sourcePath.resolve(contentPathNoVersion);

                if (Files.notExists(file)) {
                    throw new OcflStateException(String.format("Staged file %s does not exist", file));
                }

                var key = inventory.storagePath(fileId);
                objectKeys.add(key);
                cloudClient.uploadFile(file, key);
            });
        } catch (RuntimeException e) {
            cloudClient.safeDeleteObjects(objectKeys);
            throw e;
        }

        return objectKeys;
    }

    private List<String> storeFilesInCloud(Path source, String destination) {
        var objectKeys = Collections.synchronizedList(new ArrayList<String>());

        try (var paths = Files.walk(source)) {
            paths.filter(Files::isRegularFile).forEach(file -> {
                var relative = FileUtil.pathToStringStandardSeparator(source.relativize(file));
                var key = FileUtil.pathJoinFailEmpty(destination, relative);
                objectKeys.add(key);
                cloudClient.uploadFile(file, key);
            });
        } catch (IOException | RuntimeException e) {
            cloudClient.safeDeleteObjects(objectKeys);

            if (e instanceof IOException) {
                throw new OcflIOException((IOException) e);
            }
            throw (RuntimeException) e;
        }

        return objectKeys;
    }

    private List<String> copyMutableVersionToImmutableVersion(Inventory oldInventory, Inventory newInventory) {
        var contentPrefix = contentPrefix(newInventory);
        var fileIds = newInventory.getFileIdsForMatchingFiles(contentPrefix);
        var objectKeys = Collections.synchronizedList(new ArrayList<String>());

        try {
            // TODO the performance here DOES improve with increased parallelization -- perhaps add in the future
            fileIds.forEach(fileId -> {
                var srcPath = oldInventory.storagePath(fileId);
                var dstPath = newInventory.storagePath(fileId);
                objectKeys.add(dstPath);
                cloudClient.copyObject(srcPath, dstPath);
            });
        } catch (RuntimeException e) {
            cloudClient.safeDeleteObjects(objectKeys);
            throw e;
        }

        return objectKeys;
    }

    private void storeMutableHeadInventoryInCloud(Inventory inventory, Path sourcePath) {
        cloudClient.uploadFile(ObjectPaths.inventoryPath(sourcePath),
                ObjectPaths.mutableHeadInventoryPath(inventory.getObjectRootPath()), MEDIA_TYPE_JSON);
        cloudClient.uploadFile(ObjectPaths.inventorySidecarPath(sourcePath, inventory),
                ObjectPaths.mutableHeadInventorySidecarPath(inventory.getObjectRootPath(), inventory), MEDIA_TYPE_TEXT);
    }

    private void storeInventoryInCloudWithRollback(Inventory inventory, Path sourcePath, String versionPath) {
        var srcInventoryPath = ObjectPaths.inventoryPath(sourcePath);
        var srcSidecarPath = ObjectPaths.inventorySidecarPath(sourcePath, inventory);
        var versionedInventoryPath = ObjectPaths.inventoryPath(versionPath);
        var versionedSidecarPath = ObjectPaths.inventorySidecarPath(versionPath, inventory);

        cloudClient.uploadFile(srcInventoryPath, versionedInventoryPath, MEDIA_TYPE_JSON);
        cloudClient.uploadFile(srcSidecarPath, versionedSidecarPath, MEDIA_TYPE_TEXT);

        try {
            copyInventoryToRoot(versionPath, inventory);
        } catch (RuntimeException e) {
            rollbackInventory(inventory);
            cloudClient.safeDeleteObjects(versionedInventoryPath, versionedSidecarPath);
            throw e;
        }
    }

    private void rollbackInventory(Inventory inventory) {
        if (!isFirstVersion(inventory)) {
            try {
                var previousVersionPath = objectVersionPath(inventory, inventory.getHead().previousVersionNum());
                copyInventoryToRoot(previousVersionPath, inventory);
            } catch (RuntimeException e) {
                LOG.error("Failed to rollback inventory at {}. Object must be fixed manually.",
                        ObjectPaths.inventoryPath(inventory.getObjectRootPath()), e);
            }
        }
    }

    private void copyInventoryToRoot(String versionPath, Inventory inventory) {
        cloudClient.copyObject(ObjectPaths.inventoryPath(versionPath),
                ObjectPaths.inventoryPath(inventory.getObjectRootPath()));
        cloudClient.copyObject(ObjectPaths.inventorySidecarPath(versionPath, inventory),
                ObjectPaths.inventorySidecarPath(inventory.getObjectRootPath(), inventory));
    }

    private String copyRootInventorySidecarToMutableHead(Inventory inventory) {
        var rootSidecarPath = ObjectPaths.inventorySidecarPath(inventory.getObjectRootPath(), inventory);
        var sidecarName = rootSidecarPath.substring(rootSidecarPath.lastIndexOf('/') + 1);
        return cloudClient.copyObject(rootSidecarPath,
                FileUtil.pathJoinFailEmpty(ObjectPaths.mutableHeadExtensionRoot(inventory.getObjectRootPath()), "root-" + sidecarName)).getPath();
    }

    private void verifyPriorInventoryMutable(Inventory inventory, boolean isNewMutableHead) {
        String sidecarPath;

        if (isNewMutableHead) {
            sidecarPath = ObjectPaths.inventorySidecarPath(inventory.getObjectRootPath(), inventory);
        } else {
            sidecarPath = ObjectPaths.mutableHeadInventorySidecarPath(inventory.getObjectRootPath(), inventory);
        }

        verifyPriorInventory(inventory, sidecarPath);
    }

    private void verifyPriorInventory(Inventory inventory, String sidecarPath) {
        if (inventory.getPreviousDigest() != null) {
            var actualDigest = getDigestFromSidecar(sidecarPath);
            if (!actualDigest.equalsIgnoreCase(inventory.getPreviousDigest())) {
                throw new ObjectOutOfSyncException(String.format("Cannot update object %s because the update is out of sync with the current object state. " +
                                "The digest of the current inventory is %s, but the digest %s was expected.",
                        inventory.getId(), actualDigest, inventory.getPreviousDigest()));
            }
        } else if (!inventory.getHead().equals(VersionNum.V1)) {
            LOG.debug("Cannot verify prior inventory for object {} because its digest is unknown.", inventory.getId());
        }
    }

    private Inventory downloadAndVerifyInventory(String objectId, String objectRootPath) {
        var expectedDigest = findAndGetDigestFromSidecar(objectRootPath);
        var remotePath = ObjectPaths.inventoryPath(objectRootPath);

        try (var stream = new FixityCheckInputStream(cloudClient.downloadStream(remotePath),
                expectedDigest.getKey(), expectedDigest.getValue())) {
            var inventory = inventoryMapper.read(objectRootPath, expectedDigest.getValue(), stream);

            try {
                stream.checkFixity();
            } catch (FixityCheckException e) {
                throw new CorruptObjectException(String.format("Invalid root inventory in object %s", objectId), e);
            }

            return inventory;
        } catch (KeyNotFoundException e) {
            throw new CorruptObjectException(String.format("Object %s is missing its root inventory", objectId), e);
        } catch (IOException e) {
            throw new OcflIOException(e);
        }
    }

    private Inventory downloadAndVerifyMutableInventory(String objectId, String objectRootPath) {
        var expectedDigest = findAndGetDigestFromSidecar(ObjectPaths.mutableHeadVersionPath(objectRootPath));
        var remotePath = ObjectPaths.mutableHeadInventoryPath(objectRootPath);

        try (var stream = new FixityCheckInputStream(cloudClient.downloadStream(remotePath),
                expectedDigest.getKey(), expectedDigest.getValue())) {
            var revisionNum = identifyLatestRevision(objectRootPath);
            var inventory = inventoryMapper.readMutableHead(objectRootPath, expectedDigest.getValue(), revisionNum, stream);

            try {
                stream.checkFixity();
            } catch (FixityCheckException e) {
                throw new CorruptObjectException(String.format("Invalid mutable HEAD inventory in object %s", objectId), e);
            }

            return inventory;
        } catch (KeyNotFoundException e) {
            throw new CorruptObjectException(String.format("Object %s is missing its mutable HEAD inventory", objectId), e);
        } catch (IOException e) {
            throw new OcflIOException(e);
        }
    }

    private Inventory downloadInventory(String objectRootPath) {
        var inventoryPath = ObjectPaths.inventoryPath(objectRootPath);
        try (var stream = cloudClient.downloadStream(inventoryPath)) {
            // Intentionally filling in a bad digest here because all we care about is the object's id
            return inventoryMapper.read(objectRootPath, "digest", stream);
        } catch (IOException e) {
            throw new OcflIOException(e);
        }
    }

    private String createRevisionMarker(Inventory inventory) {
        var revision = inventory.getRevisionNum().toString();
        var revisionPath = FileUtil.pathJoinFailEmpty(ObjectPaths.mutableHeadRevisionsPath(inventory.getObjectRootPath()), revision);
        return cloudClient.uploadBytes(revisionPath, revision.getBytes(StandardCharsets.UTF_8), MEDIA_TYPE_TEXT).getPath();
    }

    private RevisionNum identifyLatestRevision(String objectRootPath) {
        var revisionsPath = ObjectPaths.mutableHeadRevisionsPath(objectRootPath);
        var revisions = cloudClient.listDirectory(revisionsPath);

        RevisionNum revisionNum = null;

        for (var revisionStr : revisions.getObjects()) {
            var id = RevisionNum.fromString(revisionStr.getKeySuffix());
            if (revisionNum == null) {
                revisionNum = id;
            } else if (revisionNum.compareTo(id) < 1) {
                revisionNum = id;
            }
        }

        return revisionNum;
    }

    private void deleteMutableHeadFilesNotInManifest(Inventory inventory) {
        var keys = cloudClient.list(FileUtil.pathJoinFailEmpty(
                ObjectPaths.mutableHeadVersionPath(inventory.getObjectRootPath()),
                inventory.resolveContentDirectory()));
        var deleteKeys = new ArrayList<String>();

        keys.getObjects().forEach(o -> {
            var key = o.getKey().getPath();
            var contentPath = key.substring(inventory.getObjectRootPath().length() + 1);
            if (inventory.getFileId(contentPath) == null) {
                deleteKeys.add(key);
            }
        });

        cloudClient.safeDeleteObjects(deleteKeys);
    }

    private String contentPrefix(Inventory inventory) {
        if (inventory.hasMutableHead()) {
            return FileUtil.pathJoinFailEmpty(
                    OcflConstants.MUTABLE_HEAD_VERSION_PATH,
                    inventory.resolveContentDirectory(),
                    inventory.getRevisionNum().toString());
        }

        return inventory.getHead().toString();
    }

    private Stream<String> findOcflObjectRootDirs() {
        var iterator = new CloudOcflObjectRootDirIterator("", cloudClient);
        try {
            var spliterator = Spliterators.spliteratorUnknownSize(iterator,
                    Spliterator.ORDERED | Spliterator.IMMUTABLE | Spliterator.DISTINCT);
            return StreamSupport.stream(spliterator, false)
                    .onClose(iterator::close);
        } catch (RuntimeException e) {
            iterator.close();
            throw e;
        }
    }

    private void ensureNoMutableHead(String objectId, String objectRootPath) {
        if (hasMutableHead(objectRootPath)) {
            throw new OcflStateException(String.format("Cannot create a new version of object %s because it has an active mutable HEAD.",
                    objectId));
        }
    }

    // TODO this could be incorrect due to eventual consistency issues
    private boolean hasMutableHead(String objectRootPath) {
        return !cloudClient.listDirectory(ObjectPaths.mutableHeadVersionPath(objectRootPath)).getObjects().isEmpty();
    }

    private void ensureVersionDoesNotExist(Inventory inventory, String versionPath) {
        if (!cloudClient.listDirectory(versionPath).getObjects().isEmpty()) {
            throw new ObjectOutOfSyncException(
                    String.format("Failed to create a new version of object %s. Changes are out of sync with the current object state.", inventory.getId()));
        }
    }

    private void ensureRevisionDoesNotExist(Inventory inventory) {
        var latestRevision = identifyLatestRevision(inventory.getObjectRootPath());
        if (latestRevision != null && latestRevision.compareTo(inventory.getRevisionNum()) >= 0) {
            throw new ObjectOutOfSyncException(
                    String.format("Failed to update mutable HEAD of object %s. Changes are out of sync with the current object state.", inventory.getId()));
        }
    }

    private void ensureRootObjectHasNotChanged(Inventory inventory) {
        var savedDigest = getDigestFromSidecar(FileUtil.pathJoinFailEmpty(ObjectPaths.mutableHeadExtensionRoot(inventory.getObjectRootPath()),
                "root-" + OcflConstants.INVENTORY_SIDECAR_PREFIX + inventory.getDigestAlgorithm().getOcflName()));
        var rootDigest = getDigestFromSidecar(ObjectPaths.inventorySidecarPath(inventory.getObjectRootPath(), inventory));

        if (!savedDigest.equalsIgnoreCase(rootDigest)) {
            throw new ObjectOutOfSyncException(
                    String.format("The mutable HEAD of object %s is out of sync with the root object state.", inventory.getId()));
        }
    }

    private Map.Entry<DigestAlgorithm, String> findAndGetDigestFromSidecar(String path) {
        for (var listing : cloudClient.listDirectory(path).getObjects()) {
            if (listing.getKeySuffix().startsWith(OcflConstants.INVENTORY_SIDECAR_PREFIX)) {
                var sidecarPath = listing.getKey().getPath();
                var algorithm = SidecarMapper.getDigestAlgorithmFromSidecar(sidecarPath);
                var digest = getDigestFromSidecar(sidecarPath);
                return Map.entry(algorithm, digest);
            }
        }

        throw new CorruptObjectException("Missing inventory sidecar in " + path);
    }

    private String getDigestFromSidecar(String sidecarPath) {
        try {
            var sidecarContents = cloudClient.downloadString(sidecarPath);
            var parts = sidecarContents.split("\\s");
            if (parts.length == 0) {
                throw new CorruptObjectException("Invalid inventory sidecar file: " + sidecarPath);
            }
            return parts[0];
        } catch (KeyNotFoundException e) {
            throw new CorruptObjectException("Missing inventory sidecar: " + sidecarPath, e);
        }
    }

    private String objectVersionPath(Inventory inventory, VersionNum versionNum) {
        return FileUtil.pathJoinFailEmpty(inventory.getObjectRootPath(), versionNum.toString());
    }

    private boolean isFirstVersion(Inventory inventory) {
        return inventory.getVersions().size() == 1;
    }

    private String writeObjectNamasteFile(String objectRootPath) {
        var namasteFile = new NamasteTypeFile(ocflVersion.getOcflObjectVersion());
        var key = FileUtil.pathJoinFailEmpty(objectRootPath, namasteFile.fileName());
        return cloudClient.uploadBytes(key, namasteFile.fileContent().getBytes(StandardCharsets.UTF_8), MEDIA_TYPE_TEXT).getPath();
    }

    private void copyObjects(List<ListResult.ObjectListing> objects, Path outputPath) {
        objects.forEach(object -> {
            var destination = outputPath.resolve(object.getKeySuffix());

            UncheckedFiles.createDirectories(destination.getParent());

            try (var stream = cloudClient.downloadStream(object.getKey().getPath())) {
                Files.copy(stream, destination);
            } catch (IOException e) {
                throw new OcflIOException(e);
            }
        });
    }

    private void loadObjectExtensions(String objectRoot) {
        // Currently, this just ensures that the object does not use any extensions that ocfl-java does not support
        var listResults = cloudClient.listDirectory(ObjectPaths.extensionsPath(objectRoot));
        listResults.getDirectories().forEach(dir -> {
            supportEvaluator.checkSupport(dir.getName());
        });
    }

}
