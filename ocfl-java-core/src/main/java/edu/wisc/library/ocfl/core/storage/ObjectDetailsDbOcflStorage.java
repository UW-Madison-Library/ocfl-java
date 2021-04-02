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

package edu.wisc.library.ocfl.core.storage;

import edu.wisc.library.ocfl.api.OcflFileRetriever;
import edu.wisc.library.ocfl.api.exception.FixityCheckException;
import edu.wisc.library.ocfl.api.exception.ObjectOutOfSyncException;
import edu.wisc.library.ocfl.api.model.ObjectVersionId;
import edu.wisc.library.ocfl.api.model.ValidationResults;
import edu.wisc.library.ocfl.api.model.VersionNum;
import edu.wisc.library.ocfl.api.util.Enforce;
import edu.wisc.library.ocfl.core.ObjectPaths;
import edu.wisc.library.ocfl.core.db.ObjectDetailsDatabase;
import edu.wisc.library.ocfl.core.db.OcflObjectDetails;
import edu.wisc.library.ocfl.core.extension.OcflExtensionConfig;
import edu.wisc.library.ocfl.core.inventory.SidecarMapper;
import edu.wisc.library.ocfl.core.model.Inventory;
import edu.wisc.library.ocfl.core.util.DigestUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.util.Map;
import java.util.stream.Stream;

public class ObjectDetailsDbOcflStorage extends AbstractOcflStorage {

    private static final Logger LOG = LoggerFactory.getLogger(ObjectDetailsDbOcflStorage.class);

    private final ObjectDetailsDatabase objectDetailsDb;
    private final OcflStorage delegate;

    public ObjectDetailsDbOcflStorage(ObjectDetailsDatabase objectDetailsDb, OcflStorage delegate) {
        this.objectDetailsDb = Enforce.notNull(objectDetailsDb, "objectDetailsDb cannot be null");
        this.delegate = Enforce.notNull(delegate, "delegate cannot be null");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doInitialize(OcflExtensionConfig layoutConfig) {
        delegate.initializeStorage(ocflVersion, layoutConfig, inventoryMapper, supportEvaluator);
    }

    /**
     * If the object is stored in the database with its inventory, then the inventory is loaded from there. Otherwise,
     * it's pulled from the underlying storage and inserted into the database before it's returned.
     *
     * @param objectId the id of the object to load
     * @return inventory
     */
    @Override
    public Inventory loadInventory(String objectId) {
        ensureOpen();

        var details = objectDetailsDb.retrieveObjectDetails(objectId);

        if (details == null || details.getInventoryBytes() == null) {
            var inventory = delegate.loadInventory(objectId);

            if (inventory != null) {
                try {
                    var inventoryBytes = delegate.getInventoryBytes(inventory.getId(), inventory.getHead());
                    objectDetailsDb.addObjectDetails(inventory, inventory.getCurrentDigest(), inventoryBytes);
                } catch (Exception e) {
                    LOG.warn("Failed to cache inventory for object <{}>", objectId, e);
                }
            }

            return inventory;
        }

        return parseInventory(details);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getInventoryBytes(String objectId, VersionNum versionNum) {
        return delegate.getInventoryBytes(objectId, versionNum);
    }

    /**
     * Writes the new object version to the underlying storage within a transaction that updates the object details
     * state within the database.
     *
     * @param inventory the updated object inventory
     * @param stagingDir the directory that contains the composed contents of the new object version
     */
    @Override
    public void storeNewVersion(Inventory inventory, Path stagingDir) {
        ensureOpen();

        updateDetails(inventory, stagingDir, () -> delegate.storeNewVersion(inventory, stagingDir));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, OcflFileRetriever> getObjectStreams(Inventory inventory, VersionNum versionNum) {
        ensureOpen();

        return delegate.getObjectStreams(inventory, versionNum);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void reconstructObjectVersion(Inventory inventory, VersionNum versionNum, Path stagingDir) {
        ensureOpen();

        delegate.reconstructObjectVersion(inventory, versionNum, stagingDir);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void purgeObject(String objectId) {
        ensureOpen();

        try {
            delegate.purgeObject(objectId);
        } finally {
            safeDeleteDetails(objectId);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void rollbackToVersion(Inventory inventory, VersionNum versionNum) {
        ensureOpen();

        try {
            delegate.rollbackToVersion(inventory, versionNum);
        } finally {
            safeDeleteDetails(inventory.getId());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void commitMutableHead(Inventory oldInventory, Inventory newInventory, Path stagingDir) {
        ensureOpen();

        updateDetails(newInventory, stagingDir, () -> delegate.commitMutableHead(oldInventory, newInventory, stagingDir));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void purgeMutableHead(String objectId) {
        ensureOpen();

        try {
            delegate.purgeMutableHead(objectId);
        } finally {
            safeDeleteDetails(objectId);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean containsObject(String objectId) {
        ensureOpen();

        return delegate.containsObject(objectId);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String objectRootPath(String objectId) {
        ensureOpen();

        return delegate.objectRootPath(objectId);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Stream<String> listObjectIds() {
        ensureOpen();

        return delegate.listObjectIds();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void exportVersion(ObjectVersionId objectVersionId, Path outputPath) {
        ensureOpen();

        delegate.exportVersion(objectVersionId, outputPath);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void exportObject(String objectId, Path outputPath) {
       ensureOpen();

       delegate.exportObject(objectId, outputPath);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void importObject(String objectId, Path objectPath) {
       ensureOpen();

       delegate.importObject(objectId, objectPath);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ValidationResults validateObject(String objectId, boolean contentFixityCheck) {
        ensureOpen();

        return delegate.validateObject(objectId, contentFixityCheck);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() {
        delegate.close();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void invalidateCache(String objectId) {
        objectDetailsDb.deleteObjectDetails(objectId);
        delegate.invalidateCache(objectId);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void invalidateCache() {
        objectDetailsDb.deleteAllDetails();
        delegate.invalidateCache();
    }

    private void updateDetails(Inventory inventory, Path stagingDir, Runnable runnable) {
        var inventoryPath = ObjectPaths.inventoryPath(stagingDir);
        var sidecarPath = ObjectPaths.inventorySidecarPath(stagingDir, inventory);
        var digest = SidecarMapper.readDigest(sidecarPath);
        try {
            objectDetailsDb.updateObjectDetails(inventory, digest, inventoryPath, runnable);
        } catch (ObjectOutOfSyncException e) {
            // TODO it's possible that the ObjectDetails should be deleted on any SQLException
            safeDeleteDetails(inventory.getId());
            throw e;
        }
    }

    private void safeDeleteDetails(String objectId) {
        try {
            objectDetailsDb.deleteObjectDetails(objectId);
        } catch (Exception e) {
            LOG.error("Failed to delete object details for object {}. You may need to manually remove the record from the database.",
                    objectId, e);
        }
    }

    private Inventory parseInventory(OcflObjectDetails details) {
        var actualDigest = DigestUtil.computeDigestHex(details.getDigestAlgorithm(), details.getInventoryBytes());

        if (!details.getInventoryDigest().equalsIgnoreCase(actualDigest)) {
            throw new FixityCheckException(String.format("Expected %s digest: %s; Actual: %s",
                    details.getDigestAlgorithm(), details.getInventoryDigest(), actualDigest));
        }

        if (details.getRevisionNum() == null) {
            return inventoryMapper.read(details.getObjectRootPath(), details.getInventoryDigest(), new ByteArrayInputStream(details.getInventoryBytes()));
        } else {
            return inventoryMapper.readMutableHead(details.getObjectRootPath(), details.getInventoryDigest(),
                    details.getRevisionNum(), new ByteArrayInputStream(details.getInventoryBytes()));
        }
    }

}
