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
import edu.wisc.library.ocfl.api.exception.ObjectOutOfSyncException;
import edu.wisc.library.ocfl.api.model.ObjectVersionId;
import edu.wisc.library.ocfl.api.model.ValidationResults;
import edu.wisc.library.ocfl.api.model.VersionNum;
import edu.wisc.library.ocfl.api.util.Enforce;
import edu.wisc.library.ocfl.core.cache.Cache;
import edu.wisc.library.ocfl.core.extension.OcflExtensionConfig;
import edu.wisc.library.ocfl.core.model.Inventory;

import java.nio.file.Path;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Adds an Inventory caching layer on top of an OcflStorage implementation.
 */
public class CachingOcflStorage extends AbstractOcflStorage {

    private final Cache<String, Inventory> inventoryCache;
    private final OcflStorage delegate;

    public CachingOcflStorage(Cache<String, Inventory> inventoryCache, OcflStorage delegate) {
        this.inventoryCache = Enforce.notNull(inventoryCache, "inventoryCache cannot be null");
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
     * If the inventory is cached, it's returned immediately. Otherwise, it's fetched from the delegate storage.
     *
     * @param objectId the id of the object to load
     * @return inventory
     */
    @Override
    public Inventory loadInventory(String objectId) {
        ensureOpen();

        return inventoryCache.get(objectId, delegate::loadInventory);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getInventoryBytes(String objectId, VersionNum versionNum) {
        return delegate.getInventoryBytes(objectId, versionNum);
    }

    /**
     * Stores a new version of an object and writes the inventory to the cache.
     *
     * @param inventory the updated object inventory
     * @param stagingDir the directory that contains the composed contents of the new object version
     */
    @Override
    public void storeNewVersion(Inventory inventory, Path stagingDir) {
        ensureOpen();

        try {
            delegate.storeNewVersion(inventory, stagingDir);
            inventoryCache.put(inventory.getId(), inventory);
        } catch (ObjectOutOfSyncException e) {
            inventoryCache.invalidate(inventory.getId());
            throw e;
        }
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
            inventoryCache.invalidate(objectId);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void commitMutableHead(Inventory oldInventory, Inventory newInventory, Path stagingDir) {
        ensureOpen();

        try {
            delegate.commitMutableHead(oldInventory, newInventory, stagingDir);
            inventoryCache.put(newInventory.getId(), newInventory);
        } catch (ObjectOutOfSyncException e) {
            inventoryCache.invalidate(newInventory.getId());
            throw e;
        }
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
            inventoryCache.invalidate(objectId);
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
            inventoryCache.invalidate(inventory.getId());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean containsObject(String objectId) {
        ensureOpen();

        if (inventoryCache.contains(objectId)) {
            return true;
        }

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
        inventoryCache.invalidate(objectId);
        delegate.invalidateCache(objectId);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void invalidateCache() {
        inventoryCache.invalidateAll();
        delegate.invalidateCache();
    }
}
