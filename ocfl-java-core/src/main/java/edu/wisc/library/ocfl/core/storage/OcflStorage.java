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
import edu.wisc.library.ocfl.api.exception.NotFoundException;
import edu.wisc.library.ocfl.api.exception.ObjectOutOfSyncException;
import edu.wisc.library.ocfl.api.model.ObjectVersionId;
import edu.wisc.library.ocfl.api.model.OcflVersion;
import edu.wisc.library.ocfl.api.model.ValidationResults;
import edu.wisc.library.ocfl.api.model.VersionNum;
import edu.wisc.library.ocfl.core.extension.ExtensionSupportEvaluator;
import edu.wisc.library.ocfl.core.extension.OcflExtensionConfig;
import edu.wisc.library.ocfl.core.inventory.InventoryMapper;
import edu.wisc.library.ocfl.core.model.Inventory;
import edu.wisc.library.ocfl.core.storage.filesystem.FileSystemOcflStorage;

import java.nio.file.Path;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Extension point that allows the OCFL repository to use any number of storage implementations so long as they
 * conform to this interface.
 *
 * <p>{@link #initializeStorage} MUST be called before the object may be used.
 *
 * @see FileSystemOcflStorage
 */
public interface OcflStorage {

    /**
     * Initializes the OCFL root. If it is an existing OCFL repository and the root has already been initialized, then
     * this method should do nothing. This method must be called before the object may be used.
     *
     * <p>layoutConfig may be null if the OCFL repository already exists, in which case the existing configuration is used.
     * If layoutConfig is specified for an existing repository, initialization will fail if the configurations do not match.
     *
     * @param ocflVersion the OCFL version
     * @param layoutConfig the storage layout configuration, may be null to auto-detect existing configuration
     * @param inventoryMapper the mapper to use for inventory serialization
     * @param supportEvaluator the evaluator that determines what to do when unsupported extensions are encountered
     */
    void initializeStorage(OcflVersion ocflVersion,
                           OcflExtensionConfig layoutConfig,
                           InventoryMapper inventoryMapper,
                           ExtensionSupportEvaluator supportEvaluator);

    /**
     * Returns a verified copy of the most recent object inventory. Null is returned if the object is not found.
     *
     * <p>DefaultOcflRepository calls this method within a read lock and caches the result.
     *
     * @param objectId the id of the object to load
     * @return the deserialized inventory or null if the object was not found
     * @throws FixityCheckException if the inventory fails its fixity check
     */
    Inventory loadInventory(String objectId);

    /**
     * Returns the raw inventory bytes for the specified object version
     *
     * @param objectId the id of the object
     * @param versionNum the version number
     * @return the raw inventory bytes
     * @throws NotFoundException if object or version cannot be found
     */
    byte[] getInventoryBytes(String objectId, VersionNum versionNum);

    /**
     * Persists a fully composed object version. The contents of the stagingDir are the contents of the new version,
     * including a serialized copy of the updated inventory. It is safe to move the entire stagingDir to object-root/version.
     *
     * <p>DefaultOcflRepository calls this method from a write lock.
     *
     * <p>This method MUST ensure that the version to be persisted is not out of sync with the current object state, and
     * reject the request if it is.
     *
     * <p>After persisting the new version directory, the new inventory file is installed in the object root.
     *
     * @param inventory the updated object inventory
     * @param stagingDir the directory that contains the composed contents of the new object version
     * @throws ObjectOutOfSyncException if the version cannot be created because it already exists
     * @throws FixityCheckException if one of the files in the version fails its fixity check
     */
    void storeNewVersion(Inventory inventory, Path stagingDir);

    /**
     * Returns a map of {@code OcflFileRetriever} objects that are used to lazy-load object files. The map keys are the
     * object relative file paths of all of the files in the specified version of the object.
     *
     * @param inventory the object's inventory
     * @param versionNum the id of the version to load
     * @return a map of {@code OcflFileRetriever} objects keyed off the object relative file paths of all of the files in the object
     */
    Map<String, OcflFileRetriever> getObjectStreams(Inventory inventory, VersionNum versionNum);

    /**
     * Reconstructs a complete object at the specified version in the stagingDir.
     *
     * <p>The fixity of every file must be checked after copying it to the stagingDir.
     *
     * @param inventory the deserialized object inventory
     * @param versionNum the id of the version to reconstruct
     * @param stagingDir the location the reconstructed object should be assembled in
     * @throws FixityCheckException if one of the files fails its fixity check
     */
    void reconstructObjectVersion(Inventory inventory, VersionNum versionNum, Path stagingDir);

    /**
     * Permanently removes an object from the repository. Objects that have been purged are NOT recoverable. If an object
     * with the specified id cannot be found it is considered purged and no exception is thrown.
     *
     * <p>DefaultOcflRepository calls this method from a write lock.
     *
     * @param objectId the id of the object to purge
     */
    void purgeObject(String objectId);

    /**
     * Moves the mutable HEAD of any object into the object root and into an immutable version. The mutable HEAD does
     * not exist at the end of the operation.
     *
     * <p>DefaultOcflRepository calls this method from a write lock.
     *
     * @param oldInventory the deserialized inventory of the object BEFORE it was rewritten for the commit
     * @param newInventory the deserialized inventory of the object AFTER it was rewritten for the commit
     * @param stagingDir the path to the staging directory that contains the inventory files
     */
    void commitMutableHead(Inventory oldInventory, Inventory newInventory, Path stagingDir);

    /**
     * Permanently removes the mutable HEAD of an object. If the object does not have a mutable HEAD nothing happens.
     *
     * <p>DefaultOcflRepository calls this method from a write lock.
     *
     * @param objectId the id of the object to purge the mutable HEAD of
     */
    void purgeMutableHead(String objectId);

    /**
     * Sets the head object version to the specified version by reinstating that version's inventory into the object
     * root, and purging all intermediary versions.
     *
     * @param inventory the deserialized object inventory
     * @param versionNum the id of the version to rollback to
     */
    void rollbackToVersion(Inventory inventory, VersionNum versionNum);

    /**
     * Returns true if an object with the specified id exists in the repository.
     *
     * @param objectId the id of the object
     * @return true if the object exists and false otherwise
     */
    boolean containsObject(String objectId);

    /**
     * Returns the path from the storage root to the object root.
     *
     * @param objectId the id of the object
     * @return the relative path from the storage root to the object root
     */
    String objectRootPath(String objectId);

    /**
     * Returns a stream of object ids for all of the OCFL objects stored in a repository. This stream is populated on demand,
     * and it may be quite slow. Remember to close the stream when you are done with it.
     *
     * @return stream of object ids
     */
    Stream<String> listObjectIds();

    /**
     * Copies a raw OCFL object version to the specified directory. For example, if you export version 2 of an object,
     * then the entire contents of the object's v2 directory will be exported the output directory. This is primarily
     * useful for backing up OCFL versions, as an isolated OCFL object version is not usable in and of itself.
     *
     * <p>The outputPath MUST NOT exist, but its parent MUST exist.
     *
     * <p>Mutable HEAD versions cannot be exported
     *
     * @param objectVersionId the id of the object and version to export
     * @param outputPath the directory to write the exported version to, must NOT exist
     * @throws NotFoundException when no object can be found for the specified objectVersionId
     */
    void exportVersion(ObjectVersionId objectVersionId, Path outputPath);

    /**
     * Copies a raw OCFL object to the specified directory. The output is a complete copy of everything that's contained
     * in the object's root directory.
     *
     * <p>The outputPath MUST NOT exist, but its parent MUST exist.
     *
     * @param objectId the id of the object to export
     * @param outputPath the directory to write the exported object to, must NOT exist
     * @throws NotFoundException when no object can be found for the specified objectId
     */
    void exportObject(String objectId, Path outputPath);

    /**
     * Moves an entire OCFL object into the repository. This object cannot already exist.
     *
     * @param objectId the id of the object to import
     * @param objectPath the directory that contains the object to import
     */
    void importObject(String objectId, Path objectPath);

    /**
     * Shutsdown any resources the OclfStorage may have open, such as ExecutorServices. Once closed, additional requests
     * will be rejected. Calling this method is optional, and it is more efficient to just let the shutdown hooks take care
     * of closing the resources.
     */
    void close();

    /**
     * Validates the specified object against the OCFL 1.0 spec.
     *
     * @param objectId the id of the object to validate
     * @param contentFixityCheck true if the fixity of the content files should be verified
     * @return the validation results
     * @throws NotFoundException if the object does not exist.
     */
    ValidationResults validateObject(String objectId, boolean contentFixityCheck);

    /**
     * If the OcflStorage is using an inventory cache, then this method invalidates the cache entry for the
     * specified object. Otherwise, nothing happens.
     *
     * @param objectId the ID of the object to invalidate in the cache
     */
    void invalidateCache(String objectId);

    /**
     * If the OcflStorage is using an inventory cache, then this method invalidates all entries in the cache.
     * Otherwise, nothing happens.
     */
    void invalidateCache();

}
