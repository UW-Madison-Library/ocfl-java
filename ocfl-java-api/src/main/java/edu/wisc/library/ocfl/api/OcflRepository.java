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

package edu.wisc.library.ocfl.api;

import edu.wisc.library.ocfl.api.exception.AlreadyExistsException;
import edu.wisc.library.ocfl.api.exception.CorruptObjectException;
import edu.wisc.library.ocfl.api.exception.NotFoundException;
import edu.wisc.library.ocfl.api.exception.ObjectOutOfSyncException;
import edu.wisc.library.ocfl.api.exception.OcflStateException;
import edu.wisc.library.ocfl.api.exception.ValidationException;
import edu.wisc.library.ocfl.api.model.FileChangeHistory;
import edu.wisc.library.ocfl.api.model.ObjectDetails;
import edu.wisc.library.ocfl.api.model.ObjectVersionId;
import edu.wisc.library.ocfl.api.model.OcflObjectVersion;
import edu.wisc.library.ocfl.api.model.VersionDetails;
import edu.wisc.library.ocfl.api.model.VersionInfo;

import java.nio.file.Path;
import java.util.function.Consumer;
import java.util.stream.Stream;

/**
 * Interface for interacting with an OCFL repository.
 */
public interface OcflRepository {

    /**
     * Adds the object rooted at the given path to the OCFL repository under the given objectVersionId. If their is an existing
     * object with the id, then a new version of the object is created.
     *
     * <p>It is important to note that this is NOT an additive operation. An existing object's state is NOT carried forward
     * into the new version. The only files that are included in the new version are the files that are present in the
     * supplied directory. However, files are still deduped against files present in prior versions.
     *
     * <p>This method should only be used when writing new or fully composed objects.
     *
     * <p>If the current HEAD version of the object does not match the version specified in the request, the update will
     * be rejected. If the request specifies the HEAD version, then no version check will be preformed.
     *
     * <p>By default, files are copied into the OCFL repository. If {@link OcflOption#MOVE_SOURCE} is specified, then
     * files will be moved instead. Warning: If an exception occurs and the new version is not created, the files that were
     * will be lost. This operation is more efficient but less safe than the default copy.
     *
     * @param objectVersionId the id to store the object under. If set to a specific version, then the update will only occur
     *                 if the specified version matches the head object version in the repository.
     * @param path the path to the object content
     * @param versionInfo information about the changes to the object. Can be null.
     * @param options optional config options. Use {@link OcflOption#MOVE_SOURCE} to move files into the repo instead of copying.
     * @return The objectId and version of the new object version
     * @throws ObjectOutOfSyncException when the object was modified by another process before these changes could be committed
     */
    ObjectVersionId putObject(ObjectVersionId objectVersionId, Path path, VersionInfo versionInfo, OcflOption... options);

    /**
     * Updates an existing object OR create a new object by selectively adding, removing, moving files within the object,
     * and creating a new version that encapsulates all of the changes. It always operates on the HEAD version of an object,
     * but a specific version can be specified to ensure no intermediate changes were made to the object.
     *
     * <p>If the current HEAD version of the object does not match the version specified in the request, the update will
     * be rejected. If the request specifies the HEAD version, then no version check will be preformed.
     *
     * @param objectVersionId the id of the object. If set to a specific version, then the update will only occur
     *                 if the specified version matches the head object version in the repository.
     * @param versionInfo information about the changes to the object. Can be null.
     * @param objectUpdater code block within which updates to an object may be made
     * @return The objectId and version of the new object version
     * @throws NotFoundException when no object can be found for the specified objectVersionId
     * @throws ObjectOutOfSyncException when the object was modified by another process before these changes could be committed
     */
    ObjectVersionId updateObject(ObjectVersionId objectVersionId, VersionInfo versionInfo, Consumer<OcflObjectUpdater> objectUpdater);

    /**
     * Returns the entire contents of the object at the specified version. The outputPath MUST NOT exist, but its parent
     * MUST exist.
     *
     * @param objectVersionId the id and version of an object to retrieve
     * @param outputPath the directory to write the object files to, must NOT exist
     * @throws NotFoundException when no object can be found for the specified objectVersionId
     */
    void getObject(ObjectVersionId objectVersionId, Path outputPath);

    /**
     * Returns the details about a specific version of an object along with lazy-loading handles to all of the files in
     * the object.
     *
     * @param objectVersionId the id and version of an object to retrieve
     * @return lazy-loading object version
     * @throws NotFoundException when no object can be found for the specified objectVersionId
     */
    OcflObjectVersion getObject(ObjectVersionId objectVersionId);

    /**
     * Returns all of the details about an object and all of its versions.
     *
     * @param objectId the id of the object to describe
     * @return details about the object
     * @throws NotFoundException when no object can be found for the specified objectId
     */
    ObjectDetails describeObject(String objectId);

    /**
     * Returns the details about a specific version of an object.
     *
     * @param objectVersionId the id and version of the object to describe
     * @return details about the object version
     * @throws NotFoundException when no object can be found for the specified objectVersionId
     */
    VersionDetails describeVersion(ObjectVersionId objectVersionId);

    /**
     * Retrieves the complete change history for a logical path within an object. Each entry in the change history marks
     * an object version where the contents at the logical path were changed or the logical path was removed. Object versions
     * where there were no changes to the logical path are not included.
     *
     * @param objectId the id of the object
     * @param logicalPath the logical path
     * @return the change history for the logical path
     * @throws NotFoundException when object or logical path cannot be found
     */
    FileChangeHistory fileChangeHistory(String objectId, String logicalPath);

    /**
     * Returns true if an object with the specified id exists in the repository.
     *
     * @param objectId the id of the object
     * @return true if the object exists and false otherwise
     */
    boolean containsObject(String objectId);

    /**
     * Returns a stream of OCFL object ids for all of the objects stored in the repository. This stream is populated on
     * demand. Warning: Iterating over every object id may be quite slow. Remember to close the stream when you are done with it.
     *
     * @return steam of all OCFL object ids
     */
    Stream<String> listObjectIds();

    /**
     * Permanently removes an object from the repository. Objects that have been purged are NOT recoverable. If an object
     * with the specified id cannot be found it is considered purged and no exception is thrown.
     *
     * @param objectId the id of the object to purge
     */
    void purgeObject(String objectId);

    /**
     * Creates a new head version by copying the state of the specified version. This is a non-destructive way to roll an
     * object back to a prior version without altering its version history.
     *
     * <p>Use {@link #rollbackToVersion} instead if you want to roll an object back to a prior version by purging all
     * intermediary versions.
     *
     * @param objectVersionId the id of the object and version to replicate
     * @param versionInfo information about the changes to the object. Can be null.
     * @return The objectId and version of the new object version
     * @throws NotFoundException when no object can be found for the specified objectVersionId
     */
    ObjectVersionId replicateVersionAsHead(ObjectVersionId objectVersionId, VersionInfo versionInfo);

    /**
     * Rolls an object back to the specified version. The specified version must exist and is made the head version.
     * Any intermediary versions are PURGED. There is no way to recover versions that are purged as part of rolling back
     * to a previous version.
     *
     * <p>Use {@link #replicateVersionAsHead} instead if you want to roll an object back to a prior version but do not want to
     * delete intermediary versions.
     *
     * <p>Using this method is NOT recommended unless necessary as it is inconsistent with the OCFL paradigm of version permanence.
     *
     * @param objectVersionId the id of the object and version to rollback to
     * @throws NotFoundException when no object can be found for the specified objectVersionId
     */
    void rollbackToVersion(ObjectVersionId objectVersionId);

    /**
     * Copies a raw OCFL object version to the specified directory. For example, if you export version 2 of an object,
     * then the entire contents of the object's v2 directory will be exported the output directory. This is primarily
     * useful for backing up OCFL versions, as an isolated OCFL object version is not usable in and of itself.
     *
     * <p>Mutable HEAD versions cannot be exported
     *
     * <p>This method WILL NOT cleanup files left in the output directory if it fails.
     *
     * @param objectVersionId the id of the object and version to export
     * @param outputPath the directory to write the exported version to, if it does not exist it will be created
     * @param options optional config options.
     * @throws NotFoundException when no object can be found for the specified objectVersionId
     */
    void exportVersion(ObjectVersionId objectVersionId, Path outputPath, OcflOption... options);

    /**
     * Copies a raw OCFL object to the specified directory. The output is a complete copy of everything that's contained
     * in the object's root directory.
     *
     * <p>The outputPath MUST NOT exist, but its parent MUST exist.
     *
     * <p>This method WILL NOT cleanup files left in the output directory if it fails.
     *
     * @param objectId the id of the object to export
     * @param outputPath the directory to write the exported object to, if it does not exist it will be created
     * @param options optional config options. Use {@link OcflOption#NO_VALIDATION} to disable export validation.
     * @throws NotFoundException when no object can be found for the specified objectId
     * @throws ValidationException when the exported object fails validation
     */
    void exportObject(String objectId, Path outputPath, OcflOption... options);

    /**
     * Imports the OCFL object version at the specified path into the repository. In order to successfully import the
     * version the following conditions must be met:
     * <ul>
     *     <li>The import version must be valid</li>
     *     <li>The import version must be the next sequential version of the current version of the object in the repository</li>
     *     <li>The version history of in the import version must be identical to the existing version history</li>
     *     <li>Inventory level properties such as digest algorithm and type cannot change</li>
     * </ul>
     *
     * @param versionPath path to the OCFL object version to import on disk
     * @param options optional config options. Use {@link OcflOption#MOVE_SOURCE} to move files into the repo instead of copying.
     *                Use {@link OcflOption#NO_VALIDATION} to disable file validation, version inventory is still validated.
     * @throws OcflStateException if the version number of the import is not the next sequential version for the object
     */
    void importVersion(Path versionPath, OcflOption... options);

    /**
     * Imports an entire OCFL object into the repository. The object cannot already exist in the repository, and the
     * object must be valid. The object is validated extensively as part of the import process.
     *
     * @param objectPath path to the OCFL object to import on disk
     * @param options optional config options. Use {@link OcflOption#MOVE_SOURCE} to move files into the repo instead of copying.
     *                Use {@link OcflOption#NO_VALIDATION} to disable file validation, root inventory is still validated.
     * @throws AlreadyExistsException if the object trying to be imported is already in the repository
     */
    void importObject(Path objectPath, OcflOption... options);

    /**
     * Closes any resources the OcflRepository may have open, such as ExecutorServices. Once closed, additional requests
     * will be rejected. Calling this method is optional, and it is more efficient to just let the shutdown hooks take care
     * of closing the resources.
     */
    void close();

    /**
     * Returns a copy of the OCFL configuration.
     *
     * @return copy of the OCFL configuration
     */
    OcflConfig config();

    /**
     * If the OcflRepository is using an inventory cache, then this method invalidates the cache entry for the
     * specified object. Otherwise, nothing happens.
     *
     * @param objectId the ID of the object to invalidate in the cache
     */
    void invalidateCache(String objectId);

    /**
     * If the OcflRepository is using an inventory cache, then this method invalidates all entries in the cache.
     * Otherwise, nothing happens.
     */
    void invalidateCache();

}
