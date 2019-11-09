package edu.wisc.library.ocfl.core.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import edu.wisc.library.ocfl.api.OcflFileRetriever;
import edu.wisc.library.ocfl.api.exception.FixityCheckException;
import edu.wisc.library.ocfl.api.exception.NotFoundException;
import edu.wisc.library.ocfl.api.exception.ObjectOutOfSyncException;
import edu.wisc.library.ocfl.api.exception.RuntimeIOException;
import edu.wisc.library.ocfl.api.model.VersionId;
import edu.wisc.library.ocfl.api.util.Enforce;
import edu.wisc.library.ocfl.core.DigestAlgorithmRegistry;
import edu.wisc.library.ocfl.core.ObjectPaths;
import edu.wisc.library.ocfl.core.OcflConstants;
import edu.wisc.library.ocfl.core.concurrent.ExecutorTerminator;
import edu.wisc.library.ocfl.core.concurrent.ParallelProcess;
import edu.wisc.library.ocfl.core.inventory.InventoryMapper;
import edu.wisc.library.ocfl.core.mapping.ObjectIdPathMapper;
import edu.wisc.library.ocfl.core.model.DigestAlgorithm;
import edu.wisc.library.ocfl.core.model.Inventory;
import edu.wisc.library.ocfl.core.model.RevisionId;
import edu.wisc.library.ocfl.core.model.Version;
import edu.wisc.library.ocfl.core.util.DigestUtil;
import edu.wisc.library.ocfl.core.util.FileUtil;
import edu.wisc.library.ocfl.core.util.NamasteTypeFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

public class FileSystemOcflStorage implements OcflStorage {

    private static final Logger LOG = LoggerFactory.getLogger(FileSystemOcflStorage.class);

    private boolean closed = false;

    private Path repositoryRoot;
    private ObjectIdPathMapper objectIdPathMapper;
    private InventoryMapper inventoryMapper;
    private ObjectMapper objectMapper;

    private ParallelProcess parallelProcess;

    private boolean checkNewVersionFixity;

    /**
     * Creates a new FileSystemOcflStorage object. Its thread pool is size is set to the number of available processors,
     * and fixity checks are not performed when a version is moved into the object.
     *
     * @param repositoryRoot OCFL repository root directory
     * @param objectIdPathMapper Mapper for mapping object ids to paths within the repository root
     */
    public FileSystemOcflStorage(Path repositoryRoot, ObjectIdPathMapper objectIdPathMapper) {
        this(repositoryRoot, objectIdPathMapper, Runtime.getRuntime().availableProcessors(),
                false, InventoryMapper.defaultMapper(),
                new ObjectMapper().configure(SerializationFeature.INDENT_OUTPUT, true));
    }

    /**
     * Creates a new FileSystemOcflStorage object. Consider using {@code FileSystemOcflStorageBuilder} instead.
     *
     * @param repositoryRoot OCFL repository root directory
     * @param objectIdPathMapper Mapper for mapping object ids to paths within the repository root
     * @param threadPoolSize The size of the object's thread pool, used when calculating digests
     * @param checkNewVersionFixity If a fixity check should be performed on the contents of a new version's
     *                              content directory after moving it into the object. In most cases, this should not be
     *                              required, especially if the OCFL client's work directory is on the same volume as the
     *                              storage root.
     * @param inventoryMapper mapper used to parse inventory files
     * @param objectMapper mapper used to write ocfl_layout.json
     */
    public FileSystemOcflStorage(Path repositoryRoot, ObjectIdPathMapper objectIdPathMapper, int threadPoolSize,
                                 boolean checkNewVersionFixity, InventoryMapper inventoryMapper, ObjectMapper objectMapper) {
        this.repositoryRoot = Enforce.notNull(repositoryRoot, "repositoryRoot cannot be null");
        this.objectIdPathMapper = Enforce.notNull(objectIdPathMapper, "objectIdPathMapper cannot be null");
        this.inventoryMapper = Enforce.notNull(inventoryMapper, "inventoryMapper cannot be null");
        Enforce.expressionTrue(threadPoolSize > 0, threadPoolSize, "threadPoolSize must be greater than 0");
        this.parallelProcess = new ParallelProcess(ExecutorTerminator.addShutdownHook(Executors.newFixedThreadPool(threadPoolSize)));
        this.checkNewVersionFixity = checkNewVersionFixity;
        this.objectMapper = Enforce.notNull(objectMapper, "objectMapper cannot be null");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Inventory loadInventory(String objectId) {
        ensureOpen();

        Inventory inventory = null;
        var objectRootPath = objectRootPathFull(objectId);

        if (Files.exists(objectRootPath)) {
            var mutableHeadInventoryPath = ObjectPaths.mutableHeadInventoryPath(objectRootPath);
            if (Files.exists(mutableHeadInventoryPath)) {
                ensureRootObjectHasNotChanged(objectId, objectRootPath);
                inventory = parseMutableHeadInventory(mutableHeadInventoryPath);
            } else {
                inventory = parseInventory(ObjectPaths.inventoryPath(objectRootPath));
            }
        }

        return inventory;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void storeNewVersion(Inventory inventory, Path stagingDir) {
        ensureOpen();

        var objectRootPath = objectRootPathFull(inventory.getId());
        var objectRoot = ObjectPaths.objectRoot(inventory, objectRootPath);

        if (inventory.hasMutableHead()) {
            storeNewMutableHeadVersion(inventory, objectRoot, stagingDir);
        } else {
            storeNewVersion(inventory, objectRoot, stagingDir);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, OcflFileRetriever> getObjectStreams(Inventory inventory, VersionId versionId) {
        ensureOpen();

        var objectRootPath = objectRootPathFull(inventory.getId());
        var version = ensureVersion(inventory, versionId);
        var algorithm = inventory.getDigestAlgorithm();

        var map = new HashMap<String, OcflFileRetriever>(version.getState().size());

        version.getState().forEach((digest, paths) -> {
            var srcPath = objectRootPath.resolve(ensureManifestPath(inventory, digest));

            paths.forEach(path -> {
                map.put(path, new FileSystemOcflFileRetriever(srcPath, algorithm, digest));
            });
        });

        return map;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void reconstructObjectVersion(Inventory inventory, VersionId versionId, Path stagingDir) {
        ensureOpen();

        var objectRootPath = objectRootPathFull(inventory.getId());
        var version = ensureVersion(inventory, versionId);

        parallelProcess.collection(version.getState().entrySet(), entry -> {
            var id = entry.getKey();
            var files = entry.getValue();

            var src = ensureManifestPath(inventory, id);
            var srcPath = objectRootPath.resolve(src);

            for (var dstPath : files) {
                var path = stagingDir.resolve(dstPath);

                if (Thread.interrupted()) {
                    break;
                } else {
                    FileUtil.copyFileMakeParents(srcPath, path);
                }

                if (Thread.interrupted()) {
                    break;
                } else {
                    var digest = DigestUtil.computeDigest(inventory.getDigestAlgorithm(), path);
                    var paths = inventory.getFilePaths(digest);
                    if (paths == null || !paths.contains(src)) {
                        throw new FixityCheckException(String.format("File %s in object %s failed its %s fixity check. Was: %s",
                                path, inventory.getId(), inventory.getDigestAlgorithm().getOcflName(), digest));
                    }
                }
            }
        });
    }

    // TODO should this have a different return value?
    /**
     * {@inheritDoc}
     */
    @Override
    public InputStream retrieveFile(Inventory inventory, String fileId) {
        ensureOpen();

        var objectRootPath = objectRootPathFull(inventory.getId());

        var filePath = inventory.getFilePath(fileId);

        if (filePath == null) {
            throw new NotFoundException(String.format("File %s does not exist in object %s.", fileId, inventory.getId()));
        }

        try {
            return Files.newInputStream(objectRootPath.resolve(filePath));
        } catch (IOException e) {
            throw new RuntimeIOException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void purgeObject(String objectId) {
        ensureOpen();

        var objectRootPath = objectRootPathFull(objectId);

        if (Files.exists(objectRootPath)) {
            try (var paths = Files.walk(objectRootPath)) {
                paths.sorted(Comparator.reverseOrder())
                        .forEach(f -> {
                            try {
                                Files.delete(f);
                            } catch (IOException e) {
                                throw new RuntimeIOException(String.format("Failed to delete file %s while purging object %s." +
                                        " The purge failed the object may need to be deleted manually.", f, objectId), e);
                            }
                        });
            } catch (IOException e) {
                throw new RuntimeIOException(String.format("Failed to purge object %s at %s. The object may need to be deleted manually.",
                        objectId, objectRootPath), e);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void commitMutableHead(Inventory oldInventory, Inventory newInventory, Path stagingDir) {
        ensureOpen();

        var objectRootPath = objectRootPathFull(newInventory.getId());
        var objectRoot = ObjectPaths.objectRoot(newInventory, objectRootPath);

        ensureRootObjectHasNotChanged(newInventory, objectRoot);

        if (!Files.exists(objectRoot.mutableHeadVersion().inventoryFile())) {
            throw new ObjectOutOfSyncException(
                    String.format("Cannot commit mutable HEAD of object %s because a mutable HEAD does not exist.", newInventory.getId()));
        }

        var versionRoot = objectRoot.headVersion();
        var stagingRoot = ObjectPaths.version(newInventory, stagingDir);

        versionContentFixityCheck(oldInventory, objectRoot, objectRoot.mutableHeadVersion().contentPath());

        createVersionDirectory(newInventory, versionRoot);

        try {
            FileUtil.moveDirectory(objectRoot.mutableHeadPath(), versionRoot.path());

            try {
                copyInventoryToRootWithRollback(stagingRoot, objectRoot, newInventory);
                // TODO this is still slightly dangerous if one file succeeds and the other fails...
                copyInventory(stagingRoot, versionRoot);
            } catch (RuntimeException e) {
                try {
                    FileUtil.moveDirectory(versionRoot.path(), objectRoot.mutableHeadPath());
                } catch (RuntimeException e1) {
                    LOG.error("Failed to move {} back to {}", versionRoot.path(), objectRoot.mutableHeadPath(), e1);
                }
                throw e;
            }

            try {
                // TODO need to decide how to handle empty revisions..
                FileUtil.deleteEmptyDirs(versionRoot.contentPath());
            } catch (RuntimeException e) {
                // This does not fail the commit
                LOG.error("Failed to delete an empty directory. It may need to be deleted manually.", e);
            }
        } catch (RuntimeException e) {
            FileUtil.safeDeletePath(versionRoot.path());
            throw e;
        }

        // TODO failure conditions of this?
        FileUtil.safeDeletePath(objectRoot.mutableHeadExtensionPath());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void purgeMutableHead(String objectId) {
        ensureOpen();

        var objectRootPath = objectRootPathFull(objectId);
        var extensionRoot = objectRootPath.resolve(OcflConstants.MUTABLE_HEAD_EXT_PATH);

        if (Files.exists(extensionRoot)) {
            try (var paths = Files.walk(extensionRoot)) {
                paths.sorted(Comparator.reverseOrder())
                        .forEach(f -> {
                            try {
                                Files.delete(f);
                            } catch (IOException e) {
                                throw new RuntimeIOException(String.format("Failed to delete file %s while purging mutable HEAD of object %s." +
                                        " The purge failed and the mutable HEAD may need to be deleted manually.", f, objectId), e);
                            }
                        });
            } catch (IOException e) {
                throw new RuntimeIOException(String.format("Failed to purge mutable HEAD of object %s at %s. The object may need to be deleted manually.",
                        objectId, extensionRoot), e);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean containsObject(String objectId) {
        ensureOpen();

        return Files.exists(ObjectPaths.inventoryPath(objectRootPathFull(objectId)));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String objectRootPath(String objectId) {
        ensureOpen();

        return objectIdPathMapper.map(objectId);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void initializeStorage(String ocflVersion) {
        ensureOpen();

        if (!Files.exists(repositoryRoot)) {
            FileUtil.createDirectories(repositoryRoot);
        } else {
            Enforce.expressionTrue(Files.isDirectory(repositoryRoot), repositoryRoot,
                    "repositoryRoot must be a directory");
        }

        if (!FileUtil.hasChildren(repositoryRoot)) {
            // setup new repo
            // TODO perhaps this should be moved somewhere else so it can be used by other storage implementations
            new NamasteTypeFile(ocflVersion).writeFile(repositoryRoot);
            writeOcflSpec(ocflVersion);
            writeOcflLayout();
        } else {
            validateExistingRepo(ocflVersion);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() {
        closed = true;
        parallelProcess.shutdown();
    }

    private Path objectRootPathFull(String objectId) {
        return repositoryRoot.resolve(objectIdPathMapper.map(objectId));
    }

    private Inventory parseInventory(Path inventoryPath) {
        if (Files.notExists(inventoryPath)) {
            // TODO if there's not root inventory should we look for the inventory in the latest version directory?
            throw new IllegalStateException("Missing inventory at " + inventoryPath);
        }
        verifyInventory(inventoryPath);
        return inventoryMapper.read(inventoryPath);
    }

    private Inventory parseMutableHeadInventory(Path inventoryPath) {
        verifyInventory(inventoryPath);
        var revisionId = identifyLatestRevision(inventoryPath.getParent());
        return inventoryMapper.readMutableHead(revisionId, inventoryPath);
    }

    private void verifyInventory(Path inventoryPath) {
        var sidecarPath = findInventorySidecar(inventoryPath.getParent());
        var expectedDigest = readInventoryDigest(sidecarPath);
        var algorithm = getDigestAlgorithmFromSidecar(sidecarPath);

        var actualDigest = DigestUtil.computeDigest(algorithm, inventoryPath);

        if (!expectedDigest.equalsIgnoreCase(actualDigest)) {
            throw new FixityCheckException(String.format("Invalid inventory file: %s. Expected %s digest: %s; Actual: %s",
                    inventoryPath, algorithm.getOcflName(), expectedDigest, actualDigest));
        }
    }

    private RevisionId identifyLatestRevision(Path versionPath) {
        try (var files = Files.list(versionPath)) {
            var result = files.filter(Files::isDirectory)
                    .map(Path::getFileName).map(Path::toString)
                    .filter(RevisionId::isRevisionId)
                    .map(RevisionId::fromString)
                    .max(Comparator.naturalOrder());
            if (result.isEmpty()) {
                return null;
            }
            return result.get();
        } catch (IOException e) {
            throw new RuntimeIOException(e);
        }
    }

    private Path findInventorySidecar(Path objectRootPath) {
        return findGenericInventorySidecar(objectRootPath, OcflConstants.INVENTORY_FILE + ".");
    }

    private Path findGenericInventorySidecar(Path path, String prefix) {
        try (var files = Files.list(path)) {
            var sidecars = files
                    .filter(file -> file.getFileName().toString().startsWith(prefix))
                    .collect(Collectors.toList());

            if (sidecars.size() != 1) {
                throw new IllegalStateException(String.format("Expected there to be one inventory sidecar file in %s, but found %s.",
                        path, sidecars.size()));
            }

            return sidecars.get(0);
        } catch (IOException e) {
            throw new RuntimeIOException(e);
        }
    }

    private String readInventoryDigest(Path inventorySidecarPath) {
        try {
            var parts = Files.readString(inventorySidecarPath).split("\\s");
            if (parts.length == 0) {
                throw new IllegalStateException("Invalid inventory sidecar file: " + inventorySidecarPath);
            }
            return parts[0];
        } catch (IOException e) {
            throw new RuntimeIOException(e);
        }
    }

    // TODO enforce sha256/sha512?
    private DigestAlgorithm getDigestAlgorithmFromSidecar(Path inventorySidecarPath) {
        return DigestAlgorithmRegistry.getAlgorithm(
                inventorySidecarPath.getFileName().toString().substring(OcflConstants.INVENTORY_FILE.length() + 1));
    }

    private void storeNewVersion(Inventory inventory, ObjectPaths.ObjectRoot objectRoot, Path stagingDir) {
        ensureNoMutableHead(objectRoot);

        var versionRoot = objectRoot.headVersion();

        var isFirstVersion = isFirstVersion(inventory);

        try {
            if (isFirstVersion) {
                setupNewObjectDirs(objectRoot.path());
            }

            createVersionDirectory(inventory, versionRoot);

            try {
                FileUtil.moveDirectory(stagingDir, versionRoot.path());
                optionalVersionContentFixityCheck(inventory, objectRoot, versionRoot.contentPath());
                copyInventoryToRootWithRollback(versionRoot, objectRoot, inventory);
                // TODO verify inventory integrity again?
            } catch (RuntimeException e) {
                FileUtil.safeDeletePath(versionRoot.path());
                throw e;
            }
        } catch (RuntimeException e) {
            if (isFirstVersion) {
                FileUtil.safeDeletePath(objectRoot.path());
            }
            throw e;
        }
    }

    private void storeNewMutableHeadVersion(Inventory inventory, ObjectPaths.ObjectRoot objectRoot, Path stagingDir) {
        ensureRootObjectHasNotChanged(inventory, objectRoot);

        var versionRoot = objectRoot.headVersion();
        var revisionPath = versionRoot.contentRoot().headRevisionPath();
        var stagingVersionRoot = ObjectPaths.version(inventory, stagingDir);

        var isNewMutableHead = Files.notExists(versionRoot.inventoryFile());

        try {
            createRevisionDirectory(inventory, versionRoot);

            if (isNewMutableHead) {
                copyRootInventorySidecar(objectRoot, versionRoot);
            }

            try {
                FileUtil.moveDirectory(stagingVersionRoot.contentRoot().headRevisionPath(), revisionPath);
                optionalVersionContentFixityCheck(inventory, objectRoot, revisionPath);
                copyInventory(stagingVersionRoot, versionRoot);
                // TODO verify inventory integrity?
            } catch (RuntimeException e) {
                FileUtil.safeDeletePath(revisionPath);
                throw e;
            }
        } catch (RuntimeException e) {
            if (isNewMutableHead) {
                FileUtil.safeDeletePath(versionRoot.path().getParent());
            }
            throw e;
        }

        // TODO since this isn't guaranteed to have completed do we need to run it on commit?
        deleteMutableHeadFilesNotInManifest(inventory, objectRoot, versionRoot);
    }

    private void copyRootInventorySidecar(ObjectPaths.ObjectRoot objectRoot, ObjectPaths.VersionRoot versionRoot) {
        var rootSidecar = objectRoot.inventorySidecar();
        FileUtil.copy(rootSidecar,
                versionRoot.path().getParent().resolve("root-" + rootSidecar.getFileName().toString()),
                StandardCopyOption.REPLACE_EXISTING);
    }

    private void createVersionDirectory(Inventory inventory, ObjectPaths.VersionRoot versionRoot) {
        try {
            Files.createDirectory(versionRoot.path());
        } catch (FileAlreadyExistsException e) {
            throw new ObjectOutOfSyncException(
                    String.format("Failed to create a new version of object %s. Changes are out of sync with the current object state.", inventory.getId()));
        } catch (IOException e) {
            throw new RuntimeIOException(e);
        }
    }

    private void createRevisionDirectory(Inventory inventory, ObjectPaths.VersionRoot versionRoot) {
        try {
            Files.createDirectories(versionRoot.contentPath());
            Files.createDirectory(versionRoot.contentRoot().headRevisionPath());
        } catch (FileAlreadyExistsException e) {
            throw new ObjectOutOfSyncException(
                    String.format("Failed to update mutable HEAD of object %s. Changes are out of sync with the current object state.", inventory.getId()));
        } catch (IOException e) {
            throw new RuntimeIOException(e);
        }
    }

    private boolean isFirstVersion(Inventory inventory) {
        return inventory.getVersions().size() == 1;
    }

    private void setupNewObjectDirs(Path objectRootPath) {
        FileUtil.createDirectories(objectRootPath);
        new NamasteTypeFile(OcflConstants.OCFL_OBJECT_VERSION).writeFile(objectRootPath);
    }

    private void copyInventory(ObjectPaths.HasInventory source, ObjectPaths.HasInventory destination) {
        FileUtil.copy(source.inventoryFile(), destination.inventoryFile(), StandardCopyOption.REPLACE_EXISTING);
        FileUtil.copy(source.inventorySidecar(), destination.inventorySidecar(), StandardCopyOption.REPLACE_EXISTING);
    }

    private void copyInventoryToRootWithRollback(ObjectPaths.HasInventory source, ObjectPaths.ObjectRoot objectRoot, Inventory inventory) {
        try {
            copyInventory(source, objectRoot);
        } catch (RuntimeException e) {
            try {
                var previousVersionRoot = objectRoot.version(inventory.getHead().previousVersionId());
                copyInventory(previousVersionRoot, objectRoot);
            } catch (RuntimeException e1) {
                LOG.error("Failed to rollback inventory at {}", objectRoot.inventoryFile(), e1);
            }
            throw e;
        }
    }

    private void deleteMutableHeadFilesNotInManifest(Inventory inventory, ObjectPaths.ObjectRoot objectRoot, ObjectPaths.VersionRoot versionRoot) {
        var files = FileUtil.findFiles(versionRoot.contentPath());
        files.forEach(file -> {
            if (inventory.getFileId(objectRoot.path().relativize(file)) == null) {
                try {
                    Files.delete(file);
                } catch (IOException e) {
                    LOG.warn("Failed to delete file: {}. It should be manually deleted.", file, e);
                }
            }
        });
    }

    private void optionalVersionContentFixityCheck(Inventory inventory, ObjectPaths.ObjectRoot objectRoot, Path contentPath) {
        if (checkNewVersionFixity) {
            versionContentFixityCheck(inventory, objectRoot, contentPath);
        }
    }

    private void versionContentFixityCheck(Inventory inventory, ObjectPaths.ObjectRoot objectRoot, Path contentPath) {
        var version = inventory.getHeadVersion();
        var files = FileUtil.findFiles(contentPath);
        var fileIds = inventory.getFileIdsForMatchingFiles(objectRoot.path().relativize(contentPath));

        var expected = ConcurrentHashMap.<String>newKeySet(fileIds.size());
        expected.addAll(fileIds);

        parallelProcess.collection(files, file -> {
            var fileContentPath = FileUtil.pathToStringStandardSeparator(objectRoot.path().relativize(file));
            var expectedDigest = inventory.getFileId(fileContentPath);
            if (expectedDigest == null) {
                throw new IllegalStateException(String.format("File not listed in object %s manifest: %s",
                        inventory.getId(), fileContentPath));
            } else if (version.getPaths(expectedDigest) == null) {
                throw new IllegalStateException(String.format("File not found in object %s version %s state: %s",
                        inventory.getId(), inventory.getHead(), fileContentPath));
            } else {
                var actualDigest = DigestUtil.computeDigest(inventory.getDigestAlgorithm(), file);
                if (!expectedDigest.equalsIgnoreCase(actualDigest)) {
                    throw new FixityCheckException(String.format("File %s in object %s failed its %s fixity check. Expected: %s; Actual: %s",
                            file, inventory.getId(), inventory.getDigestAlgorithm().getOcflName(), expectedDigest, actualDigest));
                }

                expected.remove(expectedDigest);
            }
        });

        if (!expected.isEmpty()) {
            var filePaths = expected.stream().map(inventory::getFilePath).collect(Collectors.toList());
            throw new IllegalStateException(String.format("Object %s is missing the following files: %s", inventory.getId(), filePaths));
        }
    }

    private Version ensureVersion(Inventory inventory, VersionId versionId) {
        var version = inventory.getVersion(versionId);

        if (version == null) {
            throw new IllegalStateException(String.format("Object %s does not contain version %s", inventory.getId(), versionId));
        }

        return version;
    }

    private String ensureManifestPath(Inventory inventory, String id) {
        if (!inventory.manifestContainsId(id)) {
            throw new IllegalStateException(String.format("Missing manifest entry for %s in object %s.",
                    id, inventory.getId()));
        }
        return inventory.getFilePath(id);
    }

    private void ensureNoMutableHead(ObjectPaths.ObjectRoot objectRoot) {
        if (Files.exists(objectRoot.mutableHeadVersion().inventoryFile())) {
            // TODO modeled exception?
            throw new IllegalStateException(String.format("Cannot create a new version of object %s because it has an active mutable HEAD.",
                    objectRoot.objectId()));
        }
    }

    private void ensureRootObjectHasNotChanged(Inventory inventory, ObjectPaths.ObjectRoot objectRoot) {
        var savedSidecarPath = ObjectPaths.inventorySidecarPath(objectRoot.mutableHeadExtensionPath(), inventory);
        if (Files.exists(savedSidecarPath)) {
            var expectedDigest = readInventoryDigest(savedSidecarPath);
            var actualDigest = readInventoryDigest(objectRoot.inventorySidecar());

            if (!expectedDigest.equalsIgnoreCase(actualDigest)) {
                throw new ObjectOutOfSyncException(
                        String.format("The mutable HEAD of object %s is out of sync with the root object state.", inventory.getId()));
            }
        }
    }

    private void ensureRootObjectHasNotChanged(String objectId, Path objectRootPath) {
        var savedSidecarPath = findGenericInventorySidecar(objectRootPath.resolve(OcflConstants.MUTABLE_HEAD_EXT_PATH), "root-" + OcflConstants.INVENTORY_FILE + ".");
        if (Files.exists(savedSidecarPath)) {
            var rootSidecarPath = findInventorySidecar(objectRootPath);
            var expectedDigest = readInventoryDigest(savedSidecarPath);
            var actualDigest = readInventoryDigest(rootSidecarPath);

            if (!expectedDigest.equalsIgnoreCase(actualDigest)) {
                throw new ObjectOutOfSyncException(
                        String.format("The mutable HEAD of object %s is out of sync with the root object state.", objectId));
            }
        }
    }

    private void validateExistingRepo(String ocflVersion) {
        String existingOcflVersion = null;

        for (var file : repositoryRoot.toFile().listFiles()) {
            if (file.isFile() && file.getName().startsWith("0=")) {
                existingOcflVersion = file.getName().substring(2);
                break;
            }
        }

        if (existingOcflVersion == null) {
            throw new IllegalStateException("OCFL root is missing its root conformance declaration.");
        } else if (!existingOcflVersion.equals(ocflVersion)) {
            throw new IllegalStateException(String.format("OCFL version mismatch. Expected: %s; Found: %s",
                    ocflVersion, existingOcflVersion));
        }

        var objectRoot = identifyRandomObjectRoot(repositoryRoot);

        if (objectRoot != null) {
            var inventory = parseInventory(ObjectPaths.inventoryPath(objectRoot));
            var expectedPath = Paths.get(objectIdPathMapper.map(inventory.getId()));
            var actualPath = repositoryRoot.relativize(objectRoot);
            if (!expectedPath.equals(actualPath)) {
                throw new IllegalStateException(String.format(
                        "The OCFL client was configured to use the following layout: %s." +
                                " This layout does not match the layout of existing objects in the repository." +
                        " Found object %s stored at %s, but was expecting it to be stored at %s.",
                        objectIdPathMapper.describeLayout(), inventory.getId(), actualPath, expectedPath
                ));
            }
        }
    }

    private void writeOcflSpec(String ocflVersion) {
        var ocflSpecFile = ocflVersion + ".txt";
        try (var ocflSpecStream = FileSystemOcflStorage.class.getClassLoader().getResourceAsStream(ocflSpecFile)) {
            Files.copy(ocflSpecStream, repositoryRoot.resolve(ocflSpecFile));
        } catch (IOException e) {
            throw new RuntimeIOException(e);
        }
    }

    private Path identifyRandomObjectRoot(Path root) {
        var ref = new AtomicReference<Path>();
        var objectMarkerPrefix = "0=ocfl_object";

        try {
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                    // TODO remove this
                    if (dir.endsWith("deposit")) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return super.preVisitDirectory(dir, attrs);
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    if (file.getFileName().toString().startsWith(objectMarkerPrefix)) {
                        ref.set(file.getParent());
                        return FileVisitResult.TERMINATE;
                    }
                    return super.visitFile(file, attrs);
                }
            });
        } catch (IOException e) {
            throw new RuntimeIOException(e);
        }

        return ref.get();
    }

    private void writeOcflLayout() {
        try {
            var map = new TreeMap<String, Object>(Comparator.naturalOrder());
            map.putAll(objectIdPathMapper.describeLayout());
            objectMapper.writeValue(repositoryRoot.resolve("ocfl_layout.json").toFile(), map);
        } catch (IOException e) {
            throw new RuntimeIOException(e);
        }
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException(FileSystemOcflStorage.class.getName() + " is closed.");
        }
    }

}
