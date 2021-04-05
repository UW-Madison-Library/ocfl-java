package edu.wisc.library.ocfl.itest;

import com.github.benmanes.caffeine.cache.Caffeine;
import edu.wisc.library.ocfl.api.OcflOption;
import edu.wisc.library.ocfl.api.OcflRepository;
import edu.wisc.library.ocfl.api.exception.AlreadyExistsException;
import edu.wisc.library.ocfl.api.exception.CorruptObjectException;
import edu.wisc.library.ocfl.api.exception.FixityCheckException;
import edu.wisc.library.ocfl.api.exception.NotFoundException;
import edu.wisc.library.ocfl.api.exception.ObjectOutOfSyncException;
import edu.wisc.library.ocfl.api.exception.OcflExtensionException;
import edu.wisc.library.ocfl.api.exception.OcflIOException;
import edu.wisc.library.ocfl.api.exception.OcflInputException;
import edu.wisc.library.ocfl.api.exception.OcflStateException;
import edu.wisc.library.ocfl.api.exception.PathConstraintException;
import edu.wisc.library.ocfl.api.exception.RepositoryConfigurationException;
import edu.wisc.library.ocfl.api.exception.ValidationException;
import edu.wisc.library.ocfl.api.io.FixityCheckInputStream;
import edu.wisc.library.ocfl.api.model.DigestAlgorithm;
import edu.wisc.library.ocfl.api.model.FileChangeType;
import edu.wisc.library.ocfl.api.model.ObjectVersionId;
import edu.wisc.library.ocfl.api.model.OcflObjectVersionFile;
import edu.wisc.library.ocfl.api.model.VersionInfo;
import edu.wisc.library.ocfl.api.model.VersionNum;
import edu.wisc.library.ocfl.core.OcflRepositoryBuilder;
import edu.wisc.library.ocfl.core.cache.CaffeineCache;
import edu.wisc.library.ocfl.core.extension.UnsupportedExtensionBehavior;
import edu.wisc.library.ocfl.core.extension.storage.layout.config.FlatLayoutConfig;
import edu.wisc.library.ocfl.core.extension.storage.layout.config.HashedNTupleIdEncapsulationLayoutConfig;
import edu.wisc.library.ocfl.core.extension.storage.layout.config.HashedNTupleLayoutConfig;
import edu.wisc.library.ocfl.core.model.Inventory;
import edu.wisc.library.ocfl.core.path.constraint.ContentPathConstraints;
import edu.wisc.library.ocfl.core.path.mapper.LogicalPathMappers;
import edu.wisc.library.ocfl.core.storage.filesystem.FileSystemOcflStorage;
import edu.wisc.library.ocfl.test.OcflAsserts;
import edu.wisc.library.ocfl.test.TestHelper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.DigestInputStream;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import static edu.wisc.library.ocfl.itest.ITestHelper.expectedOutputPath;
import static edu.wisc.library.ocfl.itest.ITestHelper.expectedRepoPath;
import static edu.wisc.library.ocfl.itest.ITestHelper.sourceObjectPath;
import static edu.wisc.library.ocfl.itest.ITestHelper.sourceRepoPath;
import static edu.wisc.library.ocfl.itest.ITestHelper.streamString;
import static edu.wisc.library.ocfl.itest.ITestHelper.verifyDirectoryContentsSame;
import static edu.wisc.library.ocfl.test.TestHelper.copyDir;
import static edu.wisc.library.ocfl.test.TestHelper.inputStream;
import static edu.wisc.library.ocfl.test.matcher.OcflMatchers.fileChange;
import static edu.wisc.library.ocfl.test.matcher.OcflMatchers.fileDetails;
import static edu.wisc.library.ocfl.test.matcher.OcflMatchers.objectVersion;
import static edu.wisc.library.ocfl.test.matcher.OcflMatchers.versionDetails;
import static edu.wisc.library.ocfl.test.matcher.OcflMatchers.versionFile;
import static edu.wisc.library.ocfl.test.matcher.OcflMatchers.versionInfo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class OcflITest {

    protected static final String O1_PATH = "235/2da/728/2352da7280f1decc3acf1ba84eb945c9fc2b7b541094e1d0992dbffd1b6664cc";
    protected static final String O2_PATH = "925/0b9/912/9250b9912ee91d6b46e23299459ecd6eb8154451d62558a3a0a708a77926ad04";

    @TempDir
    public Path tempRoot;

    protected Path outputDir;
    protected Path inputDir;
    protected Path workDir;

    protected VersionInfo defaultVersionInfo;

    @BeforeEach
    public void setup() throws IOException {
        outputDir = Files.createDirectory(tempRoot.resolve("output"));
        inputDir = Files.createDirectory(tempRoot.resolve("input"));
        workDir = Files.createDirectory(tempRoot.resolve("work"));

        defaultVersionInfo = new VersionInfo().setMessage("commit message").setUser("Peter", "peter@example.com");

        onBefore();
    }

    @AfterEach
    public void after() {
        onAfter();
    }

    protected OcflRepository defaultRepo(String name) {
        return defaultRepo(name, builder -> builder.defaultLayoutConfig(new HashedNTupleLayoutConfig()));
    }

    protected abstract OcflRepository defaultRepo(String name, Consumer<OcflRepositoryBuilder> consumer);

    protected OcflRepository existingRepo(String name, Path path) {
        return existingRepo(name, path, builder -> builder.defaultLayoutConfig(new HashedNTupleLayoutConfig()));
    }

    protected abstract OcflRepository existingRepo(String name, Path path, Consumer<OcflRepositoryBuilder> consumer);

    protected abstract void verifyRepo(String name);

    protected abstract List<String> listFilesInRepo(String name);

    protected void onBefore() {

    }

    protected void onAfter() {

    }

    @Test
    public void writeInputStreamWithFixityCheck() throws IOException {
        var repoName = "input-stream-fixity";
        var repo = defaultRepo(repoName);

        var objectId = "obj1";

        var file1Contents = "... contents of first file ...";
        var file1Sha512 = "6407d5ecc067dad1a2a3c75d088ecdab97d4df5a580a3bbc1b190ad988cea529b92eab11131fd2f5c0b40fa5891eec979e7e5e96b6bed38e6dddde7a20722345";
        var inputStream1 = new FixityCheckInputStream(streamString(file1Contents), DigestAlgorithm.sha512, file1Sha512);

        var file2Contents = "... contents of second file ...";
        var file2Sha512 = "d173736e7984e4439cab8d0bd6665e8f9a3aefc4d518a5ed5a3a46e05da40fa5803ac5dc52c9b17d302e12525619a9b6076f33a0c80b558bff051812800e0875";
        var inputStream2 = new FixityCheckInputStream(streamString(file2Contents), DigestAlgorithm.sha512, file2Sha512);
        inputStream2.enableFixityCheck(false);

        var file3Contents = "... contents of third file ...";
        var file3Sha512 = "f280e67f4142469ac514dd7ad366c6ed629e10b30f6f637e6de36b861c44ba5753d8fe8d589b9b23310df9e9d564a20a06d5f4637bd9f8e66ab628c7cce33e72";
        var inputStream3 = new DigestInputStream(streamString(file3Contents), DigestAlgorithm.sha512.getMessageDigest());

        repo.updateObject(ObjectVersionId.head(objectId), new VersionInfo(), updater -> {
            updater.writeFile(inputStream1,"file1");
            updater.writeFile(inputStream2,"file2");
            updater.writeFile(inputStream3,"file3");
        });

        var object = repo.getObject(ObjectVersionId.head(objectId));

        try (var stream = object.getFile("file1").getStream()) {
            assertEquals(file1Contents, new String(stream.readAllBytes()));
        }
        assertEquals(file1Sha512, object.getFile("file1").getFixity().get(DigestAlgorithm.sha512));

        try (var stream = object.getFile("file2").getStream()) {
            assertEquals(file2Contents, new String(stream.readAllBytes()));
        }
        assertEquals(file2Sha512, object.getFile("file2").getFixity().get(DigestAlgorithm.sha512));

        try (var stream = object.getFile("file3").getStream()) {
            assertEquals(file3Contents, new String(stream.readAllBytes()));
        }
        assertEquals(file3Sha512, object.getFile("file3").getFixity().get(DigestAlgorithm.sha512));
    }

    @Test
    public void putNewObjectAndUpdateMultipleTimesWithAdditionalPuts() {
        var repoName = "repo3";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        var sourcePathV1 = sourceObjectPath(objectId, "v1");
        var sourcePathV2 = sourceObjectPath(objectId, "v2");
        var sourcePathV3 = sourceObjectPath(objectId, "v3");
        var outputPath1 = outputPath(repoName, objectId);
        var outputPath2 = outputPath(repoName, objectId + "2");
        var outputPath3 = outputPath(repoName, objectId + "3");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1, defaultVersionInfo);
        repo.putObject(ObjectVersionId.head(objectId), sourcePathV2, defaultVersionInfo.setMessage("second"));
        repo.putObject(ObjectVersionId.head(objectId), sourcePathV3, defaultVersionInfo.setMessage("third"));

        verifyRepo(repoName);

        repo.getObject(ObjectVersionId.head(objectId), outputPath1);
        verifyDirectoryContentsSame(expectedOutputPath(repoName, "o1v3"), objectId, outputPath1);

        repo.getObject(ObjectVersionId.version(objectId, "v2"), outputPath2);
        verifyDirectoryContentsSame(sourcePathV2, outputPath2.getFileName().toString(), outputPath2);

        repo.getObject(ObjectVersionId.version(objectId, "v1"), outputPath3);
        verifyDirectoryContentsSame(sourcePathV1, outputPath3.getFileName().toString(), outputPath3);
    }

    @Test
    public void putObjectWithPathToSingleFile() {
        var repoName = "repo15";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        var sourcePathV1 = sourceObjectPath(objectId, "v1");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1.resolve("file1"), defaultVersionInfo);
        verifyRepo(repoName);
    }

    @Test
    public void shouldNotFailWhenObjectIdLongerThan255Characters() {
        var repoName = "long-id";
        var repo = defaultRepo(repoName);

        var objectId = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789" +
                "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789" +
                "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(inputStream("long-id"), "file1.txt");
        });

        var object = repo.getObject(ObjectVersionId.head(objectId));

        assertEquals(objectId, object.getObjectId());
    }

    @Test
    public void rejectRequestsWhenRepoClosed() {
        var repoName = "repo15";
        var repo = defaultRepo(repoName);

        repo.close();

        var objectId = "o1";
        var sourcePathV1 = sourceObjectPath(objectId, "v1");

        assertThat(assertThrows(OcflStateException.class, () -> {
            repo.putObject(ObjectVersionId.head(objectId), sourcePathV1.resolve("file1"), defaultVersionInfo);
        }).getMessage(), containsString("is closed"));
    }

    @Test
    public void updateObjectMakeMultipleChangesWithinTheSameVersion() {
        var repoName = "repo4";
        var repo = defaultRepo(repoName);

        var objectId = "o2";

        var sourcePathV1 = sourceObjectPath(objectId, "v1");
        var sourcePathV2 = sourceObjectPath(objectId, "v2");
        var sourcePathV3 = sourceObjectPath(objectId, "v3");
        var outputPath1 = outputPath(repoName, objectId);
        var outputPath2 = outputPath(repoName, objectId + "2");
        var outputPath3 = outputPath(repoName, objectId + "3");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1, defaultVersionInfo);

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            updater.addPath(sourcePathV2.resolve("dir1/file3"), "dir1/file3")
                    .renameFile("file1", "dir3/file1");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("3"), updater -> {
            updater.removeFile("dir1/file3").removeFile("dir3/file1")
                    .writeFile(inputStream(sourcePathV3.resolve("dir1/file3")), "dir1/file3");
        });

        verifyRepo(repoName);

        repo.getObject(ObjectVersionId.head(objectId), outputPath1);
        verifyDirectoryContentsSame(expectedOutputPath(repoName, "o2v3"), objectId, outputPath1);

        repo.getObject(ObjectVersionId.version(objectId, "v2"), outputPath2);
        verifyDirectoryContentsSame(expectedOutputPath(repoName, "o2v2"), outputPath2.getFileName().toString(), outputPath2);

        repo.getObject(ObjectVersionId.version(objectId, "v1"), outputPath3);
        verifyDirectoryContentsSame(expectedOutputPath(repoName, "o2v1"), outputPath3.getFileName().toString(), outputPath3);
    }

    @Test
    public void lazyLoadObject() throws IOException {
        var repoName = "repo3";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        var sourcePathV1 = sourceObjectPath(objectId, "v1");
        var sourcePathV2 = sourceObjectPath(objectId, "v2");
        var sourcePathV3 = sourceObjectPath(objectId, "v3");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1, defaultVersionInfo);
        repo.putObject(ObjectVersionId.head(objectId), sourcePathV2, defaultVersionInfo.setMessage("second"));
        repo.putObject(ObjectVersionId.head(objectId), sourcePathV3, defaultVersionInfo.setMessage("third"));

        verifyRepo(repoName);

        var files = repo.getObject(ObjectVersionId.head(objectId));
        assertEquals(2, files.getFiles().size());
        verifyStream(sourcePathV3.resolve("file2"), files.getFile("file2"));
        verifyStream(sourcePathV3.resolve("file4"), files.getFile("file4"));

        files = repo.getObject(ObjectVersionId.version(objectId, "v2"));
        assertEquals(3, files.getFiles().size());
        verifyStream(sourcePathV2.resolve("file1"), files.getFile("file1"));
        verifyStream(sourcePathV2.resolve("file2"), files.getFile("file2"));
        verifyStream(sourcePathV2.resolve("dir1/file3"), files.getFile("dir1/file3"));


        files = repo.getObject(ObjectVersionId.version(objectId, "v1"));
        assertEquals(2, files.getFiles().size());
        verifyStream(sourcePathV1.resolve("file1"), files.getFile("file1"));
        verifyStream(sourcePathV1.resolve("file2"), files.getFile("file2"));
    }

    @Test
    public void renameAndRemoveFilesAddedInTheCurrentVersion() {
        var repoName = "repo17";
        var repo = defaultRepo(repoName);

        var objectId = "o3";

        var sourcePathV1 = sourceObjectPath(objectId, "v1");
        var sourcePathV2 = sourceObjectPath(objectId, "v2");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1, defaultVersionInfo);

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            updater.addPath(sourcePathV2.resolve("file2"), "dir1/file2")
                    .addPath(sourcePathV2.resolve("file3"), "file3")
                    .renameFile("dir1/file2", "dir2/file3");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("3"), updater -> {
            updater.writeFile(new ByteArrayInputStream("test123".getBytes()), "file4")
                    .removeFile("file4");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("3"), updater -> {
            updater.writeFile(new ByteArrayInputStream("test123456".getBytes()), "file5")
                    .writeFile(new ByteArrayInputStream("6543210".getBytes()), "file5", OcflOption.OVERWRITE);
        });

        verifyRepo(repoName);
    }

    @Test
    public void describeObject() {
        var repoName = "repo5";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
            updater.addPath(sourceObjectPath(objectId, "v1"))
                    .addFileFixity("file1", DigestAlgorithm.md5, "95efdf0764d92207b4698025f2518456")
                    .addFileFixity("file2", DigestAlgorithm.md5, "55c1824fcae2b1b51cef5037405fc1ad");
        });
        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            updater.clearVersionState().addPath(sourceObjectPath(objectId, "v2"))
                    .addFileFixity("file1", DigestAlgorithm.md5, "a0a8bfbf51b81caf7aa5be00f5e26669")
                    .addFileFixity("file2", DigestAlgorithm.md5, "55c1824fcae2b1b51cef5037405fc1ad")
                    .addFileFixity("dir1/file3", DigestAlgorithm.md5, "72b6193fe19ec99c692eba5c798e6bdf");
        });
        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("3"), updater -> {
            updater.clearVersionState().addPath(sourceObjectPath(objectId, "v3"))
                    .addFileFixity("file2", DigestAlgorithm.md5, "55c1824fcae2b1b51cef5037405fc1ad")
                    .addFileFixity("file4", DigestAlgorithm.md5, "a0a8bfbf51b81caf7aa5be00f5e26669");
        });

        var objectDetails = repo.describeObject(objectId);

        assertEquals(objectId, objectDetails.getId());
        assertEquals(VersionNum.fromString("v3"), objectDetails.getHeadVersionNum());
        assertEquals(DigestAlgorithm.sha512, objectDetails.getDigestAlgorithm());
        assertEquals(3, objectDetails.getVersionMap().size());

        assertThat(objectDetails.getVersion(VersionNum.fromString("v1")), versionDetails(objectId, "v1",
                versionInfo(defaultVersionInfo.getUser(), "1"),
                fileDetails("file1", O1_PATH + "/v1/content/file1", Map.of(
                        DigestAlgorithm.sha512, "96a26e7629b55187f9ba3edc4acc940495d582093b8a88cb1f0303cf3399fe6b1f5283d76dfd561fc401a0cdf878c5aad9f2d6e7e2d9ceee678757bb5d95c39e",
                        DigestAlgorithm.md5, "95efdf0764d92207b4698025f2518456")),
                fileDetails("file2", O1_PATH + "/v1/content/file2", Map.of(
                        DigestAlgorithm.sha512, "4cf0ff5673ec65d9900df95502ed92b2605fc602ca20b6901652c7561b302668026095813af6adb0e663bdcdbe1f276d18bf0de254992a78573ad6574e7ae1f6",
                        DigestAlgorithm.md5, "55c1824fcae2b1b51cef5037405fc1ad"))
        ));

        assertThat(objectDetails.getVersion(VersionNum.fromString("v2")), versionDetails(objectId, "v2",
                versionInfo(defaultVersionInfo.getUser(), "2"),
                fileDetails("file1", O1_PATH + "/v2/content/file1", Map.of(
                        DigestAlgorithm.sha512, "aff2318b35d3fbc05670b834b9770fd418e4e1b4adc502e6875d598ab3072ca76667121dac04b694c47c71be80f6d259316c7bd0e19d40827cb3f27ee03aa2fc",
                        DigestAlgorithm.md5, "a0a8bfbf51b81caf7aa5be00f5e26669")),
                fileDetails("file2", O1_PATH + "/v1/content/file2", Map.of(
                        DigestAlgorithm.sha512, "4cf0ff5673ec65d9900df95502ed92b2605fc602ca20b6901652c7561b302668026095813af6adb0e663bdcdbe1f276d18bf0de254992a78573ad6574e7ae1f6",
                        DigestAlgorithm.md5, "55c1824fcae2b1b51cef5037405fc1ad")),
                fileDetails("dir1/file3", O1_PATH + "/v2/content/dir1/file3", Map.of(
                        DigestAlgorithm.sha512, "cb6f4f7b3d3eef05d3d0327335071d14c120e065fa43364690fea47d456e146dd334d78d35f73926067d0bf46f122ea026508954b71e8e25c351ff75c993c2b2",
                        DigestAlgorithm.md5, "72b6193fe19ec99c692eba5c798e6bdf"))
        ));

        assertThat(objectDetails.getVersion(VersionNum.fromString("v3")), versionDetails(objectId, "v3",
                versionInfo(defaultVersionInfo.getUser(), "3"),
                fileDetails("file2", O1_PATH + "/v1/content/file2", Map.of(
                        DigestAlgorithm.sha512, "4cf0ff5673ec65d9900df95502ed92b2605fc602ca20b6901652c7561b302668026095813af6adb0e663bdcdbe1f276d18bf0de254992a78573ad6574e7ae1f6",
                        DigestAlgorithm.md5, "55c1824fcae2b1b51cef5037405fc1ad")),
                fileDetails("file4", O1_PATH + "/v2/content/file1", Map.of(
                        DigestAlgorithm.sha512, "aff2318b35d3fbc05670b834b9770fd418e4e1b4adc502e6875d598ab3072ca76667121dac04b694c47c71be80f6d259316c7bd0e19d40827cb3f27ee03aa2fc",
                        DigestAlgorithm.md5, "a0a8bfbf51b81caf7aa5be00f5e26669"))
        ));

        assertSame(objectDetails.getHeadVersion(), objectDetails.getVersion(VersionNum.fromString("v3")));
    }

    @Test
    public void shouldNotAddAdditionalFixityWhenDefaultAlgorithmSpecified() {
        var repoName = "repo5";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
            updater.addPath(sourceObjectPath(objectId, "v1"))
                    .addFileFixity("file1", DigestAlgorithm.sha512, "96a26e7629b55187f9ba3edc4acc940495d582093b8a88cb1f0303cf3399fe6b1f5283d76dfd561fc401a0cdf878c5aad9f2d6e7e2d9ceee678757bb5d95c39e")
                    .addFileFixity("file2", DigestAlgorithm.sha512, "4cf0ff5673ec65d9900df95502ed92b2605fc602ca20b6901652c7561b302668026095813af6adb0e663bdcdbe1f276d18bf0de254992a78573ad6574e7ae1f6");
        });
        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            updater.clearVersionState().addPath(sourceObjectPath(objectId, "v2"))
                    .addFileFixity("file1", DigestAlgorithm.sha512, "aff2318b35d3fbc05670b834b9770fd418e4e1b4adc502e6875d598ab3072ca76667121dac04b694c47c71be80f6d259316c7bd0e19d40827cb3f27ee03aa2fc")
                    .addFileFixity("file2", DigestAlgorithm.sha512, "4cf0ff5673ec65d9900df95502ed92b2605fc602ca20b6901652c7561b302668026095813af6adb0e663bdcdbe1f276d18bf0de254992a78573ad6574e7ae1f6")
                    .addFileFixity("dir1/file3", DigestAlgorithm.sha512, "cb6f4f7b3d3eef05d3d0327335071d14c120e065fa43364690fea47d456e146dd334d78d35f73926067d0bf46f122ea026508954b71e8e25c351ff75c993c2b2");
        });
        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("3"), updater -> {
            updater.clearVersionState().addPath(sourceObjectPath(objectId, "v3"))
                    .addFileFixity("file2", DigestAlgorithm.sha512, "4cf0ff5673ec65d9900df95502ed92b2605fc602ca20b6901652c7561b302668026095813af6adb0e663bdcdbe1f276d18bf0de254992a78573ad6574e7ae1f6")
                    .addFileFixity("file4", DigestAlgorithm.sha512, "aff2318b35d3fbc05670b834b9770fd418e4e1b4adc502e6875d598ab3072ca76667121dac04b694c47c71be80f6d259316c7bd0e19d40827cb3f27ee03aa2fc");
        });

        var objectDetails = repo.describeObject(objectId);

        assertEquals(objectId, objectDetails.getId());
        assertEquals(VersionNum.fromString("v3"), objectDetails.getHeadVersionNum());
        assertEquals(3, objectDetails.getVersionMap().size());

        assertThat(objectDetails.getVersion(VersionNum.fromString("v1")), versionDetails(objectId, "v1",
                versionInfo(defaultVersionInfo.getUser(), "1"),
                fileDetails("file1", O1_PATH + "/v1/content/file1", Map.of(
                        DigestAlgorithm.sha512, "96a26e7629b55187f9ba3edc4acc940495d582093b8a88cb1f0303cf3399fe6b1f5283d76dfd561fc401a0cdf878c5aad9f2d6e7e2d9ceee678757bb5d95c39e")),
                fileDetails("file2", O1_PATH + "/v1/content/file2", Map.of(
                        DigestAlgorithm.sha512, "4cf0ff5673ec65d9900df95502ed92b2605fc602ca20b6901652c7561b302668026095813af6adb0e663bdcdbe1f276d18bf0de254992a78573ad6574e7ae1f6"))
        ));

        assertThat(objectDetails.getVersion(VersionNum.fromString("v2")), versionDetails(objectId, "v2",
                versionInfo(defaultVersionInfo.getUser(), "2"),
                fileDetails("file1", O1_PATH + "/v2/content/file1", Map.of(
                        DigestAlgorithm.sha512, "aff2318b35d3fbc05670b834b9770fd418e4e1b4adc502e6875d598ab3072ca76667121dac04b694c47c71be80f6d259316c7bd0e19d40827cb3f27ee03aa2fc")),
                fileDetails("file2", O1_PATH + "/v1/content/file2", Map.of(
                        DigestAlgorithm.sha512, "4cf0ff5673ec65d9900df95502ed92b2605fc602ca20b6901652c7561b302668026095813af6adb0e663bdcdbe1f276d18bf0de254992a78573ad6574e7ae1f6")),
                fileDetails("dir1/file3", O1_PATH + "/v2/content/dir1/file3", Map.of(
                        DigestAlgorithm.sha512, "cb6f4f7b3d3eef05d3d0327335071d14c120e065fa43364690fea47d456e146dd334d78d35f73926067d0bf46f122ea026508954b71e8e25c351ff75c993c2b2"))
        ));

        assertThat(objectDetails.getVersion(VersionNum.fromString("v3")), versionDetails(objectId, "v3",
                versionInfo(defaultVersionInfo.getUser(), "3"),
                fileDetails("file2", O1_PATH + "/v1/content/file2", Map.of(
                        DigestAlgorithm.sha512, "4cf0ff5673ec65d9900df95502ed92b2605fc602ca20b6901652c7561b302668026095813af6adb0e663bdcdbe1f276d18bf0de254992a78573ad6574e7ae1f6")),
                fileDetails("file4", O1_PATH + "/v2/content/file1", Map.of(
                        DigestAlgorithm.sha512, "aff2318b35d3fbc05670b834b9770fd418e4e1b4adc502e6875d598ab3072ca76667121dac04b694c47c71be80f6d259316c7bd0e19d40827cb3f27ee03aa2fc"))
        ));

        assertSame(objectDetails.getHeadVersion(), objectDetails.getVersion(VersionNum.fromString("v3")));
    }

    @Test
    public void shouldFailWhenFixityDoesNotMatch() {
        var repoName = "repo5";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        OcflAsserts.assertThrowsWithMessage(FixityCheckException.class, "Expected md5 digest of", () -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
                updater.addPath(sourceObjectPath(objectId, "v1"))
                        .addFileFixity("file1", DigestAlgorithm.md5, "bogus");
            });
        });
    }

    @Test
    public void shouldFailFixityWhenUnknownAlgorithm() {
        var repoName = "repo5";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        OcflAsserts.assertThrowsWithMessage(OcflInputException.class, "specified digest algorithm is not mapped to a Java name", () -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
                updater.addPath(sourceObjectPath(objectId, "v1"))
                        .addFileFixity("file1", DigestAlgorithm.fromOcflName("bogus"), "bogus");
            });
        });
    }

    @Test
    public void shouldFailFixityWhenFileNotAddedInBlockAndDoesNotHaveExistingFixity() {
        var repoName = "repo5";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
            updater.addPath(sourceObjectPath(objectId, "v1"));
        });

        OcflAsserts.assertThrowsWithMessage(OcflInputException.class, "not newly added in this update", () -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
                updater.clearVersionState().addPath(sourceObjectPath(objectId, "v2"))
                        .addFileFixity("file2", DigestAlgorithm.md5, "55c1824fcae2b1b51cef5037405fc1ad");
            });
        });
    }

    @Test
    public void readObjectFiles() {
        var repoName = "repo4";
        var repoDir = expectedRepoPath(repoName);
        var repo = existingRepo(repoName, repoDir);

        var objectId = "o2";

        var ocflObject = repo.getObject(ObjectVersionId.head(objectId));

        assertThat(ocflObject, objectVersion(objectId, "v3",
                versionInfo(defaultVersionInfo.getUser(), "3"),
                versionFile("dir1/dir2/file2", O2_PATH + "/v1/content/dir1/dir2/file2",
                        "Test file 2",
                        Map.of(DigestAlgorithm.sha512, "4cf0ff5673ec65d9900df95502ed92b2605fc602ca20b6901652c7561b302668026095813af6adb0e663bdcdbe1f276d18bf0de254992a78573ad6574e7ae1f6")),
                versionFile("dir1/file3", O2_PATH + "/v3/content/dir1/file3",
                        "This is a different file 3",
                        Map.of(DigestAlgorithm.sha512, "6e027f3dc89e0bfd97e4c2ec6919a8fb793bdc7b5c513bea618f174beec32a66d2fc0ce19439751e2f01ae49f78c56dcfc7b49c167a751c823d09da8419a4331"))
                ));

        ocflObject = repo.getObject(ObjectVersionId.version(objectId, "v1"));

        assertThat(ocflObject, objectVersion(objectId, "v1",
                versionInfo(defaultVersionInfo.getUser(), "commit message"),
                versionFile("dir1/dir2/file2", O2_PATH + "/v1/content/dir1/dir2/file2",
                        "Test file 2",
                        Map.of(DigestAlgorithm.sha512, "4cf0ff5673ec65d9900df95502ed92b2605fc602ca20b6901652c7561b302668026095813af6adb0e663bdcdbe1f276d18bf0de254992a78573ad6574e7ae1f6")),
                versionFile("file1", O2_PATH + "/v1/content/file1",
                        "Test file 1",
                        Map.of(DigestAlgorithm.sha512, "96a26e7629b55187f9ba3edc4acc940495d582093b8a88cb1f0303cf3399fe6b1f5283d76dfd561fc401a0cdf878c5aad9f2d6e7e2d9ceee678757bb5d95c39e"))
                ));
    }

    @Test
    public void changeHistory() {
        var repo = defaultRepo("change-history");

        var objectId = "o1";

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
            updater.writeFile(new ByteArrayInputStream("1".getBytes()), "f1")
                    .writeFile(new ByteArrayInputStream("2".getBytes()), "f2");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            updater.writeFile(new ByteArrayInputStream("3".getBytes()), "f3")
                    .removeFile("f1");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("3"), updater -> {
            updater.reinstateFile(VersionNum.fromString("v1"), "f1", "f1")
                    .writeFile(new ByteArrayInputStream("2.2".getBytes()), "f2", OcflOption.OVERWRITE);
        });

        var f1History = repo.fileChangeHistory(objectId, "f1");
        var f2History = repo.fileChangeHistory(objectId, "f2");
        var f3History = repo.fileChangeHistory(objectId, "f3");

        assertThat(f1History.getFileChanges(), contains(
                fileChange(FileChangeType.UPDATE,
                        ObjectVersionId.version(objectId, "v1"),
                        "f1", O1_PATH + "/v1/content/f1",
                        versionInfo(defaultVersionInfo.getUser(), "1"),
                        Map.of(DigestAlgorithm.sha512, "4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a")),
                fileChange(FileChangeType.REMOVE,
                        ObjectVersionId.version(objectId, "v2"),
                        "f1", null,
                        versionInfo(defaultVersionInfo.getUser(), "2"),
                        Map.of()),
                fileChange(FileChangeType.UPDATE,
                        ObjectVersionId.version(objectId, "v3"),
                        "f1", O1_PATH + "/v1/content/f1",
                        versionInfo(defaultVersionInfo.getUser(), "3"),
                        Map.of(DigestAlgorithm.sha512, "4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a"))));

        assertThat(f2History.getFileChanges(), contains(
                fileChange(FileChangeType.UPDATE,
                        ObjectVersionId.version(objectId, "v1"),
                        "f2", O1_PATH + "/v1/content/f2",
                        versionInfo(defaultVersionInfo.getUser(), "1"),
                        Map.of(DigestAlgorithm.sha512, "40b244112641dd78dd4f93b6c9190dd46e0099194d5a44257b7efad6ef9ff4683da1eda0244448cb343aa688f5d3efd7314dafe580ac0bcbf115aeca9e8dc114")),
                fileChange(FileChangeType.UPDATE,
                        ObjectVersionId.version(objectId, "v3"),
                        "f2", O1_PATH + "/v3/content/f2",
                        versionInfo(defaultVersionInfo.getUser(), "3"),
                        Map.of(DigestAlgorithm.sha512, "7db70149dac5561e411a202629d06832b06b7e8dfef61086ff9e0922459fbe14a69d565cf838fd43681fdb29a698bfe377861b966d12416298997843820bfdb7"))));

        assertThat(f3History.getFileChanges(), contains(
                fileChange(FileChangeType.UPDATE,
                        ObjectVersionId.version(objectId, "v2"),
                        "f3", O1_PATH + "/v2/content/f3",
                        versionInfo(defaultVersionInfo.getUser(), "2"),
                        Map.of(DigestAlgorithm.sha512, "3bafbf08882a2d10133093a1b8433f50563b93c14acd05b79028eb1d12799027241450980651994501423a66c276ae26c43b739bc65c4e16b10c3af6c202aebb"))));
    }

    @Test
    public void failWhenLogicalPathNotFoundInChangeHistory() {
        var repo = defaultRepo("change-history");

        var objectId = "o1";

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
            updater.writeFile(new ByteArrayInputStream("1".getBytes()), "f1")
                    .writeFile(new ByteArrayInputStream("2".getBytes()), "f2");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            updater.writeFile(new ByteArrayInputStream("3".getBytes()), "f3")
                    .removeFile("f1");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("3"), updater -> {
            updater.reinstateFile(VersionNum.fromString("v1"), "f1", "f1")
                    .writeFile(new ByteArrayInputStream("2.2".getBytes()), "f2", OcflOption.OVERWRITE);
        });

        OcflAsserts.assertThrowsWithMessage(NotFoundException.class, "The logical path f5 was not found in object o1", () -> {
            repo.fileChangeHistory(objectId, "f5");
        });
    }

    @Test
    public void getObjectFilesFromLazyLoadGetObject() {
        var repoName = "repo4";
        var repoDir = expectedRepoPath(repoName);
        var repo = existingRepo(repoName, repoDir);

        var objectId = "o2";

        var objectVersion = repo.getObject(ObjectVersionId.head(objectId));

        assertThat(objectVersion, objectVersion(objectId, "v3",
                versionInfo(defaultVersionInfo.getUser(), "3"),
                versionFile("dir1/dir2/file2", O2_PATH + "/v1/content/dir1/dir2/file2",
                        "Test file 2",
                        Map.of(DigestAlgorithm.sha512, "4cf0ff5673ec65d9900df95502ed92b2605fc602ca20b6901652c7561b302668026095813af6adb0e663bdcdbe1f276d18bf0de254992a78573ad6574e7ae1f6")),
                versionFile("dir1/file3", O2_PATH + "/v3/content/dir1/file3",
                        "This is a different file 3",
                        Map.of(DigestAlgorithm.sha512, "6e027f3dc89e0bfd97e4c2ec6919a8fb793bdc7b5c513bea618f174beec32a66d2fc0ce19439751e2f01ae49f78c56dcfc7b49c167a751c823d09da8419a4331"))
        ));

        objectVersion = repo.getObject(ObjectVersionId.version(objectId, "v1"));

        assertThat(objectVersion, objectVersion(objectId, "v1",
                versionInfo(defaultVersionInfo.getUser(), defaultVersionInfo.getMessage()),
                versionFile("dir1/dir2/file2", O2_PATH + "/v1/content/dir1/dir2/file2",
                        "Test file 2",
                        Map.of(DigestAlgorithm.sha512, "4cf0ff5673ec65d9900df95502ed92b2605fc602ca20b6901652c7561b302668026095813af6adb0e663bdcdbe1f276d18bf0de254992a78573ad6574e7ae1f6")),
                versionFile("file1", O2_PATH + "/v1/content/file1",
                        "Test file 1",
                        Map.of(DigestAlgorithm.sha512, "96a26e7629b55187f9ba3edc4acc940495d582093b8a88cb1f0303cf3399fe6b1f5283d76dfd561fc401a0cdf878c5aad9f2d6e7e2d9ceee678757bb5d95c39e"))
        ));
    }

    @Test
    public void acceptEmptyPutObjectRequests() throws IOException {
        var repoName = "repo6";
        var repo = defaultRepo(repoName);

        var objectId = "o4";

        var empty = Files.createDirectory(tempRoot.resolve("empty"));

        repo.putObject(ObjectVersionId.head(objectId), empty, defaultVersionInfo);

        assertEquals(0, repo.getObject(ObjectVersionId.head(objectId)).getFiles().size());
    }

    @Test
    public void removeAllOfTheFilesFromAnObject() throws IOException {
        var repoName = "repo4";
        var repo = defaultRepo(repoName);

        var objectId = "o2";

        repo.putObject(ObjectVersionId.head(objectId), sourceObjectPath(objectId, "v1"), defaultVersionInfo);

        var ocflObject = repo.getObject(ObjectVersionId.head(objectId));

        repo.updateObject(ocflObject.getObjectVersionId(), defaultVersionInfo.setMessage("delete content"), updater -> {
            ocflObject.getFiles().forEach(file -> {
                updater.removeFile(file.getPath());
            });
        });

        var outputPath = outputPath(repoName, objectId);
        repo.getObject(ObjectVersionId.head(objectId), outputPath);
        assertEquals(0, outputPath.toFile().list().length);
    }

    @Test
    public void rejectObjectNotFoundWhenObjectDoesNotExists() throws IOException {
        var repoName = "repo4";
        var repoDir = expectedRepoPath(repoName);
        var repo = existingRepo(repoName, repoDir);

        assertThrows(NotFoundException.class, () -> repo.getObject(ObjectVersionId.head("bogus"), outputPath(repoName, "bogus")));
    }

    @Test
    public void rejectObjectNotFoundWhenObjectExistsButVersionDoesNot() throws IOException {
        var repoName = "repo4";
        var repoDir = expectedRepoPath(repoName);
        var repo = existingRepo(repoName, repoDir);

        var objectId = "o2";

        assertThrows(NotFoundException.class, () -> repo.getObject(ObjectVersionId.version(objectId, "v100"), outputPath(repoName, objectId)));
    }

    @Test
    public void shouldUpdateObjectWhenReferenceVersionSpecifiedAndIsMostRecentVersion() {
        var repoName = "repo4";
        var repo = defaultRepo(repoName);

        var objectId = "o2";

        var sourcePathV1 = sourceObjectPath(objectId, "v1");
        var sourcePathV2 = sourceObjectPath(objectId, "v2");
        var sourcePathV3 = sourceObjectPath(objectId, "v3");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1, defaultVersionInfo);

        repo.updateObject(ObjectVersionId.version(objectId, "v1"), defaultVersionInfo.setMessage("2"), updater -> {
            updater.addPath(sourcePathV2.resolve("dir1/file3"), "dir1/file3")
                    .renameFile("file1", "dir3/file1");
        });

        repo.updateObject(ObjectVersionId.version(objectId, "v2"), defaultVersionInfo.setMessage("3"), updater -> {
            updater.removeFile("dir1/file3").removeFile("dir3/file1")
                    .writeFile(inputStream(sourcePathV3.resolve("dir1/file3")), "dir1/file3");
        });

        verifyRepo(repoName);
    }

    @Test
    public void rejectUpdateObjectWhenReferenceVersionSpecifiedAndIsNotMostRecentVersion() {
        var repoName = "repo4";
        var repo = defaultRepo(repoName);

        var objectId = "o2";

        var sourcePathV1 = sourceObjectPath(objectId, "v1");
        var sourcePathV2 = sourceObjectPath(objectId, "v2");
        var sourcePathV3 = sourceObjectPath(objectId, "v3");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1, defaultVersionInfo);

        repo.updateObject(ObjectVersionId.version(objectId, "v1"), defaultVersionInfo.setMessage("2"), updater -> {
            updater.addPath(sourcePathV2.resolve("dir1/file3"), "dir1/file3")
                    .renameFile("file1", "dir3/file1");
        });

        assertThrows(ObjectOutOfSyncException.class, () -> repo.updateObject(ObjectVersionId.version(objectId, "v1"), defaultVersionInfo.setMessage("3"), updater -> {
            updater.removeFile("dir1/file3").removeFile("dir3/file1")
                    .writeFile(inputStream(sourcePathV3.resolve("dir1/file3")), "dir1/file3");
        }));
    }

    @Test
    public void shouldCreateNewVersionWhenObjectUpdateWithNoChanges() {
        var repoName = "repo7";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        repo.putObject(ObjectVersionId.head(objectId), sourceObjectPath(objectId, "v1"), defaultVersionInfo.setMessage("1"));
        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            // no op
        });

        verifyRepo(repoName);
    }

    @Test
    public void failGetObjectWhenInventoryFixityCheckFails() {
        var repoName = "invalid-inventory-fixity";
        var repoDir = sourceRepoPath(repoName);
        var repo = existingRepo(repoName, repoDir);

        assertThrows(CorruptObjectException.class, () -> repo.describeObject("z1"));
    }

    @Test
    public void failToInitRepoWhenObjectsStoredUsingDifferentLayout() {
        var repoName = "no-layout";
        var repoDir = expectedRepoPath(repoName);
        assertThrows(RepositoryConfigurationException.class, () -> {
            new OcflRepositoryBuilder()
                    .defaultLayoutConfig(new HashedNTupleLayoutConfig().setTupleSize(1))
                    .inventoryMapper(ITestHelper.testInventoryMapper())
                    .storage(FileSystemOcflStorage.builder().repositoryRoot(repoDir).build())
                    .workDir(workDir)
                    .build();
        });
    }

    @Test
    public void failGetObjectWhenFileFixityCheckFails() {
        var repoName = "invalid-file-fixity";
        var repoDir = sourceRepoPath(repoName);
        var repo = existingRepo(repoName, repoDir);

        assertThrows(FixityCheckException.class, () -> repo.getObject(ObjectVersionId.head("o1"), outputPath(repoName, "blah")));
    }

    @Test
    public void failGetObjectWhenInvalidDigestAlgorithmUsed() {
        var repoName = "invalid-digest-algorithm";
        var repoDir = sourceRepoPath(repoName);
        var repo = existingRepo(repoName, repoDir);

        assertThat(assertThrows(OcflIOException.class, () -> {
            repo.getObject(ObjectVersionId.head("o1"));
        }).getMessage(), containsString("digestAlgorithm must be sha512 or sha256"));
    }

    @Test
    public void putObjectWithDuplicateFiles() {
        var repoName = "repo8";
        var repo = defaultRepo(repoName);

        var objectId = "o5";

        var sourcePathV1 = sourceObjectPath(objectId, "v1");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1, defaultVersionInfo);

        // Which duplicate file that's preserved is non-deterministic
        var expectedPaths = ITestHelper.listAllPaths(expectedRepoPath(repoName));
        var actualPaths = listFilesInRepo(repoName);
        assertEquals(expectedPaths.size(), actualPaths.size());
    }

    @Test
    public void useZeroPaddedVersionsWhenExistingVersionIsZeroPadded() {
        var repoName = "zero-padded";
        var repo = existingRepo(repoName, sourceRepoPath(repoName));

        var objectId = "o1";

        var sourcePathV2 = sourceObjectPath(objectId, "v2");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV2, defaultVersionInfo.setMessage("second"));

        verifyRepo(repoName);
    }

    @Test
    public void useDifferentContentDirectoryWhenExistingObjectIsUsingDifferentDir() {
        var repoName = "different-content";
        var repo = existingRepo(repoName, sourceRepoPath(repoName));

        var objectId = "o1";

        var sourcePathV2 = sourceObjectPath(objectId, "v2");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV2, defaultVersionInfo.setMessage("second"));

        verifyRepo(repoName);
    }

    @Test
    public void shouldUseDifferentDigestAlgorithmWhenInventoryHasDifferent() {
        var repoName = "different-digest";
        var repo = existingRepo(repoName, sourceRepoPath(repoName));

        var objectId = "o1";

        var sourcePathV2 = sourceObjectPath(objectId, "v2");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV2, defaultVersionInfo.setMessage("second"));

        verifyRepo(repoName);
    }

    @Test
    public void rejectPathsWhenInvalidAndNotSanitized() {
        var repoName = "repo9";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        var sourcePathV1 = sourceObjectPath(objectId, "v1");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1, defaultVersionInfo);

        assertThrows(PathConstraintException.class, () -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("second"), updater -> {
                updater.writeFile(new ByteArrayInputStream("test2".getBytes()), "file/");
            });
        });

        assertThrows(PathConstraintException.class, () -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("second"), updater -> {
                updater.writeFile(new ByteArrayInputStream("test".getBytes()), "/absolute/path/file");
            });
        });

        assertThrows(PathConstraintException.class, () -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("second"), updater -> {
                updater.writeFile(new ByteArrayInputStream("test".getBytes()), "empty//path/file");
            });
        });

        assertThrows(PathConstraintException.class, () -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("second"), updater -> {
                updater.writeFile(new ByteArrayInputStream("test".getBytes()), "relative/../../path/file");
            });
        });

        assertThrows(PathConstraintException.class, () -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("second"), updater -> {
                updater.writeFile(new ByteArrayInputStream("test".getBytes()), "./file");
            });
        });
    }

    @Test
    public void rejectLogicalPathWhenAddConflicts() {
        var repoName = "conflict";
        var repo = defaultRepo(repoName);
        var objectId = "o1";

        OcflAsserts.assertThrowsWithMessage(OcflInputException.class, "The logical path file1/file2 conflicts with the existing path file1.", () -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
                updater.writeFile(streamString("file1"), "file1");
                updater.writeFile(streamString("file2"), "file1/file2");
            });
        });

        OcflAsserts.assertThrowsWithMessage(OcflInputException.class, "The logical path file1 conflicts with the existing path file1/file2.", () -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
                updater.writeFile(streamString("file2"), "file1/file2");
                updater.writeFile(streamString("file1"), "file1");
            });
        });
    }

    @Test
    public void rejectLogicalPathWhenRenameConflicts() {
        var repoName = "conflict-2";
        var repo = defaultRepo(repoName);
        var objectId = "o1";

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file1"), "file1");
            updater.writeFile(streamString("file2"), "file2");
        });

        OcflAsserts.assertThrowsWithMessage(OcflInputException.class, "The logical path file2/file1 conflicts with the existing path file2.", () -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
                updater.renameFile("file1", "file2/file1");
            });
        });
    }

    @Test
    public void rejectLogicalPathWhenReinstateConflicts() {
        var repoName = "conflict-2";
        var repo = defaultRepo(repoName);
        var objectId = "o1";

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file1"), "file1");
            updater.writeFile(streamString("file2"), "file2");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.removeFile("file1");
        });

        OcflAsserts.assertThrowsWithMessage(OcflInputException.class, "The logical path file2/file1 conflicts with the existing path file2.", () -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
                updater.reinstateFile(VersionNum.fromInt(1), "file1", "file2/file1");
            });
        });
    }

    @Test
    public void reinstateFileThatWasRemoved() {
        var repoName = "repo9";
        var repo = defaultRepo(repoName);

        var objectId = "o3";

        var sourcePathV1 = sourceObjectPath(objectId, "v2");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1, defaultVersionInfo);
        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            updater.removeFile("file3");
        });
        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("3"), updater -> {
            updater.reinstateFile(VersionNum.fromString("v1"), "file3", "file3");
        });

        verifyRepo(repoName);
    }

    @Test
    public void reinstateFileThatWasNeverRemoved() {
        var repoName = "repo10";
        var repo = defaultRepo(repoName);

        var objectId = "o3";

        var sourcePathV1 = sourceObjectPath(objectId, "v2");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1, defaultVersionInfo);
        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            updater.reinstateFile(VersionNum.fromString("v1"), "file2", "file1");
        });

        verifyRepo(repoName);
    }

    @Test
    public void shouldRejectReinstateWhenVersionDoesNotExist() {
        var repoName = "repo10";
        var repo = defaultRepo(repoName);

        var objectId = "o3";

        var sourcePathV1 = sourceObjectPath(objectId, "v2");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1, defaultVersionInfo);

        assertThat(assertThrows(OcflInputException.class, () -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
                updater.reinstateFile(VersionNum.fromString("v3"), "file2", "file1");
            });
        }).getMessage(), containsString("does not contain a file at"));
    }

    @Test
    public void shouldRejectReinstateWhenFileDoesNotExist() {
        var repoName = "repo10";
        var repo = defaultRepo(repoName);

        var objectId = "o3";

        var sourcePathV1 = sourceObjectPath(objectId, "v2");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1, defaultVersionInfo);

        assertThrows(OcflInputException.class, () -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
                updater.reinstateFile(VersionNum.fromString("v1"), "file4", "file1");
            });
        });
    }

    @Test
    public void purgeObjectWhenExists() {
        var repoName = "purge-object";
        var repo = defaultRepo(repoName);

        var objectId = "o3";

        var sourcePathV1 = sourceObjectPath(objectId, "v2");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1, defaultVersionInfo);

        repo.purgeObject(objectId);

        assertThrows(NotFoundException.class, () -> {
            repo.describeObject(objectId);
        });

        assertEquals(6, listFilesInRepo(repoName).size());
    }

    @Test
    public void purgeObjectDoNothingWhenDoesNotExist() {
        var repoName = "purge-object";
        var repo = defaultRepo(repoName);

        var objectId = "o3";

        var sourcePathV1 = sourceObjectPath(objectId, "v2");

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1, defaultVersionInfo);

        repo.purgeObject("o4");

        assertThrows(NotFoundException.class, () -> {
            repo.describeObject("o4");
        });

        assertEquals(13, listFilesInRepo(repoName).size());
    }

    @Test
    public void shouldCreateNewObjectWithUpdateObjectApi() {
        var repoName = "repo11";
        var repo = defaultRepo(repoName);

        var objectId = "o3";

        var sourcePath = sourceObjectPath(objectId, "v2");

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
            updater.addPath(sourcePath.resolve("file2"), "file2")
                    .addPath(sourcePath.resolve("file3"), "file3");
        });

        verifyRepo(repoName);
    }

    @Test
    public void shouldReturnObjectExistence() {
        var repoName = "repo11";
        var repo = defaultRepo(repoName);

        var objectId = "o3";

        var sourcePath = sourceObjectPath(objectId, "v2");

        repo.putObject(ObjectVersionId.head(objectId), sourcePath, defaultVersionInfo.setMessage("1"));

        assertTrue(repo.containsObject(objectId));
        assertFalse(repo.containsObject("o4"));
    }

    @Test
    public void shouldMoveFilesIntoRepoOnPutObjectWhenMoveSourceSpecified() {
        var repoName = "repo3";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        var sourcePathV1 = copyDir(sourceObjectPath(objectId, "v1"), inputDir.resolve("v1"));
        var sourcePathV2 = copyDir(sourceObjectPath(objectId, "v2"), inputDir.resolve("v2"));
        var sourcePathV3 = copyDir(sourceObjectPath(objectId, "v3"), inputDir.resolve("v3"));

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1, defaultVersionInfo, OcflOption.MOVE_SOURCE);
        repo.putObject(ObjectVersionId.head(objectId), sourcePathV2, defaultVersionInfo.setMessage("second"), OcflOption.MOVE_SOURCE);
        repo.putObject(ObjectVersionId.head(objectId), sourcePathV3, defaultVersionInfo.setMessage("third"), OcflOption.MOVE_SOURCE);

        verifyRepo(repoName);
        assertFalse(Files.exists(sourcePathV1));
        assertFalse(Files.exists(sourcePathV2));
        assertFalse(Files.exists(sourcePathV3));
    }

    @Test
    public void shouldMoveFilesIntoRepoOnUpdateObjectWhenMoveSourceSpecified() {
        var repoName = "repo4";
        var repo = defaultRepo(repoName);

        var objectId = "o2";

        var sourcePathV1 = copyDir(sourceObjectPath(objectId, "v1"), inputDir.resolve("v1"));
        var sourcePathV2 = copyDir(sourceObjectPath(objectId, "v2"), inputDir.resolve("v2"));
        var sourcePathV3 = copyDir(sourceObjectPath(objectId, "v3"), inputDir.resolve("v3"));

        repo.putObject(ObjectVersionId.head(objectId), sourcePathV1, defaultVersionInfo);

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            updater.addPath(sourcePathV2.resolve("dir1/file3"), "dir1/file3", OcflOption.MOVE_SOURCE)
                    .renameFile("file1", "dir3/file1");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("3"), updater -> {
            updater.removeFile("dir1/file3").removeFile("dir3/file1")
                    .addPath(sourcePathV3.resolve("dir1"), "dir1", OcflOption.MOVE_SOURCE);
        });

        verifyRepo(repoName);
        assertEquals(0, ITestHelper.listAllPaths(sourcePathV2).size());
        assertEquals(0, ITestHelper.listAllPaths(sourcePathV3).size());
    }

    @Test
    public void shouldMoveSrcDirContentsIntoSubdirWhenSubdirSpecifiedAsDst() {
        var repoName = "repo12";
        var repo = defaultRepo(repoName);

        var objectId = "o2";

        var sourcePathV1 = copyDir(sourceObjectPath(objectId, "v1"), inputDir.resolve("v1"));
        var sourcePathV2 = copyDir(sourceObjectPath(objectId, "v2"), inputDir.resolve("v2"));

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.addPath(sourcePathV1, "sub", OcflOption.MOVE_SOURCE);
        });
        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.addPath(sourcePathV2, "sub", OcflOption.MOVE_SOURCE);
        });

        verifyRepo(repoName);
    }

    @Test
    public void shouldAddFileWithFileNameWhenNoDestinationGiven() {
        var repoName = "repo13";
        var repo = defaultRepo(repoName);

        var objectId = "o2";

        var sourcePathV1 = sourceObjectPath(objectId, "v1");

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.addPath(sourcePathV1.resolve("file1"));
        });

        var files = repo.describeVersion(ObjectVersionId.head(objectId)).getFiles();

        assertEquals(1, files.size());
        assertEquals("file1", files.iterator().next().getPath());
    }

    @Test
    public void addDirectoryToRootWhenDestinationNotSpecified() {
        var repoName = "repo13";
        var repo = defaultRepo(repoName);

        var objectId = "o2";

        var sourcePathV1 = sourceObjectPath(objectId, "v1");

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.addPath(sourcePathV1, "");
        });

        verifyRepo(repoName);
    }

    @Test
    public void writeInputStreamToObjectWhenHasFixityCheckAndValid() {
        var repoName = "repo14";
        var repo = defaultRepo(repoName);

        var objectId = "o2";

        var sourcePath = sourceObjectPath(objectId, "v1");

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(
                    new FixityCheckInputStream(inputStream(sourcePath.resolve("file1")), DigestAlgorithm.md5, "95efdf0764d92207b4698025f2518456"),
                    "file1");
        });

        verifyRepo(repoName);
    }

    @Test
    public void failInputStreamToObjectWhenHasFixityCheckAndNotValid() {
        var repoName = "repo14";
        var repo = defaultRepo(repoName);

        var objectId = "o2";

        var sourcePath = sourceObjectPath(objectId, "v1");

        assertThrows(FixityCheckException.class, () -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
                updater.writeFile(
                        new FixityCheckInputStream(inputStream(sourcePath.resolve("file1")), DigestAlgorithm.md5, "bogus"),
                        "file1");
            });
        });
    }

    @Test
    public void replicatePreviousVersionToHead() {
        var repoName = "replicate1";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
            updater.writeFile(new ByteArrayInputStream("1".getBytes()), "f1")
                    .writeFile(new ByteArrayInputStream("2".getBytes()), "f2");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            updater.writeFile(new ByteArrayInputStream("3".getBytes()), "f3")
                    .removeFile("f1");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("3"), updater -> {
            updater.reinstateFile(VersionNum.fromString("v1"), "f1", "f1")
                    .writeFile(new ByteArrayInputStream("2.2".getBytes()), "f2", OcflOption.OVERWRITE);
        });

        repo.replicateVersionAsHead(ObjectVersionId.version(objectId, "v1"), defaultVersionInfo.setMessage("replicate"));

        verifyRepo(repoName);
    }

    @Test
    public void replicatePreviousVersionToHeadWhenHeadVersionSpecified() {
        var repoName = "replicate2";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
            updater.writeFile(new ByteArrayInputStream("1".getBytes()), "f1")
                    .writeFile(new ByteArrayInputStream("2".getBytes()), "f2");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            updater.writeFile(new ByteArrayInputStream("3".getBytes()), "f3")
                    .removeFile("f1");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("3"), updater -> {
            updater.reinstateFile(VersionNum.fromString("v1"), "f1", "f1")
                    .writeFile(new ByteArrayInputStream("2.2".getBytes()), "f2", OcflOption.OVERWRITE);
        });

        repo.replicateVersionAsHead(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("replicate"));

        verifyRepo(repoName);
    }

    @Test
    public void failReplicateWhenVersionDoesNotExist() {
        var repoName = "replicate3";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
            updater.writeFile(new ByteArrayInputStream("1".getBytes()), "f1")
                    .writeFile(new ByteArrayInputStream("2".getBytes()), "f2");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            updater.writeFile(new ByteArrayInputStream("3".getBytes()), "f3")
                    .removeFile("f1");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("3"), updater -> {
            updater.reinstateFile(VersionNum.fromString("v1"), "f1", "f1")
                    .writeFile(new ByteArrayInputStream("2.2".getBytes()), "f2", OcflOption.OVERWRITE);
        });

        OcflAsserts.assertThrowsWithMessage(NotFoundException.class, "version v4 was not found", () -> {
            repo.replicateVersionAsHead(ObjectVersionId.version(objectId, "v4"), defaultVersionInfo.setMessage("replicate"));
        });
    }

    @Test
    public void rollbackToPriorVersion() {
        var repoName = "rollback1";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
            updater.writeFile(new ByteArrayInputStream("1".getBytes()), "f1")
                    .writeFile(new ByteArrayInputStream("2".getBytes()), "f2");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            updater.writeFile(new ByteArrayInputStream("3".getBytes()), "f3")
                    .removeFile("f1");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("3"), updater -> {
            updater.reinstateFile(VersionNum.fromString("v1"), "f1", "f1")
                    .writeFile(new ByteArrayInputStream("2.2".getBytes()), "f2", OcflOption.OVERWRITE);
        });

        repo.rollbackToVersion(ObjectVersionId.version(objectId, "v1"));

        verifyRepo(repoName);
    }

    @Test
    public void doNothingWhenRollbackToHead() {
        var repoName = "rollback2";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
            updater.writeFile(new ByteArrayInputStream("1".getBytes()), "f1")
                    .writeFile(new ByteArrayInputStream("2".getBytes()), "f2");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            updater.writeFile(new ByteArrayInputStream("3".getBytes()), "f3")
                    .removeFile("f1");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("3"), updater -> {
            updater.reinstateFile(VersionNum.fromString("v1"), "f1", "f1")
                    .writeFile(new ByteArrayInputStream("2.2".getBytes()), "f2", OcflOption.OVERWRITE);
        });

        repo.rollbackToVersion(ObjectVersionId.head(objectId));

        verifyRepo(repoName);
    }

    @Test
    public void rollbackToPreviousVersion() {
        var repoName = "rollback3";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
            updater.writeFile(new ByteArrayInputStream("1".getBytes()), "f1")
                    .writeFile(new ByteArrayInputStream("2".getBytes()), "f2");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            updater.writeFile(new ByteArrayInputStream("3".getBytes()), "f3")
                    .removeFile("f1");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("3"), updater -> {
            updater.reinstateFile(VersionNum.fromString("v1"), "f1", "f1")
                    .writeFile(new ByteArrayInputStream("2.2".getBytes()), "f2", OcflOption.OVERWRITE);
        });

        repo.rollbackToVersion(ObjectVersionId.version(objectId, "v2"));

        verifyRepo(repoName);
    }

    @Test
    public void failRollbackWhenVersionDoesNotExist() {
        var repoName = "rollback3";
        var repo = defaultRepo(repoName);

        var objectId = "o1";

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
            updater.writeFile(new ByteArrayInputStream("1".getBytes()), "f1")
                    .writeFile(new ByteArrayInputStream("2".getBytes()), "f2");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("2"), updater -> {
            updater.writeFile(new ByteArrayInputStream("3".getBytes()), "f3")
                    .removeFile("f1");
        });

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("3"), updater -> {
            updater.reinstateFile(VersionNum.fromString("v1"), "f1", "f1")
                    .writeFile(new ByteArrayInputStream("2.2".getBytes()), "f2", OcflOption.OVERWRITE);
        });

        OcflAsserts.assertThrowsWithMessage(NotFoundException.class, "version v4 was not found", () -> {
            repo.rollbackToVersion(ObjectVersionId.version(objectId, "v4"));
        });
    }

    @Test
    public void useFinerGrainTimestamp() {
        var repoName = "timestamp";
        var repo = defaultRepo(repoName);

        var timestamp = "2020-06-29T13:40:53.703314Z";

        ITestHelper.fixTime(repo, timestamp);

        var objectId = "o1";

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
            updater.writeFile(new ByteArrayInputStream("1".getBytes()), "f1")
                    .writeFile(new ByteArrayInputStream("2".getBytes()), "f2");
        });

        var desc = repo.describeObject(objectId);

        assertEquals(timestamp, desc.getHeadVersion().getCreated().toString());
    }

    @Test
    public void flatLayoutWithValidIds() {
        var repoName = "flat-layout";
        var repo = defaultRepo(repoName, builder -> builder.defaultLayoutConfig(new FlatLayoutConfig()));


        var objectIds = List.of("o1", "object-2");

        objectIds.forEach(objectId -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
                updater.writeFile(new ByteArrayInputStream("1".getBytes()), "f1")
                        .writeFile(new ByteArrayInputStream("2".getBytes()), "f2");
            });
        });

        verifyRepo(repoName);
    }

    @Test
    public void hashedIdLayout() {
        var repoName = "hashed-id-layout";
        var repo = defaultRepo(repoName, builder -> builder.defaultLayoutConfig(new HashedNTupleIdEncapsulationLayoutConfig()));

        var objectIds = List.of("o1",
                "http://library.wisc.edu/123",
                "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghija");

        objectIds.forEach(objectId -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo.setMessage("1"), updater -> {
                updater.writeFile(new ByteArrayInputStream("1".getBytes()), "f1")
                        .writeFile(new ByteArrayInputStream("2".getBytes()), "f2");
            });
        });

        verifyRepo(repoName);
    }

    @Test
    public void makeContentPathsWindowsSafe() throws IOException {
        var repoName = "windows-safe";
        var repo = defaultRepo(repoName, builder ->
                builder.logicalPathMapper(LogicalPathMappers.percentEncodingWindowsMapper())
                        .contentPathConstraints(ContentPathConstraints.windows()));

        var logicalPath = "tést/<bad>:Path 1/\\|obj/?8*%id/#{something}/[0]/۞.txt";

        repo.updateObject(ObjectVersionId.head("o1"), defaultVersionInfo.setMessage("1"), updater -> {
            updater.writeFile(new ByteArrayInputStream("1".getBytes()), logicalPath);
        });

        verifyRepo(repoName);

        var object = repo.getObject(ObjectVersionId.head("o1"));

        assertTrue(object.containsFile(logicalPath),
                "expected object to contain logical path " + logicalPath);

        try (var stream = object.getFile(logicalPath).getStream()) {
            assertEquals("1", new String(stream.readAllBytes()));
        }
    }

    @Test
    public void createVersionsWithCustomCreateDates() {
        var repo = defaultRepo("custom-date");

        var created = OffsetDateTime.now(ZoneOffset.UTC).minusWeeks(6);

        repo.updateObject(ObjectVersionId.head("o1"), defaultVersionInfo.setCreated(created), updater -> {
            updater.writeFile(new ByteArrayInputStream("1".getBytes()), "test.txt");
        });

        assertEquals(created, repo.describeVersion(ObjectVersionId.head("o1")).getCreated());
    }

    @Test
    public void exportObjectWhenExistsWithSingleVersion() {
        var repoName = "repo1";
        var repoRoot = expectedRepoPath(repoName);
        var repo = existingRepo(repoName, repoRoot);

        var output = outputPath(repoName, "o1");

        repo.exportObject("o1", output);

        ITestHelper.verifyDirectoryContentsSame(
                repoRoot.resolve("235/2da/728/2352da7280f1decc3acf1ba84eb945c9fc2b7b541094e1d0992dbffd1b6664cc"),
                "o1",
                output);
    }

    @Test
    public void exportObjectWhenExistsWithMultipleVersion() {
        var repoName = "repo3";
        var repoRoot = expectedRepoPath(repoName);
        var repo = existingRepo(repoName, repoRoot);

        var output = outputPath(repoName, "o1");

        repo.exportObject("o1", output);

        ITestHelper.verifyDirectoryContentsSame(
                repoRoot.resolve("235/2da/728/2352da7280f1decc3acf1ba84eb945c9fc2b7b541094e1d0992dbffd1b6664cc"),
                "o1",
                output);
    }

    @Test
    public void failExportObjectWhenDoesNotExist() {
        var repoName = "repo3";
        var repoRoot = expectedRepoPath(repoName);
        var repo = existingRepo(repoName, repoRoot);

        var output = outputPath(repoName, "o2");

        OcflAsserts.assertThrowsWithMessage(NotFoundException.class, "Object ObjectId{objectId='o2', versionNum='null'} was not found.", () -> {
            repo.exportObject("o2", output);
        });
    }

    @Test
    public void exportObjectVersionWhenExists() {
        var repoName = "repo3";
        var repoRoot = expectedRepoPath(repoName);
        var repo = existingRepo(repoName, repoRoot);

        var output = outputPath(repoName, "o1v2");

        repo.exportVersion(ObjectVersionId.version("o1", "v2"), output);

        ITestHelper.verifyDirectoryContentsSame(
                repoRoot.resolve("235/2da/728/2352da7280f1decc3acf1ba84eb945c9fc2b7b541094e1d0992dbffd1b6664cc/v2"),
                "o1v2",
                output);
    }

    @Test
    public void exportObjectVersionWhenHeadRequested() {
        var repoName = "repo3";
        var repoRoot = expectedRepoPath(repoName);
        var repo = existingRepo(repoName, repoRoot);

        var output = outputPath(repoName, "o1-head");

        repo.exportVersion(ObjectVersionId.head("o1"), output);

        ITestHelper.verifyDirectoryContentsSame(
                repoRoot.resolve("235/2da/728/2352da7280f1decc3acf1ba84eb945c9fc2b7b541094e1d0992dbffd1b6664cc/v3"),
                "o1-head",
                output);
    }

    @Test
    public void failExportObjectVersionWhenObjectsExistsButNotVersion() {
        var repoName = "repo3";
        var repoRoot = expectedRepoPath(repoName);
        var repo = existingRepo(repoName, repoRoot);

        var output = outputPath(repoName, "o1-head");

        OcflAsserts.assertThrowsWithMessage(NotFoundException.class, "Object o1 version v4", () -> {
            repo.exportVersion(ObjectVersionId.version("o1", "v4"), output);
        });
    }

    @Test
    public void failExportObjectVersionWhenObjectsDoesNotExist() {
        var repoName = "repo3";
        var repoRoot = expectedRepoPath(repoName);
        var repo = existingRepo(repoName, repoRoot);

        var output = outputPath(repoName, "o1-head");

        OcflAsserts.assertThrowsWithMessage(NotFoundException.class, "Object o2", () -> {
            repo.exportVersion(ObjectVersionId.version("o2", "v1"), output);
        });
    }

    @Test
    public void failObjectImportWhenRepoAlreadyContainsObject() {
        var repoName1 = "repo1";
        var repoRoot1 = expectedRepoPath(repoName1);
        var repo1 = existingRepo(repoName1, repoRoot1);

        var output = outputPath(repoName1, "o1");

        repo1.exportObject("o1", output);

        var repoName2 = "repo3";
        var repoRoot2 = expectedRepoPath(repoName2);
        var repo2 = existingRepo(repoName2, repoRoot2);

        OcflAsserts.assertThrowsWithMessage(AlreadyExistsException.class, "object already exists", () -> {
            repo2.importObject(output);
        });
    }

    @Test
    public void importObjectWhenDoesNotAlreadyExist() {
        var objectId = "o1";
        var repoName1 = "repo1";
        var repoRoot1 = expectedRepoPath(repoName1);
        var repo1 = existingRepo(repoName1, repoRoot1);

        var output = outputPath(repoName1, objectId);

        repo1.exportObject(objectId, output);

        var repoName2 = "repo4";
        var repoRoot2 = expectedRepoPath(repoName2);
        var repo2 = existingRepo(repoName2, repoRoot2);

        repo2.importObject(output);

        assertTrue(repo2.containsObject(objectId));
        assertEquals(repo1.describeObject(objectId), repo2.describeObject(objectId));
    }

    @Test
    public void importObjectWhenDoesNotAlreadyExistAndMoveOperation() {
        var objectId = "o1";
        var repoName1 = "repo1";
        var repoRoot1 = expectedRepoPath(repoName1);
        var repo1 = existingRepo(repoName1, repoRoot1);

        var output = outputPath(repoName1, objectId);

        repo1.exportObject(objectId, output);

        var repoName2 = "repo4";
        var repoRoot2 = expectedRepoPath(repoName2);
        var repo2 = existingRepo(repoName2, repoRoot2);

        repo2.importObject(output, OcflOption.MOVE_SOURCE);

        assertTrue(repo2.containsObject(objectId));
        assertEquals(repo1.describeObject(objectId), repo2.describeObject(objectId));
    }

    @Test
    public void rejectImportObjectWhenObjectFailsValidation() throws IOException {
        var objectId = "o1";
        var repoName1 = "repo1";
        var repoRoot1 = expectedRepoPath(repoName1);
        var repo1 = existingRepo(repoName1, repoRoot1);

        var output = outputPath(repoName1, objectId);

        repo1.exportObject(objectId, output);

        var repoName2 = "repo4";
        var repoRoot2 = expectedRepoPath(repoName2);
        var repo2 = existingRepo(repoName2, repoRoot2);

        Files.delete(output.resolve("v1/content/file1"));

        OcflAsserts.assertThrowsWithMessage(ValidationException.class, "file1", () -> {
            repo2.importObject(output, OcflOption.MOVE_SOURCE);
        });
    }

    @Test
    public void rejectImportObjectWhenObjectMissingInventory() throws IOException {
        var objectId = "o1";
        var repoName1 = "repo1";
        var repoRoot1 = expectedRepoPath(repoName1);
        var repo1 = existingRepo(repoName1, repoRoot1);

        var output = outputPath(repoName1, objectId);

        repo1.exportObject(objectId, output);

        var repoName2 = "repo4";
        var repoRoot2 = expectedRepoPath(repoName2);
        var repo2 = existingRepo(repoName2, repoRoot2);

        Files.delete(output.resolve("inventory.json"));

        OcflAsserts.assertThrowsWithMessage(OcflInputException.class, "inventory.json", () -> {
            repo2.importObject(output, OcflOption.MOVE_SOURCE);
        });
    }

    @Test
    public void importVersionWhenObjectExistsAndIsNextVersion() {
        var objectId = "o1";

        var repoName1 = "import-version-1";
        var repo1 = defaultRepo(repoName1);
        var repo2 = defaultRepo("import-version-2");

        repo1.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file1"), "file1.txt");
            updater.writeFile(streamString("file2"), "file2.txt");
        });
        repo2.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file1"), "file1.txt");
            updater.writeFile(streamString("file2"), "file2.txt");
        });

        repo1.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file3"), "file3.txt");
            updater.removeFile("file1.txt");
        });

        var output = outputPath(repoName1, objectId);

        repo1.exportVersion(ObjectVersionId.version(objectId, "v2"), output);

        repo2.importVersion(output);

        assertEquals("v2", repo2.describeObject(objectId).getHeadVersionNum().toString());
        assertEquals(repo1.describeObject(objectId), repo2.describeObject(objectId));
    }

    @Test
    public void importVersionWhenObjectDoesNotExistAndIsFirstVersion() {
        var objectId = "o1";

        var repoName1 = "import-version-1";
        var repo1 = defaultRepo(repoName1);
        var repo2 = defaultRepo("import-version-2");

        repo1.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file1"), "file1.txt");
            updater.writeFile(streamString("file2"), "file2.txt");
        });
        repo1.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file3"), "file3.txt");
            updater.removeFile("file1.txt");
        });

        var output = outputPath(repoName1, objectId);

        repo1.exportVersion(ObjectVersionId.version(objectId, "v1"), output);

        repo2.importVersion(output);

        assertEquals("v1", repo2.describeObject(objectId).getHeadVersionNum().toString());
        assertEquals(repo1.describeVersion(ObjectVersionId.version(objectId, "v1")),
                repo2.describeVersion(ObjectVersionId.version(objectId, "v1")));
    }

    @Test
    public void rejectImportVersionWhenObjectExistsAndNotNextVersion() {
        var objectId = "o1";

        var repoName1 = "import-version-1";
        var repo1 = defaultRepo(repoName1);
        var repo2 = defaultRepo("import-version-2");

        repo1.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file1"), "file1.txt");
            updater.writeFile(streamString("file2"), "file2.txt");
        });
        repo2.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file1"), "file1.txt");
            updater.writeFile(streamString("file2"), "file2.txt");
        });

        repo1.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file3"), "file3.txt");
            updater.removeFile("file1.txt");
        });

        var output = outputPath(repoName1, objectId);

        repo1.exportVersion(ObjectVersionId.version(objectId, "v1"), output);

        OcflAsserts.assertThrowsWithMessage(OcflStateException.class, "must be the next sequential version", () -> {
            repo2.importVersion(output);
        });
    }

    @Test
    public void rejectImportVersionWhenObjectDoesNotExistAndNotFirstVersion() {
        var objectId = "o1";

        var repoName1 = "import-version-1";
        var repo1 = defaultRepo(repoName1);
        var repo2 = defaultRepo("import-version-2");

        repo1.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file1"), "file1.txt");
            updater.writeFile(streamString("file2"), "file2.txt");
        });

        repo1.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file3"), "file3.txt");
            updater.removeFile("file1.txt");
        });

        var output = outputPath(repoName1, objectId);

        repo1.exportVersion(ObjectVersionId.version(objectId, "v2"), output);

        OcflAsserts.assertThrowsWithMessage(OcflStateException.class, "The object doest not exist in the repository; therefore only v1 may be imported", () -> {
            repo2.importVersion(output);
        });
    }

    @Test
    public void rejectImportVersionWhenVersionMissingInventory() throws IOException {
        var objectId = "o1";

        var repoName1 = "import-version-1";
        var repo1 = defaultRepo(repoName1);
        var repo2 = defaultRepo("import-version-2");

        repo1.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file1"), "file1.txt");
            updater.writeFile(streamString("file2"), "file2.txt");
        });
        repo2.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file1"), "file1.txt");
            updater.writeFile(streamString("file2"), "file2.txt");
        });

        repo1.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file3"), "file3.txt");
            updater.removeFile("file1.txt");
        });

        var output = outputPath(repoName1, objectId);

        repo1.exportVersion(ObjectVersionId.version(objectId, "v2"), output);

        Files.delete(output.resolve("inventory.json"));

        OcflAsserts.assertThrowsWithMessage(OcflInputException.class, "inventory.json", () -> {
            repo2.importVersion(output);
        });
    }

    @Test
    public void rejectImportVersionWhenVersionInvalid() throws IOException {
        var objectId = "o1";

        var repoName1 = "import-version-1";
        var repo1 = defaultRepo(repoName1);
        var repo2 = defaultRepo("import-version-2");

        repo1.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file1"), "file1.txt");
            updater.writeFile(streamString("file2"), "file2.txt");
        });
        repo2.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file1"), "file1.txt");
            updater.writeFile(streamString("file2"), "file2.txt");
        });

        repo1.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file3"), "file3.txt");
            updater.removeFile("file1.txt");
        });

        var output = outputPath(repoName1, objectId);

        repo1.exportVersion(ObjectVersionId.version(objectId, "v2"), output);

        Files.delete(output.resolve("content/file3.txt"));

        OcflAsserts.assertThrowsWithMessage(OcflStateException.class, "file3.txt", () -> {
            repo2.importVersion(output);
        });
    }

    @Test
    public void rejectUpdateWhenConcurrentChangeToPreviousVersion() throws InterruptedException {
        var objectId = "o1";

        var repoName = "concurrent-change";
        var repo = defaultRepo(repoName);

        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file1"), "file1.txt");
        });
        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file2"), "file2.txt");
        });

        var future = CompletableFuture.runAsync(() -> {
            repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
                try {
                    TimeUnit.SECONDS.sleep(3);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                updater.writeFile(streamString("file3"), "file3.txt");
            });
        });

        TimeUnit.MILLISECONDS.sleep(100);

        repo.rollbackToVersion(ObjectVersionId.version(objectId, "v1"));
        repo.updateObject(ObjectVersionId.head(objectId), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file4"), "file4.txt");
        });

        OcflAsserts.assertThrowsWithMessage(ObjectOutOfSyncException.class,
                "Cannot update object o1 because the update is out of sync with the current object state. The digest of the current inventory is ", () -> {
                    try {
                        future.get();
                    } catch (ExecutionException e) {
                        throw e.getCause();
                    }
            });

        var desc = repo.describeObject(objectId);

        assertEquals("v2", desc.getHeadVersionNum().toString());
        assertTrue(desc.getHeadVersion().containsFile("file4.txt"));
        assertFalse(desc.getHeadVersion().containsFile("file3.txt"));
    }

    @Test
    public void rejectPathsThatConflictWithExtensions() {
        var repo = defaultRepo("flat", builder -> builder.defaultLayoutConfig(new FlatLayoutConfig()));

        OcflAsserts.assertThrowsWithMessage(OcflExtensionException.class, "conflicts with the extensions directory", () -> {
            repo.updateObject(ObjectVersionId.head("extensions"), null, updater -> {
                updater.writeFile(streamString("file3"), "file3.txt");
            });
        });
    }

    @Test
    public void failWhenRepoContainsUnsupportedExtension() {
        var repoName = "unsupported-root-ext";
        var repoRoot = sourceRepoPath(repoName);

        OcflAsserts.assertThrowsWithMessage(OcflExtensionException.class, "1000-bogus", () -> {
            existingRepo(repoName, repoRoot);
        });
    }

    @Test
    public void failWhenRepoContainsUnsupportedObjectExtension() {
        var repoName = "unsupported-object-ext";
        var repoRoot = sourceRepoPath(repoName);
        var repo = existingRepo(repoName, repoRoot);

        OcflAsserts.assertThrowsWithMessage(OcflExtensionException.class, "1000-bogus", () -> {
            repo.describeObject("o2");
        });
    }

    @Test
    public void doNotFailWhenRepoContainsUnsupportedExtensionAndSetToWarn() {
        var repoName = "unsupported-root-ext";
        var repoRoot = sourceRepoPath(repoName);

        existingRepo(repoName, repoRoot, builder -> {
            builder.unsupportedExtensionBehavior(UnsupportedExtensionBehavior.WARN);
        });
    }

    @Test
    public void doNotFailWhenRepoContainsUnsupportedObjectExtensionAndSetToWarn() {
        var repoName = "unsupported-object-ext";
        var repoRoot = sourceRepoPath(repoName);

        var repo = existingRepo(repoName, repoRoot, builder -> {
            builder.unsupportedExtensionBehavior(UnsupportedExtensionBehavior.WARN);
        });

        repo.describeObject("o2");
    }

    @Test
    public void invalidateCacheWhenObjectExists() {
        var repoName = "clear-cache";

        var cache = new CaffeineCache<String, Inventory>(Caffeine.newBuilder()
                .expireAfterAccess(Duration.ofMinutes(10))
                .maximumSize(512).build());

        var repo = defaultRepo(repoName, builder -> {
            builder.inventoryCache(cache);
        });

        var objectId1 = "o1";
        var objectId2 = "o2";

        repo.updateObject(ObjectVersionId.head(objectId1), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file1"), "file1.txt");
        });
        repo.updateObject(ObjectVersionId.head(objectId1), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file2"), "file2.txt");
        });
        repo.updateObject(ObjectVersionId.head(objectId2), defaultVersionInfo, updater -> {
            updater.writeFile(streamString("file3"), "file3.txt");
        });

        assertTrue(cache.contains(objectId1));
        assertTrue(cache.contains(objectId2));

        repo.invalidateCache(objectId1);

        assertFalse(cache.contains(objectId1));
        assertTrue(cache.contains(objectId2));

        repo.describeObject(objectId1);

        assertTrue(cache.contains(objectId1));

        repo.invalidateCache();

        assertFalse(cache.contains(objectId1));
        assertFalse(cache.contains(objectId2));
    }

    @Test
    public void shouldReturnValidationErrorsWhenObjectIsInvalid() {
        var repoName = "repo-with-invalid-object";
        var repoRoot = sourceRepoPath(repoName);

        var repo = existingRepo(repoName, repoRoot);

        var results = repo.validateObject("E003_no_decl", true);

        assertEquals(4, results.getErrors().size(), () -> results.getErrors().toString());
        assertEquals(3, results.getWarnings().size(), () -> results.getWarnings().toString());
    }

    @Test
    public void shouldFailWhenInventoryIdDoesNotMatchExpectedId() {
        var repoName = "repo-with-mismatched-id";
        var repoRoot = sourceRepoPath(repoName);

        var repo = existingRepo(repoName, repoRoot);

        OcflAsserts.assertThrowsWithMessage(CorruptObjectException.class,
                "Expected object at object-2 to have id object-2. Found: object-1", () -> {
            repo.describeObject("object-2");
        });
    }

    private void verifyStream(Path expectedFile, OcflObjectVersionFile actual) throws IOException {
        var stream = actual.getStream();
        var contents = TestHelper.inputToString(stream);
        stream.checkFixity();
        assertEquals(TestHelper.inputToString(Files.newInputStream(expectedFile)), contents);
    }

    private Path outputPath(String repoName, String path) {
        try {
            var output = outputDir.resolve(Paths.get(repoName, path));
            Files.createDirectories(output.getParent());
            return output;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
