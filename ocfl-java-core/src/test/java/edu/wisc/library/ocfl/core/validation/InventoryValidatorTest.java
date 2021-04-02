package edu.wisc.library.ocfl.core.validation;

import edu.wisc.library.ocfl.api.OcflConfig;
import edu.wisc.library.ocfl.api.exception.InvalidInventoryException;
import edu.wisc.library.ocfl.api.model.DigestAlgorithm;
import edu.wisc.library.ocfl.api.model.VersionNum;
import edu.wisc.library.ocfl.core.model.Inventory;
import edu.wisc.library.ocfl.core.model.InventoryBuilder;
import edu.wisc.library.ocfl.core.model.User;
import edu.wisc.library.ocfl.core.model.Version;
import edu.wisc.library.ocfl.test.OcflAsserts;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;

public class InventoryValidatorTest {

    @Test
    public void failWhenHeadV0() {
        OcflAsserts.assertThrowsWithMessage(InvalidInventoryException.class, "HEAD version must be greater than v0", () -> {
            InventoryValidator.validateShallow(defaultBuilder().build());
        });
    }

    @Test
    public void failWhenContentDirHasSlashes() {
        OcflAsserts.assertThrowsWithMessage(InvalidInventoryException.class, "Content directory cannot contain", () -> {
            InventoryValidator.validateShallow(defaultBuilder()
                    .head(new VersionNum(1))
                    .contentDirectory("path/dir")
                    .build());
        });
        OcflAsserts.assertThrowsWithMessage(InvalidInventoryException.class, "Content directory cannot contain", () -> {
            InventoryValidator.validateShallow(defaultBuilder()
                    .head(new VersionNum(1))
                    .contentDirectory("path\\dir")
                    .build());
        });
    }

    @Test
    public void failWhenContentDirBlank() {
        OcflAsserts.assertThrowsWithMessage(InvalidInventoryException.class, "Content directory cannot be blank", () -> {
            InventoryValidator.validateShallow(defaultBuilder()
                    .head(new VersionNum(1))
                    .contentDirectory("")
                    .build());
        });
    }

    @Test
    public void failWhenVersionsEmpty() {
        OcflAsserts.assertThrowsWithMessage(InvalidInventoryException.class, "Versions cannot be empty", () -> {
            InventoryValidator.validateShallow(defaultBuilder()
                    .head(new VersionNum(1))
                    .build());
        });
    }

    @Test
    public void failWhenUserNameBlank() {
        OcflAsserts.assertThrowsWithMessage(InvalidInventoryException.class, "User name in version v1 cannot be blank", () -> {
            InventoryValidator.validateShallow(defaultBuilder()
                    .addHeadVersion(Version.builder()
                            .created(OffsetDateTime.now())
                            .user(new User(null, null))
                            .build()).build());
        });
    }

    @Test
    public void failWhenMissingVersion() {
        OcflAsserts.assertThrowsWithMessage(InvalidInventoryException.class, "Version v1 is missing", () -> {
            InventoryValidator.validateShallow(defaultBuilder()
                    .head(new VersionNum(1))
                    .addHeadVersion(Version.builder()
                            .created(OffsetDateTime.now())
                            .build()).build());
        });
    }

    @Test
    public void failWhenFileNotReferencedInManifest() {
        OcflAsserts.assertThrowsWithMessage(InvalidInventoryException.class, "Version state entry 1 => [file1] in version v1 does not have a corresponding entry in the manifest block.", () -> {
            InventoryValidator.validateShallow(defaultBuilder()
                    .addHeadVersion(Version.builder()
                            .created(OffsetDateTime.now())
                            .addFile("1", "file1")
                            .build()).build());
        });
    }

    @Test
    public void failWhenHeadVersionNotLatestVersion() {
        OcflAsserts.assertThrowsWithMessage(InvalidInventoryException.class, "HEAD must be the latest version. Expected: v2; Was: v1", () -> {
            InventoryValidator.validateShallow(defaultBuilder()
                    .addHeadVersion(Version.builder()
                            .created(OffsetDateTime.now())
                            .build())
                    .addHeadVersion(Version.builder()
                            .created(OffsetDateTime.now())
                            .build())
                    .head(new VersionNum(1)).build());
        });
    }

    @Test
    public void failWhenVersionNumberPaddedDifferently() {
        var currentInventory = defaultBuilder()
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .build())
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .build()).build();

        var previousInventory = defaultBuilder()
                .head(VersionNum.fromString("v000"))
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .build()).build();

        OcflAsserts.assertThrowsWithMessage(InvalidInventoryException.class, "Inventory o1 v2: Version number formatting differs: v001 vs v1", () -> {
            InventoryValidator.validateVersionStates(currentInventory, previousInventory);
        });
    }

    @Test
    public void failWhenVersionStatesDoNotMatch() {
        var currentInventory = defaultBuilder()
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .addFile("abc123", "file1")
                        .addFile("abc456", "file2")
                        .build())
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .build()).build();

        var previousInventory = defaultBuilder()
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .addFile("abc123", "file1")
                        .addFile("def456", "file2")
                        .build()).build();

        OcflAsserts.assertThrowsWithMessage(InvalidInventoryException.class, "In object o1 the inventories in version v2 and v1 define a different state for version v1.", () -> {
            InventoryValidator.validateVersionStates(currentInventory, previousInventory);
        });
    }

    @Test
    public void failWhenVersionStatesDoNotMatchAndOneValid() {
        var currentInventory = defaultBuilder()
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .addFile("abc123", "file1")
                        .addFile("abc456", "file2")
                        .build())
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .addFile("abc123", "file1")
                        .addFile("abc456", "file2")
                        .addFile("abc789", "file3")
                        .build())
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .build()).build();

        var previousInventory = defaultBuilder()
                .head(new VersionNum(0))
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .addFile("abc123", "file1")
                        .build())
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .addFile("abc123", "file1")
                        .addFile("abc456", "file2")
                        .addFile("abc789", "file3")
                        .build()).build();

        OcflAsserts.assertThrowsWithMessage(InvalidInventoryException.class, "In object o1 the inventories in version v3 and v2 define a different state for version v1.", () -> {
            InventoryValidator.validateVersionStates(currentInventory, previousInventory);
        });
    }

    @Test
    public void doNotFailWhenUserChanged() {
        var currentInventory = defaultBuilder()
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .addFile("abc123", "file1")
                        .addFile("abc456", "file2")
                        .user(new User("test", "test@example.com"))
                        .build())
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .build()).build();

        var previousInventory = defaultBuilder()
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .addFile("abc123", "file1")
                        .addFile("abc456", "file2")
                        .user(new User("example", "example@test.com"))
                        .build()).build();

        InventoryValidator.validateVersionStates(currentInventory, previousInventory);
    }

    @Test
    public void failWhenIdDifferent() {
        var currentInventory = defaultBuilder()
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .addFile("abc123", "file1")
                        .addFile("abc456", "file2")
                        .build())
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .build()).build();

        var previousInventory = builder("o2")
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .addFile("abc123", "file1")
                        .addFile("abc456", "file2")
                        .build()).build();

        OcflAsserts.assertThrowsWithMessage(InvalidInventoryException.class, "Object IDs are not the same. Existing: o2; New: o1", () -> {
            InventoryValidator.validateCompatibleInventories(currentInventory, previousInventory);
        });
    }

    @Test
    public void failWhenAlgorithmsDifferent() {
        var currentInventory = defaultBuilder()
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .addFile("abc123", "file1")
                        .addFile("abc456", "file2")
                        .build())
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .build()).build();

        var previousInventory = defaultBuilder()
                .digestAlgorithm(DigestAlgorithm.sha256)
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .addFile("abc123", "file1")
                        .addFile("abc456", "file2")
                        .build()).build();

        OcflAsserts.assertThrowsWithMessage(InvalidInventoryException.class, "Inventory digest algorithms are not the same. Existing: sha256; New: sha512", () -> {
            InventoryValidator.validateCompatibleInventories(currentInventory, previousInventory);
        });
    }

    @Test
    public void failWhenContentDirectoryDifferent() {
        var currentInventory = defaultBuilder()
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .addFile("abc123", "file1")
                        .addFile("abc456", "file2")
                        .build())
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .build()).build();

        var previousInventory = defaultBuilder()
                .contentDirectory("new-content")
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .addFile("abc123", "file1")
                        .addFile("abc456", "file2")
                        .build()).build();

        OcflAsserts.assertThrowsWithMessage(InvalidInventoryException.class, "Inventory content directories are not the same. Existing: new-content; New: content", () -> {
            InventoryValidator.validateCompatibleInventories(currentInventory, previousInventory);
        });
    }

    @Test
    public void failWhenNotOneVersionApart() {
        var currentInventory = defaultBuilder()
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .addFile("abc123", "file1")
                        .addFile("abc456", "file2")
                        .build())
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .build())
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .build()).build();

        var previousInventory = defaultBuilder()
                .addHeadVersion(Version.builder()
                        .created(OffsetDateTime.now())
                        .addFile("abc123", "file1")
                        .addFile("abc456", "file2")
                        .build()).build();

        OcflAsserts.assertThrowsWithMessage(InvalidInventoryException.class, "The new HEAD inventory version must be the next sequential version number. Existing: v1; New: v3", () -> {
            InventoryValidator.validateCompatibleInventories(currentInventory, previousInventory);
        });
    }

    private InventoryBuilder defaultBuilder() {
        return builder("o1");
    }

    private InventoryBuilder builder(String id) {
        return Inventory.stubInventory(id, new OcflConfig(), "root").buildFrom();
    }

}
