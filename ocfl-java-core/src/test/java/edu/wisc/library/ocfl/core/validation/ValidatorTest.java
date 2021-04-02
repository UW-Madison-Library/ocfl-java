package edu.wisc.library.ocfl.core.validation;

import edu.wisc.library.ocfl.api.model.ValidationCode;
import edu.wisc.library.ocfl.api.model.ValidationResults;
import edu.wisc.library.ocfl.core.validation.storage.FileSystemStorage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Paths;
import java.security.Security;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class ValidatorTest {

    private static final String OFFICIAL_BAD_FIXTURES = "official/bad-objects";
    private static final String OFFICIAL_WARN_FIXTURES = "official/warn-objects";
    private static final String CUSTOM_BAD_FIXTURES = "custom/bad-objects";

    @BeforeAll
    public static void beforeAll() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "minimal_content_dir_called_stuff",
            "minimal_mixed_digests",
            "minimal_no_content",
            "minimal_one_version_one_file",
            "minimal_uppercase_digests",
            "ocfl_object_all_fixity_digests",
            "spec-ex-full",
            "updates_all_actions",
            "updates_three_versions_one_file",
    })
    public void validateGoodFixtureObject(String name) {
        var validator = createValidator("official/good-objects");
        var results = validator.validateObject(name, true);
        assertNoIssues(results);
    }

    @Test
    public void errorOnExtraDirInRoot() {
        var name = "E001_extra_dir_in_root";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E001, "Object root E001_extra_dir_in_root contains an unexpected file extra_dir");
        assertWarningsCount(results, 2);
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a user in E001_extra_dir_in_root/inventory.json");
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a message in E001_extra_dir_in_root/inventory.json");
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnContentNotInContentDir() {
        var name = "E015_content_not_in_content_dir";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 9);
        assertHasError(results, ValidationCode.E015, "Version directory v3 in E015_content_not_in_content_dir contains an unexpected file a_file.txt");
        assertHasError(results, ValidationCode.E015, "Version directory v2 in E015_content_not_in_content_dir contains an unexpected file a_file.txt");
        assertHasError(results, ValidationCode.E015, "Version directory v1 in E015_content_not_in_content_dir contains an unexpected file a_file.txt");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnExtraFileInRoot() {
        var name = "E001_extra_file_in_root";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E001, "Object root E001_extra_file_in_root contains an unexpected file extra_file");
        assertWarningsCount(results, 2);
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a user in E001_extra_file_in_root/inventory.json");
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a message in E001_extra_file_in_root/inventory.json");
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnEmptyObjectRot() {
        var name = "E003_E034_empty";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 2);
        assertHasError(results, ValidationCode.E003, "OCFL object version declaration must exist at E003_E034_empty/0=ocfl_object_1.0");
        assertHasError(results, ValidationCode.E063, "Object root inventory not found at E003_E034_empty/inventory.json");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnNoObjectDeclarationWithOtherIssues() {
        var name = "E003_no_decl";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 7);
        assertHasError(results, ValidationCode.E003, "OCFL object version declaration must exist at E003_no_decl/0=ocfl_object_1.0");
        assertHasError(results, ValidationCode.E102, "Inventory version v1 cannot contain unknown property type in E003_no_decl/inventory.json");
        assertHasError(results, ValidationCode.E038, "Inventory type must equal 'https://ocfl.io/1.0/spec/#inventory' in E003_no_decl/inventory.json");
        assertHasError(results, ValidationCode.E036, "Inventory head must be set in E003_no_decl/inventory.json");
        assertHasError(results, ValidationCode.E048, "Inventory version v1 must contain a created timestamp in E003_no_decl/inventory.json");
        assertHasError(results, ValidationCode.E060, "Inventory at E003_no_decl/inventory.json does not match expected sha512 digest. Expected: 14f15a87d1f9d02c1bf9cf08d6c7f9af96d2a69a9715a8dbb2e938cba271e1f204f3b2b6d3df93ead1bb5b7b925fc23dc207207220aa190947349729c2c1f74a; Found: 1c27836424fc93b67d9eac795f234fcc8c3825d54c26ab7254dfbb47bf432a184df5e96e65bd4c1e2db4c0d5172ce2f0fc589fd6a6a30ebbec0aae7938318815");
        assertHasError(results, ValidationCode.E061, "Inventory sidecar file at E003_no_decl/inventory.json.sha512 is in an invalid format");
        assertWarningsCount(results, 2);
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a user in E003_no_decl/inventory.json");
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a message in E003_no_decl/inventory.json");
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnNoObjectDeclaration() {
        var name = "E003_no_decl";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E003, "OCFL object version declaration must exist at E003_no_decl/0=ocfl_object_1.0");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnBadDeclarationContents() {
        var name = "E007_bad_declaration_contents";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E007, "OCFL object version declaration must be '0=ocfl_object_1.0' in E007_bad_declaration_contents/0=ocfl_object_1.0");
        assertWarningsCount(results, 2);
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a user in E007_bad_declaration_contents/inventory.json");
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a message in E007_bad_declaration_contents/inventory.json");
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnMissingHeadVersion() {
        var name = "E008_E036_no_versions_no_head";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 2);
        assertHasError(results, ValidationCode.E008, "Inventory must contain at least one version E008_E036_no_versions_no_head/inventory.json");
        assertHasError(results, ValidationCode.E036, "Inventory head must be set in E008_E036_no_versions_no_head/inventory.json");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnExtraContentFile() {
        var name = "E023_extra_file";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E023, "Object contains a file in version content that is not referenced in the manifest of E023_extra_file/inventory.json: v1/content/file2.txt");
        assertWarningsCount(results, 1);
        assertHasWarn(results, ValidationCode.W009, "Inventory version v1 user address should be a URI in E023_extra_file/inventory.json. Found: somewhere");
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnMissingContentFile() {
        var name = "E023_missing_file";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E092, "Inventory manifest in E023_missing_file/inventory.json contains a content path that does not exist: v1/content/file2.txt");
        assertWarningsCount(results, 1);
        assertHasWarn(results, ValidationCode.W009, "Inventory version v1 user address should be a URI in E023_missing_file/inventory.json. Found: somewhere");
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnMissingInventory() {
        var name = "E034_no_inv";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E063, "Object root inventory not found at E034_no_inv/inventory.json");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnMissingId() {
        var name = "E036_no_id";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E036, "Inventory id must be set in E036_no_id/inventory.json");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnHeadDoesNotExist() {
        var name = "E040_wrong_head_doesnt_exist";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 2);
        assertHasError(results, ValidationCode.E044, "Inventory versions is missing an entry for version v2 in E040_wrong_head_doesnt_exist/inventory.json");
        assertHasError(results, ValidationCode.E040, "Inventory head must be the highest version number in E040_wrong_head_doesnt_exist/inventory.json. Expected: v1; Found: v2");
        assertWarningsCount(results, 2);
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a user in E040_wrong_head_doesnt_exist/inventory.json");
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a message in E040_wrong_head_doesnt_exist/inventory.json");
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnWrongHeadFormat() {
        var name = "E040_wrong_head_format";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 2);
        assertHasError(results, ValidationCode.E040, "Inventory head must be a string in E040_wrong_head_format/inventory.json");
        assertHasError(results, ValidationCode.E036, "Inventory head must be set in E040_wrong_head_format/inventory.json");
        assertWarningsCount(results, 2);
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a user in E040_wrong_head_format/inventory.json");
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a message in E040_wrong_head_format/inventory.json");
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnNoManifest() {
        var name = "E041_no_manifest";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E041, "Inventory manifest must be set in E041_no_manifest/inventory.json");
        assertWarningsCount(results, 2);
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a user in E041_no_manifest/inventory.json");
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a message in E041_no_manifest/inventory.json");
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnMissingTimezone() {
        var name = "E049_created_no_timezone";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E049, "Inventory version v1 created timestamp must be formatted in accordance to RFC3339 in E049_created_no_timezone/inventory.json. Found: 2019-01-01T02:03:04");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnTimeNotInSeconds() {
        var name = "E049_created_not_to_seconds";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E049, "Inventory version v1 created timestamp must be formatted in accordance to RFC3339 in E049_created_not_to_seconds/inventory.json. Found: 2019-01-01T01:02Z");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnBadVersionBlock() {
        var name = "E049_E050_E054_bad_version_block_values";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 7);
        assertHasError(results, ValidationCode.E049, "Inventory version v1 created timestamp must be a string in E049_E050_E054_bad_version_block_values/inventory.json");
        assertHasError(results, ValidationCode.E050, "Inventory version v1 state must be an object in E049_E050_E054_bad_version_block_values/inventory.json");
        assertHasError(results, ValidationCode.E094, "Inventory version v1 message must be a string in E049_E050_E054_bad_version_block_values/inventory.json");
        assertHasError(results, ValidationCode.E054, "Inventory version v1 user must be an object in E049_E050_E054_bad_version_block_values/inventory.json");
        assertHasError(results, ValidationCode.E048, "Inventory version v1 must contain a created timestamp in E049_E050_E054_bad_version_block_values/inventory.json");
        assertHasError(results, ValidationCode.E054, "Inventory version v1 user name must be set in E049_E050_E054_bad_version_block_values/inventory.json");
        assertHasError(results, ValidationCode.E048, "Inventory version v1 must contain a state in E049_E050_E054_bad_version_block_values/inventory.json");
        assertWarningsCount(results, 2);
        assertHasWarn(results, ValidationCode.W008, "Inventory version v1 user address should be set in E049_E050_E054_bad_version_block_values/inventory.json");
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a message in E049_E050_E054_bad_version_block_values/inventory.json");
        assertInfoCount(results, 0);
    }

    // TODO dubious recommended code for this one
    // TODO not currently verifying all manifest entries are used
//    @Test
    public void errorOnFileInManifestNotUsed() {
        var name = "E050_file_in_manifest_not_used";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E050, "Inventory version v1 created timestamp must be a string in E049_E050_E054_bad_version_block_values/inventory.json");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnNoSidecarWithOtherIssues() {
        var name = "E058_no_sidecar";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 3);
        assertHasError(results, ValidationCode.E058, "Inventory sidecar missing at E058_no_sidecar/inventory.json.sha512");
        assertHasError(results, ValidationCode.E023, "Object contains a file in version content that is not referenced in the manifest of E058_no_sidecar/inventory.json: v1/content/file.txt");
        assertHasError(results, ValidationCode.E092, "Inventory manifest in E058_no_sidecar/inventory.json contains a content path that does not exist: v1/content/a_file.txt");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnNoSidecar() {
        var name = "E058_no_sidecar";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E058, "Inventory sidecar missing at E058_no_sidecar/inventory.json.sha512");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnInventoryMismatch() {
        var name = "E064_different_root_and_latest_inventories";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E064, "Inventory at E064_different_root_and_latest_inventories/v1/inventory.json must be identical to the inventory in the object root");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnFileInExtensionsDir() {
        var name = "E067_file_in_extensions_dir";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E067, "Object extensions directory E067_file_in_extensions_dir/extensions cannot contain file extra_file");
        assertWarningsCount(results, 3);
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a user in E067_file_in_extensions_dir/inventory.json");
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a message in E067_file_in_extensions_dir/inventory.json");
        assertHasWarn(results, ValidationCode.W013, "Object extensions directory E067_file_in_extensions_dir/extensions contains unregistered extension unregistered");
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnConflictingLogicalPaths() {
        var name = "E095_conflicting_logical_paths";
        var validator = createValidator(OFFICIAL_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E095, "Inventory version v1 paths must be non-conflicting in E095_conflicting_logical_paths/inventory.json. Found conflicting path: sub-path");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnIncorrectContentDigest() {
        var name = "E025_E001_wrong_digest_algorithm";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 2);
        assertHasError(results, ValidationCode.E025, "Inventory digest algorithm must be one of [sha512, sha256] in E025_E001_wrong_digest_algorithm/inventory.json. Found: md5");
        assertHasError(results, ValidationCode.E001, "Object root E025_E001_wrong_digest_algorithm contains an unexpected file inventory.json.md5");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnMissingHeadField() {
        var name = "E036_no_head";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E036, "Inventory head must be set in E036_no_head/inventory.json");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnInvalidHeadVersion() {
        var name = "E011_E001_invalid_head_version_format";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 3);
        assertHasError(results, ValidationCode.E011, "Inventory contains invalid version number in E011_E001_invalid_head_version_format/inventory.json. Found: 1");
        assertHasError(results, ValidationCode.E011, "Inventory contains invalid version number in E011_E001_invalid_head_version_format/inventory.json. Found: 1");
        assertHasError(results, ValidationCode.E001, "Object root E011_E001_invalid_head_version_format contains an unexpected file 1");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnInvalidZeroPaddedHeadVersion() {
        var name = "E013_invalid_padded_head_version";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E013, "Inventory versions contain inconsistently padded version numbers in E013_invalid_padded_head_version/inventory.json");
        assertWarningsCount(results, 9);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnSkippedVersions() {
        var name = "E044_skipped_versions";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 3);
        assertHasError(results, ValidationCode.E044, "Inventory versions is missing an entry for version v2 in E044_skipped_versions/inventory.json");
        assertHasError(results, ValidationCode.E044, "Inventory versions is missing an entry for version v3 in E044_skipped_versions/inventory.json");
        assertHasError(results, ValidationCode.E044, "Inventory versions is missing an entry for version v6 in E044_skipped_versions/inventory.json");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnMissingVersions() {
        var name = "E010_missing_versions";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E010, "Object root at E010_missing_versions is missing version directory v3");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnRootInventoryDigestMismatch() {
        var name = "E060_E064_root_inventory_digest_mismatch";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 2);
        assertHasError(results, ValidationCode.E060, "Inventory at E060_E064_root_inventory_digest_mismatch/inventory.json does not match expected sha512 digest. Expected: cb7a451c595050e0e50d979b79bce86e28728b8557a3cf4ea430114278b5411c7bad6a7ecc1f4d0250e94f9d8add3b648194d75a74c0cb14c4439f427829569e; Found: 5bf08b6519f6692cc83f3d275de1f02414a41972d069ac167c5cf34468fad82ae621c67e1ff58a8ef15d5f58a193aa1f037f588372bdfc33ae6c38a2b349d846");
        assertHasError(results, ValidationCode.E064, "Inventory at E060_E064_root_inventory_digest_mismatch/v1/inventory.json must be identical to the inventory in the object root");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnVersionInventoryDigestMismatch() {
        var name = "E060_version_inventory_digest_mismatch";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 3);
        assertHasError(results, ValidationCode.E060, "Inventory at E060_version_inventory_digest_mismatch/v1/inventory.json does not match expected sha512 digest. Expected: cb7a451c595050e0e50d979b79bce86e28728b8557a3cf4ea430114278b5411c7bad6a7ecc1f4d0250e94f9d8add3b648194d75a74c0cb14c4439f427829569e; Found: 5bf08b6519f6692cc83f3d275de1f02414a41972d069ac167c5cf34468fad82ae621c67e1ff58a8ef15d5f58a193aa1f037f588372bdfc33ae6c38a2b349d846");
        assertHasError(results, ValidationCode.E064, "Inventory at E060_version_inventory_digest_mismatch/v2/inventory.json must be identical to the inventory in the object root");
        assertHasError(results, ValidationCode.E060, "Inventory at E060_version_inventory_digest_mismatch/v2/inventory.json does not match expected sha512 digest. Expected: 4c4299547f3a093936d99484f4ecb1a3b40368819b77d1f03593fdce7d67ef67a8f4c620737ffb3b8108f91f496a164682659b8d991ae60fb4c44b4aaa002485; Found: c56b92c06dd381999ef073476cee9a6ec5aed6a4c11ad74487bec838d532104456cd5575266dd8ae85529fd6b6e600023806601a3fe7f5affe9487701722fdb4");
        assertWarningsCount(results, 1);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnInvalidContentDir() {
        var name = "E017_invalid_content_dir";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E017, "Inventory content directory cannot contain '/' in E017_invalid_content_dir/inventory.json");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnRootInventoryNotMostRecent() {
        var name = "E046_root_not_most_recent";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E046, "Object root E046_root_not_most_recent contains version directory v2 but the version does not exist in the root inventory");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnHeadNotMostRecent() {
        var name = "E040_head_not_most_recent";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E040, "Inventory head must be the highest version number in E040_head_not_most_recent/inventory.json. Expected: v2; Found: v1");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnManifestDuplicateDigests() {
        var name = "E096_manifest_duplicate_digests";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 2);
        assertHasError(results, ValidationCode.E096, "Inventory manifest cannot contain duplicates of digest 24f950aac7b9ea9b3cb728228a0c82b67c39e96b4b344798870d5daee93e3ae5931baae8c7cacfea4b629452c38026a81d138bc7aad1af3ef7bfd5ec646d6c28 in E096_manifest_duplicate_digests/inventory.json");
        assertHasError(results, ValidationCode.E101, "Inventory manifest content paths must be unique in E096_manifest_duplicate_digests/inventory.json. Found: v1/content/test.txt");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnInvalidContentPaths() {
        var name = "E100_E099_manifest_invalid_content_paths";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 3);
        assertHasError(results, ValidationCode.E099, "Inventory manifest cannot contain blank content path parts in E100_E099_manifest_invalid_content_paths/inventory.json. Found: v1/content//file-2.txt");
        assertHasError(results, ValidationCode.E099, "Inventory manifest cannot contain content path parts equal to '.' or '..' in E100_E099_manifest_invalid_content_paths/inventory.json. Found: v1/content/../content/file-1.txt");
        assertHasError(results, ValidationCode.E100, "Inventory manifest cannot contain content paths that begin or end with '/' in E100_E099_manifest_invalid_content_paths/inventory.json. Found: /v1/content/file-3.txt");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnNonUniqueContentPath() {
        var name = "E101_non_unique_content_paths";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E101, "Inventory manifest content paths must be unique in E101_non_unique_content_paths/inventory.json. Found: v1/content/test.txt");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnLogicalPathReferencingNonExistentDigest() {
        var name = "E050_missing_manifest_entry";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E050, "Inventory version v1 contains digest 07e41ccb166d21a5327d5a2ae1bb48192b8470e1357266c9d119c294cb1e95978569472c9de64fb6d93cbd4dd0aed0bf1e7c47fd1920de17b038a08a85eb4fa1 that does not exist in the manifest in E050_missing_manifest_entry/inventory.json");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnLogicalPathReferencesDigestDifferentCase() {
        var name = "E050_manifest_digest_wrong_case";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E050, "Inventory version v1 contains digest 24F950AAC7B9EA9B3CB728228A0C82B67C39E96B4B344798870D5DAEE93E3AE5931BAAE8C7CACFEA4B629452C38026A81D138BC7AAD1AF3EF7BFD5EC646D6C28 that does not exist in the manifest in E050_manifest_digest_wrong_case/inventory.json");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnNonUniqueLogicalPath() {
        var name = "E095_non_unique_logical_paths";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 2);
        assertHasError(results, ValidationCode.E095, "Inventory version v1 paths must be unique in E095_non_unique_logical_paths/inventory.json. Found: file-1.txt");
        assertHasError(results, ValidationCode.E095, "Inventory version v1 paths must be unique in E095_non_unique_logical_paths/inventory.json. Found: file-3.txt");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }


    @Test
    public void errorOnInvalidLogicalPaths() {
        var name = "E053_E052_invalid_logical_paths";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 4);
        assertHasError(results, ValidationCode.E052, "Inventory version v1 cannot contain path parts equal to '.' or '..' in E053_E052_invalid_logical_paths/inventory.json. Found: ../../file-2.txt");
        assertHasError(results, ValidationCode.E053, "Inventory version v1 cannot contain paths that begin or end with '/' in E053_E052_invalid_logical_paths/inventory.json. Found: /file-1.txt");
        assertHasError(results, ValidationCode.E053, "Inventory version v1 cannot contain paths that begin or end with '/' in E053_E052_invalid_logical_paths/inventory.json. Found: //file-3.txt");
        assertHasError(results, ValidationCode.E052, "Inventory version v1 cannot contain blank path parts in E053_E052_invalid_logical_paths/inventory.json. Found: //file-3.txt");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnFixityDuplicateDigests() {
        var name = "E097_fixity_duplicate_digests";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 2);
        assertHasError(results, ValidationCode.E097, "Inventory fixity block cannot contain duplicates of digest eb1a3227cdc3fedbaec2fe38bf6c044a in E097_fixity_duplicate_digests/inventory.json");
        assertHasError(results, ValidationCode.E101, "Inventory fixity block content paths must be unique in E097_fixity_duplicate_digests/inventory.json. Found: v1/content/test.txt");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnFixityInvalidContentPaths() {
        var name = "E100_E099_fixity_invalid_content_paths";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 3);
        assertHasError(results, ValidationCode.E099, "Inventory fixity block cannot contain content path parts equal to '.' or '..' in E100_E099_fixity_invalid_content_paths/inventory.json. Found: v1/content/../content/file-1.txt");
        assertHasError(results, ValidationCode.E099, "Inventory fixity block cannot contain blank content path parts in E100_E099_fixity_invalid_content_paths/inventory.json. Found: v1/content//file-2.txt");
        assertHasError(results, ValidationCode.E100, "Inventory fixity block cannot contain content paths that begin or end with '/' in E100_E099_fixity_invalid_content_paths/inventory.json. Found: /v1/content/file-3.txt");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnInvalidSidecar() {
        var name = "E061_invalid_sidecar";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E061, "Inventory sidecar file at E061_invalid_sidecar/inventory.json.sha512 is in an invalid format");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnInconsistentId() {
        var name = "E037_inconsistent_id";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E037, "Inventory id is inconsistent between versions in E037_inconsistent_id/v1/inventory.json. Expected: urn:example-2; Found: urn:example-two");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnWrongVersion() {
        var name = "E040_wrong_version_in_version_dir";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E040, "Inventory head must be the highest version number in E040_wrong_version_in_version_dir/inventory.json. Expected: v3; Found: v2");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnInconsistentContentDir() {
        var name = "E019_inconsistent_content_dir";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 3);
        assertHasError(results, ValidationCode.E019, "Inventory content directory is inconsistent between versions in E019_inconsistent_content_dir/v1/inventory.json. Expected: content; Found: content-dir");
        assertHasError(results, ValidationCode.E092, "Inventory manifest in E019_inconsistent_content_dir/v1/inventory.json contains a content path that does not exist: v1/content-dir/test.txt");
        assertHasError(results, ValidationCode.E092, "Inventory manifest in E019_inconsistent_content_dir/inventory.json contains a content path that does not exist: v1/content-dir/test.txt");
        assertWarningsCount(results, 1);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnInconsistentVersionState() {
        var name = "E066_inconsistent_version_state";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 3);
        assertHasError(results, ValidationCode.E066, "In E066_inconsistent_version_state/v1/inventory.json version v1's state contains a path that does not exist in the root inventory: 1.txt");
        assertHasError(results, ValidationCode.E066, "In E066_inconsistent_version_state/v1/inventory.json version v1's state contains a path that does not exist in the root inventory: 2.txt");
        assertHasError(results, ValidationCode.E066, "In E066_inconsistent_version_state/v1/inventory.json version v1's state contains a path that does not exist in the root inventory: 3.txt");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnContentPathDoesNotExist() {
        var name = "E092_E093_content_path_does_not_exist";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 2);
        assertHasError(results, ValidationCode.E092, "Inventory manifest in E092_E093_content_path_does_not_exist/inventory.json contains a content path that does not exist: v1/content/bonus.txt");
        assertHasError(results, ValidationCode.E093, "Inventory fixity in E092_E093_content_path_does_not_exist/inventory.json contains a content path that does not exist: v1/content/bonus.txt");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnContentFileDoesNotMatchDigest() {
        var name = "E092_content_file_digest_mismatch";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E092, "File E092_content_file_digest_mismatch/v1/content/test.txt failed sha512 fixity check. Expected: 24f950aac7b9ea9b3cb728228a0c82b67c39e96b4b344798870d5daee93e3ae5931baae8c7cacfea4b629452c38026a81d138bc7aad1af3ef7bfd5ec646d6c28; Actual: 1277a792c8196a2504007a40f31ed93bf826e71f16273d8503f7d3e46503d00b8d8cda0a59d6a33b9c1aebc84ea6a79f7062ee080f4a9587055a7b6fb92f5fa8");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnFixityDoesNotMatchDigest() {
        var name = "E093_fixity_digest_mismatch";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E093, "File E093_fixity_digest_mismatch/v1/content/test.txt failed md5 fixity check. Expected: 9eacfb9289073dd9c9a8c4cdf820ac71; Actual: eb1a3227cdc3fedbaec2fe38bf6c044a");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnOldManifestMissingEntries() {
        var name = "E023_old_manifest_missing_entries";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 1);
        assertHasError(results, ValidationCode.E023, "Object contains a file in version content that is not referenced in the manifest of E023_old_manifest_missing_entries/v2/inventory.json: v1/content/file-3.txt");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnDigestChangeStateMismatch() {
        var name = "E066_algorithm_change_state_mismatch";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 4);
        assertHasError(results, ValidationCode.E066, "In E066_algorithm_change_state_mismatch/v1/inventory.json version v1's state contains a path that is inconsistent with the root inventory: file-2.txt");
        assertHasError(results, ValidationCode.E066, "In E066_algorithm_change_state_mismatch/v1/inventory.json version v1's state contains a path that is inconsistent with the root inventory: file-3.txt");
        assertHasError(results, ValidationCode.E066, "In E066_algorithm_change_state_mismatch/v1/inventory.json version v1's state is missing a path that exist in the root inventory: changed");
        assertHasError(results, ValidationCode.E066, "In E066_algorithm_change_state_mismatch/v1/inventory.json version v1's state contains a path that does not exist in the root inventory: file-1.txt");
        assertWarningsCount(results, 1);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnAlgorithmChangeInvalidDigest() {
        var name = "E093_algorithm_change_incorrect_digest";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 3);
        assertHasError(results, ValidationCode.E093, "File E093_algorithm_change_incorrect_digest/v1/content/file-2.txt failed sha512 fixity check. Expected: 1fef2458ee1a9277925614272adfe60872f4c1bf02eecce7276166957d1ab30f65cf5c8065a294bf1b13e3c3589ba936a3b5db911572e30dfcb200ef71ad33d5; Actual: 9fef2458ee1a9277925614272adfe60872f4c1bf02eecce7276166957d1ab30f65cf5c8065a294bf1b13e3c3589ba936a3b5db911572e30dfcb200ef71ad33d5");
        assertHasError(results, ValidationCode.E093, "File E093_algorithm_change_incorrect_digest/v1/content/file-3.txt failed sha512 fixity check. Expected: 13b26d26c9d8cfbb884b50e798f93ac6bef275a018547b1560af3e6d38f2723785731d3ca6338682fa7ac9acb506b3c594a125ce9d3d60cd14498304cc864cf2; Actual: b3b26d26c9d8cfbb884b50e798f93ac6bef275a018547b1560af3e6d38f2723785731d3ca6338682fa7ac9acb506b3c594a125ce9d3d60cd14498304cc864cf2");
        assertHasError(results, ValidationCode.E093, "File E093_algorithm_change_incorrect_digest/v1/content/file-1.txt failed sha512 fixity check. Expected: 17e41ccb166d21a5327d5a2ae1bb48192b8470e1357266c9d119c294cb1e95978569472c9de64fb6d93cbd4dd0aed0bf1e7c47fd1920de17b038a08a85eb4fa1; Actual: 07e41ccb166d21a5327d5a2ae1bb48192b8470e1357266c9d119c294cb1e95978569472c9de64fb6d93cbd4dd0aed0bf1e7c47fd1920de17b038a08a85eb4fa1");
        assertWarningsCount(results, 1);
        assertInfoCount(results, 0);
    }

    @Test
    public void errorOnManifestDigestWrongInOldVersion() {
        var name = "E066_E092_old_manifest_digest_incorrect";
        var validator = createValidator(CUSTOM_BAD_FIXTURES);

        var results = validator.validateObject(name, true);

        assertErrorCount(results, 2);
        assertHasError(results, ValidationCode.E066, "In E066_E092_old_manifest_digest_incorrect/v1/inventory.json version v1's state contains a path that is inconsistent with the root inventory: file-1.txt");
        assertHasError(results, ValidationCode.E092, "Inventory manifest entry in E066_E092_old_manifest_digest_incorrect/v1/inventory.json for content path v1/content/file-1.txt differs from later versions. Expected: 07e41ccb166d21a5327d5a2ae1bb48192b8470e1357266c9d119c294cb1e95978569472c9de64fb6d93cbd4dd0aed0bf1e7c47fd1920de17b038a08a85eb4fa1; Found: 17e41ccb166d21a5327d5a2ae1bb48192b8470e1357266c9d119c294cb1e95978569472c9de64fb6d93cbd4dd0aed0bf1e7c47fd1920de17b038a08a85eb4fa1");
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void warnOnZeroPaddedVersionsAndOtherErrors() {
        var name = "W001_W004_W005_zero_padded_versions";
        var validator = createValidator(OFFICIAL_WARN_FIXTURES);

        var results = validator.validateObject(name, true);

        assertWarningsCount(results, 12);
        assertHasWarn(results, ValidationCode.W001, "Object contains zero-padded version v0003 in W001_W004_W005_zero_padded_versions");
        assertHasWarn(results, ValidationCode.W001, "Object contains zero-padded version v0001 in W001_W004_W005_zero_padded_versions");
        assertHasWarn(results, ValidationCode.W001, "Object contains zero-padded version v0004 in W001_W004_W005_zero_padded_versions");
        assertHasWarn(results, ValidationCode.W001, "Object contains zero-padded version v0002 in W001_W004_W005_zero_padded_versions");
        assertHasWarn(results, ValidationCode.W005, "Inventory id should be a URI in W001_W004_W005_zero_padded_versions/inventory.json. Found: bb123cd4567");
        assertHasWarn(results, ValidationCode.W005, "Inventory id should be a URI in W001_W004_W005_zero_padded_versions/v0001/inventory.json. Found: bb123cd4567");
        assertHasWarn(results, ValidationCode.W005, "Inventory id should be a URI in W001_W004_W005_zero_padded_versions/v0003/inventory.json. Found: bb123cd4567");
        assertHasWarn(results, ValidationCode.W005, "Inventory id should be a URI in W001_W004_W005_zero_padded_versions/v0002/inventory.json. Found: bb123cd4567");
        assertHasWarn(results, ValidationCode.W004, "Inventory digest algorithm should be sha512 in W001_W004_W005_zero_padded_versions/inventory.json. Found: sha256");
        assertHasWarn(results, ValidationCode.W004, "Inventory digest algorithm should be sha512 in W001_W004_W005_zero_padded_versions/v0001/inventory.json. Found: sha256");
        assertHasWarn(results, ValidationCode.W004, "Inventory digest algorithm should be sha512 in W001_W004_W005_zero_padded_versions/v0002/inventory.json. Found: sha256");
        assertHasWarn(results, ValidationCode.W004, "Inventory digest algorithm should be sha512 in W001_W004_W005_zero_padded_versions/v0003/inventory.json. Found: sha256");
        assertErrorCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void warnOnZeroPaddedVersions() {
        var name = "W001_zero_padded_versions";
        var validator = createValidator(OFFICIAL_WARN_FIXTURES);

        var results = validator.validateObject(name, true);

        assertWarningsCount(results, 3);
        assertHasWarn(results, ValidationCode.W001, "Object contains zero-padded version v003 in W001_zero_padded_versions");
        assertHasWarn(results, ValidationCode.W001, "Object contains zero-padded version v002 in W001_zero_padded_versions");
        assertHasWarn(results, ValidationCode.W001, "Object contains zero-padded version v001 in W001_zero_padded_versions");
        assertErrorCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void warnOnExtraDirInVersion() {
        var name = "W002_extra_dir_in_version_dir";
        var validator = createValidator(OFFICIAL_WARN_FIXTURES);

        var results = validator.validateObject(name, true);

        assertWarningsCount(results, 1);
        assertHasWarn(results, ValidationCode.W002, "Version directory v1 in W002_extra_dir_in_version_dir contains an unexpected directory extra_dir");
        assertErrorCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void warnOnSha256() {
        var name = "W004_uses_sha256";
        var validator = createValidator(OFFICIAL_WARN_FIXTURES);

        var results = validator.validateObject(name, true);

        assertWarningsCount(results, 1);
        assertHasWarn(results, ValidationCode.W004, "Inventory digest algorithm should be sha512 in W004_uses_sha256/inventory.json. Found: sha256");
        assertErrorCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void warnOnSha256InVersion() {
        var name = "W004_versions_diff_digests";
        var validator = createValidator(OFFICIAL_WARN_FIXTURES);

        var results = validator.validateObject(name, true);

        assertWarningsCount(results, 1);
        assertHasWarn(results, ValidationCode.W004, "Inventory digest algorithm should be sha512 in W004_versions_diff_digests/v1/inventory.json. Found: sha256");
        assertErrorCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void warnOnIdNotUri() {
        var name = "W005_id_not_uri";
        var validator = createValidator(OFFICIAL_WARN_FIXTURES);

        var results = validator.validateObject(name, true);

        assertWarningsCount(results, 1);
        assertHasWarn(results, ValidationCode.W005, "Inventory id should be a URI in W005_id_not_uri/inventory.json. Found: not_a_uri");
        assertErrorCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void warnOnNoMessageOrUser() {
        var name = "W007_no_message_or_user";
        var validator = createValidator(OFFICIAL_WARN_FIXTURES);

        var results = validator.validateObject(name, true);

        assertWarningsCount(results, 2);
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a user in W007_no_message_or_user/inventory.json");
        assertHasWarn(results, ValidationCode.W007, "Inventory version v1 should contain a message in W007_no_message_or_user/inventory.json");
        assertErrorCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void warnOnUserNoAddress() {
        var name = "W008_user_no_address";
        var validator = createValidator(OFFICIAL_WARN_FIXTURES);

        var results = validator.validateObject(name, true);

        assertWarningsCount(results, 1);
        assertHasWarn(results, ValidationCode.W008, "Inventory version v1 user address should be set in W008_user_no_address/inventory.json");
        assertErrorCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void warnOnUserAddressNotUri() {
        var name = "W009_user_address_not_uri";
        var validator = createValidator(OFFICIAL_WARN_FIXTURES);

        var results = validator.validateObject(name, true);

        assertWarningsCount(results, 1);
        assertHasWarn(results, ValidationCode.W009, "Inventory version v1 user address should be a URI in W009_user_address_not_uri/inventory.json. Found: 1 Wonky Way, Wibblesville, WW");
        assertErrorCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void warnOnNoVersionInventory() {
        var name = "W010_no_version_inventory";
        var validator = createValidator(OFFICIAL_WARN_FIXTURES);

        var results = validator.validateObject(name, true);

        assertWarningsCount(results, 1);
        assertHasWarn(results, ValidationCode.W010, "Every version should contain an inventory. Missing: W010_no_version_inventory/v1/inventory.json");
        assertErrorCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void warnOnVersionMetaChangeBetweenVersions() {
        var name = "W011_version_inv_diff_metadata";
        var validator = createValidator(OFFICIAL_WARN_FIXTURES);

        var results = validator.validateObject(name, true);

        assertWarningsCount(results, 3);
        assertHasWarn(results, ValidationCode.W011, "The version created timestamp of version v1 in W011_version_inv_diff_metadata/v1/inventory.json is inconsistent with the root inventory");
        assertHasWarn(results, ValidationCode.W011, "The version message of version v1 in W011_version_inv_diff_metadata/v1/inventory.json is inconsistent with the root inventory");
        assertHasWarn(results, ValidationCode.W011, "The version user of version v1 in W011_version_inv_diff_metadata/v1/inventory.json is inconsistent with the root inventory");
        assertErrorCount(results, 0);
        assertInfoCount(results, 0);
    }

    @Test
    public void warnOnUnregisteredExtension() {
        var name = "W013_unregistered_extension";
        var validator = createValidator(OFFICIAL_WARN_FIXTURES);

        var results = validator.validateObject(name, true);

        assertWarningsCount(results, 1);
        assertHasWarn(results, ValidationCode.W013, "Object extensions directory W013_unregistered_extension/extensions contains unregistered extension unregistered");
        assertErrorCount(results, 0);
        assertInfoCount(results, 0);
    }

    private void assertHasError(ValidationResults results, ValidationCode code, String message) {
        for (var error : results.getErrors()) {
            if (error.getCode() == code && Objects.equals(error.getMessage(), message)) {
                return;
            }
        }

        fail(String.format("Expected error <code=%s; message=%s>. Found: %s",
                code, message, results.getErrors()));
    }

    private void assertHasWarn(ValidationResults results, ValidationCode code, String message) {
        for (var warning : results.getWarnings()) {
            if (warning.getCode() == code && Objects.equals(warning.getMessage(), message)) {
                return;
            }
        }

        fail(String.format("Expected warning <code=%s; message=%s>. Found: %s",
                code, message, results.getWarnings()));
    }

    private void assertNoIssues(ValidationResults results) {
        assertErrorCount(results, 0);
        assertWarningsCount(results, 0);
        assertInfoCount(results, 0);
    }

    private void assertErrorCount(ValidationResults results, int count) {
        assertEquals(count, results.getErrors().size(),
                () -> String.format("Expected %s errors. Found: %s", count, results.getErrors()));
    }

    private void assertWarningsCount(ValidationResults results, int count) {
        assertEquals(count, results.getWarnings().size(),
                () -> String.format("Expected %s warnings. Found: %s", count, results.getWarnings()));
    }

    private void assertInfoCount(ValidationResults results, int count) {
        assertEquals(count, results.getInfos().size(),
                () -> String.format("Expected %s info. Found: %s", count, results.getInfos()));
    }

    private Validator createValidator(String rootName) {
        var storage = new FileSystemStorage(Paths.get("src/test/resources/fixtures", rootName));
        return new Validator(storage);
    }

}
