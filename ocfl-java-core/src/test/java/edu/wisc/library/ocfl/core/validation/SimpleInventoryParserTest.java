package edu.wisc.library.ocfl.core.validation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.wisc.library.ocfl.api.model.DigestAlgorithm;
import edu.wisc.library.ocfl.api.model.InventoryType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class SimpleInventoryParserTest {

    private static final String ID_KEY = "id";
    private static final String TYPE_KEY = "type";
    private static final String ALGO_KEY = "digestAlgorithm";
    private static final String HEAD_KEY = "head";
    private static final String CONTENT_DIR_KEY = "contentDirectory";
    private static final String FIXITY_KEY = "fixity";
    private static final String MANIFEST_KEY = "manifest";
    private static final String VERSIONS_KEY = "versions";

    private static final String CREATED_KEY = "created";
    private static final String MESSAGE_KEY = "message";
    private static final String USER_KEY = "user";
    private static final String STATE_KEY = "state";

    private static final String NAME_KEY = "name";
    private static final String ADDRESS_KEY = "address";

    private static final String NAME = "inventory.json";

    private SimpleInventoryParser parser;
    private ObjectMapper objectMapper;

    @BeforeEach
    public void setup() {
        parser = new SimpleInventoryParser();
        objectMapper = new ObjectMapper();
    }

    @Test
    public void validateMostMinimalInventory() {
        var results = parser.parse(toStream(inventoryStub()), NAME);

        assertWarnCount(results, 0);
        assertErrorCount(results, 0);
        assertTrue(results.getInventory().isPresent());
    }

    @Test
    public void errorWhenHasUnknownProps() {
        var inv = inventoryStub();
        inv.put("bogus", "this should not exist");

        var results = parser.parse(toStream(inv), NAME);

        assertErrorCount(results, 1);
        assertWarnCount(results, 0);
        assertError(results, ValidationCode.E102, "Inventory cannot contain unknown property bogus in inventory.json");
        assertTrue(results.getInventory().isPresent());
    }

    @Test
    public void errorWhenIdWrongType() {
        var inv = inventoryStub();
        var manifest = new HashMap<String, Object>();
        manifest.put("digest", null);
        inv.put(ID_KEY, manifest);

        var results = parser.parse(toStream(inv), NAME);

        assertErrorCount(results, 1);
        assertWarnCount(results, 0);
        assertError(results, ValidationCode.E037, "Inventory id must be a string in inventory.json");
        assertTrue(results.getInventory().isPresent());
    }

    @Test
    public void errorWhenVersionWrongType() {
        var inv = inventoryStub();
        ((Map<String, Object>) inv.get(VERSIONS_KEY)).put("v1", "version one");

        var results = parser.parse(toStream(inv), NAME);

        assertErrorCount(results, 1);
        assertWarnCount(results, 0);
        assertError(results, ValidationCode.E047, "Inventory versions must be objects in inventory.json");
        assertTrue(results.getInventory().isPresent());
    }

    @Test
    public void errorWhenJsonNotParsable() {
        var results = parser.parse(
                new ByteArrayInputStream("{\"bad\": \"json\"".getBytes(StandardCharsets.UTF_8)), NAME);

        assertErrorCount(results, 1);
        assertWarnCount(results, 0);
        assertError(results, ValidationCode.E033, "Inventory at inventory.json is an invalid JSON document");
        assertFalse(results.getInventory().isPresent());
    }

    private void assertErrorCount(SimpleInventoryParser.ParseSimpleInventoryResult results, int count) {
        assertEquals(count, results.getValidationResults().getErrors().size(),
                () -> String.format("Expected %s errors. Found: %s", count, results.getValidationResults().getErrors()));
    }

    private void assertError(SimpleInventoryParser.ParseSimpleInventoryResult results, ValidationCode code, String message) {
        for (var error : results.getValidationResults().getErrors()) {
            if (error.getCode() == code && error.getMessage().contains(message)) {
                return;
            }
        }

        fail(String.format("Expected error <code=%s; message=%s>. Found: %s",
                code, message, results.getValidationResults().getErrors()));
    }

    private void assertWarnCount(SimpleInventoryParser.ParseSimpleInventoryResult results, int count) {
        assertEquals(count, results.getValidationResults().getWarnings().size(),
                () -> String.format("Expected %s warnings. Found: %s", count, results.getValidationResults().getWarnings()));
    }

    private void assertWarn(SimpleInventoryParser.ParseSimpleInventoryResult results, ValidationCode code, String message) {
        for (var warn : results.getValidationResults().getWarnings()) {
            if (warn.getCode() == code && warn.getMessage().contains(message)) {
                return;
            }
        }

        fail(String.format("Expected warning <code=%s; message=%s>. Found: %s",
                code, message, results.getValidationResults().getWarnings()));
    }

    private Map<String, Object> inventoryStub() {
        var inv = new HashMap<String, Object>();

        inv.put(ID_KEY, "id");
        inv.put(TYPE_KEY, InventoryType.OCFL_1_0.getId());
        inv.put(ALGO_KEY, DigestAlgorithm.sha512.getOcflName());
        inv.put(HEAD_KEY, "v1");
        inv.put(MANIFEST_KEY, new HashMap<String, Object>());

        var versions = new HashMap<String, Object>();
        versions.put("v1", versionStub());

        inv.put(VERSIONS_KEY, versions);

        return inv;
    }

    private Map<String, Object> versionStub() {
        var version = new HashMap<String, Object>();
        version.put(CREATED_KEY, OffsetDateTime.now().toString());
        version.put(STATE_KEY, new HashMap<String, Object>());
        return version;
    }

    private InputStream toStream(Map<String, Object> map) {
        try {
            return new ByteArrayInputStream(objectMapper.writeValueAsBytes(map));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

}
