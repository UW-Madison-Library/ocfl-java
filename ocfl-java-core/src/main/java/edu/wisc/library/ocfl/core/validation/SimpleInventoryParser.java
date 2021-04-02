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

package edu.wisc.library.ocfl.core.validation;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.wisc.library.ocfl.api.exception.OcflIOException;
import edu.wisc.library.ocfl.api.model.ValidationCode;
import edu.wisc.library.ocfl.api.model.ValidationResults;
import edu.wisc.library.ocfl.api.util.Enforce;
import edu.wisc.library.ocfl.core.validation.model.SimpleInventory;
import edu.wisc.library.ocfl.core.validation.model.SimpleUser;
import edu.wisc.library.ocfl.core.validation.model.SimpleVersion;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Parses a JSON inventory into a minimally valid SimpleInventory object.
 */
public class SimpleInventoryParser {

    private final ObjectMapper objectMapper;

    public SimpleInventoryParser() {
        objectMapper = new ObjectMapper();
    }

    /**
     * Parses the input stream JSON into a minimally valid SimpleInventory object. The only reason an inventory
     * object would not be returned is if the JSON is syntactically invalid. Otherwise, a SimpleInventory is returned
     * with any validation issues noted. The validation issues reported here are strictly related to JSON structural
     * issues such as invalid types or keys.
     *
     * @param inventoryStream JSON inventory stream
     * @param inventoryPath path to the source JSON file, this is used for constructing validation messages
     * @return the results of the parse
     */
    public ParseSimpleInventoryResult parse(InputStream inventoryStream, String inventoryPath) {
        Enforce.notNull(inventoryStream, "jsonTree cannot be null");
        Enforce.notNull(inventoryPath, "inventoryPath cannot be null");

        SimpleInventory inventory = null;
        var results = new ValidationResultsBuilder();

        var jsonTree = parseStream(inventoryStream, inventoryPath, results);

        if (jsonTree != null) {
            inventory = convertToSimpleInventory(jsonTree, inventoryPath, results);
        }

        return new ParseSimpleInventoryResult(inventory, results.build());
    }

    private JsonNode parseStream(InputStream inventoryStream, String inventoryPath, ValidationResultsBuilder results) {
        try {
            return objectMapper.readTree(inventoryStream);
        } catch (JsonParseException e) {
            results.addIssue(ValidationCode.E033, "Inventory at %s is an invalid JSON document", inventoryPath);
            return null;
        } catch (IOException e) {
            throw new OcflIOException(e);
        }
    }

    private SimpleInventory convertToSimpleInventory(JsonNode jsonTree, String inventoryPath, ValidationResultsBuilder results) {
        var inventory = new SimpleInventory();

        jsonTree.fields().forEachRemaining(entry -> {
            var fieldName = entry.getKey();
            var field = entry.getValue();

            switch (fieldName) {
                case SimpleInventory.ID_KEY:
                    inventory.setId(parseString(field,
                            () -> results.addIssue(ValidationCode.E037,
                                    "Inventory id must be a string in %s",
                                    inventoryPath)));
                    break;
                case SimpleInventory.TYPE_KEY:
                    inventory.setType(parseString(field,
                            () -> results.addIssue(ValidationCode.E038,
                                    "Inventory type must be a string in %s",
                                    inventoryPath)));
                    break;
                case SimpleInventory.DIGEST_ALGO_KEY:
                    inventory.setDigestAlgorithm(parseString(field,
                            () -> results.addIssue(ValidationCode.E033,
                                    "Inventory digest algorithm must be a string in %s",
                                    inventoryPath)));
                    break;
                case SimpleInventory.HEAD_KEY:
                    inventory.setHead(parseString(field,
                            () -> results.addIssue(ValidationCode.E040,
                                    "Inventory head must be a string in %s",
                                    inventoryPath)));
                    break;
                case SimpleInventory.CONTENT_DIR_KEY:
                    inventory.setContentDirectory(parseString(field,
                            () -> results.addIssue(ValidationCode.E033,
                                    "Inventory content directory must be a string in %s",
                                    inventoryPath)));
                    break;
                case SimpleInventory.FIXITY_KEY:
                    inventory.setFixity(parseFixity(field, inventoryPath, results));
                    break;
                case SimpleInventory.MANIFEST_KEY:
                    inventory.setManifest(parseManifest(field, inventoryPath, results));
                    break;
                case SimpleInventory.VERSIONS_KEY:
                    inventory.setVersions(parseVersions(field, inventoryPath, results));
                    break;
                default:
                    results.addIssue(ValidationCode.E102, "Inventory cannot contain unknown property %s in %s",
                            fieldName, inventoryPath);
                    break;
            }
        });

        return inventory;
    }

    private SimpleVersion parseVersion(JsonNode versionNode, String versionNum, String inventoryPath, ValidationResultsBuilder results) {
        var version = new SimpleVersion();

        versionNode.fields().forEachRemaining(entry -> {
            var fieldName = entry.getKey();
            var field = entry.getValue();

            switch (fieldName) {
                case SimpleVersion.CREATED_KEY:
                    version.setCreated(parseString(field,
                            () -> results.addIssue(ValidationCode.E049,
                                    "Inventory version %s created timestamp must be a string in %s",
                                    versionNum, inventoryPath)));
                    break;
                case SimpleVersion.MESSAGE_KEY:
                    version.setMessage(parseString(field,
                            () -> results.addIssue(ValidationCode.E094,
                                    "Inventory version %s message must be a string in %s",
                                    versionNum, inventoryPath)));
                    break;
                case SimpleVersion.USER_KEY:
                    version.setUser(parseUser(field, versionNum, inventoryPath, results));
                    break;
                case SimpleVersion.STATE_KEY:
                    version.setState(parseState(field, versionNum, inventoryPath, results));
                    break;
                default:
                    results.addIssue(ValidationCode.E102,
                            "Inventory version %s cannot contain unknown property %s in %s",
                            versionNum, fieldName, inventoryPath);
                    break;
            }
        });

        return version;
    }

    private SimpleUser parseUser(JsonNode userNode, String versionNum, String inventoryPath, ValidationResultsBuilder results) {
        var user = new SimpleUser();

        if (!userNode.isNull()) {
            if (userNode.isObject()) {
                userNode.fields().forEachRemaining(entry -> {
                    var fieldName = entry.getKey();
                    var field = entry.getValue();

                    switch (fieldName) {
                        case SimpleUser.NAME_KEY:
                            user.setName(parseString(field,
                                    () -> results.addIssue(ValidationCode.E054,
                                            "Inventory version %s user name must be a string in %s",
                                            versionNum, inventoryPath)));
                            break;
                        case SimpleUser.ADDRESS_KEY:
                            user.setAddress(parseString(field,
                                    () -> results.addIssue(ValidationCode.E033,
                                            "Inventory version %s user address must be a string in %s",
                                            versionNum, inventoryPath)));
                            break;
                        default:
                            results.addIssue(ValidationCode.E102,
                                    "Inventory version %s user cannot contain unknown property %s in %s",
                                    versionNum, fieldName, inventoryPath);
                            break;
                    }
                });
            } else {
                results.addIssue(ValidationCode.E054,
                        "Inventory version %s user must be an object in %s",
                        versionNum, inventoryPath);
            }
        }

        return user;
    }

    private Map<String, List<String>> parseManifest(JsonNode field, String inventoryPath, ValidationResultsBuilder results) {
        Map<String, List<String>> manifest = null;

        if (field.isNull()) {
            // nothing to do
        } else if (field.isObject()) {
            manifest = parseDigestPathsMap(field,
                    () -> results.addIssue(ValidationCode.E096,
                            "Inventory manifest cannot contain null digests in %s",
                            inventoryPath),
                    digest -> results.addIssue(ValidationCode.E092,
                            "Inventory manifest cannot contain null content paths for %s in %s",
                            digest, inventoryPath),
                    digest -> results.addIssue(ValidationCode.E092,
                            "Inventory manifest digest %s must reference a list value in %s",
                            digest, inventoryPath),
                    digest -> results.addIssue(ValidationCode.E092,
                            "Inventory manifest digest %s cannot contain null paths in %s",
                            digest, inventoryPath),
                    digest -> results.addIssue(ValidationCode.E092,
                            "Inventory manifest digest %s content paths must be strings in %s",
                            digest, inventoryPath));
        } else {
            results.addIssue(ValidationCode.E033,
                    "Inventory manifest must be an object in %s",
                    inventoryPath);
        }

        return manifest;
    }

    private Map<String, SimpleVersion> parseVersions(JsonNode field, String inventoryPath, ValidationResultsBuilder results) {
        Map<String, SimpleVersion> versions = null;

        if (field.isNull()) {
            // nothing to do
        } else if (field.isObject()) {
            versions = new HashMap<>();

            for (var it = field.fields(); it.hasNext();) {
                var entry = it.next();
                var num = entry.getKey();
                var versionNode = entry.getValue();

                if (num == null) {
                    results.addIssue(ValidationCode.E046,
                            "Inventory version numbers cannot be null in %s",
                            inventoryPath);
                } else if (versionNode.isNull()) {
                    results.addIssue(ValidationCode.E047,
                            "Inventory version objects cannot be null in %s",
                            inventoryPath);
                } else if (versionNode.isObject()) {
                    var version = parseVersion(versionNode, num, inventoryPath, results);
                    versions.put(num, version);
                } else {
                    results.addIssue(ValidationCode.E047,
                            "Inventory versions must be objects in %s",
                            inventoryPath);
                }
            }
        } else {
            results.addIssue(ValidationCode.E044,
                    "Inventory versions must be an object in %s",
                    inventoryPath);
        }

        return versions;
    }

    private Map<String, List<String>> parseState(JsonNode stateNode, String versionNum, String inventoryPath, ValidationResultsBuilder results) {
        Map<String, List<String>> state = null;

        if (stateNode.isNull()) {
            // Nothing to do
        } else if (stateNode.isObject()) {
            state = parseDigestPathsMap(stateNode,
                    () -> results.addIssue(ValidationCode.E050,
                            "Inventory version %s cannot contain null digests in %s",
                            versionNum, inventoryPath),
                    // TODO this code is a little iffy
                    digest -> results.addIssue(ValidationCode.E050,
                            "Inventory version %s cannot contain null logical paths for %s in %s",
                            versionNum, digest, inventoryPath),
                    digest -> results.addIssue(ValidationCode.E050,
                            "Inventory version %s digest %s must reference a list value in %s",
                            versionNum, digest, inventoryPath),
                    digest -> results.addIssue(ValidationCode.E051,
                            "Inventory version %s digest %s cannot contain null paths in %s",
                            versionNum, digest, inventoryPath),
                    digest -> results.addIssue(ValidationCode.E051,
                            "Inventory version %s digest %s logical paths must be strings in %s",
                            versionNum, digest, inventoryPath));
        } else {
            results.addIssue(ValidationCode.E050,
                    "Inventory version %s state must be an object in %s",
                    versionNum, inventoryPath);
        }

        return state;
    }

    private Map<String, Map<String, List<String>>> parseFixity(JsonNode field, String inventoryPath, ValidationResultsBuilder results) {
        Map<String, Map<String, List<String>>> fixity = null;

        if (!field.isNull()) {
            if (field.isObject()) {
                fixity = new HashMap<>();

                for (var it = field.fields(); it.hasNext();) {
                    var entry = it.next();
                    var algorithm = entry.getKey();
                    var digestsNode = entry.getValue();

                    if (algorithm == null) {
                        results.addIssue(ValidationCode.E056,
                                "Inventory fixity cannot contain null digest algorithms in %s",
                                inventoryPath);
                    } else if (digestsNode.isNull()) {
                        results.addIssue(ValidationCode.E057,
                                "Inventory fixity for %s cannot be null in %s",
                                algorithm, inventoryPath);
                    } else if (digestsNode.isObject()) {
                        var fixitySection = parseDigestPathsMap(digestsNode,
                                () -> results.addIssue(ValidationCode.E057,
                                        "Inventory fixity algorithm %s cannot contain null digests in %s",
                                        algorithm, inventoryPath),
                                digest -> results.addIssue(ValidationCode.E057,
                                        "Inventory fixity algorithm %s digest %s cannot contain null content paths in %s",
                                        algorithm, digest, inventoryPath),
                                digest -> results.addIssue(ValidationCode.E057,
                                        "Inventory fixity algorithm %s digest %s must reference a list value in %s",
                                        algorithm, digest, inventoryPath),
                                digest -> results.addIssue(ValidationCode.E057,
                                        "Inventory fixity algorithm %s digest %s cannot contain null paths in %s",
                                        algorithm, digest, inventoryPath),
                                digest -> results.addIssue(ValidationCode.E057,
                                        "Inventory fixity algorithm %s digest %s content paths must be strings in %s",
                                        algorithm, digest, inventoryPath));

                        fixity.put(algorithm, fixitySection);
                    } else {
                        results.addIssue(ValidationCode.E057,
                                "Inventory fixity for %s must be an object in %s",
                                algorithm, inventoryPath);
                    }
                }
            } else {
                results.addIssue(ValidationCode.E056,
                        "Inventory fixity must be an object in %s",
                        inventoryPath);
            }
        }

        return fixity;
    }

    private Map<String, List<String>> parseDigestPathsMap(JsonNode field,
                                                          Runnable keyIsNull,
                                                          Consumer<String> pathsIsNull,
                                                          Consumer<String> pathsIsWrongType,
                                                          Consumer<String> pathIsNull,
                                                          Consumer<String> pathIsWrongType) {
        var map = new HashMap<String, List<String>>();

        field.fields().forEachRemaining(entry -> {
            var digest = entry.getKey();
            var pathsNode = entry.getValue();

            if (digest == null) {
                keyIsNull.run();
            } else if (pathsNode.isNull()) {
                pathsIsNull.accept(digest);
            } else if (!pathsNode.isArray()) {
                pathsIsWrongType.accept(digest);
            } else {
                var paths = new ArrayList<String>();
                map.put(digest, paths);

                pathsNode.elements().forEachRemaining(pathNode -> {
                    if (pathNode.isNull()) {
                        pathIsNull.accept(digest);
                    } else if (!pathNode.isTextual()) {
                        pathIsWrongType.accept(digest);
                    } else {
                        paths.add(pathNode.textValue());
                    }
                });
            }
        });

        return map;
    }

    private String parseString(JsonNode field, Runnable isWrongType) {
        String value = null;

        if (field.isNull()) {
            // nothing to do
        } else if (field.isTextual()) {
            value = field.textValue();
        } else {
            isWrongType.run();
        }

        return value;
    }

    public static class ParseSimpleInventoryResult {
        private final Optional<SimpleInventory> inventory;
        private final ValidationResults validationResults;

        public ParseSimpleInventoryResult(SimpleInventory inventory, ValidationResults validationResults) {
            this.inventory = Optional.ofNullable(inventory);
            this.validationResults = Enforce.notNull(validationResults, "validationResults cannot be null");
        }

        /**
         * @return The parsed inventory if it was able to be parsed, which should be most of the time
         */
        public Optional<SimpleInventory> getInventory() {
            return inventory;
        }

        /**
         * @return Any validation issues detected while parsing
         */
        public ValidationResults getValidationResults() {
            return validationResults;
        }
    }

}
