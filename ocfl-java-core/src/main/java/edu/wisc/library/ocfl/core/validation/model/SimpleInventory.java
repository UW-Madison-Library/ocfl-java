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

package edu.wisc.library.ocfl.core.validation.model;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class SimpleInventory {

    public static final String ID_KEY = "id";
    public static final String TYPE_KEY = "type";
    public static final String DIGEST_ALGO_KEY = "digestAlgorithm";
    public static final String HEAD_KEY = "head";
    public static final String CONTENT_DIR_KEY = "contentDirectory";
    public static final String FIXITY_KEY = "fixity";
    public static final String MANIFEST_KEY = "manifest";
    public static final String VERSIONS_KEY = "versions";

    private String id;
    private String type;
    private String digestAlgorithm;
    private String head;
    private String contentDirectory;
    private Map<String, Map<String, List<String>>> fixity;
    private Map<String, List<String>> manifest;
    private Map<String, SimpleVersion> versions;

    private Map<String, String> invertedManifest;

    public SimpleInventory() {
    }

    public SimpleInventory(String id,
                           String type,
                           String digestAlgorithm,
                           String head,
                           String contentDirectory,
                           Map<String, Map<String, List<String>>> fixity,
                           Map<String, List<String>> manifest,
                           Map<String, SimpleVersion> versions) {
        this.id = id;
        this.type = type;
        this.digestAlgorithm = digestAlgorithm;
        this.head = head;
        this.contentDirectory = contentDirectory;
        this.fixity = fixity;
        this.manifest = manifest;
        this.versions = versions;
    }

    public String getId() {
        return id;
    }

    public SimpleInventory setId(String id) {
        this.id = id;
        return this;
    }

    public String getType() {
        return type;
    }

    public SimpleInventory setType(String type) {
        this.type = type;
        return this;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public SimpleInventory setDigestAlgorithm(String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
        return this;
    }

    public String getHead() {
        return head;
    }

    public SimpleInventory setHead(String head) {
        this.head = head;
        return this;
    }

    public String getContentDirectory() {
        return contentDirectory;
    }

    public SimpleInventory setContentDirectory(String contentDirectory) {
        this.contentDirectory = contentDirectory;
        return this;
    }

    public Map<String, Map<String, List<String>>> getFixity() {
        return fixity;
    }

    public SimpleInventory setFixity(Map<String, Map<String, List<String>>> fixity) {
        this.fixity = fixity;
        return this;
    }

    public Map<String, List<String>> getManifest() {
        return manifest;
    }

    public SimpleInventory setManifest(Map<String, List<String>> manifest) {
        this.manifest = manifest;
        return this;
    }

    public Map<String, SimpleVersion> getVersions() {
        return versions;
    }

    public SimpleInventory setVersions(Map<String, SimpleVersion> versions) {
        this.versions = versions;
        return this;
    }

    public Map<String, String> getInvertedManifest() {
        if (invertedManifest == null && manifest != null) {
            invertedManifest = invertMap(manifest);
        }
        return invertedManifest;
    }

    public Map<String, String> getInvertedManifestCopy() {
        if (invertedManifest == null && manifest != null) {
            return invertMap(manifest);
        } else if (invertedManifest != null) {
            return new HashMap<>(invertedManifest);
        }
        return null;
    }

    private Map<String, String> invertMap(Map<String, List<String>> original) {
        var inverted = new HashMap<String, String>(original.size());
        original.forEach((key, values) -> {
            values.forEach(value -> inverted.put(value, key));
        });
        return inverted;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SimpleInventory that = (SimpleInventory) o;
        return Objects.equals(id, that.id)
                && Objects.equals(type, that.type)
                && Objects.equals(digestAlgorithm, that.digestAlgorithm)
                && Objects.equals(head, that.head)
                && Objects.equals(contentDirectory, that.contentDirectory)
                && Objects.equals(fixity, that.fixity)
                && Objects.equals(manifest, that.manifest)
                && Objects.equals(versions, that.versions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, type, digestAlgorithm, head, contentDirectory, fixity, manifest, versions);
    }

    @Override
    public String toString() {
        return "SimpleInventory{" +
                "id='" + id + '\'' +
                ", type='" + type + '\'' +
                ", digestAlgorithm='" + digestAlgorithm + '\'' +
                ", head='" + head + '\'' +
                ", contentDirectory='" + contentDirectory + '\'' +
                ", fixity=" + fixity +
                ", manifest=" + manifest +
                ", versions=" + versions +
                '}';
    }

}
