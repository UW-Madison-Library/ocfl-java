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
package edu.wisc.library.ocfl.core.extension.storage.layout.config;

import com.fasterxml.jackson.annotation.JsonIgnore;
import edu.wisc.library.ocfl.api.util.Enforce;
import edu.wisc.library.ocfl.core.extension.OcflExtensionConfig;
import edu.wisc.library.ocfl.core.extension.storage.layout.FlatOmitPrefixLayoutExtension;

import java.util.Objects;

/**
 * Configuration for the <a href="https://ocfl.github.io/extensions/0006-flat-omit-prefix-storage-layout.html">
 * Flat Omit Prefix Storage Layout</a> extension.
 *
 * @author awoods
 * @since 2021-06-22
 */
public class FlatOmitPrefixLayoutConfig implements OcflExtensionConfig {

    private String delimiter;

    @JsonIgnore
    @Override
    public String getExtensionName() {
        return FlatOmitPrefixLayoutExtension.EXTENSION_NAME;
    }

    @JsonIgnore
    @Override
    public boolean hasParameters() {
        return true;
    }

    /**
     *  @return the delimiter marking end of prefix
     */
    public String getDelimiter() {
        return delimiter;
    }

    /**
     * The case-insensitive, delimiter marking the end of the OCFL object identifier prefix; MUST consist of a
     * character string of length one or greater. If the delimiter is found multiple times in the OCFL object
     * identifier, its last occurence (right-most) will be used to select the termination of the prefix.
     *
     * @param delimiter marking the end of prefix
     */
    public FlatOmitPrefixLayoutConfig setDelimiter(String delimiter) {
        Enforce.notNull(delimiter, "delimiter cannot be null");
        if (delimiter.isEmpty()) {
            throw new IllegalArgumentException("Arg must not be empty: 'delimiter'");
        }
        this.delimiter = delimiter;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FlatOmitPrefixLayoutConfig that = (FlatOmitPrefixLayoutConfig) o;
        return delimiter.equals(that.delimiter);
    }

    @Override
    public int hashCode() {
        return Objects.hash(delimiter);
    }

    @Override
    public String toString() {
        return "FlatOmitPrefixLayoutConfig{ delimiter='" + delimiter + "' }";
    }


}
