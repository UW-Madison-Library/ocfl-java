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

package edu.wisc.library.ocfl.api.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import edu.wisc.library.ocfl.api.exception.InvalidVersionException;
import edu.wisc.library.ocfl.api.util.Enforce;

import java.util.regex.Pattern;

/**
 * Represents an OCFL version number. It is able to handle zero-padded version numbers.
 */
public class VersionNum implements Comparable<VersionNum> {

    public static final VersionNum V1 = new VersionNum(1);

    private static final Pattern VALID_VERSION = Pattern.compile("^v\\d+$");

    private final long versionNumber;
    private final int zeroPaddingWidth;
    private final long maxVersion;
    private final String stringValue;

    /**
     * Creates a new VersionNum from a version string in the format of "vN" where "N" is an integer greater than -1.
     * Zero-padded values are supported.
     *
     * @param value version string
     * @return version number
     */
    @JsonCreator
    public static VersionNum fromString(String value) {
        if (!VALID_VERSION.matcher(value).matches()) {
            throw new InvalidVersionException("Invalid VersionNum: " + value);
        }

        var numPart = value.substring(1);
        var padding = 0;

        // Special case to allow v0 through
        if (!numPart.equals("0") && numPart.startsWith("0")) {
            padding = numPart.length();
        }

        return new VersionNum(Long.parseLong(numPart), padding);
    }

    /**
     * Creates a new VersionNum from an integer.
     *
     * @param versionNumber the version number, must be greater than -1
     * @return version number
     */
    public static VersionNum fromInt(int versionNumber) {
        return new VersionNum(versionNumber);
    }

    /**
     * Creates a new VersionNum. Zero-padding is not used.
     *
     * @param versionNumber the version number, must be greater than -1
     */
    public VersionNum(long versionNumber) {
        this(versionNumber, 0);
    }

    /**
     * Creates a new VersionNum
     *
     * @param versionNumber the version number, must be greater than -1
     * @param zeroPaddingWidth the width of zero-padding, or 0 if the version is not zero-padded
     */
    public VersionNum(long versionNumber, int zeroPaddingWidth) {
        this.versionNumber = Enforce.expressionTrue(versionNumber >= 0, versionNumber, "versionNumber must be greater than or equal to 0");
        this.zeroPaddingWidth = Enforce.expressionTrue(zeroPaddingWidth >= 0, zeroPaddingWidth, "zeroPaddingWidth must be greater than or equal to 0");

        if (zeroPaddingWidth == 0) {
            stringValue = "v" + versionNumber;
        } else {
            stringValue = String.format("v%0" + zeroPaddingWidth + "d", versionNumber);
        }

        if (zeroPaddingWidth == 0) {
            maxVersion = Long.MAX_VALUE;
        } else {
            maxVersion = (10 * (zeroPaddingWidth - 1)) - 1;
        }
    }

    /**
     * Returns a new VersionNum that is one more than this. If the version number is zero-padded, versions higher than
     * the max number are now allowed.
     *
     * @return a new VersionNum with an incremented version number
     * @throws InvalidVersionException if the next version is higher than the max allowed value
     */
    public VersionNum nextVersionNum() {
        var nextVersionNum = versionNumber + 1;
        if (nextVersionNum > maxVersion) {
            throw new InvalidVersionException("Cannot increment version number. Current version " + toString() + " is the highest possible.");
        }
        return new VersionNum(nextVersionNum, zeroPaddingWidth);
    }

    /**
     * Returns a new VersionNum that is one less than this. Version numbers lower than 0 are not allowed.
     *
     * @return a new VersionNum with a decremented version number
     * @throws InvalidVersionException if the previous version is lower than 1
     */
    public VersionNum previousVersionNum() {
        if (versionNumber == 1) {
            throw new InvalidVersionException("Cannot decrement version number. Current version " + toString() + " is the lowest possible.");
        }
        return new VersionNum(versionNumber - 1, zeroPaddingWidth);
    }

    /**
     * @return the zero-padding width, 0 when not padded
     */
    public int getZeroPaddingWidth() {
        return zeroPaddingWidth;
    }

    /**
     * @return the numeric version number
     */
    public long getVersionNum() {
        return versionNumber;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VersionNum versionNum = (VersionNum) o;
        return versionNumber == versionNum.versionNumber;
    }

    @Override
    public int hashCode() {
        return Long.hashCode(versionNumber);
    }

    @JsonValue
    @Override
    public String toString() {
        return stringValue;
    }

    @Override
    public int compareTo(VersionNum o) {
        return Long.compare(versionNumber, o.versionNumber);
    }

}
