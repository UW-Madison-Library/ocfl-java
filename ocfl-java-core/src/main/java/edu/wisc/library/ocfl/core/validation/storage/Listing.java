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

package edu.wisc.library.ocfl.core.validation.storage;

import edu.wisc.library.ocfl.api.util.Enforce;

// TODO
public class Listing {

    public enum Type {
        Directory,
        File,
    }

    private final Type type;
    private final String relativePath;

    public static Listing file(String relativePath) {
        return new Listing(Type.File, relativePath);
    }

    public static Listing directory(String relativePath) {
        return new Listing(Type.Directory, relativePath);
    }

    public Listing(Type type, String relativePath) {
        this.type = Enforce.notNull(type, "type cannot be null");
        this.relativePath = Enforce.notNull(relativePath, "relativePath cannot be null");
    }

    public String getRelativePath() {
        return relativePath;
    }

    public Type getType() {
        return type;
    }

    public boolean isFile() {
        return type == Type.File;
    }

    public boolean isDirectory() {
        return type == Type.Directory;
    }

    @Override
    public String toString() {
        return "Listing{" +
                "type=" + type +
                ", relativePath='" + relativePath + '\'' +
                '}';
    }

}
