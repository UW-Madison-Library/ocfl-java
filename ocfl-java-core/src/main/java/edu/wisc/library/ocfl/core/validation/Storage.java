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

import java.io.InputStream;
import java.util.List;

// TODO
public interface Storage {

    /**
     * Return a list of all of the files an directories contained in the specified directory.
     * An empty list is returned if the directory does not exist or has no children. If recursion
     * is specified, then only leaf nodes are returned.
     *
     * @param directoryPath the path to the directory to list
     * @param recursive if children should be recursively listed
     * @return list of children
     */
    List<Listing> listDirectory(String directoryPath, boolean recursive);

    /**
     * Indicates if the file exists
     *
     * @param filePath path to the file
     * @return true if it exists
     */
    boolean fileExists(String filePath);

    /**
     * Streams the content of the specified file
     *
     * @param filePath path to the file
     * @return input stream of file content
     */
    InputStream readFile(String filePath);

}
