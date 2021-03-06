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

package edu.wisc.library.ocfl.core.storage;

import edu.wisc.library.ocfl.api.util.Enforce;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * Iterator that iterates over OCFL object root directories. Object roots are identified by the presence of a file that's
 * prefixed with '0=ocfl_object'.
 */
public abstract class OcflObjectRootDirIterator implements Iterator<String>, Closeable {

    private final String start;
    private boolean started = false;
    private boolean closed = false;

    private final ArrayDeque<Directory> dirStack;
    private String next;

    public OcflObjectRootDirIterator(String start) {
        this.start = Enforce.notNull(start, "start cannot be null");
        this.dirStack = new ArrayDeque<>();
    }

    /**
     * Indicates if a directory path is an object root path
     *
     * @param path directory path
     * @return true if path is an object root path
     */
    abstract protected boolean isObjectRoot(String path);

    /**
     * Returns true if the path should be skipped
     *
     * @param path directory path
     * @return true if path should be skipped
     */
    abstract protected boolean shouldSkip(String path);

    /**
     * Creates an object to maintain directory state
     *
     * @param path directory path
     * @return directory object
     */
    abstract protected Directory createDirectory(String path);

    @Override
    public void close() {
        if (!closed) {
            while (!dirStack.isEmpty()) {
                popDirectory();
            }
            closed = true;
        }
    }

    @Override
    public boolean hasNext() {
        if (closed) {
            throw new IllegalStateException("Iterator is closed.");
        }
        fetchNextIfNeeded();
        return next != null;
    }

    @Override
    public String next() {
        if (!hasNext()) {
            throw new NoSuchElementException("No more files found.");
        }
        var result = next;
        next = null;
        return result;
    }

    private void fetchNextIfNeeded() {
        if (next == null) {
            var nextDirectory = fetchNextDirectory();

            while (nextDirectory != null) {
                if (shouldSkip(nextDirectory)) {
                    popDirectory();
                } else if (isObjectRoot(nextDirectory)) {
                    // Do not process children
                    popDirectory();
                    next = nextDirectory;
                    return;
                }

                nextDirectory = fetchNextDirectory();
            }
        }
    }

    private String fetchNextDirectory() {
        if (!started) {
            dirStack.push(createDirectory(start));
            started = true;
        }

        var top = dirStack.peek();

        while (top != null) {
            var child = top.nextChildDirectory();

            if (child == null) {
                popDirectory();
                top = dirStack.peek();
            } else {
                dirStack.push(createDirectory(child));
                return child;
            }
        }

        return null;
    }

    private void popDirectory() {
        if (!dirStack.isEmpty()) {
            try {
                dirStack.pop().close();
            } catch (IOException e) {
                // ignore
            }
        }
    }

    /**
     * Encapsulates a directory for iterating over its children
     */
    protected interface Directory extends Closeable {
        /**
         * @return path to next child directory
         */
        String nextChildDirectory();
    }

}
