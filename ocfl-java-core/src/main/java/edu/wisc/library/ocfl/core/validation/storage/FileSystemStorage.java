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

import edu.wisc.library.ocfl.api.exception.OcflIOException;
import edu.wisc.library.ocfl.api.util.Enforce;
import edu.wisc.library.ocfl.core.util.FileUtil;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

// TODO
public class FileSystemStorage implements Storage {

    private final Path storageRoot;

    public FileSystemStorage(Path storageRoot) {
        this.storageRoot = Enforce.notNull(storageRoot, "storageRoot cannot be null");
    }

    @Override
    public List<Listing> listDirectory(String directoryPath, boolean recursive) {
        var fullPath = storageRoot.resolve(directoryPath);

        // TODO what to do about symlinks?

        if (Files.notExists(fullPath)) {
            return new ArrayList<>();
        } else if (recursive) {
            return listLeaves(fullPath);
        } else {
            return listChildren(fullPath);
        }
    }

    @Override
    public boolean fileExists(String filePath) {
        return Files.exists(storageRoot.resolve(filePath));
    }

    @Override
    public InputStream readFile(String filePath) {
        try {
            return Files.newInputStream(storageRoot.resolve(filePath));
        } catch (IOException e) {
            throw new OcflIOException(e);
        }
    }

    private List<Listing> listChildren(Path root) {
        try (var children = Files.list(root)) {
            return children.map(child -> {
                var name = child.getFileName().toString();
                if (Files.isRegularFile(child)) {
                    return Listing.file(name);
                } else {
                    return Listing.directory(name);
                }
            }).collect(Collectors.toList());
        } catch (IOException e) {
            throw new OcflIOException(e);
        }
    }

    private List<Listing> listLeaves(Path root) {
        var listings = new ArrayList<Listing>();

        try {
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    listings.add(createListing(Listing.Type.File, file));
                    return super.visitFile(file, attrs);
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    if (FileUtil.isDirEmpty(dir)) {
                        listings.add(createListing(Listing.Type.Directory, dir));
                    }
                    return super.postVisitDirectory(dir, exc);
                }

                private Listing createListing(Listing.Type type, Path file) {
                    var relative = FileUtil.pathToStringStandardSeparator(root.relativize(file));
                    return new Listing(type, relative);
                }
            });
        } catch (IOException e) {
            throw new OcflIOException(e);
        }

        return listings;
    }

}
