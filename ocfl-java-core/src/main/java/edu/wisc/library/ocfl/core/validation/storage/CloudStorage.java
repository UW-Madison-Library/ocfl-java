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
import edu.wisc.library.ocfl.core.storage.cloud.CloudClient;
import edu.wisc.library.ocfl.core.storage.cloud.KeyNotFoundException;
import edu.wisc.library.ocfl.core.storage.cloud.ListResult;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

// TODO
public class CloudStorage implements Storage {

    private final CloudClient client;

    public CloudStorage(CloudClient client) {
        this.client = Enforce.notNull(client, "client cannot be null");
    }

    @Override
    public List<Listing> listDirectory(String directoryPath, boolean recursive) {
        var listings = new ArrayList<Listing>();

        ListResult result;

        if (recursive) {
            var prefix = directoryPath.endsWith("/") ? directoryPath : directoryPath + "/";
            result = client.list(prefix);
        } else {
            result = client.listDirectory(directoryPath);
        }

        result.getObjects().forEach(object -> {
            listings.add(Listing.file(object.getKeySuffix()));
        });
        result.getDirectories().forEach(dir -> {
            listings.add(Listing.directory(dir.getName()));
        });

        return listings;
    }

    @Override
    public boolean fileExists(String filePath) {
        try {
            client.head(filePath);
            return true;
        } catch (KeyNotFoundException e) {
            return false;
        }
    }

    @Override
    public InputStream readFile(String filePath) {
        return client.downloadStream(filePath);
    }

}
