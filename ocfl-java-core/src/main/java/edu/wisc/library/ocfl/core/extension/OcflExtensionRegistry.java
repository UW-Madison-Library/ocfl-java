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

package edu.wisc.library.ocfl.core.extension;

import edu.wisc.library.ocfl.api.exception.OcflExtensionException;
import edu.wisc.library.ocfl.api.util.Enforce;
import edu.wisc.library.ocfl.core.extension.storage.layout.FlatLayoutExtension;
import edu.wisc.library.ocfl.core.extension.storage.layout.FlatOmitPrefixLayoutExtension;
import edu.wisc.library.ocfl.core.extension.storage.layout.HashedNTupleIdEncapsulationLayoutExtension;
import edu.wisc.library.ocfl.core.extension.storage.layout.HashedNTupleLayoutExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Registry for mapping extensions to their implementations. The following out-of-the-box extensions are pre-registered
 * with a default implementation:
 *
 * <ul>
 *     <li>0002-flat-direct-storage-layout: {@link FlatLayoutExtension}</li>
 *     <li>0003-hash-and-id-n-tuple-storage-layout: {@link HashedNTupleIdEncapsulationLayoutExtension}</li>
 *     <li>0004-hashed-n-tuple-storage-layout: {@link HashedNTupleLayoutExtension}</li>
 * </ul>
 */
public final class OcflExtensionRegistry {

    private static final Logger LOG = LoggerFactory.getLogger(OcflExtensionRegistry.class);

    private static final Map<String, Class<? extends OcflExtension>> REGISTRY = new HashMap<>(Map.of(
            HashedNTupleLayoutExtension.EXTENSION_NAME, HashedNTupleLayoutExtension.class,
            HashedNTupleIdEncapsulationLayoutExtension.EXTENSION_NAME, HashedNTupleIdEncapsulationLayoutExtension.class,
            FlatLayoutExtension.EXTENSION_NAME, FlatLayoutExtension.class,
            FlatOmitPrefixLayoutExtension.EXTENSION_NAME, FlatOmitPrefixLayoutExtension.class
    ));

    private OcflExtensionRegistry() {

    }

    /**
     * Registers a new extension implementation.
     *
     * @param extensionId the id of the extension to register
     * @param extensionClass the class that implements the
     */
    public static void register(String extensionId, Class<? extends OcflExtension> extensionClass) {
        Enforce.notBlank(extensionId, "extensionId cannot be blank");
        Enforce.notNull(extensionClass, "extensionClass cannot be null");
        REGISTRY.put(extensionId, extensionClass);
    }

    /**
     * Removes an extension from the registry.
     *
     * @param extensionName the name of the extension to remove
     */
    public static void remove(String extensionName) {
        REGISTRY.remove(extensionName);
    }

    /**
     * Returns a registered extension implementation, if one exists.
     *
     * @param extensionName the name of the extension to load
     * @param <T> the extension class
     * @return the extension
     */
    public static <T extends OcflExtension> Optional<T> lookup(String extensionName) {
        var extensionClass = REGISTRY.get(extensionName);

        LOG.debug("Found OCFL extension {} implementation {}", extensionName, extensionClass);

        if (extensionClass == null) {
            return Optional.empty();
        }

        try {
            return (Optional<T>) Optional.of(extensionClass.getDeclaredConstructor().newInstance());
        } catch (Exception e) {
            throw new OcflExtensionException(String.format("Failed to load extension %s class %s.",
                    extensionName, extensionClass), e);
        }
    }

    /**
     * Returns true if there is a known implementation of the given extension name
     *
     * @param extensionName the extension to look for
     * @return true if there is an implementation of the extension
     */
    public static boolean isSupported(String extensionName) {
        return REGISTRY.containsKey(extensionName);
    }

}
