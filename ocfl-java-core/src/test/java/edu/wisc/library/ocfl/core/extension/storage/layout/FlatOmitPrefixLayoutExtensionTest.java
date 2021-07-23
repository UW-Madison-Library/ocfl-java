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
package edu.wisc.library.ocfl.core.extension.storage.layout;

import edu.wisc.library.ocfl.api.exception.OcflInputException;
import edu.wisc.library.ocfl.core.extension.storage.layout.config.FlatOmitPrefixLayoutConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author awoods
 * @since 2021-06-23
 */
public class FlatOmitPrefixLayoutExtensionTest {

    private FlatOmitPrefixLayoutExtension ext;
    private FlatOmitPrefixLayoutConfig config;

    @BeforeEach
    public void setUp() {
        ext = new FlatOmitPrefixLayoutExtension();
        config = new FlatOmitPrefixLayoutConfig();
    }

    @Test
    public void testNullDelimiter() {
        assertThrows(OcflInputException.class, () -> config.setDelimiter(null),
                "Expected OcflInputException");
    }

    @Test
    public void testEmptyDelimiter() {
        assertThrows(IllegalArgumentException.class, () -> config.setDelimiter(""),
                "Expected IllegalArgumentException");
    }

    @Test
    public void testDelimiterNotFound() {
        config.setDelimiter("/");
        ext.init(config);

        String result = ext.mapObjectId("namespace:12887296");
        assertEquals("namespace:12887296", result);
    }

    @Test
    public void testOneOccurrenceOfSingleCharDelimiter() {
        config.setDelimiter(":");
        ext.init(config);

        String result = ext.mapObjectId("namespace:12887296");
        assertEquals("12887296", result);
    }

    @Test
    public void testTwoOccurrencesOfSingleCharDelimiter() {
        config.setDelimiter(":");
        ext.init(config);

        String result = ext.mapObjectId("urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66");
        assertEquals("6e8bc430-9c3a-11d9-9669-0800200c9a66", result);
    }

    @Test
    public void testTwoOccurrencesOfSingleCharDelimiterDRS() {
        config.setDelimiter(":");
        ext.init(config);

        String result = ext.mapObjectId("urn-3:HUL.DRS.OBJECT:12887296");
        assertEquals("12887296", result);
    }

    @Test
    public void testOneOccurrenceOfMultiCharDelimiter() {
        config.setDelimiter("edu/");
        ext.init(config);

        String result = ext.mapObjectId("https://institution.edu/3448793");
        assertEquals("3448793", result);
    }

    @Test
    public void testTwoOccurrencesOfMultiCharDelimiter() {
        config.setDelimiter("edu/");
        ext.init(config);

        String result = ext.mapObjectId("https://institution.edu/abc/edu/f8.05v");
        assertEquals("f8.05v", result);
    }

}
