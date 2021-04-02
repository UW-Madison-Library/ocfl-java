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

import edu.wisc.library.ocfl.api.util.Enforce;

/**
 * Encapsulates a validation code and a descriptive message
 */
public class ValidationIssue {

    private final ValidationCode code;
    private final String message;

    public ValidationIssue(ValidationCode code, String message) {
        this.code = Enforce.notNull(code, "code cannot be null");
        this.message = Enforce.notBlank(message, "message cannot be blank");
    }

    /**
     * @return the validation code
     */
    public ValidationCode getCode() {
        return code;
    }

    /**
     * @return the descriptive message
     */
    public String getMessage() {
        return message;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s", code, message);
    }
}
