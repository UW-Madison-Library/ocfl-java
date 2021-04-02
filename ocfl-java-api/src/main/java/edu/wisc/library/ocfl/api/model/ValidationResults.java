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

import java.util.List;

/**
 * Encapsulates the results of validating an object
 */
public class ValidationResults {

    private final List<ValidationIssue> errors;
    private final List<ValidationIssue> warnings;
    private final List<ValidationIssue> infos;

    public ValidationResults(List<ValidationIssue> errors, List<ValidationIssue> warnings, List<ValidationIssue> infos) {
        this.errors = errors;
        this.warnings = warnings;
        this.infos = infos;
    }

    /**
     * @return true if the results contain validation errors
     */
    public boolean hasErrors() {
        return !errors.isEmpty();
    }

    /**
     * @return true if the results contain validation warnings
     */
    public boolean hasWarnings() {
        return !warnings.isEmpty();
    }

    /**
     * @return true if the results contain validation infos
     */
    public boolean hasInfos() {
        return !infos.isEmpty();
    }

    /**
     * @return the list of validation errors
     */
    public List<ValidationIssue> getErrors() {
        return errors;
    }

    /**
     * @return the list of validation warnings
     */
    public List<ValidationIssue> getWarnings() {
        return warnings;
    }

    /**
     * @return the list of validation infos
     */
    public List<ValidationIssue> getInfos() {
        return infos;
    }

    @Override
    public String toString() {
        return "ValidationResults{" +
                "errors=" + errors +
                ", warnings=" + warnings +
                ", infos=" + infos +
                '}';
    }
}
