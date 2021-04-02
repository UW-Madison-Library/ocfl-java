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

package edu.wisc.library.ocfl.api.exception;

import edu.wisc.library.ocfl.api.model.ValidationIssue;
import edu.wisc.library.ocfl.api.model.ValidationResults;

import java.util.List;

/**
 * This exception indicates that there were object validation errors
 */
public class ValidationException extends OcflJavaException {

    private final ValidationResults validationResults;

    public ValidationException(String message, ValidationResults results) {
        super(message);
        this.validationResults = results;
    }

    public ValidationResults getValidationResults() {
        return validationResults;
    }

    @Override
    public String getMessage() {
        var builder = new StringBuilder(super.getMessage());

        builder.append("\nErrors:\n");
        printIssues(validationResults.getErrors(), builder);

        if (validationResults.hasWarnings()) {
            builder.append("\nWarnings:\n");
            printIssues(validationResults.getWarnings(), builder);
        }

        if (validationResults.hasInfos()) {
            builder.append("\nInfos:\n");
            printIssues(validationResults.getInfos(), builder);
        }

        return builder.toString();
    }

    private void printIssues(List<ValidationIssue> issues, StringBuilder builder) {
        for (int i = 1; i <= issues.size(); i++) {
            builder.append(" ").append(i).append(". ");
            builder.append(issues.get(i - 1).toString());
            if (i < issues.size()) {
                builder.append("\n");
            }
        }
    }
}
