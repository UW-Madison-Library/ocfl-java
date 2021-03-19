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

import edu.wisc.library.ocfl.api.util.Enforce;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

// TODO move?
public class ValidationResults {

    private final List<ValidationIssue> errors;
    private final List<ValidationIssue> warnings;
    private final List<ValidationIssue> infos;

    public ValidationResults() {
        this.errors = new ArrayList<>();
        this.warnings = new ArrayList<>();
        this.infos = new ArrayList<>();
    }

    public void addAll(ValidationResults other) {
        this.errors.addAll(other.errors);
        this.warnings.addAll(other.warnings);
        this.infos.addAll(other.infos);
    }

    public ValidationResults addIssue(ValidationCode code, String messageTemplate, Object... args) {
        Enforce.notNull(code, "code cannot be null");

        var message = messageTemplate;

        if (args != null && args.length > 0) {
            message = String.format(messageTemplate, args);
        }

        return addIssue(Optional.of(new ValidationIssue(code, message)));
    }

    public ValidationResults addIssue(Optional<ValidationIssue> issue) {
        issue.ifPresent(i -> {
            switch (i.getCode().getType()) {
                case ERROR:
                    errors.add(i);
                    break;
                case WARN:
                    warnings.add(i);
                    break;
                case INFO:
                    infos.add(i);
                    break;
            }
        });
        return this;
    }

    public boolean hasErrors() {
        return !errors.isEmpty();
    }

    public boolean hasWarnings() {
        return !warnings.isEmpty();
    }

    public boolean hasInfos() {
        return !infos.isEmpty();
    }

    public List<ValidationIssue> getErrors() {
        return errors;
    }

    public List<ValidationIssue> getWarnings() {
        return warnings;
    }

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
