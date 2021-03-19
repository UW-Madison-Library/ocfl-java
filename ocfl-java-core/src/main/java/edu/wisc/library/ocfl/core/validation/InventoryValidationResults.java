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
import edu.wisc.library.ocfl.core.validation.model.SimpleInventory;

public class InventoryValidationResults {

    private final SimpleInventory inventory;
    private final String digest;
    private final ValidationResults validationResults;

    public InventoryValidationResults(SimpleInventory inventory,
                                      String digest,
                                      ValidationResults validationResults) {
        this.inventory = inventory;
        this.digest = digest;
        this.validationResults = Enforce.notNull(validationResults, "validationResults cannot be null");
    }

    public boolean hasInventory() {
        return inventory != null;
    }

    public boolean hasErrors() {
        return validationResults.hasErrors();
    }

    public boolean hasWarnings() {
        return validationResults.hasWarnings();
    }

    public boolean hasInfos() {
        return validationResults.hasInfos();
    }

    public SimpleInventory getInventory() {
        return inventory;
    }

    public String getDigest() {
        return digest;
    }

    public ValidationResults getValidationResults() {
        return validationResults;
    }

    @Override
    public String toString() {
        return "InventoryValidationResults{" +
                "inventory=" + inventory +
                ", digest='" + digest + '\'' +
                ", validationResults=" + validationResults +
                '}';
    }
}
