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

public enum ValidationCode {

    E001(Type.ERROR),
    E002(Type.ERROR),
    E003(Type.ERROR),
    E004(Type.ERROR),
    E005(Type.ERROR),
    E006(Type.ERROR),
    E007(Type.ERROR),
    E008(Type.ERROR),
    E009(Type.ERROR),
    E010(Type.ERROR),
    E011(Type.ERROR),
    E012(Type.ERROR),
    E013(Type.ERROR),
    E014(Type.ERROR),
    E015(Type.ERROR),
    E016(Type.ERROR),
    E017(Type.ERROR),
    E018(Type.ERROR),
    E019(Type.ERROR),
    E020(Type.ERROR),
    E021(Type.ERROR),
    E022(Type.ERROR),
    E023(Type.ERROR),
    E024(Type.ERROR),
    E025(Type.ERROR),
    E026(Type.ERROR),
    E027(Type.ERROR),
    E028(Type.ERROR),
    E029(Type.ERROR),
    E030(Type.ERROR),
    E031(Type.ERROR),
    E032(Type.ERROR),
    E033(Type.ERROR),
    E034(Type.ERROR),
    E035(Type.ERROR),
    E036(Type.ERROR),
    E037(Type.ERROR),
    E038(Type.ERROR),
    E039(Type.ERROR),
    E040(Type.ERROR),
    E041(Type.ERROR),
    E042(Type.ERROR),
    E043(Type.ERROR),
    E044(Type.ERROR),
    E045(Type.ERROR),
    E046(Type.ERROR),
    E047(Type.ERROR),
    E048(Type.ERROR),
    E049(Type.ERROR),
    E050(Type.ERROR),
    E051(Type.ERROR),
    E052(Type.ERROR),
    E053(Type.ERROR),
    E054(Type.ERROR),
    E055(Type.ERROR),
    E056(Type.ERROR),
    E057(Type.ERROR),
    E058(Type.ERROR),
    E059(Type.ERROR),
    E060(Type.ERROR),
    E061(Type.ERROR),
    E062(Type.ERROR),
    E063(Type.ERROR),
    E064(Type.ERROR),
    // https://github.com/OCFL/spec/issues/529
//    E065(Type.ERROR),
    E066(Type.ERROR),
    E067(Type.ERROR),
    E068(Type.ERROR),
    E069(Type.ERROR),
    E070(Type.ERROR),
    E071(Type.ERROR),
    E072(Type.ERROR),
    E073(Type.ERROR),
    E074(Type.ERROR),
    E075(Type.ERROR),
    E076(Type.ERROR),
    E077(Type.ERROR),
    E078(Type.ERROR),
    E079(Type.ERROR),
    E080(Type.ERROR),
    E081(Type.ERROR),
    E082(Type.ERROR),
    E083(Type.ERROR),
    E084(Type.ERROR),
    E085(Type.ERROR),
    E086(Type.ERROR),
    E087(Type.ERROR),
    E088(Type.ERROR),
    E089(Type.ERROR),
    E090(Type.ERROR),
    E091(Type.ERROR),
    E092(Type.ERROR),
    E093(Type.ERROR),
    E094(Type.ERROR),
    E095(Type.ERROR),
    E096(Type.ERROR),
    E097(Type.ERROR),
    E098(Type.ERROR),
    E099(Type.ERROR),
    E100(Type.ERROR),
    E101(Type.ERROR),
    E102(Type.ERROR),


    W001(Type.WARN),
    W002(Type.WARN),
    W003(Type.WARN),
    W004(Type.WARN),
    W005(Type.WARN),
    W006(Type.WARN),
    W007(Type.WARN),
    W008(Type.WARN),
    W009(Type.WARN),
    W010(Type.WARN),
    W011(Type.WARN),
    W012(Type.WARN),
    W013(Type.WARN),
    W014(Type.WARN),
    W015(Type.WARN);

    public enum Type {
        INFO, WARN, ERROR
    }

    private final Type type;

    ValidationCode(Type type) {
        this.type = type;
    }

    public Type getType() {
        return type;
    }

}
