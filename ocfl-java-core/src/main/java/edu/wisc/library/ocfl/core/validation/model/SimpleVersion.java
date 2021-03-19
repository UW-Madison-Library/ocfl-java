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

package edu.wisc.library.ocfl.core.validation.model;

import java.util.List;
import java.util.Map;
import java.util.Objects;

public class SimpleVersion {

    public static final String CREATED_KEY = "created";
    public static final String MESSAGE_KEY = "message";
    public static final String USER_KEY = "user";
    public static final String STATE_KEY = "state";

    private String created;
    private String message;
    private SimpleUser user;
    private Map<String, List<String>> state;

    public SimpleVersion() {
    }

    public SimpleVersion(
            String created,
            String message,
            SimpleUser user,
            Map<String, List<String>> state) {
        this.created = created;
        this.message = message;
        this.user = user;
        this.state = state;
    }

    public String getCreated() {
        return created;
    }

    public SimpleVersion setCreated(String created) {
        this.created = created;
        return this;
    }

    public String getMessage() {
        return message;
    }

    public SimpleVersion setMessage(String message) {
        this.message = message;
        return this;
    }

    public SimpleUser getUser() {
        return user;
    }

    public SimpleVersion setUser(SimpleUser user) {
        this.user = user;
        return this;
    }

    public Map<String, List<String>> getState() {
        return state;
    }

    public SimpleVersion setState(Map<String, List<String>> state) {
        this.state = state;
        return this;
    }

    @Override
    public String toString() {
        return "SimpleVersion{" +
                "created='" + created + '\'' +
                ", message='" + message + '\'' +
                ", user=" + user +
                ", state=" + state +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SimpleVersion that = (SimpleVersion) o;
        return Objects.equals(created, that.created)
                && Objects.equals(message, that.message)
                && Objects.equals(user, that.user)
                && Objects.equals(state, that.state);
    }

    @Override
    public int hashCode() {
        return Objects.hash(created, message, user, state);
    }
}
