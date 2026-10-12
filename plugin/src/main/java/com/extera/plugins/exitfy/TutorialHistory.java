package com.extera.plugins.exitfy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Predicate;

/** Reuse the existing plugin root without crossing another client screen. */
final class TutorialHistory {
    static <T> int rootIndex(List<T> stack, T owner, Predicate<T> root, Predicate<T> screen) {
        int index = stack.indexOf(owner);
        for (int i = index; i >= 0; i--) {
            T entry = stack.get(i);
            if (root.test(entry)) return i;
            if (!screen.test(entry)) return -1;
        }
        return -1;
    }

    static <T> List<T> intermediateScreens(List<T> stack, T root, T owner, Predicate<T> screen) {
        int first = rootIndex(stack, owner, entry -> entry == root, screen);
        int last = stack.indexOf(owner);
        if (first < 0 || last <= first) return Collections.emptyList();
        return new ArrayList<>(stack.subList(first + 1, last));
    }
}
