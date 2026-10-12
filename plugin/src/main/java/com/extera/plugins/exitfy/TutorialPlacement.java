package com.extera.plugins.exitfy;

/** Screen-safe hint placement, independent of font size and Android Views. */
final class TutorialPlacement {
    static int availableHeight(int top, int bottom, int safeTop, int safeBottom, int gap, int margin) {
        return Math.max(0, Math.max(top - safeTop - gap - margin, safeBottom - bottom - gap - margin));
    }

    static int cardTop(int top, int bottom, int safeTop, int safeBottom, int height, int gap, int margin) {
        int above = top - safeTop - gap - margin;
        int below = safeBottom - bottom - gap - margin;
        return below >= above ? bottom + gap : top - gap - height;
    }
}
