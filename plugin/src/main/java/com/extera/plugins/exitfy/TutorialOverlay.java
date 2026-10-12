package com.extera.plugins.exitfy;

import android.animation.ObjectAnimator;
import android.content.Context;
import android.graphics.Rect;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.R;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;

/** Native Views form a dimmed frame around the live target; no custom drawing. */
final class TutorialOverlay implements AutoCloseable {
    private final FrameLayout layer;
    private final View[] shades = new View[4];
    private final FrameLayout focus;
    private final LinearLayout card;
    private final LinearLayout description;
    private final ScrollView descriptionScroll;
    private final TextView progress;
    private final TextView title;
    private final TextView body;
    private final TextView press;
    private final TextView stop;
    private final ImageView pointer;
    private final ObjectAnimator pulse;
    private final ViewTreeObserver.OnPreDrawListener layoutListener = () -> { layout(); return true; };
    private final int[] origin = new int[2];
    private View target;
    private Runnable action;
    private Runnable end;
    private boolean allowed;
    private boolean closed;

    TutorialOverlay(BaseFragment owner) {
        Context context = owner.getParentActivity();
        ViewGroup root = (ViewGroup) owner.getParentActivity().getWindow().getDecorView();
        layer = new FrameLayout(context);
        layer.setClickable(true);
        layer.setFocusableInTouchMode(true);
        root.addView(layer, new ViewGroup.LayoutParams(-1, -1));
        for (int i = 0; i < shades.length; i++) {
            shades[i] = new View(context);
            shades[i].setBackgroundColor(0xB0000000);
            shades[i].setClickable(true);
            layer.addView(shades[i], new FrameLayout.LayoutParams(0, 0));
        }
        focus = new FrameLayout(context);
        focus.setClickable(true);
        focus.setContentDescription(I18n.t("Нажать выделенную кнопку", "Tap the highlighted button"));
        layer.addView(focus, new FrameLayout.LayoutParams(0, 0));
        pointer = new ImageView(context);
        pointer.setImageResource(R.drawable.msg_arrowright);
        pointer.setRotation(90f);
        pointer.setColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
        pointer.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        FrameLayout.LayoutParams pointerParams = new FrameLayout.LayoutParams(dp(28), dp(28), Gravity.TOP | Gravity.END);
        focus.addView(pointer, pointerParams);
        pulse = ObjectAnimator.ofFloat(pointer, "alpha", 1f, 0.25f, 1f);
        pulse.setDuration(1100L);
        pulse.setRepeatCount(ObjectAnimator.INFINITE);
        pulse.start();

        card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(16), dp(14), dp(16), dp(12));
        card.setElevation(dp(8));
        layer.addView(card, new FrameLayout.LayoutParams(0, 0));
        descriptionScroll = new ScrollView(context);
        descriptionScroll.setFillViewport(false);
        description = new LinearLayout(context);
        description.setOrientation(LinearLayout.VERTICAL);
        descriptionScroll.addView(description);
        progress = text(context, 13, false);
        title = text(context, 19, true);
        body = text(context, 15, false);
        description.addView(progress, new LinearLayout.LayoutParams(-1, -2));
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(-1, -2);
        titleParams.topMargin = dp(7);
        description.addView(title, titleParams);
        LinearLayout.LayoutParams bodyParams = new LinearLayout.LayoutParams(-1, -2);
        bodyParams.topMargin = dp(8);
        description.addView(body, bodyParams);
        card.addView(descriptionScroll, new LinearLayout.LayoutParams(-1, -2));
        press = text(context, 15, true);
        press.setGravity(Gravity.CENTER);
        press.setMinHeight(dp(48));
        press.setPadding(dp(4), dp(8), dp(4), dp(8));
        card.addView(press, new LinearLayout.LayoutParams(-1, -2));
        stop = text(context, 13, false);
        stop.setGravity(Gravity.CENTER);
        stop.setMinHeight(dp(44));
        stop.setText(I18n.t("Закончить обучение", "End tutorial"));
        card.addView(stop, new LinearLayout.LayoutParams(-1, -2));
        focus.setOnClickListener(view -> pressTarget());
        press.setOnClickListener(view -> pressTarget());
        stop.setOnClickListener(view -> { if (end != null) end.run(); });
        layer.setOnKeyListener((view, key, event) -> {
            if (key != KeyEvent.KEYCODE_BACK) return false;
            if (event.getAction() == KeyEvent.ACTION_UP && end != null) end.run();
            return true;
        });
        layer.getViewTreeObserver().addOnPreDrawListener(layoutListener);
        layer.requestFocus();
    }

    void present(View next, String heading, String explanation, String counter,
                 String button, Runnable customAction, Runnable finish, boolean clickAllowed) {
        if (closed) return;
        if (target != next) {
            target = next;
            target.requestRectangleOnScreen(new Rect(0, -dp(90),
                    Math.max(1, target.getWidth()), target.getHeight() + dp(170)), true);
        }
        action = customAction;
        end = finish;
        allowed = clickAllowed;
        title.setText(heading);
        body.setText(explanation);
        progress.setText(counter);
        press.setText(button);
        int accent = Theme.getColor(Theme.key_windowBackgroundWhiteBlueText);
        pointer.setColorFilter(accent);
        card.setBackground(rounded(Theme.getColor(Theme.key_windowBackgroundWhite), 0, 0));
        focus.setBackground(rounded(0x00000000, accent, dp(2)));
        title.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        body.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        progress.setTextColor(accent);
        press.setTextColor(accent);
        stop.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
        layout();
    }

    boolean isClosed() { return closed; }

    private void pressTarget() {
        View clicked = target;
        if (closed || !allowed || clicked == null || !clicked.isShown()
                || (action == null && !clicked.isEnabled())) return;
        Runnable custom = action;
        close();
        if (custom != null) custom.run();
        else {
            clicked.setPressed(true);
            clicked.postDelayed(() -> clicked.setPressed(false), 150L);
            clicked.performClick();
        }
    }

    private void layout() {
        if (closed || target == null || layer.getWidth() == 0 || layer.getHeight() == 0) return;
        boolean enabled = allowed && (action != null || target.isEnabled());
        press.setEnabled(enabled);
        press.setAlpha(enabled ? 1f : 0.45f);
        focus.setAlpha(enabled ? 1f : 0.6f);
        Rect area = new Rect();
        if (!target.getGlobalVisibleRect(area)) { hideTarget(); return; }
        layer.getLocationOnScreen(origin);
        area.offset(-origin[0], -origin[1]);
        area.inset(-dp(4), -dp(4));
        int width = layer.getWidth(), height = layer.getHeight();
        if (!area.intersect(0, 0, width, height)) { hideTarget(); return; }
        card.setVisibility(View.VISIBLE);
        focus.setVisibility(View.VISIBLE);
        place(shades[0], 0, 0, width, area.top);
        place(shades[1], 0, area.bottom, width, height - area.bottom);
        place(shades[2], 0, area.top, area.left, area.height());
        place(shades[3], area.right, area.top, width - area.right, area.height());
        place(focus, area.left, area.top, area.width(), area.height());
        int cardWidth = Math.min(dp(360), width - dp(24));
        int above = area.top - dp(18), below = height - area.bottom - dp(18);
        boolean underneath = below >= above;
        int maxHeight = Math.max(dp(120), Math.max(above, below));
        description.measure(View.MeasureSpec.makeMeasureSpec(Math.max(1, cardWidth - dp(32)), View.MeasureSpec.EXACTLY),
                View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED));
        LinearLayout.LayoutParams textParams = (LinearLayout.LayoutParams) descriptionScroll.getLayoutParams();
        int textHeight = Math.min(description.getMeasuredHeight(), Math.max(dp(30), maxHeight - dp(125)));
        if (textParams.height != textHeight) { textParams.height = textHeight; descriptionScroll.setLayoutParams(textParams); }
        card.measure(View.MeasureSpec.makeMeasureSpec(Math.max(1, cardWidth), View.MeasureSpec.EXACTLY),
                View.MeasureSpec.makeMeasureSpec(maxHeight, View.MeasureSpec.AT_MOST));
        int cardHeight = card.getMeasuredHeight();
        int top = underneath ? area.bottom + dp(10) : area.top - cardHeight - dp(10);
        place(card, (width - cardWidth) / 2, Math.max(dp(8), Math.min(top, height - cardHeight - dp(8))), cardWidth, cardHeight);
    }

    private void hideTarget() {
        close();
    }

    private static void place(View view, int x, int y, int width, int height) {
        FrameLayout.LayoutParams old = (FrameLayout.LayoutParams) view.getLayoutParams();
        width = Math.max(0, width); height = Math.max(0, height);
        if (old.leftMargin == x && old.topMargin == y && old.width == width && old.height == height) return;
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(width, height, Gravity.TOP | Gravity.LEFT);
        params.leftMargin = x; params.topMargin = y;
        view.setLayoutParams(params);
    }

    @Override public void close() {
        if (closed) return;
        closed = true;
        pulse.cancel();
        if (layer.getViewTreeObserver().isAlive()) layer.getViewTreeObserver().removeOnPreDrawListener(layoutListener);
        if (layer.getParent() instanceof ViewGroup) ((ViewGroup) layer.getParent()).removeView(layer);
        target = null; action = null; end = null;
    }

    private static TextView text(Context context, int size, boolean bold) {
        TextView text = new TextView(context);
        text.setTextSize(size);
        text.setTypeface(Typeface.DEFAULT, bold ? Typeface.BOLD : Typeface.NORMAL);
        return text;
    }
    private static GradientDrawable rounded(int fill, int border, int width) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill); drawable.setCornerRadius(dp(14));
        if (width > 0) drawable.setStroke(width, border);
        return drawable;
    }
    private static int dp(float value) { return AndroidUtilities.dp(value); }
}
