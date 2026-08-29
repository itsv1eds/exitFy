package com.extera.plugins.exitfy;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.text.InputFilter;
import android.text.InputType;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;
import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.R;
import org.telegram.ui.ActionBar.ActionBar;
import org.telegram.ui.ActionBar.AlertDialog;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;
import org.telegram.ui.ActionBar.ThemeDescription;
import org.telegram.ui.Cells.RadioColorCell;
import org.telegram.ui.Components.EditTextBoldCursor;

import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Shared lifecycle and Telegram-themed View toolkit for exitFy sub-screens.
 *
 * <p>Each fragment owns one serial worker. State refreshes are coalesced and
 * at most one command is accepted at a time, so taps cannot grow an unbounded
 * work queue. Neither runtime state parsing nor command execution happens on
 * the UI thread.</p>
 */
abstract class ExitFySubscreenFragment<S> extends BaseFragment {
    private static final int MAX_CONTENT_WIDTH_DP = 720;
    private static final int MAX_TEXT_INPUT_CHARS = 4096;

    private final AtomicBoolean refreshQueued = new AtomicBoolean();
    private final AtomicBoolean refreshPending = new AtomicBoolean();
    private final AtomicBoolean commandRunning = new AtomicBoolean();
    private final AtomicLong lifecycleGeneration = new AtomicLong();
    private final Runnable runtimeListener = this::requestStateRefresh;
    private final ArrayList<ThemeBinding> themeBindings = new ArrayList<>();

    private volatile boolean alive;
    private volatile ExecutorService worker;
    private boolean themeRefreshQueued;

    @Override
    public boolean onFragmentCreate() {
        if (!super.onFragmentCreate()) return false;
        alive = true;
        worker = Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, workerThreadName());
            thread.setDaemon(true);
            return thread;
        });
        return true;
    }

    @Override
    public final View createView(Context context) {
        // BaseFragment may ask an existing fragment instance to rebuild its
        // view. Do not keep theme bindings to the detached hierarchy.
        themeBindings.clear();
        themeRefreshQueued = false;
        configureActionBar();

        ScrollView scroll = new ScrollView(context);
        fragmentView = scroll;
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        bindBackground(scroll, BackgroundRole.ROOT, 0, 0);

        FrameLayout holder = new FrameLayout(context);
        scroll.addView(holder, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        MaxWidthLinearLayout content = new MaxWidthLinearLayout(
                context, dp(MAX_CONTENT_WIDTH_DP));
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(12), dp(12), dp(12), dp(28));
        FrameLayout.LayoutParams contentParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.TOP | Gravity.CENTER_HORIZONTAL);
        holder.addView(content, contentParams);

        try {
            buildContent(context, content);
        } catch (Throwable ignored) {
            clearDynamicViews(content);
            TextView unavailable = text(context, 16,
                    Theme.key_windowBackgroundWhiteGrayText2, false);
            unavailable.setText(I18n.t(
                    "Не удалось открыть этот экран",
                    "This screen could not be opened"));
            unavailable.setGravity(Gravity.CENTER);
            LinearLayout fallback = card(context, false);
            fallback.addView(unavailable, matchWrap());
            content.addView(fallback, sectionParams());
        }
        applyTheme();
        requestStateRefresh();
        return scroll;
    }

    @Override
    public void onResume() {
        super.onResume();
        try {
            ExitFyBridge.addUiListener(runtimeListener);
        } catch (Throwable ignored) {
            // The explicit refresh below still keeps this screen usable.
        }
        applyTheme();
        requestStateRefresh();
    }

    @Override
    public void onPause() {
        try {
            ExitFyBridge.removeUiListener(runtimeListener);
        } catch (Throwable ignored) {
        }
        super.onPause();
    }

    @Override
    public void onFragmentDestroy() {
        alive = false;
        lifecycleGeneration.incrementAndGet();
        refreshPending.set(false);
        refreshQueued.set(false);
        commandRunning.set(false);
        try {
            ExitFyBridge.removeUiListener(runtimeListener);
        } catch (Throwable ignored) {
        }
        ExecutorService value = worker;
        worker = null;
        if (value != null) value.shutdownNow();
        themeBindings.clear();
        super.onFragmentDestroy();
    }

    @Override
    public ArrayList<ThemeDescription> getThemeDescriptions() {
        ArrayList<ThemeDescription> descriptions = new ArrayList<>();
        ThemeDescription.ThemeDescriptionDelegate delegate = this::scheduleThemeRefresh;
        int[] keys = {
                Theme.key_windowBackgroundGray,
                Theme.key_windowBackgroundWhite,
                Theme.key_divider,
                Theme.key_windowBackgroundWhiteBlackText,
                Theme.key_windowBackgroundWhiteGrayText2,
                Theme.key_windowBackgroundWhiteBlueText,
                Theme.key_windowBackgroundWhiteGrayIcon,
        };
        for (int key : keys) {
            descriptions.add(new ThemeDescription(fragmentView, 0, null, null,
                    null, delegate, key));
        }
        if (actionBar != null) {
            descriptions.add(new ThemeDescription(actionBar, ThemeDescription.FLAG_BACKGROUND,
                    null, null, null, null, Theme.key_actionBarDefault));
            descriptions.add(new ThemeDescription(actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR,
                    null, null, null, null, Theme.key_actionBarDefaultIcon));
            descriptions.add(new ThemeDescription(actionBar, ThemeDescription.FLAG_AB_TITLECOLOR,
                    null, null, null, null, Theme.key_actionBarDefaultTitle));
            descriptions.add(new ThemeDescription(actionBar,
                    ThemeDescription.FLAG_AB_SELECTORCOLOR,
                    null, null, null, null, Theme.key_actionBarDefaultSelector));
        }
        return descriptions;
    }

    protected abstract CharSequence screenTitle();

    protected abstract void buildContent(Context context, LinearLayout content);

    /** Runs on the fragment's worker thread. */
    protected abstract S parseUiState(String json);

    /** Runs on the Android UI thread. */
    protected abstract void renderUiState(S state);

    protected void onCommandBusyChanged(boolean busy) {
    }

    protected String workerThreadName() {
        return "exitfy-subscreen";
    }

    protected final void requestStateRefresh() {
        ExecutorService executor = worker;
        if (!alive || executor == null || executor.isShutdown()) return;
        refreshPending.set(true);
        if (!refreshQueued.compareAndSet(false, true)) return;
        long generation = lifecycleGeneration.get();
        try {
            executor.execute(() -> {
                refreshPending.set(false);
                S parsed = null;
                try {
                    parsed = parseUiState(ExitFyBridge.getUiState());
                } catch (Throwable ignored) {
                }
                S state = parsed;
                if (!postToUi(() -> {
                    refreshQueued.set(false);
                    if (!alive || generation != lifecycleGeneration.get()) return;
                    if (state != null) runUiAction(() -> renderUiState(state));
                    if (refreshPending.get()) requestStateRefresh();
                })) {
                    refreshQueued.set(false);
                }
            });
        } catch (RejectedExecutionException ignored) {
            refreshQueued.set(false);
            refreshPending.set(false);
        }
    }

    /**
     * The only settings persistence path exposed by this base class.
     * RuntimeCoordinator persists the normalized value after applying it.
     */
    protected final void setSetting(String key, Object value) {
        if (TextUtils.isEmpty(key) || value == null) {
            showToast(I18n.t("Некорректная настройка", "Invalid setting"), false);
            return;
        }
        executeCommand(() -> new JSONObject()
                .put("command", "set_setting")
                .put("key", key)
                .put("value", value), false, null);
    }

    protected final void executeCommand(CommandFactory factory, boolean showSuccess,
                                        CommandCompletion completion) {
        ExecutorService executor = worker;
        if (!alive || executor == null || executor.isShutdown() || factory == null) return;
        if (!commandRunning.compareAndSet(false, true)) {
            showToast(I18n.t("Дождитесь завершения текущей операции",
                    "Wait for the current operation to finish"), false);
            return;
        }
        runUiAction(() -> onCommandBusyChanged(true));
        try {
            executor.execute(() -> {
                ExitFyCommandResult result;
                try {
                    JSONObject request = factory.create();
                    if (request == null) throw new IllegalArgumentException(
                            I18n.t("Пустая команда", "Empty command"));
                    String json = request.toString();
                    if (JsonGuard.exceedsUtf8Limit(
                            json, RuntimeCoordinator.MAX_COMMAND_JSON_UTF8_BYTES)) {
                        throw new IllegalArgumentException(I18n.t(
                                "Команда слишком большая", "Command is too large"));
                    }
                    result = ExitFyCommandResult.parse(ExitFyBridge.execute(json));
                } catch (Throwable error) {
                    String raw = error.getMessage();
                    result = new ExitFyCommandResult(false, ErrorSanitizer.clean(
                            TextUtils.isEmpty(raw)
                                    ? I18n.t("Операция не выполнена", "Operation failed")
                                    : raw));
                }
                ExitFyCommandResult completed = result;
                if (!postToUi(() -> finishCommand(
                        completed, showSuccess, completion))) {
                    commandRunning.set(false);
                }
            });
        } catch (RejectedExecutionException ignored) {
            commandRunning.set(false);
            runUiAction(() -> onCommandBusyChanged(false));
        }
    }

    private void finishCommand(ExitFyCommandResult result, boolean showSuccess,
                               CommandCompletion completion) {
        commandRunning.set(false);
        if (!alive) return;
        runUiAction(() -> onCommandBusyChanged(false));
        if (!result.ok || showSuccess) {
            String message = result.message;
            if (TextUtils.isEmpty(message)) {
                message = result.ok
                        ? I18n.t("Готово", "Done")
                        : I18n.t("Операция не выполнена", "Operation failed");
            }
            showToast(message, result.ok);
        }
        if (completion != null) {
            runUiAction(() -> completion.onComplete(result));
        }
        requestStateRefresh();
    }

    /**
     * A list of actions, not a choice between values: radio cells would ask
     * the user to pick a state that nothing here stores.
     */
    protected final void showActionDialog(CharSequence title, CharSequence[] labels,
                                          ChoiceListener listener) {
        runUiAction(() -> {
            Context context = getParentActivity();
            if (context == null || labels == null || labels.length == 0) return;
            AlertDialog.Builder builder = new AlertDialog.Builder(context, getResourceProvider());
            builder.setTitle(title);
            builder.setItems(labels, (dialog, index) -> {
                if (listener != null && index >= 0 && index < labels.length) {
                    listener.onChoice(index);
                }
            });
            builder.setNegativeButton(I18n.t("Отмена", "Cancel"), null);
            showDialog(builder.create());
        });
    }

    protected final void showChoiceDialog(CharSequence title, CharSequence[] labels,
                                          int selected, ChoiceListener listener) {
        showChoiceDialog(title, labels, selected, null, listener);
    }

    protected final void showChoiceDialog(CharSequence title, CharSequence[] labels,
                                          int selected, boolean[] enabled,
                                          ChoiceListener listener) {
        runUiAction(() -> {
            Context context = getParentActivity();
            if (context == null || labels == null || labels.length == 0) return;

            LinearLayout choices = new LinearLayout(context);
            choices.setOrientation(LinearLayout.VERTICAL);
            AlertDialog[] holder = new AlertDialog[1];
            for (int index = 0; index < labels.length; index++) {
                final int choice = index;
                boolean choiceEnabled = enabled == null
                        || index < enabled.length && enabled[index];
                RadioColorCell cell = new RadioColorCell(context, getResourceProvider());
                cell.setPadding(dp(4), 0, dp(4), 0);
                cell.setCheckColor(
                        getThemedColor(Theme.key_radioBackground),
                        getThemedColor(Theme.key_dialogRadioBackgroundChecked));
                cell.setTextAndValue(labels[index], selected == index);
                cell.setBackground(Theme.createSelectorDrawable(
                        getThemedColor(Theme.key_listSelector), Theme.RIPPLE_MASK_ALL));
                cell.setEnabled(choiceEnabled);
                cell.setClickable(choiceEnabled);
                cell.setAlpha(choiceEnabled ? 1f : 0.45f);
                cell.setOnClickListener(view -> runUiAction(() -> {
                    if (!view.isEnabled()) return;
                    AlertDialog dialog = holder[0];
                    if (dialog != null) dialog.dismiss();
                    if (listener != null) listener.onChoice(choice);
                }));
                choices.addView(cell, matchWrap());
            }

            AlertDialog.Builder builder = new AlertDialog.Builder(
                    context, getResourceProvider());
            builder.setTitle(title);
            builder.makeCustomMaxHeight();
            builder.setView(choices);
            builder.setNegativeButton(I18n.t("Отмена", "Cancel"), null);
            AlertDialog dialog = builder.create();
            holder[0] = dialog;
            showDialog(dialog);
        });
    }

    /**
     * Opens a non-prefilled editor. Reset is a separate action, so an empty
     * replacement can never erase a saved value by accident.
     */
    protected final void showTextInputDialog(CharSequence title, CharSequence explanation,
                                             CharSequence hint, CharSequence positiveText,
                                             CharSequence resetText,
                                             TextInputListener submitListener,
                                             Runnable resetListener) {
        showTextInputDialog(title, explanation, hint, positiveText, resetText,
                MAX_TEXT_INPUT_CHARS, false, true, submitListener, resetListener);
    }

    protected final void showTextInputDialog(CharSequence title, CharSequence explanation,
                                             CharSequence hint, CharSequence positiveText,
                                             CharSequence resetText, boolean showCancel,
                                             TextInputListener submitListener,
                                             Runnable resetListener) {
        showTextInputDialog(title, explanation, hint, positiveText, resetText,
                MAX_TEXT_INPUT_CHARS, false, showCancel,
                submitListener, resetListener);
    }

    protected final void showTextInputDialog(CharSequence title, CharSequence explanation,
                                             CharSequence hint, CharSequence positiveText,
                                             CharSequence resetText, int maxChars,
                                             boolean multiline,
                                             TextInputListener submitListener,
                                             Runnable resetListener) {
        showTextInputDialog(title, explanation, hint, positiveText, resetText,
                maxChars, multiline, true, submitListener, resetListener);
    }

    private void showTextInputDialog(CharSequence title, CharSequence explanation,
                                     CharSequence hint, CharSequence positiveText,
                                     CharSequence resetText, int maxChars,
                                     boolean multiline, boolean showCancel,
                                     TextInputListener submitListener,
                                     Runnable resetListener) {
        runUiAction(() -> {
            Context context = getParentActivity();
            if (context == null) return;

            LinearLayout container = new LinearLayout(context);
            container.setOrientation(LinearLayout.VERTICAL);
            if (!TextUtils.isEmpty(explanation)) {
                TextView description = new TextView(context);
                description.setTextColor(getThemedColor(Theme.key_dialogTextBlack));
                description.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 15);
                description.setText(explanation);
                description.setGravity(Gravity.START);
                LinearLayout.LayoutParams descriptionParams = matchWrap();
                descriptionParams.leftMargin = dp(24);
                descriptionParams.topMargin = dp(5);
                descriptionParams.rightMargin = dp(24);
                descriptionParams.bottomMargin = dp(10);
                container.addView(description, descriptionParams);
            }

            // Keep the variable typed as the Android base class: the host JAR
            // intentionally omits transitive AndroidX compile classes used by
            // EditTextBoldCursor, while the runtime instance remains Telegram's
            // own editor.
            EditText editText = new EditTextBoldCursor(context);
            editText.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 18);
            editText.setText("");
            editText.setTextColor(getThemedColor(Theme.key_dialogTextBlack));
            editText.setHintTextColor(getThemedColor(Theme.key_groupcreate_hintText));
            editText.setHint(hint);
            editText.setFocusable(true);
            editText.setSingleLine(!multiline);
            editText.setMaxLines(multiline ? 8 : 1);
            editText.setInputType(InputType.TYPE_CLASS_TEXT
                    | (multiline ? InputType.TYPE_TEXT_FLAG_MULTI_LINE
                    : InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)
                    | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
            if (maxChars > 0) {
                editText.setFilters(new InputFilter[]{
                        new InputFilter.LengthFilter(maxChars)
                });
            }
            editText.setBackground(Theme.createEditTextDrawable(context,
                    getThemedColor(Theme.key_dialogInputField),
                    getThemedColor(Theme.key_dialogInputFieldActivated)));
            editText.setPadding(0, dp(6), 0, dp(6));
            LinearLayout.LayoutParams inputParams = matchWrap();
            inputParams.leftMargin = dp(24);
            inputParams.rightMargin = dp(24);
            inputParams.bottomMargin = dp(10);
            container.addView(editText, inputParams);

            AlertDialog[] holder = new AlertDialog[1];
            AlertDialog.Builder builder = new AlertDialog.Builder(
                    context, getResourceProvider());
            builder.setTitle(title);
            builder.makeCustomMaxHeight();
            builder.setView(container);
            builder.setWidth(dp(292));
            builder.setPositiveButton(positiveText, (ignored, which) -> runUiAction(() -> {
                String value = editText.getText() == null
                        ? "" : editText.getText().toString();
                if (value.trim().isEmpty()) {
                    AndroidUtilities.shakeView(editText);
                    boolean canReset = !TextUtils.isEmpty(resetText)
                            && resetListener != null;
                    showToast(canReset
                            ? I18n.t(
                            "Введите новое значение или нажмите «Сбросить»",
                            "Enter a new value or tap Reset")
                            : I18n.t("Введите значение", "Enter a value"), false);
                    return;
                }
                if (submitListener != null) submitListener.onSubmit(value);
                AlertDialog dialog = holder[0];
                if (dialog != null) dialog.dismiss();
            }));
            if (showCancel) {
                builder.setNegativeButton(I18n.t("Отмена", "Cancel"),
                        (ignored, which) -> runUiAction(() -> {
                            AlertDialog dialog = holder[0];
                            if (dialog != null) dialog.dismiss();
                        }));
            }
            if (!TextUtils.isEmpty(resetText) && resetListener != null) {
                builder.setNeutralButton(resetText, (ignored, which) -> runUiAction(() -> {
                    AlertDialog dialog = holder[0];
                    if (dialog != null) dialog.dismiss();
                    resetListener.run();
                }));
            }

            AlertDialog dialog = builder.create();
            holder[0] = dialog;
            dialog.setOnShowListener(ignored -> {
                try {
                    editText.requestFocus();
                    editText.setSelection(editText.length());
                    AndroidUtilities.showKeyboard(editText);
                } catch (Throwable ignoredError) {
                }
            });
            dialog.setDismissDialogByButtons(false);
            showDialog(dialog, ignored -> {
                try {
                    AndroidUtilities.hideKeyboard(editText);
                } catch (Throwable ignoredError) {
                }
            });
        });
    }

    protected final LinearLayout card(Context context, boolean clickable) {
        LinearLayout value = new LinearLayout(context);
        value.setPadding(dp(16), dp(15), dp(16), dp(15));
        value.setMinimumHeight(dp(64));
        bindBackground(value, clickable
                ? BackgroundRole.CARD_CLICKABLE : BackgroundRole.CARD_STATIC,
                dp(18), 0);
        if (clickable) {
            value.setClickable(true);
            value.setFocusable(true);
        }
        return value;
    }

    protected final SettingRow settingRow(Context context, int iconResource,
                                          CharSequence title, CharSequence summary) {
        boolean hasSummary = !TextUtils.isEmpty(summary);
        LinearLayout row = card(context, true);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setMinimumHeight(dp(hasSummary ? 86 : 74));
        row.setPadding(dp(14), dp(12), dp(12), dp(12));

        ImageView badge = iconBadge(context, iconResource, title, 46);
        badge.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        row.addView(badge, fixed(dp(46), dp(46)));

        LinearLayout labels = new LinearLayout(context);
        labels.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams labelsParams = weighted();
        labelsParams.leftMargin = dp(13);
        row.addView(labels, labelsParams);

        TextView titleView = text(context, 17,
                Theme.key_windowBackgroundWhiteBlackText, true);
        titleView.setText(title);
        labels.addView(titleView, matchWrap());

        TextView valueView = text(context, 15,
                Theme.key_windowBackgroundWhiteBlueText, true);
        valueView.setMaxLines(1);
        valueView.setEllipsize(TextUtils.TruncateAt.END);
        labels.addView(valueView, topMargin(3));

        TextView summaryView = null;
        if (hasSummary) {
            summaryView = text(context, 13,
                    Theme.key_windowBackgroundWhiteGrayText2, false);
            summaryView.setText(summary);
            summaryView.setMaxLines(2);
            summaryView.setEllipsize(TextUtils.TruncateAt.END);
            labels.addView(summaryView, topMargin(3));
        }

        ImageView arrow = icon(context, R.drawable.msg_arrowright,
                I18n.t("Открыть", "Open"),
                Theme.key_windowBackgroundWhiteGrayIcon);
        arrow.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        LinearLayout.LayoutParams arrowParams = fixed(dp(28), dp(40));
        arrowParams.leftMargin = dp(8);
        row.addView(arrow, arrowParams);

        return new SettingRow(row, title,
                hasSummary ? summary : "", valueView, summaryView);
    }

    protected final TextView sectionLabel(Context context, CharSequence label) {
        TextView value = text(context, 13,
                Theme.key_windowBackgroundWhiteBlueText, true);
        value.setText(label);
        value.setPadding(dp(6), dp(8), dp(6), dp(8));
        return value;
    }

    protected final ImageView iconBadge(Context context, int resource,
                                        CharSequence description, int sizeDp) {
        ImageView image = icon(context, resource, description,
                Theme.key_windowBackgroundWhiteBlueText);
        int padding = Math.max(dp(9), dp(sizeDp / 4f));
        image.setPadding(padding, padding, padding, padding);
        bindBackground(image, BackgroundRole.ACCENT_BADGE,
                dp(sizeDp / 2f), 0x18);
        return image;
    }

    protected final TextView text(Context context, int sizeSp,
                                  int colorKey, boolean bold) {
        TextView value = new TextView(context);
        value.setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp);
        value.setTypeface(Typeface.DEFAULT,
                bold ? Typeface.BOLD : Typeface.NORMAL);
        value.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
        value.setIncludeFontPadding(false);
        bindText(value, colorKey);
        return value;
    }

    protected final void setSafeClick(View view, Runnable action) {
        if (view == null) return;
        view.setOnClickListener(ignored -> runUiAction(action));
    }

    /**
     * Removes generated rows and their theme records while preserving the
     * container's own binding.
     */
    protected final void clearDynamicViews(LinearLayout container) {
        if (container == null) return;
        for (int index = themeBindings.size() - 1; index >= 0; index--) {
            View view = themeBindings.get(index).view;
            if (view != container && isDescendantOf(view, container)) {
                themeBindings.remove(index);
            }
        }
        container.removeAllViews();
    }

    protected final void showToast(String message, boolean success) {
        try {
            Context context = getParentActivity();
            if (context == null || TextUtils.isEmpty(message)) return;
            Toast.makeText(context, message,
                    success ? Toast.LENGTH_SHORT : Toast.LENGTH_LONG).show();
        } catch (Throwable ignored) {
        }
    }

    protected final void runUiAction(Runnable action) {
        if (!alive || action == null) return;
        try {
            action.run();
        } catch (Throwable ignored) {
            showToast(I18n.t("Действие не выполнено", "Action failed"), false);
        }
    }

    private void configureActionBar() {
        if (actionBar == null) return;
        actionBar.setBackButtonImage(R.drawable.ic_ab_back);
        actionBar.setTitle(screenTitle());
        actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() {
            @Override
            public void onItemClick(int id) {
                runUiAction(() -> {
                    if (id == -1) finishFragment();
                });
            }
        });
    }

    private ImageView icon(Context context, int resource, CharSequence description,
                           int colorKey) {
        ImageView image = new ImageView(context);
        image.setImageResource(resource);
        image.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        image.setContentDescription(description);
        bindIcon(image, colorKey);
        return image;
    }

    private void bindText(TextView view, int colorKey) {
        ThemeBinding binding = new ThemeBinding(
                view, colorKey, -1, BackgroundRole.NONE, 0, 0);
        themeBindings.add(binding);
        applyThemeBinding(binding);
    }

    private void bindIcon(ImageView view, int colorKey) {
        ThemeBinding binding = new ThemeBinding(
                view, -1, colorKey, BackgroundRole.NONE, 0, 0);
        themeBindings.add(binding);
        applyThemeBinding(binding);
    }

    private void bindBackground(View view, BackgroundRole role, int radius, int alpha) {
        ThemeBinding binding = new ThemeBinding(view, -1, -1, role, radius, alpha);
        themeBindings.add(binding);
        applyThemeBinding(binding);
    }

    private void scheduleThemeRefresh() {
        if (!alive || themeRefreshQueued) return;
        themeRefreshQueued = true;
        if (!postToUi(() -> {
            themeRefreshQueued = false;
            if (alive) applyTheme();
        })) {
            themeRefreshQueued = false;
        }
    }

    private void applyTheme() {
        for (ThemeBinding binding : themeBindings) {
            applyThemeBinding(binding);
        }
    }

    private void applyThemeBinding(ThemeBinding binding) {
        View view = binding.view;
        if (view instanceof TextView && binding.textColorKey >= 0) {
            ((TextView) view).setTextColor(
                    getThemedColor(binding.textColorKey));
        }
        if (view instanceof ImageView && binding.iconColorKey >= 0) {
            ((ImageView) view).setColorFilter(
                    getThemedColor(binding.iconColorKey), PorterDuff.Mode.SRC_IN);
        }
        switch (binding.backgroundRole) {
            case ROOT:
                view.setBackgroundColor(
                        getThemedColor(Theme.key_windowBackgroundGray));
                break;
            case CARD_STATIC:
                view.setBackground(rounded(
                        getThemedColor(Theme.key_windowBackgroundWhite),
                        binding.radius, getThemedColor(Theme.key_divider)));
                break;
            case CARD_CLICKABLE:
                view.setBackground(rippleOver(
                        getThemedColor(Theme.key_windowBackgroundWhite),
                        binding.radius));
                break;
            case ACCENT_BADGE:
                view.setBackground(rounded(withAlpha(getThemedColor(
                                Theme.key_windowBackgroundWhiteBlueText),
                        binding.alpha), binding.radius, Color.TRANSPARENT));
                break;
            case NONE:
            default:
                break;
        }
    }

    private Drawable rippleOver(int fill, int radius) {
        return new RippleDrawable(ColorStateList.valueOf(withAlpha(
                getThemedColor(Theme.key_windowBackgroundWhiteBlueText), 0x25)),
                rounded(fill, radius, getThemedColor(Theme.key_divider)), null);
    }

    private GradientDrawable rounded(int fill, int radius, int stroke) {
        GradientDrawable value = new GradientDrawable();
        value.setColor(fill);
        value.setCornerRadius(radius);
        if (Color.alpha(stroke) != 0) value.setStroke(dp(1), stroke);
        return value;
    }

    private static int withAlpha(int color, int alpha) {
        return (color & 0x00ffffff) | ((alpha & 0xff) << 24);
    }

    private boolean postToUi(Runnable action) {
        if (action == null) return false;
        try {
            AndroidUtilities.runOnUIThread(action);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean isDescendantOf(View view, ViewGroup ancestor) {
        ViewParent parent = view == null ? null : view.getParent();
        while (parent != null) {
            if (parent == ancestor) return true;
            parent = parent.getParent();
        }
        return false;
    }

    protected final LinearLayout.LayoutParams sectionParams() {
        LinearLayout.LayoutParams value = matchWrap();
        value.bottomMargin = dp(10);
        return value;
    }

    protected static LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    protected static LinearLayout.LayoutParams weighted() {
        return new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
    }

    protected static LinearLayout.LayoutParams fixed(int width, int height) {
        return new LinearLayout.LayoutParams(width, height);
    }

    protected final LinearLayout.LayoutParams topMargin(int marginDp) {
        LinearLayout.LayoutParams value = matchWrap();
        value.topMargin = dp(marginDp);
        return value;
    }

    protected static int dp(float value) {
        return AndroidUtilities.dp(value);
    }

    @FunctionalInterface
    protected interface CommandFactory {
        JSONObject create() throws Exception;
    }

    @FunctionalInterface
    protected interface CommandCompletion {
        void onComplete(ExitFyCommandResult result);
    }

    @FunctionalInterface
    protected interface ChoiceListener {
        void onChoice(int index);
    }

    @FunctionalInterface
    protected interface TextInputListener {
        void onSubmit(String value);
    }

    protected static final class SettingRow {
        final View view;
        private final CharSequence title;
        private CharSequence summary;
        private final TextView valueView;
        private final TextView summaryView;

        SettingRow(View view, CharSequence title, CharSequence summary,
                   TextView valueView, TextView summaryView) {
            this.view = view;
            this.title = title;
            this.summary = summary;
            this.valueView = valueView;
            this.summaryView = summaryView;
        }

        void setValue(CharSequence value) {
            valueView.setText(value);
            String description = title + ". " + value;
            if (!TextUtils.isEmpty(summary)) description += ". " + summary;
            view.setContentDescription(description);
        }

        /** A summary that states a number has to follow it. */
        void setSummary(CharSequence value) {
            if (summaryView == null) return;
            summary = value == null ? "" : value;
            summaryView.setText(summary);
            setValue(valueView.getText());
        }

        void setEnabled(boolean enabled) {
            view.setEnabled(enabled);
            view.setAlpha(enabled ? 1f : 0.45f);
        }
    }

    private enum BackgroundRole {
        NONE,
        ROOT,
        CARD_STATIC,
        CARD_CLICKABLE,
        ACCENT_BADGE,
    }

    private static final class ThemeBinding {
        final View view;
        final int textColorKey;
        final int iconColorKey;
        final BackgroundRole backgroundRole;
        final int radius;
        final int alpha;

        ThemeBinding(View view, int textColorKey, int iconColorKey,
                     BackgroundRole backgroundRole, int radius, int alpha) {
            this.view = view;
            this.textColorKey = textColorKey;
            this.iconColorKey = iconColorKey;
            this.backgroundRole = backgroundRole;
            this.radius = radius;
            this.alpha = alpha;
        }
    }

    private static final class MaxWidthLinearLayout extends LinearLayout {
        private final int maximumWidth;

        MaxWidthLinearLayout(Context context, int maximumWidth) {
            super(context);
            this.maximumWidth = maximumWidth;
        }

        @Override
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            if (width > maximumWidth) {
                widthMeasureSpec = View.MeasureSpec.makeMeasureSpec(
                        maximumWidth, View.MeasureSpec.EXACTLY);
            }
            super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        }
    }
}
