package com.extera.plugins.exitfy;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;
import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.R;
import org.telegram.ui.ActionBar.ActionBar;
import org.telegram.ui.ActionBar.AlertDialog;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;
import org.telegram.ui.ActionBar.ThemeDescription;
import org.telegram.ui.Components.BulletinFactory;

import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Root of exitFy's Telegram-native settings surface. It projects runtime state
 * and dispatches the dashboard's bounded commands off the UI thread.
 */
final class ExitFyDashboardFragment extends BaseFragment {
    private static final long CORE_INSTALL_DIALOG_DELAY_MS = 150L;
    private static final long CORE_INSTALL_DIALOG_MIN_VISIBLE_MS = 1_000L;

    private final AtomicLong renderGeneration = new AtomicLong();
    private final AtomicBoolean refreshQueued = new AtomicBoolean();
    private final AtomicBoolean refreshPending = new AtomicBoolean();
    private final AtomicBoolean commandRunning = new AtomicBoolean();
    private final Runnable runtimeListener = this::requestRefresh;

    private volatile boolean alive;
    private boolean listening;
    private boolean themeRefreshQueued;
    private volatile ExecutorService worker;
    private volatile ExitFyDashboardState latestState = ExitFyDashboardState.EMPTY;

    private boolean coreInstallSnapshotSeen;
    private long observedCoreInstallGeneration = -1L;
    private String observedCoreInstallState = "idle";
    private long announcedCoreInstallGeneration = -1L;
    private long pendingCoreInstallTerminalGeneration = -1L;
    private AlertDialog coreInstallDialog;
    private CoreInstallProgressView coreInstallProgressView;
    private long coreInstallDialogGeneration = -1L;
    private long coreInstallDialogShownAt = -1L;
    private long scheduledCoreInstallGeneration = -1L;
    private Runnable showCoreInstallDialogRunnable;
    private Runnable finishCoreInstallDialogRunnable;

    private TextView connectionStatusView;
    private TextView connectionIssueView;
    private TextView connectionHintView;
    private TextView connectButton;
    private TextView sourceValueView;
    private TextView sourceSummaryView;
    private View sourceOpenArea;
    private ImageView sourceRefreshView;
    private TextView activeNameView;
    private TextView activeMetaView;
    private TextView activePingView;
    private View activeOpenArea;
    private TextView pingButton;
    private View advancedCard;

    @Override
    public boolean onFragmentCreate() {
        if (!super.onFragmentCreate()) return false;
        alive = true;
        worker = Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, "exitfy-dashboard");
            thread.setDaemon(true);
            return thread;
        });
        return true;
    }

    @Override
    public View createView(Context context) {
        configureActionBar();

        ScrollView scroll = new ScrollView(context);
        fragmentView = scroll;
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        bindBackground(scroll, BackgroundRole.ROOT, 0, 0);
        applyThemeBinding(scroll);

        FrameLayout holder = new FrameLayout(context);
        scroll.addView(holder, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        MaxWidthLinearLayout content = new MaxWidthLinearLayout(context, dp(720));
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(12), dp(10), dp(12), dp(28));
        FrameLayout.LayoutParams contentParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.TOP | Gravity.CENTER_HORIZONTAL);
        holder.addView(content, contentParams);

        content.addView(createConnectionCard(context), sectionParams());
        content.addView(createActiveServerCard(context), sectionParams());
        content.addView(createSourceCard(context), sectionParams());
        content.addView(createAdvancedCard(context), sectionParams());

        applyState(latestState);
        requestRefresh();
        return scroll;
    }

    @Override
    public void onResume() {
        super.onResume();
        setListening(true);
        applyTheme();
        requestRefresh();
    }

    @Override
    public void onPause() {
        setListening(false);
        cancelCoreInstallUiCallbacks();
        super.onPause();
    }

    @Override
    public void onFragmentDestroy() {
        alive = false;
        renderGeneration.incrementAndGet();
        setListening(false);
        cancelCoreInstallUiCallbacks();
        dismissCoreInstallDialog();
        pendingCoreInstallTerminalGeneration = -1L;
        ExecutorService value = worker;
        worker = null;
        if (value != null) value.shutdownNow();
        super.onFragmentDestroy();
    }

    private void setListening(boolean value) {
        if (value == listening) return;
        listening = value;
        if (value) ExitFyBridge.addUiListener(runtimeListener);
        else ExitFyBridge.removeUiListener(runtimeListener);
    }

    @Override
    public ArrayList<ThemeDescription> getThemeDescriptions() {
        ArrayList<ThemeDescription> descriptions = new ArrayList<>();
        ThemeDescription.ThemeDescriptionDelegate delegate = this::scheduleThemeRefresh;
        int[] dashboardKeys = {
                Theme.key_windowBackgroundGray,
                Theme.key_windowBackgroundWhite,
                Theme.key_divider,
                Theme.key_windowBackgroundWhiteBlueText,
                Theme.key_windowBackgroundWhiteBlackText,
                Theme.key_windowBackgroundWhiteGrayText2,
                Theme.key_windowBackgroundWhiteGreenText,
                Theme.key_text_RedRegular,
                Theme.key_color_orange,
                Theme.key_featuredStickers_addButton,
                Theme.key_featuredStickers_buttonText,
                Theme.key_dialogTextBlack,
                Theme.key_dialogTextGray2,
                Theme.key_switchTrackChecked,
        };
        for (int key : dashboardKeys) {
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

    private void configureActionBar() {
        if (actionBar == null) return;
        actionBar.setBackButtonImage(R.drawable.ic_ab_back);
        actionBar.setTitle("exitFy");
        actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() {
            @Override
            public void onItemClick(int id) {
                try {
                    if (!alive) return;
                    if (id == -1) finishFragment();
                } catch (Throwable error) {
                    showToast(I18n.t("Действие не выполнено", "Action failed"), false);
                }
            }
        });
    }

    private View createConnectionCard(Context context) {
        LinearLayout card = card(context, false);
        card.setOrientation(LinearLayout.VERTICAL);

        LinearLayout header = new LinearLayout(context);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.addView(iconBadge(context, R.drawable.msg_speed,
                I18n.t("Состояние подключения", "Connection status"), 56),
                fixed(dp(56), dp(56)));

        LinearLayout labels = new LinearLayout(context);
        labels.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams labelsParams = weighted();
        labelsParams.leftMargin = dp(14);
        header.addView(labels, labelsParams);

        connectionStatusView = text(context, 21,
                Theme.key_windowBackgroundWhiteBlackText, true);
        labels.addView(connectionStatusView, matchWrap());
        connectionIssueView = text(context, 13, Theme.key_text_RedRegular, false);
        connectionIssueView.setMaxLines(3);
        connectionIssueView.setEllipsize(TextUtils.TruncateAt.END);
        connectionIssueView.setVisibility(View.GONE);
        labels.addView(connectionIssueView, topMargin(4));
        connectionHintView = text(context, 13,
                Theme.key_windowBackgroundWhiteGrayText, false);
        connectionHintView.setMaxLines(3);
        connectionHintView.setVisibility(View.GONE);
        labels.addView(connectionHintView, topMargin(4));

        card.addView(header, matchWrap());

        connectButton = primaryButton(context);
        connectButton.setOnClickListener(view -> onPrimaryActionClicked());
        card.addView(connectButton, topMargin(15));
        return card;
    }

    private View createSourceCard(Context context) {
        LinearLayout card = card(context, false);
        card.setOrientation(LinearLayout.HORIZONTAL);
        card.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout openArea = new LinearLayout(context);
        sourceOpenArea = openArea;
        openArea.setOrientation(LinearLayout.HORIZONTAL);
        openArea.setGravity(Gravity.CENTER_VERTICAL);
        openArea.setMinimumHeight(dp(48));
        openArea.setClickable(true);
        openArea.setFocusable(true);
        openArea.setOnClickListener(view -> openServers());
        bindBackground(openArea, BackgroundRole.ACCENT_SURFACE, dp(14), 0);
        applyThemeBinding(openArea);
        openArea.addView(iconBadge(context, R.drawable.msg_folders,
                I18n.t("Источник серверов", "Server source"), 48), fixed(dp(48), dp(48)));

        LinearLayout labels = new LinearLayout(context);
        labels.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams labelsParams = weighted();
        labelsParams.leftMargin = dp(13);
        openArea.addView(labels, labelsParams);
        TextView title = text(context, 15, Theme.key_windowBackgroundWhiteGrayText2, false);
        title.setText(I18n.t("Источник серверов", "Server source"));
        labels.addView(title, matchWrap());
        sourceValueView = text(context, 17, Theme.key_windowBackgroundWhiteBlackText, true);
        labels.addView(sourceValueView, topMargin(2));
        sourceSummaryView = text(context, 14, Theme.key_windowBackgroundWhiteGrayText2, false);
        labels.addView(sourceSummaryView, topMargin(2));
        card.addView(openArea, weighted());

        sourceRefreshView = icon(context, R.drawable.msg_retry,
                I18n.t("Обновить подписки", "Refresh subscriptions"));
        bindBackground(sourceRefreshView, BackgroundRole.ACCENT_SURFACE, dp(14), 0x14);
        applyThemeBinding(sourceRefreshView);
        sourceRefreshView.setPadding(dp(13), dp(13), dp(13), dp(13));
        sourceRefreshView.setOnClickListener(view -> runSimpleCommand(
                "refresh_subscriptions", true));
        card.addView(sourceRefreshView, fixed(dp(48), dp(48)));
        return card;
    }

    private View createActiveServerCard(Context context) {
        LinearLayout card = card(context, false);
        card.setOrientation(LinearLayout.VERTICAL);

        LinearLayout top = new LinearLayout(context);
        activeOpenArea = top;
        top.setOrientation(LinearLayout.HORIZONTAL);
        top.setGravity(Gravity.CENTER_VERTICAL);
        top.setMinimumHeight(dp(48));
        top.setClickable(true);
        top.setFocusable(true);
        top.setOnClickListener(view -> openServers());
        bindBackground(top, BackgroundRole.ACCENT_SURFACE, dp(14), 0);
        applyThemeBinding(top);
        top.addView(iconBadge(context, R.drawable.msg_speed,
                I18n.t("Активный сервер", "Active server"), 48), fixed(dp(48), dp(48)));

        LinearLayout labels = new LinearLayout(context);
        labels.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams labelsParams = weighted();
        labelsParams.leftMargin = dp(13);
        top.addView(labels, labelsParams);
        activeNameView = text(context, 18, Theme.key_windowBackgroundWhiteBlackText, true);
        activeNameView.setMaxLines(1);
        activeNameView.setEllipsize(TextUtils.TruncateAt.END);
        labels.addView(activeNameView, matchWrap());
        activeMetaView = text(context, 14, Theme.key_windowBackgroundWhiteBlueText, false);
        activeMetaView.setMaxLines(1);
        activeMetaView.setEllipsize(TextUtils.TruncateAt.END);
        labels.addView(activeMetaView, topMargin(3));
        activePingView = text(context, 14, Theme.key_windowBackgroundWhiteGrayText2, false);
        labels.addView(activePingView, topMargin(3));

        card.addView(top, matchWrap());

        pingButton = outlineButton(context);
        pingButton.setOnClickListener(view -> onPingClicked());
        card.addView(pingButton, topMargin(13));
        return card;
    }

    private View createAdvancedCard(Context context) {
        LinearLayout card = card(context, true);
        advancedCard = card;
        card.setOnClickListener(view -> openPreferences());
        card.setOrientation(LinearLayout.HORIZONTAL);
        card.setGravity(Gravity.CENTER_VERTICAL);
        card.addView(iconBadge(context, R.drawable.msg_settings,
                I18n.t("Дополнительно", "Advanced"), 48), fixed(dp(48), dp(48)));
        LinearLayout labels = new LinearLayout(context);
        labels.setOrientation(LinearLayout.VERTICAL);
        TextView title = text(context, 17, Theme.key_windowBackgroundWhiteBlackText, true);
        title.setText(I18n.t("Дополнительно", "Advanced"));
        labels.addView(title, matchWrap());
        TextView summary = text(context, 13,
                Theme.key_windowBackgroundWhiteGrayText, false);
        summary.setText(I18n.t(
                "Способ проверки задержки и замена идентификатора",
                "Latency check method and identifier replacement"));
        labels.addView(summary, topMargin(2));
        LinearLayout.LayoutParams labelsParams = weighted();
        labelsParams.leftMargin = dp(13);
        card.addView(labels, labelsParams);
        card.setContentDescription(I18n.t(
                "Дополнительно: способ проверки задержки и замена идентификатора",
                "Advanced: latency check method and identifier replacement"));
        return card;
    }

    private void requestRefresh() {
        ExecutorService executor = worker;
        if (!alive || executor == null || executor.isShutdown()) return;
        refreshPending.set(true);
        if (!refreshQueued.compareAndSet(false, true)) return;
        long token = renderGeneration.incrementAndGet();
        try {
            executor.execute(() -> {
                // A request observed before this point is covered by the state
                // read below. A later request stays set and schedules one more
                // coalesced pass after this render.
                refreshPending.set(false);
                ExitFyDashboardState parsed;
                try {
                    parsed = ExitFyDashboardState.parse(ExitFyBridge.getUiState());
                } catch (Throwable ignored) {
                    parsed = ExitFyDashboardState.EMPTY;
                }
                ExitFyDashboardState state = parsed;
                if (!postToUi(() -> {
                    refreshQueued.set(false);
                    if (!alive || token != renderGeneration.get()) return;
                    latestState = state;
                    applyState(state);
                    if (refreshPending.get()) requestRefresh();
                })) {
                    refreshQueued.set(false);
                }
            });
        } catch (RejectedExecutionException ignored) {
            refreshQueued.set(false);
            refreshPending.set(false);
        }
    }

    private void applyState(ExitFyDashboardState state) {
        if (connectButton == null) return;
        connectionStatusView.setText(state.connectionTitle());
        connectionStatusView.setTextColor(connectionColor(state.runtimeState));
        boolean showConnectionIssue = "ERROR".equals(state.runtimeState)
                && !state.connectionIssue.isEmpty();
        connectionIssueView.setText(showConnectionIssue ? state.connectionIssue : "");
        connectionIssueView.setVisibility(showConnectionIssue ? View.VISIBLE : View.GONE);
        String hint = showConnectionIssue ? "" : state.nextStepHint();
        connectionHintView.setText(hint);
        connectionHintView.setVisibility(hint.isEmpty() ? View.GONE : View.VISIBLE);
        connectButton.setText(state.primaryAction().label());
        boolean commandIdle = state.runtimeAvailable
                && !commandRunning.get()
                && !state.coreInstall.active();
        connectButton.setEnabled(commandIdle && !state.isTransitioning());
        connectButton.setAlpha(connectButton.isEnabled() ? 1f : 0.55f);

        sourceValueView.setText(state.providerName());
        sourceSummaryView.setText(state.providerSummary());
        sourceOpenArea.setContentDescription(I18n.format(
                "Источник серверов: %s, %s", "Server source: %s, %s",
                state.providerName(), state.providerSummary()));
        setActionEnabled(sourceOpenArea, commandIdle);
        sourceRefreshView.setEnabled(commandIdle && !state.refreshRunning);
        sourceRefreshView.setAlpha(sourceRefreshView.isEnabled() ? 1f : 0.45f);

        activeNameView.setText(state.activeTitle());
        activeMetaView.setText(state.activeProtocolSummary());
        activePingView.setText(state.activePingSummary());
        activeOpenArea.setContentDescription(I18n.format(
                "Активный сервер: %s, %s, %s", "Active server: %s, %s, %s",
                state.activeTitle(), state.activeProtocolSummary(),
                state.activePingSummary()));
        setActionEnabled(activeOpenArea, commandIdle);
        activePingView.setTextColor(pingColor(state));
        pingButton.setEnabled(commandIdle && (state.hasActiveNode() || state.pingRunning));
        pingButton.setAlpha(pingButton.isEnabled() ? 1f : 0.45f);
        pingButton.setText(state.pingRunning
                ? I18n.t("Отменить проверку", "Cancel check")
                    + (state.pingProgress().isEmpty() ? "" : " · " + state.pingProgress())
                : I18n.t("Проверить задержку", "Check latency"));

        setActionEnabled(advancedCard, commandIdle);

        updateCoreInstallUi(state);
    }

    private void onPrimaryActionClicked() {
        ExitFyDashboardState state = latestState;
        switch (state.primaryAction()) {
            case INSTALLING:
                return;
            case INSTALL_CORES:
                runSimpleCommand("install_cores", false);
                return;
            case CONNECT:
            case DISCONNECT:
            default:
                toggleConnection();
        }
    }

    private void toggleConnection() {
        ExitFyDashboardState state = latestState;
        runCommand(() -> new JSONObject()
                .put("command", "set_setting")
                .put("key", "enabled")
                .put("value", !state.enabled), false);
    }

    private void updateCoreInstallUi(ExitFyDashboardState dashboardState) {
        if (!dashboardState.runtimeAvailable) {
            resetCoreInstallUi();
            return;
        }

        ExitFyDashboardState.CoreInstallState install =
                dashboardState.coreInstall;
        if (!coreInstallSnapshotSeen) {
            coreInstallSnapshotSeen = true;
            observedCoreInstallGeneration = install.generation;
            observedCoreInstallState = install.state;
            if (install.active()) beginCoreInstallUi(install);
            return;
        }
        if (install.generation < observedCoreInstallGeneration) {
            return;
        }

        boolean generationChanged =
                install.generation != observedCoreInstallGeneration;
        boolean becameTerminal = install.terminal()
                && (generationChanged
                || !install.state.equals(observedCoreInstallState));
        observedCoreInstallGeneration = install.generation;
        observedCoreInstallState = install.state;

        if (install.active()) {
            beginCoreInstallUi(install);
            return;
        }

        cancelScheduledCoreInstallShow();
        if (coreInstallProgressView != null
                && coreInstallDialogGeneration == install.generation) {
            coreInstallProgressView.setState(install);
        }
        if (becameTerminal
                && announcedCoreInstallGeneration != install.generation) {
            pendingCoreInstallTerminalGeneration = install.generation;
            finishCoreInstallUi(install);
            return;
        }
        if (install.terminal()
                && pendingCoreInstallTerminalGeneration == install.generation) {
            finishCoreInstallUi(install);
            return;
        }
        if (!install.terminal()) {
            pendingCoreInstallTerminalGeneration = -1L;
            cancelScheduledCoreInstallFinish();
            dismissCoreInstallDialog();
        }
    }

    private void beginCoreInstallUi(
            ExitFyDashboardState.CoreInstallState install) {
        cancelScheduledCoreInstallFinish();
        if (pendingCoreInstallTerminalGeneration != install.generation) {
            pendingCoreInstallTerminalGeneration = -1L;
        }
        if (isPaused || !alive) return;

        if (coreInstallDialog != null && coreInstallDialog.isShowing()) {
            coreInstallDialogGeneration = install.generation;
            if (coreInstallProgressView != null) {
                coreInstallProgressView.setState(install);
            }
            return;
        }
        scheduleCoreInstallDialog(install.generation);
    }

    private void scheduleCoreInstallDialog(long generation) {
        if (!alive || isPaused) return;
        if (showCoreInstallDialogRunnable != null
                && scheduledCoreInstallGeneration == generation) {
            return;
        }
        cancelScheduledCoreInstallShow();
        scheduledCoreInstallGeneration = generation;
        showCoreInstallDialogRunnable = () -> showCoreInstallDialog(generation);
        try {
            AndroidUtilities.runOnUIThread(
                    showCoreInstallDialogRunnable,
                    CORE_INSTALL_DIALOG_DELAY_MS);
        } catch (Throwable ignored) {
            showCoreInstallDialogRunnable = null;
            scheduledCoreInstallGeneration = -1L;
        }
    }

    private void showCoreInstallDialog(long generation) {
        showCoreInstallDialogRunnable = null;
        scheduledCoreInstallGeneration = -1L;
        ExitFyDashboardState.CoreInstallState install =
                latestState.coreInstall;
        Context context = getParentActivity();
        if (!alive || isPaused || context == null || !install.active()
                || install.generation != generation) {
            return;
        }
        if (coreInstallDialog != null && coreInstallDialog.isShowing()) {
            coreInstallDialogGeneration = generation;
            if (coreInstallProgressView != null) {
                coreInstallProgressView.setState(install);
            }
            return;
        }

        CoreInstallProgressView progressView = new CoreInstallProgressView(
                context, getCurrentAccount(), getResourceProvider());
        progressView.setState(install);
        AlertDialog dialog = new AlertDialog.Builder(
                context, getResourceProvider())
                .setView(progressView)
                .create();
        dialog.setCanceledOnTouchOutside(false);
        dialog.setCancelable(false);

        coreInstallDialog = dialog;
        coreInstallProgressView = progressView;
        coreInstallDialogGeneration = generation;
        coreInstallDialogShownAt = -1L;
        if (showDialog(dialog,
                ignored -> onCoreInstallDialogDismissed(dialog)) == null) {
            clearCoreInstallDialog(dialog);
            scheduleCoreInstallDialog(generation);
            return;
        }
        // BaseFragment.showDialog enables outside cancellation before showing.
        // Restore the Vosk-style noncancelable contract after that call.
        dialog.setCanceledOnTouchOutside(false);
        dialog.setCancelable(false);
        coreInstallDialogShownAt = SystemClock.elapsedRealtime();
    }

    private void finishCoreInstallUi(
            ExitFyDashboardState.CoreInstallState install) {
        cancelScheduledCoreInstallShow();
        if (coreInstallProgressView != null
                && coreInstallDialogGeneration == install.generation) {
            coreInstallProgressView.setState(install);
        }
        AlertDialog dialog = coreInstallDialog;
        if (dialog == null || !dialog.isShowing()
                || coreInstallDialogGeneration != install.generation) {
            if (dialog != null) dismissCoreInstallDialog();
            deliverPendingCoreInstallBulletin();
            return;
        }

        long elapsed = coreInstallDialogShownAt < 0L ? 0L
                : SystemClock.elapsedRealtime() - coreInstallDialogShownAt;
        long remaining = Math.max(
                0L, CORE_INSTALL_DIALOG_MIN_VISIBLE_MS - elapsed);
        cancelScheduledCoreInstallFinish();
        long generation = install.generation;
        finishCoreInstallDialogRunnable = () -> {
            finishCoreInstallDialogRunnable = null;
            ExitFyDashboardState.CoreInstallState latest =
                    latestState.coreInstall;
            if (!alive || latest.generation != generation
                    || !latest.terminal()) {
                return;
            }
            AlertDialog current = coreInstallDialog;
            if (current != null && coreInstallDialogGeneration == generation) {
                try {
                    current.dismiss();
                } catch (Throwable ignored) {
                    clearCoreInstallDialog(current);
                }
            }
            deliverPendingCoreInstallBulletin();
        };
        try {
            AndroidUtilities.runOnUIThread(
                    finishCoreInstallDialogRunnable, remaining);
        } catch (Throwable ignored) {
            finishCoreInstallDialogRunnable = null;
            dismissCoreInstallDialog();
            deliverPendingCoreInstallBulletin();
        }
    }

    private void onCoreInstallDialogDismissed(AlertDialog dialog) {
        if (dialog != coreInstallDialog) return;
        clearCoreInstallDialog(dialog);
        cancelScheduledCoreInstallFinish();
        deliverPendingCoreInstallBulletin();

        ExitFyDashboardState.CoreInstallState install =
                latestState.coreInstall;
        if (alive && !isPaused && install.active()) {
            scheduleCoreInstallDialog(install.generation);
        }
    }

    private void deliverPendingCoreInstallBulletin() {
        long generation = pendingCoreInstallTerminalGeneration;
        ExitFyDashboardState.CoreInstallState install =
                latestState.coreInstall;
        if (generation < 0L || announcedCoreInstallGeneration == generation) {
            return;
        }
        if (!alive || isPaused || fragmentView == null
                || install.generation != generation || !install.terminal()) {
            return;
        }

        pendingCoreInstallTerminalGeneration = -1L;
        announcedCoreInstallGeneration = generation;
        try {
            if (install.successful()) {
                BulletinFactory.of(this)
                        .createSuccessBulletin(install.terminalMessage())
                        .show();
            } else if (install.partial()) {
                BulletinFactory.of(this)
                        .createSimpleBulletin(
                                R.raw.info, install.terminalMessage())
                        .show();
            } else {
                BulletinFactory.of(this)
                        .createErrorBulletin(install.terminalMessage())
                        .show();
            }
        } catch (Throwable ignored) {
            showToast(install.terminalMessage(), install.successful());
        }
    }

    private void resetCoreInstallUi() {
        coreInstallSnapshotSeen = false;
        observedCoreInstallGeneration = -1L;
        observedCoreInstallState = "idle";
        announcedCoreInstallGeneration = -1L;
        pendingCoreInstallTerminalGeneration = -1L;
        cancelCoreInstallUiCallbacks();
        dismissCoreInstallDialog();
    }

    private void cancelCoreInstallUiCallbacks() {
        cancelScheduledCoreInstallShow();
        cancelScheduledCoreInstallFinish();
    }

    private void cancelScheduledCoreInstallShow() {
        Runnable pending = showCoreInstallDialogRunnable;
        showCoreInstallDialogRunnable = null;
        scheduledCoreInstallGeneration = -1L;
        if (pending == null) return;
        try {
            AndroidUtilities.cancelRunOnUIThread(pending);
        } catch (Throwable ignored) {
        }
    }

    private void cancelScheduledCoreInstallFinish() {
        Runnable pending = finishCoreInstallDialogRunnable;
        finishCoreInstallDialogRunnable = null;
        if (pending == null) return;
        try {
            AndroidUtilities.cancelRunOnUIThread(pending);
        } catch (Throwable ignored) {
        }
    }

    private void dismissCoreInstallDialog() {
        AlertDialog dialog = coreInstallDialog;
        if (dialog == null) return;
        clearCoreInstallDialog(dialog);
        try {
            dialog.dismiss();
        } catch (Throwable ignored) {
        }
    }

    private void clearCoreInstallDialog(AlertDialog expected) {
        if (coreInstallDialog != expected) return;
        coreInstallDialog = null;
        coreInstallProgressView = null;
        coreInstallDialogGeneration = -1L;
        coreInstallDialogShownAt = -1L;
    }

    private void onPingClicked() {
        try {
            ExitFyDashboardState state = latestState;
            if (state.pingRunning) {
                runSimpleCommand("cancel_ping", false);
                return;
            }
            if (!state.hasActiveNode()) return;
            if (SettingsModel.PING_PROXY_GET.equals(state.pingType)) {
                Context context = getParentActivity();
                if (context == null) return;
                AlertDialog dialog = new AlertDialog.Builder(context, getResourceProvider())
                        .setTitle(I18n.t("Проверка задержки", "Latency check"))
                        .setMessage(I18n.t(
                                "Подключение будет временно приостановлено. exitFy проверит весь путь подключения, а затем восстановит прежний сервер.",
                                "The connection will be paused temporarily. exitFy will test the complete connection path, then restore the previous server."))
                        .setNegativeButton(I18n.t("Отмена", "Cancel"), null)
                        .setPositiveButton(I18n.t("Проверить", "Check"),
                                (ignored, which) -> runCurrentPing(state.pingType))
                        .create();
                showDialog(dialog);
            } else {
                runCurrentPing(state.pingType);
            }
        } catch (Throwable error) {
            showToast(I18n.t("Не удалось запустить проверку",
                    "Could not start latency check"), false);
        }
    }

    private void runCurrentPing(String expectedPingType) {
        runCommand(() -> {
            ExitFyDashboardState current = ExitFyDashboardState.parse(
                    ExitFyBridge.getUiState());
            if (!current.hasActiveNode()) {
                throw new IllegalStateException(I18n.t(
                        "Сервер больше не выбран", "The server is no longer selected"));
            }
            return new JSONObject()
                    .put("command", "ping_nodes")
                    .put("keys", new JSONArray().put(current.activeKey))
                    .put("expected_ping_type", expectedPingType);
        }, true);
    }

    private void runSimpleCommand(String command, boolean showSuccess) {
        runCommand(() -> new JSONObject().put("command", command), showSuccess);
    }

    private void runCommand(CommandFactory factory, boolean showSuccess) {
        ExecutorService executor = worker;
        if (!alive || executor == null || executor.isShutdown()) return;
        if (!commandRunning.compareAndSet(false, true)) {
            showToast(I18n.t("Дождитесь завершения текущей операции",
                    "Wait for the current operation to finish"), false);
            return;
        }
        applyCommandBusyState();
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
                    result = new ExitFyCommandResult(false, ErrorSanitizer.clean(
                            error.getMessage() == null
                                    ? I18n.t("Операция не выполнена", "Operation failed")
                                    : error.getMessage()));
                }
                ExitFyCommandResult completed = result;
                if (!postToUi(() -> {
                    commandRunning.set(false);
                    if (!alive) return;
                    if (!completed.ok || showSuccess) {
                        showToast(completed.message.isEmpty()
                                ? (completed.ok
                                ? I18n.t("Готово", "Done")
                                : I18n.t("Операция не выполнена", "Operation failed"))
                                : completed.message, completed.ok);
                    }
                    requestRefresh();
                })) {
                    commandRunning.set(false);
                }
            });
        } catch (RejectedExecutionException ignored) {
            commandRunning.set(false);
            requestRefresh();
        }
    }

    private void openServers() {
        try {
            ExitFyServersFragment servers = new ExitFyServersFragment();
            servers.setCurrentAccount(getCurrentAccount());
            if (!presentFragment(servers)) {
                showToast(I18n.t("Не удалось открыть серверы",
                        "Could not open servers"), false);
            }
        } catch (Throwable error) {
            showToast(I18n.t("Не удалось открыть серверы",
                    "Could not open servers"), false);
        }
    }

    private void openPreferences() {
        try {
            ExitFyPreferencesFragment preferences = new ExitFyPreferencesFragment();
            preferences.setCurrentAccount(getCurrentAccount());
            if (!presentFragment(preferences)) {
                showToast(I18n.t("Не удалось открыть настройки",
                        "Could not open settings"), false);
            }
        } catch (Throwable error) {
            showToast(I18n.t("Не удалось открыть настройки",
                    "Could not open settings"), false);
        }
    }

    private void applyCommandBusyState() {
        if (connectButton != null) {
            connectButton.setEnabled(false);
            connectButton.setAlpha(0.55f);
        }
        if (sourceRefreshView != null) {
            sourceRefreshView.setEnabled(false);
            sourceRefreshView.setAlpha(0.45f);
        }
        if (pingButton != null) {
            pingButton.setEnabled(false);
            pingButton.setAlpha(0.45f);
        }
        setActionEnabled(sourceOpenArea, false);
        setActionEnabled(activeOpenArea, false);
        setActionEnabled(advancedCard, false);
    }

    private static void setActionEnabled(View view, boolean enabled) {
        if (view == null) return;
        view.setEnabled(enabled);
        view.setAlpha(enabled ? 1f : 0.45f);
    }

    private void showToast(String message, boolean success) {
        try {
            Context context = getParentActivity();
            if (context == null || message == null || message.isEmpty()) return;
            Toast.makeText(context, message,
                    success ? Toast.LENGTH_SHORT : Toast.LENGTH_LONG).show();
        } catch (Throwable ignored) {
        }
    }

    private boolean postToUi(Runnable task) {
        if (task == null) return false;
        try {
            AndroidUtilities.runOnUIThread(task);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private int connectionColor(String state) {
        if ("RUNNING".equals(state)) {
            return getThemedColor(Theme.key_windowBackgroundWhiteGreenText);
        }
        if ("ERROR".equals(state)) return getThemedColor(Theme.key_text_RedRegular);
        if ("STARTING".equals(state) || "STOPPING".equals(state)) {
            return getThemedColor(Theme.key_color_orange);
        }
        return getThemedColor(Theme.key_windowBackgroundWhiteGrayText2);
    }

    private int pingColor(ExitFyDashboardState state) {
        if (state.activeLatency >= 0) {
            return getThemedColor(Theme.key_windowBackgroundWhiteGreenText);
        }
        if ("failed".equals(state.activePingStatus)) {
            return getThemedColor(Theme.key_text_RedRegular);
        }
        return getThemedColor(Theme.key_windowBackgroundWhiteGrayText2);
    }

    private LinearLayout card(Context context, boolean clickable) {
        LinearLayout value = new LinearLayout(context);
        value.setPadding(dp(16), dp(15), dp(16), dp(15));
        value.setMinimumHeight(dp(64));
        bindBackground(value, clickable
                ? BackgroundRole.CARD_CLICKABLE : BackgroundRole.CARD_STATIC,
                dp(18), 0);
        applyThemeBinding(value);
        if (clickable) {
            value.setClickable(true);
            value.setFocusable(true);
        }
        return value;
    }

    private ImageView iconBadge(Context context, int resource, String description, int sizeDp) {
        ImageView image = icon(context, resource, description);
        // The adjacent text or clickable parent already exposes the same
        // meaning; keep decorative badges out of TalkBack focus order.
        image.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        int padding = Math.max(dp(9), dp(sizeDp / 4));
        image.setPadding(padding, padding, padding, padding);
        bindBackground(image, BackgroundRole.ACCENT_BADGE, dp(sizeDp / 2), 0x18);
        applyThemeBinding(image);
        return image;
    }

    private ImageView icon(Context context, int resource, String description) {
        ImageView image = new ImageView(context);
        image.setImageResource(resource);
        image.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        bindIcon(image);
        applyThemeBinding(image);
        image.setContentDescription(description);
        return image;
    }

    private TextView text(Context context, int sizeSp, int colorKey, boolean bold) {
        TextView value = new TextView(context);
        value.setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp);
        bindText(value, colorKey);
        applyThemeBinding(value);
        value.setTypeface(Typeface.DEFAULT, bold ? Typeface.BOLD : Typeface.NORMAL);
        value.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
        value.setIncludeFontPadding(false);
        return value;
    }

    private TextView primaryButton(Context context) {
        TextView button = text(context, 16, Theme.key_featuredStickers_buttonText, true);
        button.setGravity(Gravity.CENTER);
        button.setMinHeight(dp(50));
        button.setClickable(true);
        button.setFocusable(true);
        bindBackground(button, BackgroundRole.PRIMARY, dp(14), 0);
        applyThemeBinding(button);
        return button;
    }

    private TextView outlineButton(Context context) {
        TextView button = text(context, 15, Theme.key_windowBackgroundWhiteBlueText, true);
        button.setGravity(Gravity.CENTER);
        button.setMinHeight(dp(48));
        button.setPadding(dp(12), dp(8), dp(12), dp(8));
        button.setClickable(true);
        button.setFocusable(true);
        bindBackground(button, BackgroundRole.OUTLINE, dp(14), 0);
        applyThemeBinding(button);
        return button;
    }

    private void bindText(TextView view, int colorKey) {
        binding(view).textColorKey = colorKey;
    }

    private void bindIcon(ImageView view) {
        binding(view).accentIcon = true;
    }

    private void bindBackground(View view, BackgroundRole role, int radius, int alpha) {
        ThemeBinding binding = binding(view);
        binding.backgroundRole = role;
        binding.radius = radius;
        binding.alpha = alpha;
    }

    private static ThemeBinding binding(View view) {
        Object existing = view.getTag();
        if (existing instanceof ThemeBinding) return (ThemeBinding) existing;
        ThemeBinding created = new ThemeBinding();
        view.setTag(created);
        return created;
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
        View root = fragmentView;
        if (root == null) return;
        applyThemeTree(root);
        if (coreInstallProgressView != null) {
            coreInstallProgressView.applyTheme();
        }
        applyState(latestState);
    }

    private void applyThemeTree(View view) {
        applyThemeBinding(view);
        if (!(view instanceof ViewGroup)) return;
        ViewGroup group = (ViewGroup) view;
        for (int index = 0; index < group.getChildCount(); index++) {
            applyThemeTree(group.getChildAt(index));
        }
    }

    private void applyThemeBinding(View view) {
        Object raw = view.getTag();
        if (!(raw instanceof ThemeBinding)) return;
        ThemeBinding binding = (ThemeBinding) raw;
        if (view instanceof TextView && binding.textColorKey >= 0) {
            ((TextView) view).setTextColor(getThemedColor(binding.textColorKey));
        }
        if (view instanceof ImageView && binding.accentIcon) {
            ((ImageView) view).setColorFilter(
                    getThemedColor(Theme.key_windowBackgroundWhiteBlueText),
                    PorterDuff.Mode.SRC_IN);
        }
        switch (binding.backgroundRole) {
            case ROOT:
                view.setBackgroundColor(getThemedColor(Theme.key_windowBackgroundGray));
                break;
            case CARD_STATIC:
                view.setBackground(rounded(getThemedColor(Theme.key_windowBackgroundWhite),
                        binding.radius, getThemedColor(Theme.key_divider)));
                break;
            case CARD_CLICKABLE:
                view.setBackground(rippleOver(getThemedColor(Theme.key_windowBackgroundWhite),
                        binding.radius));
                break;
            case ACCENT_SURFACE:
                view.setBackground(clickableBackground(withAlpha(getThemedColor(
                        Theme.key_windowBackgroundWhiteBlueText), binding.alpha),
                        binding.radius));
                break;
            case ACCENT_BADGE:
                view.setBackground(rounded(withAlpha(getThemedColor(
                        Theme.key_windowBackgroundWhiteBlueText), binding.alpha),
                        binding.radius, Color.TRANSPARENT));
                break;
            case PRIMARY:
                view.setBackground(rippleOver(
                        getThemedColor(Theme.key_featuredStickers_addButton), binding.radius));
                break;
            case OUTLINE:
                view.setBackground(rippleOutline(binding.radius));
                break;
            case NONE:
            default:
                break;
        }
    }

    private Drawable rippleOver(int fill, int radius) {
        return new RippleDrawable(
                ColorStateList.valueOf(withAlpha(
                        getThemedColor(Theme.key_windowBackgroundWhiteBlueText), 0x25)),
                rounded(fill, radius, getThemedColor(Theme.key_divider)), null);
    }

    private Drawable clickableBackground(int fill, int radius) {
        return new RippleDrawable(
                ColorStateList.valueOf(withAlpha(
                        getThemedColor(Theme.key_windowBackgroundWhiteBlueText), 0x2a)),
                rounded(fill, radius, Color.TRANSPARENT), null);
    }

    private Drawable rippleOutline(int radius) {
        return new RippleDrawable(
                ColorStateList.valueOf(withAlpha(
                        getThemedColor(Theme.key_windowBackgroundWhiteBlueText), 0x24)),
                rounded(Color.TRANSPARENT, radius,
                        withAlpha(getThemedColor(Theme.key_windowBackgroundWhiteBlueText), 0x65)),
                null);
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

    private LinearLayout.LayoutParams sectionParams() {
        LinearLayout.LayoutParams value = matchWrap();
        value.bottomMargin = dp(10);
        return value;
    }

    private static LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private static LinearLayout.LayoutParams fixed(int width, int height) {
        return new LinearLayout.LayoutParams(width, height);
    }

    private static LinearLayout.LayoutParams weighted() {
        return new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
    }

    private LinearLayout.LayoutParams topMargin(int marginDp) {
        LinearLayout.LayoutParams value = matchWrap();
        value.topMargin = dp(marginDp);
        return value;
    }

    private static int dp(float value) {
        return AndroidUtilities.dp(value);
    }

    @FunctionalInterface
    private interface CommandFactory {
        JSONObject create() throws Exception;
    }

    private enum BackgroundRole {
        NONE,
        ROOT,
        CARD_STATIC,
        CARD_CLICKABLE,
        ACCENT_SURFACE,
        ACCENT_BADGE,
        PRIMARY,
        OUTLINE,
    }

    private static final class ThemeBinding {
        int textColorKey = -1;
        boolean accentIcon;
        BackgroundRole backgroundRole = BackgroundRole.NONE;
        int radius;
        int alpha;
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
