package com.extera.plugins.exitfy;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;
import org.telegram.messenger.R;
import org.telegram.ui.ActionBar.AlertDialog;
import org.telegram.ui.ActionBar.Theme;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Telegram-native server browser and provider management surface.
 *
 * <p>Search, protocol filtering and pagination intentionally remain local
 * to this fragment. Only actual plugin settings and explicit runtime commands
 * cross the bridge.</p>
 */
final class ExitFyServersFragment
        extends ExitFySubscreenFragment<ExitFyDashboardState> {
    private static final int[] PAGE_SIZES = {
            SubscriptionManager.DEFAULT_PAGE_SIZE, 100, SubscriptionManager.MAX_PAGE_SIZE,
    };

    private int pageSize = SubscriptionManager.DEFAULT_PAGE_SIZE;
    private static final int MAX_SUBSCRIPTION_CHARS = 4096;

    private static final String[] PROTOCOL_VALUES = {
            "all", "vless", "vmess", "trojan", "shadowsocks",
            "hysteria", "hysteria2", "tuic",
    };
    private final ArrayList<SettingRow> nodeRows = new ArrayList<>();
    private final ArrayList<SettingRow> customSourceRows = new ArrayList<>();

    private ExitFyDashboardState state = ExitFyDashboardState.EMPTY;
    private ExitFyServerPage page = ExitFyServerPage.INVALID;

    private String query = "";
    private String protocol = "all";
    private int offset;

    private String observedFingerprint = "";
    private boolean pageDirty = true;
    private boolean pageRequestInFlight;
    private boolean commandBusy;

    private SettingRow providerRow;
    private SettingRow searchRow;
    private SettingRow protocolRow;
    private SettingRow refreshRow;
    private SettingRow pingRow;
    private SettingRow referralRow;
    private SettingRow addNodeRow;
    private SettingRow addSubscriptionRow;
    private SettingRow clearNodesRow;
    private SettingRow pageStatusRow;
    private SettingRow previousPageRow;
    private SettingRow nextPageRow;
    private SettingRow pageSizeRow;
    private TextView customSourcesLabel;
    private LinearLayout nodesContainer;
    private LinearLayout customSourcesContainer;

    @Override
    protected CharSequence screenTitle() {
        return I18n.t("Серверы exitFy", "exitFy servers");
    }

    @Override
    protected String workerThreadName() {
        return "exitfy-servers";
    }

    @Override
    protected void buildContent(Context context, LinearLayout content) {
        // BaseFragment can rebuild the View hierarchy without destroying this
        // fragment instance. Drop row wrappers from the detached hierarchy
        // and force one authoritative page projection into the new container.
        nodeRows.clear();
        customSourceRows.clear();
        observedFingerprint = "";

        content.addView(createIntroCard(context), sectionParams());

        content.addView(sectionLabel(context,
                I18n.t("ИСТОЧНИК И ФИЛЬТРЫ", "SOURCE AND FILTERS")), matchWrap());

        providerRow = settingRow(context, R.drawable.msg_folders,
                I18n.t("Провайдер", "Provider"),
                I18n.t("Выберите встроенный или пользовательский источник",
                        "Choose a built-in or custom source"));
        setSafeClick(providerRow.view, this::showProviderDialog);
        content.addView(providerRow.view, sectionParams());

        searchRow = settingRow(context, R.drawable.msg_edit,
                I18n.t("Поиск", "Search"),
                I18n.t("По имени сервера или источника",
                        "By server or source name"));
        setSafeClick(searchRow.view, this::showSearchDialog);
        content.addView(searchRow.view, sectionParams());

        protocolRow = settingRow(context, R.drawable.msg_settings,
                I18n.t("Протокол", "Protocol"),
                I18n.t("Показывать только выбранный протокол",
                        "Show only the selected protocol"));
        setSafeClick(protocolRow.view, this::showProtocolDialog);
        content.addView(protocolRow.view, sectionParams());

        content.addView(sectionLabel(context,
                I18n.t("ДЕЙСТВИЯ", "ACTIONS")), matchWrap());

        refreshRow = settingRow(context, R.drawable.msg_retry,
                I18n.t("Обновить подписки", "Refresh subscriptions"),
                I18n.t("Загрузить свежие серверы из сохранённых источников",
                        "Fetch fresh servers from saved sources"));
        setSafeClick(refreshRow.view, this::refreshSubscriptions);
        content.addView(refreshRow.view, sectionParams());

        pingRow = settingRow(context, R.drawable.msg_speed,
                I18n.t("Проверить страницу", "Check this page"),
                I18n.t("Проверяется не более 50 видимых серверов",
                        "Checks at most 50 visible servers"));
        setSafeClick(pingRow.view, this::onPingClicked);
        content.addView(pingRow.view, sectionParams());

        referralRow = settingRow(context, R.drawable.msg_info,
                I18n.t("Открыть страницу провайдера", "Open provider page"),
                I18n.t("Позволяет включить интернет везде",
                        "Lets you turn the internet on anywhere"));
        setSafeClick(referralRow.view, this::openProviderReferral);
        content.addView(referralRow.view, sectionParams());

        addNodeRow = settingRow(context, R.drawable.msg_edit,
                I18n.t("Добавить ключ сервера", "Add server key"),
                I18n.t("VLESS, VMess, Trojan, Shadowsocks, Hysteria или TUIC",
                        "VLESS, VMess, Trojan, Shadowsocks, Hysteria, or TUIC"));
        setSafeClick(addNodeRow.view, this::showAddNodeDialog);
        content.addView(addNodeRow.view, sectionParams());

        addSubscriptionRow = settingRow(context, R.drawable.msg_download,
                I18n.t("Добавить подписку", "Add subscription"),
                I18n.t("HTTP- или HTTPS-ссылка; провайдер сменится на пользовательский",
                        "HTTP or HTTPS URL; provider switches to Custom"));
        setSafeClick(addSubscriptionRow.view, this::showAddSubscriptionDialog);
        content.addView(addSubscriptionRow.view, sectionParams());

        clearNodesRow = settingRow(context, R.drawable.msg_retry,
                I18n.t("Очистить серверы", "Clear servers"),
                I18n.t("Подписки сохранятся, подключение будет выключено",
                        "Subscriptions stay saved; the connection will be disabled"));
        setSafeClick(clearNodesRow.view, this::confirmClearNodes);
        content.addView(clearNodesRow.view, sectionParams());

        customSourcesLabel = sectionLabel(context,
                I18n.t("СОХРАНЁННЫЕ ПОДПИСКИ", "SAVED SUBSCRIPTIONS"));
        content.addView(customSourcesLabel, matchWrap());
        customSourcesContainer = new LinearLayout(context);
        customSourcesContainer.setOrientation(LinearLayout.VERTICAL);
        content.addView(customSourcesContainer, sectionParams());

        content.addView(sectionLabel(context,
                I18n.t("СЕРВЕРЫ", "SERVERS")), matchWrap());

        pageStatusRow = settingRow(context, R.drawable.msg_folders,
                I18n.t("Список серверов", "Server list"),
                I18n.t("Нажмите, чтобы перечитать текущую страницу",
                        "Tap to reload the current page"));
        setSafeClick(pageStatusRow.view, this::reloadPage);
        content.addView(pageStatusRow.view, sectionParams());

        nodesContainer = new LinearLayout(context);
        nodesContainer.setOrientation(LinearLayout.VERTICAL);
        content.addView(nodesContainer, sectionParams());

        previousPageRow = settingRow(context, R.drawable.msg_arrow_back,
                I18n.t("Предыдущая страница", "Previous page"),
                pageSizeSummary());
        setSafeClick(previousPageRow.view, this::goToPreviousPage);
        content.addView(previousPageRow.view, sectionParams());

        nextPageRow = settingRow(context, R.drawable.msg_arrowright,
                I18n.t("Следующая страница", "Next page"),
                pageSizeSummary());
        setSafeClick(nextPageRow.view, this::goToNextPage);
        content.addView(nextPageRow.view, sectionParams());

        // The subtitles of the paging rows keep the size they were built with;
        // the value on this row is what changes.
        pageSizeRow = settingRow(context, R.drawable.msg_folders,
                I18n.t("Серверов на странице", "Servers per page"),
                I18n.t("Больше серверов сразу, без перелистывания",
                        "See more of a source without paging"));
        pageSizeRow.setValue(String.valueOf(pageSize));
        setSafeClick(pageSizeRow.view, this::showPageSizeDialog);
        content.addView(pageSizeRow.view, sectionParams());

        renderUiState(state);
    }

    private View createIntroCard(Context context) {
        LinearLayout value = card(context, false);
        value.setOrientation(LinearLayout.HORIZONTAL);
        value.setGravity(Gravity.CENTER_VERTICAL);
        value.addView(iconBadge(context, R.drawable.msg_folders,
                I18n.t("Браузер серверов", "Server browser"), 52),
                fixed(dp(52), dp(52)));

        LinearLayout labels = new LinearLayout(context);
        labels.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams labelsParams = weighted();
        labelsParams.leftMargin = dp(14);
        value.addView(labels, labelsParams);

        TextView title = text(context, 19,
                Theme.key_windowBackgroundWhiteBlackText, true);
        title.setText(I18n.t("Источники и серверы", "Sources and servers"));
        labels.addView(title, matchWrap());

        TextView summary = text(context, 14,
                Theme.key_windowBackgroundWhiteGrayText2, false);
        summary.setText(I18n.t(
                "Выбор провайдера, ручные ключи, подписки, фильтры и проверка задержки",
                "Provider selection, manual keys, subscriptions, filters, and latency checks"));
        summary.setMaxLines(3);
        labels.addView(summary, topMargin(4));
        return value;
    }

    @Override
    protected ExitFyDashboardState parseUiState(String json) {
        return ExitFyDashboardState.parse(json);
    }

    @Override
    protected void renderUiState(ExitFyDashboardState next) {
        if (next == null) return;
        int previousProvider = state.providerId;
        state = next;
        if (providerRow == null) return;

        boolean pagePresentationChanged = false;
        if (previousProvider != next.providerId) {
            offset = 0;
            page = ExitFyServerPage.INVALID;
            pageDirty = true;
            pagePresentationChanged = true;
        }
        String fingerprint = stateFingerprint(next);
        if (!fingerprint.equals(observedFingerprint)) {
            observedFingerprint = fingerprint;
            pageDirty = true;
            pagePresentationChanged = true;
        }

        providerRow.setValue(next.runtimeAvailable
                ? next.providerName()
                : I18n.t("Runtime недоступен", "Runtime unavailable"));
        searchRow.setValue(query.isEmpty()
                ? I18n.t("Без фильтра", "No filter") : query);
        protocolRow.setValue(protocolLabel(protocol));
        refreshRow.setValue(next.refreshRunning
                ? I18n.t("Обновление…", "Refreshing…")
                : I18n.t("Готово к обновлению", "Ready to refresh"));
        pingRow.setValue(next.pingRunning
                ? I18n.format("Проверено %s", "Checked %s",
                next.pingProgress().isEmpty() ? "0/0" : next.pingProgress())
                : I18n.t("Проверить видимые серверы", "Check visible servers"));
        referralRow.setValue(next.providerName());
        addNodeRow.setValue(I18n.t("Пользовательский источник", "Custom source"));
        addSubscriptionRow.setValue(next.customUrlCount + " "
                + I18n.t("сохранено", "saved"));
        clearNodesRow.setValue(I18n.t(
                "Все источники", "All sources"));

        boolean customProvider =
                next.providerId == SettingsModel.CUSTOM_PROVIDER_ID;
        customSourcesLabel.setVisibility(customProvider ? View.VISIBLE : View.GONE);
        customSourcesContainer.setVisibility(customProvider
                ? View.VISIBLE : View.GONE);
        referralRow.view.setVisibility(customProvider ? View.GONE : View.VISIBLE);

        // Ping progress may publish state four times per second. The compact
        // action value should update, but rebuilding up to 306 generated rows
        // is only necessary when the actual page becomes dirty or completes.
        if (pagePresentationChanged) renderPage();
        updateRowsEnabled();
        maybeLoadPage();
    }

    @Override
    protected void onCommandBusyChanged(boolean busy) {
        commandBusy = busy;
        updateRowsEnabled();
    }

    private void updateRowsEnabled() {
        if (providerRow == null) return;
        boolean ready = state.runtimeAvailable && !commandBusy;
        String pagePosition = page.valid && !pageDirty && !pageRequestInFlight
                ? pagePositionLabel(page)
                : "—";
        previousPageRow.setValue(pagePosition);
        nextPageRow.setValue(pagePosition);
        providerRow.setEnabled(ready);
        searchRow.setEnabled(ready);
        protocolRow.setEnabled(ready);
        refreshRow.setEnabled(ready && !state.refreshRunning
                && !state.importRunning);
        pingRow.setEnabled(ready && (state.pingRunning
                || page.valid && !page.nodes.isEmpty()));
        referralRow.setEnabled(ready
                && state.providerId != SettingsModel.CUSTOM_PROVIDER_ID);
        addNodeRow.setEnabled(ready);
        addSubscriptionRow.setEnabled(ready);
        clearNodesRow.setEnabled(ready);
        pageStatusRow.setEnabled(ready && !pageRequestInFlight);
        previousPageRow.setEnabled(ready && page.valid && page.hasPrevious);
        nextPageRow.setEnabled(ready && page.valid && page.hasNext);
        for (SettingRow row : nodeRows) row.setEnabled(ready);
        for (SettingRow row : customSourceRows) row.setEnabled(ready);
    }

    private void showProviderDialog() {
        // Built from the catalog itself: a hard-coded list silently drifts when
        // the order changes, and an entry whose position no longer matches its
        // name selects a different provider than the one that was tapped.
        int count = SettingsModel.CUSTOM_PROVIDER_ID + 1;
        CharSequence[] labels = new CharSequence[count];
        boolean[] available = new boolean[count];
        for (int index = 0; index < count; index++) {
            labels[index] = ExitFyDashboardState.providerName(index);
            available[index] = state.providerAvailable(index);
        }
        showChoiceDialog(I18n.t("Провайдер", "Provider"), labels,
                state.providerId, available, index -> {
                    if (index < 0 || index >= available.length
                            || !available[index] || index == state.providerId) {
                        return;
                    }
                    offset = 0;
                    pageDirty = true;
                    setSetting("provider_id", index);
                });
    }

    private void showSearchDialog() {
        showTextInputDialog(
                I18n.t("Поиск серверов", "Search servers"),
                I18n.t("Поиск выполняется по имени сервера и источника.",
                        "Search uses the server and source names."),
                I18n.t("Имя или источник", "Name or source"),
                I18n.t("Найти", "Search"),
                query.isEmpty() ? null : I18n.t("Очистить", "Clear"),
                SubscriptionManager.MAX_UI_QUERY_CODE_POINTS,
                false,
                this::applyQuery,
                query.isEmpty() ? null : () -> applyQuery(""));
    }

    private void applyQuery(String raw) {
        try {
            String safe = ExitFyDashboardState.safeLabel(
                    raw == null ? "" : raw, SubscriptionManager.MAX_UI_QUERY_CODE_POINTS, "");
            String normalized = SubscriptionManager.requireUiQuery(safe);
            if (normalized.equals(query)) return;
            query = normalized;
            offset = 0;
            markPageDirty();
        } catch (Throwable error) {
            String message = ErrorSanitizer.clean(error.getMessage());
            showToast(TextUtils.isEmpty(message)
                    ? I18n.t("Некорректный поисковый запрос",
                    "Invalid search query") : message, false);
        }
    }

    private void showProtocolDialog() {
        CharSequence[] labels = {
                I18n.t("Все протоколы", "All protocols"),
                "VLESS",
                "VMess",
                "Trojan",
                "Shadowsocks",
                "Hysteria",
                "Hysteria 2",
                "TUIC",
        };
        showChoiceDialog(I18n.t("Протокол", "Protocol"), labels,
                indexOf(PROTOCOL_VALUES, protocol), index -> {
                    if (index < 0 || index >= PROTOCOL_VALUES.length) return;
                    String next = PROTOCOL_VALUES[index];
                    if (next.equals(protocol)) return;
                    protocol = next;
                    offset = 0;
                    markPageDirty();
                });
    }

    private void reloadPage() {
        markPageDirty();
    }

    private void markPageDirty() {
        pageDirty = true;
        renderPage();
        updateRowsEnabled();
        maybeLoadPage();
    }

    private void maybeLoadPage() {
        if (!pageDirty || pageRequestInFlight || commandBusy
                || !state.runtimeAvailable) {
            return;
        }
        final int requestedProvider = state.providerId;
        final int requestedOffset = offset;
        final String requestedQuery = query;
        final String requestedProtocol = protocol;
        final String requestedFingerprint = observedFingerprint;

        pageRequestInFlight = true;
        updateRowsEnabled();
        executeCommand(() -> new JSONObject()
                        .put("command", "list_nodes")
                        .put("offset", requestedOffset)
                        .put("limit", pageSize)
                        .put("query", requestedQuery)
                        .put("protocol", requestedProtocol),
                false, result -> {
                    pageRequestInFlight = false;
                    if (!result.ok) {
                        page = ExitFyServerPage.INVALID;
                        pageDirty = state.providerId != requestedProvider
                                || offset != requestedOffset
                                || !requestedQuery.equals(query)
                                || !requestedProtocol.equals(protocol)
                                || !requestedFingerprint.equals(observedFingerprint);
                        renderPage();
                        updateRowsEnabled();
                        if (pageDirty) {
                            if (state.providerId != requestedProvider) {
                                requestStateRefresh();
                            } else {
                                maybeLoadPage();
                            }
                        }
                        return;
                    }
                    ExitFyServerPage parsed = ExitFyServerPage.parse(result);
                    boolean localRequestStillCurrent =
                            state.providerId == requestedProvider
                                    && offset == requestedOffset
                                    && requestedQuery.equals(query)
                                    && requestedProtocol.equals(protocol);
                    if (parsed.valid && !localRequestStillCurrent) {
                        // A still-open filter dialog can change local state
                        // while the previous read-only query finishes.
                        page = ExitFyServerPage.INVALID;
                        pageDirty = true;
                        renderPage();
                        updateRowsEnabled();
                        maybeLoadPage();
                        return;
                    }
                    boolean matchingRequest = parsed.valid
                            && parsed.providerId == requestedProvider
                            && state.providerId == requestedProvider
                            && requestedQuery.equals(parsed.query)
                            && requestedProtocol.equals(parsed.protocol);
                    if (!matchingRequest) {
                        page = ExitFyServerPage.INVALID;
                        if (parsed.valid
                                && parsed.providerId != requestedProvider) {
                            // The provider changed while the read-only page
                            // query was in flight. Refresh state and retry
                            // silently under the authoritative provider id.
                            pageDirty = true;
                            renderPage();
                            updateRowsEnabled();
                            requestStateRefresh();
                            return;
                        }
                        pageDirty = false;
                        showToast(I18n.t(
                                "Runtime вернул некорректную страницу серверов",
                                "Runtime returned an invalid server page"), false);
                    } else {
                        if (parsed.total > 0 && parsed.nodes.isEmpty()
                                && parsed.offset >= parsed.total) {
                            // Deleting or refreshing the last page can shrink
                            // the result set below its old offset. Rewind to
                            // the new last page instead of showing “21–20”.
                            offset = ((parsed.total - 1) / parsed.limit)
                                    * parsed.limit;
                            page = ExitFyServerPage.INVALID;
                            pageDirty = true;
                            renderPage();
                            updateRowsEnabled();
                            maybeLoadPage();
                            return;
                        }
                        page = parsed;
                        offset = parsed.offset;
                        pageDirty = !requestedFingerprint.equals(observedFingerprint);
                    }
                    renderPage();
                    updateRowsEnabled();
                    maybeLoadPage();
                });
    }

    private void renderPage() {
        if (nodesContainer == null || customSourcesContainer == null) return;
        nodeRows.clear();
        customSourceRows.clear();
        clearDynamicViews(nodesContainer);
        clearDynamicViews(customSourcesContainer);
        boolean showCustomSources =
                state.providerId == SettingsModel.CUSTOM_PROVIDER_ID;

        if (!state.runtimeAvailable) {
            pageStatusRow.setValue(I18n.t(
                    "Runtime недоступен", "Runtime unavailable"));
            addEmptyCard(nodesContainer, I18n.t(
                    "Запустите plugin runtime, чтобы открыть список серверов.",
                    "Start the plugin runtime to open the server list."));
            if (showCustomSources) {
                addEmptyCard(customSourcesContainer, I18n.t(
                        "Runtime недоступен", "Runtime unavailable"));
            }
            return;
        }
        if (pageRequestInFlight || pageDirty) {
            pageStatusRow.setValue(I18n.t("Загрузка…", "Loading…"));
            addEmptyCard(nodesContainer, I18n.t(
                    "Загружаем серверы…", "Loading servers…"));
            if (showCustomSources) {
                addEmptyCard(customSourcesContainer, I18n.t(
                        "Загружаем подписки…", "Loading subscriptions…"));
            }
            return;
        }
        if (!page.valid) {
            pageStatusRow.setValue(I18n.t(
                    "Не удалось загрузить", "Could not load"));
            addEmptyCard(nodesContainer, I18n.t(
                    "Нажмите «Список серверов», чтобы повторить.",
                    "Tap “Server list” to retry."));
            if (showCustomSources) {
                addEmptyCard(customSourcesContainer, I18n.t(
                        "Список подписок не загружен",
                        "Subscription list was not loaded"));
            }
            return;
        }

        pageStatusRow.setValue(pageRangeLabel(page));
        Context context = getParentActivity();
        if (context == null) return;
        if (page.nodes.isEmpty()) {
            addEmptyCard(nodesContainer, page.unfilteredTotal == 0
                    ? I18n.t(
                    "У этого источника пока нет серверов.",
                    "This source does not have any servers yet.")
                    : I18n.t(
                    "По выбранным фильтрам серверы не найдены.",
                    "No servers match the selected filters."));
        } else {
            for (ExitFyServerPage.Node node : page.nodes) {
                SettingRow row = createNodeRow(context, node);
                nodeRows.add(row);
                nodesContainer.addView(row.view, sectionParams());
            }
        }

        if (!showCustomSources) return;
        if (page.customSources.isEmpty()) {
            addEmptyCard(customSourcesContainer, I18n.t(
                    "Сохранённых подписок нет.",
                    "There are no saved subscriptions."));
        } else {
            for (ExitFyServerPage.CustomSource source : page.customSources) {
                SettingRow row = settingRow(context, R.drawable.msg_download,
                        TextUtils.isEmpty(source.title)
                                ? I18n.t("Подписка", "Subscription") : source.title,
                        I18n.t("Нажмите, чтобы удалить подписку",
                                "Tap to remove this subscription"));
                row.setValue(source.nodeCount > 0
                        ? I18n.t("Серверов: ", "Servers: ") + source.nodeCount
                        : I18n.t("Серверов нет", "No servers"));
                setSafeClick(row.view, () -> confirmDeleteSubscription(source));
                customSourceRows.add(row);
                customSourcesContainer.addView(row.view, sectionParams());
            }
        }
    }

    private SettingRow createNodeRow(Context context, ExitFyServerPage.Node node) {
        String title = TextUtils.isEmpty(node.name)
                ? I18n.t("Сервер без названия", "Unnamed server") : node.name;
        String summary = nodeSummary(node);
        SettingRow row = settingRow(context, R.drawable.msg_folders,
                title, summary);
        boolean selected = node.key.equals(page.selectedKey);
        String status = pingLabel(node);
        row.setValue(selected
                ? I18n.t("✓ Выбран", "✓ Selected")
                + (TextUtils.isEmpty(status) ? "" : " · " + status)
                : status);
        setSafeClick(row.view, () -> showNodeDialog(node));
        return row;
    }

    private void addEmptyCard(LinearLayout container, CharSequence message) {
        Context context = getParentActivity();
        if (context == null || container == null) return;
        LinearLayout value = card(context, false);
        TextView text = text(context, 14,
                Theme.key_windowBackgroundWhiteGrayText2, false);
        text.setText(message);
        text.setGravity(Gravity.CENTER);
        text.setPadding(dp(4), dp(8), dp(4), dp(8));
        value.addView(text, matchWrap());
        container.addView(value, sectionParams());
    }

    private void showNodeDialog(ExitFyServerPage.Node node) {
        Context context = getParentActivity();
        if (context == null || node == null) return;
        boolean selected = node.key.equals(page.selectedKey);
        AlertDialog.Builder builder = new AlertDialog.Builder(
                context, getResourceProvider())
                .setTitle(TextUtils.isEmpty(node.name)
                        ? I18n.t("Сервер", "Server") : node.name)
                .setMessage(nodeDetails(node))
                .setNegativeButton(I18n.t("Закрыть", "Close"), null);
        if (!selected) {
            builder.setPositiveButton(I18n.t("Выбрать", "Select"),
                    (ignored, which) -> runUiAction(() -> selectNode(node)));
        }
        if (node.manual) {
            builder.setNeutralButton(I18n.t("Удалить", "Delete"),
                    (ignored, which) -> runUiAction(
                            () -> confirmDeleteManualNode(node)));
        }
        showDialog(builder.create());
    }

    private void selectNode(ExitFyServerPage.Node node) {
        runMutation(() -> new JSONObject()
                .put("command", "select_node")
                .put("key", node.key));
    }

    private void confirmDeleteManualNode(ExitFyServerPage.Node node) {
        confirm(
                I18n.t("Удалить сервер?", "Delete server?"),
                I18n.t(
                        "Ручной ключ будет удалён без возможности восстановления.",
                        "The manual key will be removed and cannot be restored."),
                I18n.t("Удалить", "Delete"),
                () -> runMutation(() -> new JSONObject()
                        .put("command", "delete_manual_node")
                        .put("key", node.key)));
    }

    private void confirmDeleteSubscription(ExitFyServerPage.CustomSource source) {
        confirm(
                I18n.t("Удалить подписку?", "Delete subscription?"),
                I18n.t(
                        "Ссылка и загруженные из неё серверы будут удалены.",
                        "The URL and servers loaded from it will be removed."),
                I18n.t("Удалить", "Delete"),
                () -> runMutation(() -> new JSONObject()
                        .put("command", "delete_subscription")
                        .put("id", source.id)));
    }

    private void showAddNodeDialog() {
        showTextInputDialog(
                I18n.t("Добавить ключ сервера", "Add server key"),
                I18n.t(
                        "После добавления exitFy автоматически переключится на пользовательский источник.",
                        "After adding, exitFy automatically switches to the Custom source."),
                I18n.t("vless://, vmess://, trojan://…",
                        "vless://, vmess://, trojan://…"),
                I18n.t("Добавить", "Add"),
                null,
                ProtocolParser.MAX_URI_BYTES,
                false,
                uri -> runMutation(() -> new JSONObject()
                        .put("command", "add_node")
                        .put("uri", uri)),
                null);
    }

    private void showAddSubscriptionDialog() {
        showTextInputDialog(
                I18n.t("Добавить подписку", "Add subscription"),
                I18n.t(
                        "Поддерживаются только HTTP- и HTTPS-ссылки. После добавления exitFy переключится на пользовательский источник.",
                        "Only HTTP and HTTPS URLs are accepted. After adding, exitFy switches to the Custom source."),
                "https://",
                I18n.t("Добавить", "Add"),
                null,
                MAX_SUBSCRIPTION_CHARS,
                false,
                url -> runMutation(() -> new JSONObject()
                        .put("command", "add_subscription")
                        .put("url", url)),
                null);
    }

    private void confirmClearNodes() {
        confirm(
                I18n.t("Очистить серверы?", "Clear servers?"),
                I18n.t(
                        "Все загруженные и ручные серверы будут удалены. Ссылки подписок сохранятся, а подключение exitFy выключится.",
                        "All loaded and manual servers will be removed. Subscription URLs stay saved, and the exitFy connection will be disabled."),
                I18n.t("Очистить", "Clear"),
                () -> runMutation(() -> new JSONObject()
                        .put("command", "clear_nodes")));
    }

    private void refreshSubscriptions() {
        runMutation(() -> new JSONObject()
                .put("command", "refresh_subscriptions"));
    }

    private void onPingClicked() {
        if (state.pingRunning) {
            runMutation(() -> new JSONObject().put("command", "cancel_ping"));
            return;
        }
        List<String> keys = pageKeysSnapshot();
        String expectedPingType = state.pingType;
        if (keys.isEmpty()) {
            showToast(I18n.t(
                    "На странице нет серверов для проверки",
                    "There are no servers to check on this page"), false);
            return;
        }
        if (SettingsModel.PING_PROXY_GET.equals(state.pingType)) {
            confirm(
                    I18n.t("Проверить задержку?", "Check latency?"),
                    I18n.t(
                            "Подключение будет временно приостановлено. exitFy проверит весь путь подключения, затем восстановит выбранный сервер.",
                            "The connection will pause temporarily. exitFy will check the complete connection path, then restore the selected server."),
                    I18n.t("Проверить", "Check"),
                    () -> runPagePing(keys, expectedPingType));
        } else {
            runPagePing(keys, expectedPingType);
        }
    }

    private String pageSizeSummary() {
        return I18n.t("До ", "Up to ") + pageSize
                + I18n.t(" серверов на странице", " servers per page");
    }

    private void showPageSizeDialog() {
        CharSequence[] labels = new CharSequence[PAGE_SIZES.length];
        int selected = 0;
        for (int index = 0; index < PAGE_SIZES.length; index++) {
            labels[index] = String.valueOf(PAGE_SIZES[index]);
            if (PAGE_SIZES[index] == pageSize) selected = index;
        }
        showChoiceDialog(I18n.t("Серверов на странице", "Servers per page"),
                labels, selected, index -> {
                    if (index < 0 || index >= PAGE_SIZES.length) return;
                    if (PAGE_SIZES[index] == pageSize) return;
                    pageSize = PAGE_SIZES[index];
                    offset = 0;
                    if (pageSizeRow != null) {
                        pageSizeRow.setValue(String.valueOf(pageSize));
                    }
                    reloadPage();
                });
    }

    private List<String> pageKeysSnapshot() {
        ArrayList<String> keys = new ArrayList<>();
        if (!page.valid) return keys;
        for (ExitFyServerPage.Node node : page.nodes) {
            // Probing is capped independently of how much the page shows.
            if (keys.size() >= SubscriptionManager.MAX_PING_KEYS) break;
            keys.add(node.key);
        }
        return keys;
    }

    private void runPagePing(List<String> snapshot, String expectedPingType) {
        final JSONArray keys = new JSONArray();
        if (snapshot != null) {
            for (String key : snapshot) keys.put(key);
        }
        if (keys.length() == 0 || keys.length() > SubscriptionManager.MAX_PING_KEYS) return;
        runMutation(() -> new JSONObject()
                .put("command", "ping_nodes")
                .put("keys", keys)
                .put("expected_ping_type", expectedPingType));
    }

    private void goToPreviousPage() {
        if (!page.valid || !page.hasPrevious) return;
        offset = Math.max(0, page.offset - page.limit);
        markPageDirty();
    }

    private void goToNextPage() {
        if (!page.valid || !page.hasNext) return;
        offset = Math.min(SubscriptionManager.MAX_TOTAL_NODES,
                page.offset + page.nodes.size());
        markPageDirty();
    }

    private void runMutation(CommandFactory command) {
        executeCommand(command, true, result -> {
            if (!result.ok) return;
            // Mutations such as add_node may also switch the provider. Wait
            // for the authoritative runtime state before asking for a page,
            // otherwise the old provider id could label a page from the new
            // source during the short bridge round-trip.
            pageDirty = true;
            renderPage();
            updateRowsEnabled();
            requestStateRefresh();
        });
    }

    private void openProviderReferral() {
        if (state.providerId == SettingsModel.CUSTOM_PROVIDER_ID) return;
        executeCommand(() -> new JSONObject()
                        .put("command", "provider_referral"),
                false, result -> {
                    if (result.ok) openValidatedReferral(result.data);
                });
    }

    private void openValidatedReferral(String value) {
        Context context = getParentActivity();
        if (context == null) return;
        if (!openValidatedUrl(context, value)) {
            showToast(I18n.t(
                    "Не удалось открыть страницу провайдера",
                    "Could not open the provider page"), false);
        }
    }

    /**
     * Opens a provider page only when the runtime returned a web or Telegram
     * link. The value crosses the bridge as text, so it is re-validated here
     * rather than trusted because of where it came from.
     */
    static boolean openValidatedUrl(Context context, String value) {
        try {
            String raw = value == null ? "" : value.trim();
            if (raw.length() == 0 || raw.length() > 2048) {
                throw new IllegalArgumentException("invalid referral");
            }
            URI parsed = new URI(raw);
            String scheme = parsed.getScheme() == null
                    ? "" : parsed.getScheme().toLowerCase(Locale.ROOT);
            boolean web = ("http".equals(scheme) || "https".equals(scheme))
                    && parsed.getHost() != null && !parsed.getHost().isEmpty();
            boolean telegram = "tg".equals(scheme)
                    && parsed.getRawSchemeSpecificPart() != null
                    && !parsed.getRawSchemeSpecificPart().isEmpty();
            if (!web && !telegram) {
                throw new IllegalArgumentException("invalid referral");
            }
            openExternalUrl(context, raw);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Hands the link to Telegram's own opener, which keeps t.me targets inside
     * the app and honours the user's browser preference. A direct view intent
     * is only the fallback for a host that does not expose it.
     */
    private static void openExternalUrl(Context context, String url) {
        try {
            Class<?> browser = Class.forName("org.telegram.messenger.browser.Browser");
            browser.getMethod("openUrl", Context.class, String.class)
                    .invoke(null, context, url);
            return;
        } catch (Throwable ignored) {
            // Fall through to the platform intent below.
        }
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
        if (!(context instanceof Activity)) {
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        }
        context.startActivity(intent);
    }

    private void confirm(CharSequence title, CharSequence message,
                         CharSequence positive, Runnable action) {
        Context context = getParentActivity();
        if (context == null) return;
        AlertDialog dialog = new AlertDialog.Builder(context, getResourceProvider())
                .setTitle(title)
                .setMessage(message)
                .setNegativeButton(I18n.t("Отмена", "Cancel"), null)
                .setPositiveButton(positive,
                        (ignored, which) -> runUiAction(action))
                .create();
        showDialog(dialog);
    }

    private String nodeDetails(ExitFyServerPage.Node node) {
        StringBuilder value = new StringBuilder();
        appendDetail(value, I18n.t("Источник", "Source"),
                TextUtils.isEmpty(node.group)
                        ? I18n.t("Без названия", "Unnamed") : node.group);
        appendDetail(value, I18n.t("Протокол", "Protocol"),
                node.protocol.toUpperCase(Locale.ROOT));
        if (!TextUtils.isEmpty(node.transport)) {
            appendDetail(value, I18n.t("Транспорт", "Transport"),
                    node.transport);
        }
        if (!TextUtils.isEmpty(node.security)
                && !"none".equals(node.security)) {
            appendDetail(value, I18n.t("Защита", "Security"), node.security);
        }
        appendDetail(value, I18n.t("Задержка", "Latency"), pingLabel(node));
        appendDetail(value, I18n.t("Тип", "Type"), node.manual
                ? I18n.t("Ручной ключ", "Manual key")
                : I18n.t("Из подписки", "From subscription"));
        return value.toString();
    }

    private static void appendDetail(StringBuilder output,
                                     CharSequence label, CharSequence value) {
        if (output.length() > 0) output.append('\n');
        output.append(label).append(": ").append(value);
    }

    private static String nodeSummary(ExitFyServerPage.Node node) {
        StringBuilder value = new StringBuilder();
        if (!TextUtils.isEmpty(node.group)) value.append(node.group);
        appendToken(value, node.protocol.toUpperCase(Locale.ROOT));
        appendToken(value, node.transport);
        if (!"none".equals(node.security)) appendToken(value, node.security);
        return value.length() == 0 ? "—" : value.toString();
    }

    private static void appendToken(StringBuilder output, String value) {
        if (TextUtils.isEmpty(value)) return;
        if (output.length() > 0) output.append(" · ");
        output.append(value);
    }

    private static String pingLabel(ExitFyServerPage.Node node) {
        if (node.latency >= 0) {
            return node.latency + " " + I18n.t("мс", "ms");
        }
        if ("pending".equals(node.pingStatus)) {
            return I18n.t("Проверяется…", "Checking…");
        }
        if ("cancelled".equals(node.pingStatus)) {
            return I18n.t("Проверка отменена", "Check cancelled");
        }
        if ("restart_required".equals(node.pingStatus)) {
            return I18n.t("Недоступен", "Unavailable");
        }
        if ("connect_required".equals(node.pingStatus)) {
            return I18n.t(
                    "Сначала подключитесь",
                    "Connect first");
        }
        if ("tcp_failed_quic".equals(node.pingStatus)) {
            return I18n.t(
                    "TCP-проверка неприменима",
                    "TCP check not applicable");
        }
        if (!"idle".equals(node.pingStatus)
                && !"ok".equals(node.pingStatus)) {
            return I18n.t("Нет ответа", "No response");
        }
        return I18n.t("Не проверен", "Not checked");
    }

    private static String pageRangeLabel(ExitFyServerPage value) {
        if (value.total == 0) {
            return "0 " + I18n.t("серверов", "servers");
        }
        int first = value.offset + 1;
        int last = value.offset + value.nodes.size();
        String filtered = first + "–" + last + " "
                + I18n.t("из", "of") + " " + value.total;
        if (value.total != value.unfilteredTotal) {
            filtered += " · " + value.unfilteredTotal + " "
                    + I18n.t("всего", "total");
        }
        return filtered;
    }

    private static String pagePositionLabel(ExitFyServerPage value) {
        int pages = Math.max(1, (value.total + value.limit - 1) / value.limit);
        int current = value.total == 0 ? 1 : value.offset / value.limit + 1;
        return I18n.format("Страница %s из %s", "Page %s of %s",
                Math.min(current, pages), pages);
    }

    private static String stateFingerprint(ExitFyDashboardState value) {
        return value.runtimeAvailable + "|" + value.providerId + "|"
                + value.serverCount + "|" + value.customUrlCount + "|"
                + value.activeKey + "|" + value.refreshRunning + "|"
                + value.importRunning + "|" + value.pingRunning;
    }

    private static int indexOf(String[] values, String expected) {
        for (int index = 0; index < values.length; index++) {
            if (values[index].equals(expected)) return index;
        }
        return 0;
    }

    private static String protocolLabel(String value) {
        if ("all".equals(value)) return I18n.t("Все протоколы", "All protocols");
        if ("shadowsocks".equals(value)) return "Shadowsocks";
        if ("hysteria2".equals(value)) return "Hysteria 2";
        if ("vmess".equals(value)) return "VMess";
        return value.toUpperCase(Locale.ROOT);
    }

}
