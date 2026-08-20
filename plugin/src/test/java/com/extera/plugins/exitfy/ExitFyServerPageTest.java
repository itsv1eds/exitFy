package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.util.Collections;
import java.util.Locale;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ExitFyServerPageTest {
    @Test
    public void parsesEveryNodeSourcePaginationAndFilterField() throws Exception {
        String firstKey = key(1);
        String secondKey = key(2);
        JSONArray nodes = new JSONArray()
                .put(node(firstKey, "Frankfurt", false)
                        .put("group", "Premium")
                        .put("protocol", "vless")
                        .put("transport", "ws")
                        .put("security", "reality")
                        .put("latency", 84)
                        .put("pingStatus", "ok"))
                .put(node(secondKey, "Tokyo", true)
                        .put("group", "Manual")
                        .put("protocol", "trojan")
                        .put("transport", "tcp")
                        .put("security", "tls")
                        .put("latency", -1)
                        .put("pingStatus", "pending"));
        JSONArray sources = new JSONArray().put(new JSONObject()
                .put("id", "source-1").put("title", "Personal"));

        ExitFyServerPage page = ExitFyServerPage.parse(page(
                nodes, sources, 0, 50, 2, 3,
                false, false, secondKey, "fr", "vless").toString());

        assertTrue(page.valid);
        assertEquals(2, page.nodes.size());
        assertEquals(1, page.customSources.size());
        assertEquals(SettingsModel.CUSTOM_PROVIDER_ID, page.providerId);
        ExitFyServerPage.Node first = page.nodes.get(0);
        assertEquals(firstKey, first.key);
        assertEquals("Frankfurt", first.name);
        assertEquals("Premium", first.group);
        assertFalse(first.manual);
        assertEquals("vless", first.protocol);
        assertEquals("ws", first.transport);
        assertEquals("reality", first.security);
        assertEquals(84L, first.latency);
        assertEquals("ok", first.pingStatus);
        assertEquals("source-1", page.customSources.get(0).id);
        assertEquals("Personal", page.customSources.get(0).title);
        assertEquals(0, page.offset);
        assertEquals(50, page.limit);
        assertEquals(2, page.total);
        assertEquals(3, page.unfilteredTotal);
        assertFalse(page.hasPrevious);
        assertFalse(page.hasNext);
        assertEquals(secondKey, page.selectedKey);
        assertEquals("fr", page.query);
        assertEquals("vless", page.protocol);
        JSONObject compact = page(nodes, sources, 0, 50, 2, 3,
                false, false, secondKey, "fr", "vless");
        assertFalse(compact.has("compatibility"));
        assertFalse(compact.getJSONArray("nodes").getJSONObject(0)
                .has("supportsSingBox"));
        assertFalse(compact.getJSONArray("nodes").getJSONObject(0)
                .has("supportsXray"));
    }

    @Test
    public void acceptsExactlyFiftyNodesAndRejectsFiftyOne() throws Exception {
        JSONArray fifty = nodes(50);
        ExitFyServerPage accepted = ExitFyServerPage.parse(page(
                fifty, new JSONArray(), 0, 50, 50, 50,
                false, false, "", "", "all").toString());
        assertTrue(accepted.valid);
        assertEquals(50, accepted.nodes.size());

        JSONArray fiftyOne = nodes(51);
        ExitFyServerPage rejected = ExitFyServerPage.parse(page(
                fiftyOne, new JSONArray(), 0, 50, 51, 51,
                false, false, "", "", "all").toString());
        assertFalse(rejected.valid);
        assertTrue(rejected.nodes.isEmpty());
    }

    @Test
    public void supportsAllCustomSubscriptionRowsWithinRuntimeLimit() throws Exception {
        JSONArray sources = new JSONArray();
        for (int index = 0; index < SubscriptionManager.MAX_CUSTOM_URLS; index++) {
            sources.put(new JSONObject()
                    .put("id", "source-" + index)
                    .put("title", "Subscription " + index));
        }
        ExitFyServerPage accepted = ExitFyServerPage.parse(page(
                new JSONArray(), sources, 0, 50, 0, 0,
                false, false, "", "", "all").toString());
        assertTrue(accepted.valid);
        assertEquals(SubscriptionManager.MAX_CUSTOM_URLS,
                accepted.customSources.size());

        sources.put(new JSONObject().put("id", "overflow").put("title", "Overflow"));
        ExitFyServerPage rejected = ExitFyServerPage.parse(page(
                new JSONArray(), sources, 0, 50, 0, 0,
                false, false, "", "", "all").toString());
        assertFalse(rejected.valid);
    }

    @Test
    public void listsAreImmutable() throws Exception {
        ExitFyServerPage page = ExitFyServerPage.parse(page(
                nodes(1), new JSONArray(), 0, 50, 1, 1,
                false, false, "", "", "all").toString());
        assertTrue(page.valid);
        try {
            page.nodes.addAll(Collections.singletonList(page.nodes.get(0)));
            throw new AssertionError("node list was mutable");
        } catch (UnsupportedOperationException expected) {
        }
        try {
            page.customSources.clear();
            throw new AssertionError("source list was mutable");
        } catch (UnsupportedOperationException expected) {
        }
    }

    @Test
    public void malformedShapeTypesAndDuplicateIdsFailClosed() throws Exception {
        JSONObject wrongNodes = page(new JSONArray(), new JSONArray(),
                0, 50, 0, 0, false, false, "", "", "all")
                .put("nodes", "not-an-array");
        JSONObject fractionalOffset = page(new JSONArray(), new JSONArray(),
                0, 50, 0, 0, false, false, "", "", "all")
                .put("offset", 0.5d);
        JSONObject shortNodeKey = page(
                new JSONArray().put(node("short", "Invalid", false)),
                new JSONArray(), 0, 50, 1, 1,
                false, false, "", "", "all");
        JSONObject shortSelectedKey = page(
                new JSONArray(), new JSONArray(), 0, 50, 0, 0,
                false, false, "short", "", "all");
        JSONArray duplicateNodes = new JSONArray()
                .put(node(key(7), "First", false))
                .put(node(key(7), "Second", false));
        JSONArray duplicateSources = new JSONArray()
                .put(new JSONObject().put("id", "same").put("title", "First"))
                .put(new JSONObject().put("id", "same").put("title", "Second"));
        String[] invalid = {
                null,
                "",
                "{",
                "{}",
                wrongNodes.toString(),
                fractionalOffset.toString(),
                shortNodeKey.toString(),
                shortSelectedKey.toString(),
                page(duplicateNodes, new JSONArray(), 0, 50, 2, 2,
                        false, false, "", "", "all").toString(),
                page(new JSONArray(), duplicateSources, 0, 50, 0, 0,
                        false, false, "", "", "all").toString(),
        };
        for (String value : invalid) {
            assertFalse(ExitFyServerPage.parse(value).valid);
        }
    }

    @Test
    public void invalidPaginationAndFiltersFailClosed() throws Exception {
        JSONObject wrongPrevious = page(
                new JSONArray(), new JSONArray(), 0, 50, 0, 0,
                true, false, "", "", "all");
        JSONObject wrongNext = page(
                nodes(1), new JSONArray(), 0, 1, 2, 2,
                false, false, "", "", "all");
        JSONObject impossibleTotal = page(
                nodes(1), new JSONArray(), 0, 50, 1, 0,
                false, false, "", "", "all");
        JSONObject invalidProtocol = page(
                new JSONArray(), new JSONArray(), 0, 50, 0, 0,
                false, false, "", "", "ftp");
        JSONObject invalidProvider = page(
                new JSONArray(), new JSONArray(), 0, 50, 0, 0,
                false, false, "", "", "all")
                .put("providerId", SettingsModel.CUSTOM_PROVIDER_ID + 1);

        for (JSONObject value : new JSONObject[]{
                wrongPrevious, wrongNext, impossibleTotal,
                invalidProtocol, invalidProvider}) {
            assertFalse(ExitFyServerPage.parse(value.toString()).valid);
        }
    }

    @Test
    public void displayLabelsAreSanitizedButIdentityFieldsMustBeExact() throws Exception {
        String safeKey = key(8);
        JSONObject unsafeNode = node(safeKey, "vless://secret@example.invalid", false)
                .put("group", "Group\u202eName");
        ExitFyServerPage sanitized = ExitFyServerPage.parse(page(
                new JSONArray().put(unsafeNode),
                new JSONArray().put(new JSONObject()
                        .put("id", "safe-source")
                        .put("title", "https://secret.invalid/sub")),
                0, 50, 1, 1, false, false,
                safeKey, "", "all").toString());
        assertTrue(sanitized.valid);
        assertEquals("", sanitized.nodes.get(0).name);
        assertEquals("GroupName", sanitized.nodes.get(0).group);
        assertEquals("", sanitized.customSources.get(0).title);

        JSONObject unsafeIdentity = node(
                key(9).substring(0, 63) + "\u202e", "Name", false);
        assertFalse(ExitFyServerPage.parse(page(
                new JSONArray().put(unsafeIdentity), new JSONArray(),
                0, 50, 1, 1, false, false,
                "", "", "all").toString()).valid);
    }

    @Test
    public void parserAcceptsSuccessfulEnvelopeAndRejectsFailedEnvelope() throws Exception {
        String data = page(new JSONArray(), new JSONArray(),
                0, 50, 0, 0, false, false,
                "", "", "all").toString();
        assertTrue(ExitFyServerPage.parse(
                new ExitFyCommandResult(true, "", data)).valid);
        assertFalse(ExitFyServerPage.parse(
                new ExitFyCommandResult(false, "failed", data)).valid);
    }

    @Test
    public void oversizedDataFailsBeforeJsonObjectAllocation() throws Exception {
        JSONObject value = page(new JSONArray(), new JSONArray(),
                0, 50, 0, 0, false, false,
                "", "", "all");
        value.put("padding", repeated(
                'x', ExitFyCommandResult.MAX_DATA_UTF8_BYTES));

        ExitFyServerPage result = ExitFyServerPage.parse(value.toString());

        assertFalse(result.valid);
        assertTrue(result.nodes.isEmpty());
    }

    private static JSONObject page(JSONArray nodes, JSONArray sources,
                                   int offset, int limit, int total, int unfilteredTotal,
                                   boolean hasPrevious, boolean hasNext,
                                   String selectedKey, String query,
                                   String protocol) throws Exception {
        return new JSONObject()
                .put("providerId", SettingsModel.CUSTOM_PROVIDER_ID)
                .put("nodes", nodes)
                .put("customSources", sources)
                .put("offset", offset)
                .put("limit", limit)
                .put("total", total)
                .put("unfilteredTotal", unfilteredTotal)
                .put("hasPrevious", hasPrevious)
                .put("hasNext", hasNext)
                .put("selectedKey", selectedKey)
                .put("query", query)
                .put("protocol", protocol);
    }

    private static JSONArray nodes(int count) throws Exception {
        JSONArray values = new JSONArray();
        for (int index = 0; index < count; index++) {
            values.put(node(key(index + 1), "Node " + index, index % 2 == 0));
        }
        return values;
    }

    private static String key(int value) {
        return String.format(Locale.US, "%064x", value);
    }

    private static JSONObject node(String key, String name, boolean manual) throws Exception {
        return new JSONObject()
                .put("key", key)
                .put("name", name)
                .put("group", "")
                .put("manual", manual)
                .put("protocol", "vless")
                .put("transport", "tcp")
                .put("security", "tls")
                .put("latency", -1)
                .put("pingStatus", "idle");
    }

    private static String repeated(char value, int count) {
        StringBuilder output = new StringBuilder(count);
        for (int index = 0; index < count; index++) output.append(value);
        return output.toString();
    }
}
