package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.Closeable;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

class CoreUpdater {
    private static final String CORES_RELEASES_API =
            "https://api.github.com/repos/itsv1eds/exitFy/releases?per_page=100";
    private static final long CHECK_INTERVAL_MS = 24L * 60L * 60L * 1000L;
    private static final int MAX_CORE_BYTES = 64 * 1024 * 1024;
    private static final int MIN_CORE_BYTES = 1024 * 1024;
    private static final int MAX_MANIFEST_BYTES = 1024 * 1024;
    private static final int MAX_RELEASES_PER_PAGE = 100;
    private static final int MAX_RELEASE_PAGES = 10;
    private static final int MAX_RELEASE_BYTES_TOTAL = 32 * 1024 * 1024;
    private static final long MAX_SOURCE_BUNDLE_BYTES = 512L * 1024L * 1024L;
    private static final int CORE_API = 2;
    private static final int CONFIG_CONTRACT = 1;
    private static final int MANIFEST_SCHEMA = 3;
    private static final int MIN_ANDROID_API = 29;
    private static final String ANDROID_ABI = "arm64-v8a";
    private static final String CORE_ORIGIN = "itsv1eds/exitFy";
    // Release downloads are blocked outright on some networks. Every byte these
    // return is pinned by the SHA-256 the GitHub API already reported, so a
    // mirror cannot substitute content; it can only observe the request, which
    // is why they are tried after the direct URL and never before it.
    private static final String[] DOWNLOAD_MIRRORS = {
            "https://ghfast.top/",
            "https://gh-proxy.com/",
            "https://ghproxy.net/",
    };
    private static final String SB_NDK_VERSION = "27.2.12479018";
    private static final String[] SB_BUILD_TAGS = {
            "badlinkname", "tfogo_checklinkname0", "with_quic", "with_utls"
    };
    private static final ConcurrentHashMap<String, FamilyLocks> FAMILY_LOCKS =
            new ConcurrentHashMap<>();
    private static final UpdateObserver NOOP_OBSERVER = new UpdateObserver() {
        @Override
        public void onStage(UpdateStage stage) {
        }

        @Override
        public void onProgress(long downloadedBytes, long totalBytes) {
        }
    };

    private final AtomicStore store;
    private final LimitedHttpClient http;
    private final String abi;
    private final CoreFamily family;
    private final String releaseApi;
    private final ReentrantLock updateLock;
    private final ReentrantLock transactionLock;
    private final CommitHook commitHook;
    private final InspectionHook inspectionHook;
    private JSONObject metadata;
    private volatile ReadinessSnapshot readinessSnapshot;

    CoreUpdater(AtomicStore store, LimitedHttpClient http,
                String abi, CoreFamily family) throws Exception {
        this(store, http, abi, family, null);
    }

    CoreUpdater(AtomicStore store, LimitedHttpClient http,
                String abi, CoreFamily family, String releaseApi) throws Exception {
        this(store, http, abi, family, releaseApi, CommitHook.NOOP);
    }

    CoreUpdater(AtomicStore store, LimitedHttpClient http,
                String abi, CoreFamily family, String releaseApi,
                CommitHook commitHook) throws Exception {
        this(store, http, abi, family, releaseApi, commitHook, InspectionHook.NOOP);
    }

    CoreUpdater(AtomicStore store, LimitedHttpClient http,
                String abi, CoreFamily family, String releaseApi,
                CommitHook commitHook, InspectionHook inspectionHook) throws Exception {
        this.store = store;
        this.http = http;
        if (!ANDROID_ABI.equals(abi)) {
            throw new IllegalArgumentException("only arm64-v8a cores are supported");
        }
        this.abi = abi;
        this.family = family;
        this.releaseApi = releaseApi == null || releaseApi.trim().isEmpty()
                ? CORES_RELEASES_API : releaseApi.trim();
        String updateKey = store.child("core/" + family.id).getCanonicalPath();
        FamilyLocks locks = FAMILY_LOCKS.computeIfAbsent(updateKey,
                ignored -> new FamilyLocks());
        this.updateLock = locks.update;
        this.transactionLock = locks.transaction;
        this.commitHook = commitHook == null ? CommitHook.NOOP : commitHook;
        this.inspectionHook = inspectionHook == null ? InspectionHook.NOOP : inspectionHook;
        transactionLock.lock();
        try {
            reloadMetadata();
        } finally {
            transactionLock.unlock();
        }
    }

    CoreFamily family() {
        return family;
    }

    File prepareForFirstLoad() throws Exception {
        LoadTarget target = prepareLoadTarget();
        return target == null ? null : target.file;
    }

    LoadTarget prepareLoadTarget() throws Exception {
        for (int attempt = 0; attempt < 16; attempt++) {
            PrepareResult result = withInspectedState(state -> {
                if (metadata.optBoolean("rollbackRequested", false)) {
                    if (state.backup.valid) restoreBackup(state);
                    else discardRejectedActive();
                    return PrepareResult.retry();
                }
                // Never let a second pending release replace the last verified
                // rollback while the current active core is still awaiting its
                // first start/stop self-test. A process kill can leave exactly
                // this active-candidate + last-good-backup + newer-pending
                // state. Test the active candidate first; markStartSuccess()
                // removes the guard, while a failure takes the rollback branch
                // above before any later pending promotion.
                if (state.active.valid && metadata.optBoolean("candidate", false)) {
                    return PrepareResult.complete(new LoadTarget(
                            activeFile(), state.active.coreApi, state.active.digest));
                }
                if (state.pending.valid && pendingViolatesInstalledFloor(state)) {
                    discardPending("pending core is older than installed rollback floor");
                    return PrepareResult.retry();
                }
                if (!state.active.valid) {
                    if (state.pending.valid) {
                        promotePending(state, false);
                        return PrepareResult.retry();
                    }
                    return PrepareResult.complete(null);
                }
                if (state.pending.valid) {
                    promotePending(state, true);
                    return PrepareResult.retry();
                }
                return PrepareResult.complete(new LoadTarget(
                        activeFile(), state.active.coreApi, state.active.digest));
            }, true);
            if (!result.retry) return result.target;
        }
        throw new IllegalStateException("core preparation changed repeatedly");
    }

    /**
     * Pins the exact active inode that was digested and inspected.  The
     * returned descriptor must remain open until native loading has consumed
     * it; reopening {@link LoadTarget#file} would reintroduce a digest-to-load
     * race.
     */
    PinnedLoadTarget preparePinnedLoadTarget() throws Exception {
        for (int attempt = 0; attempt < 16; attempt++) {
            LoadTarget target = prepareLoadTarget();
            if (target == null) return null;
            if (!isDigest(target.digest)) {
                throw new IllegalStateException("core digest metadata is missing");
            }

            CoreFileHandle handle = CoreFileHandle.open(target.file);
            boolean retained = false;
            try {
                if (handle.length() < MIN_CORE_BYTES || handle.length() > MAX_CORE_BYTES) {
                    throw new IllegalStateException("core size is invalid");
                }
                CoreFileHandle.Verification verification = handle.verify(abi, target.digest);
                if (!verification.valid) {
                    throw new IllegalStateException(verification.error);
                }

                transactionLock.lockInterruptibly();
                try {
                    reloadMetadata();
                    if (metadata.optJSONObject("transaction") != null
                            || metadata.optBoolean("rollbackRequested", false)
                            || !target.digest.equals(metadata.optString("activeDigest", ""))
                            || target.coreApi != metadata.optInt("activeCoreApi", 1)
                            || metadata.optInt("activeManifestSchema", 0) != MANIFEST_SCHEMA
                            || metadata.optInt("activeMinAndroidApi", 0) != MIN_ANDROID_API
                            || !abi.equals(metadata.optString("activeAbi", ""))
                            || !activeFile().isFile()) {
                        continue;
                    }
                    retained = true;
                    return new PinnedLoadTarget(target.file, target.coreApi,
                            target.digest, handle);
                } finally {
                    transactionLock.unlock();
                }
            } finally {
                if (!retained) handle.close();
            }
        }
        throw new IllegalStateException("core changed repeatedly before native load");
    }

    boolean checkForUpdate(boolean force) throws Exception {
        return checkForUpdate(force, NOOP_OBSERVER);
    }

    boolean checkForUpdate(boolean force, UpdateObserver observer) throws Exception {
        updateLock.lockInterruptibly();
        try {
            return checkForUpdateTransaction(force,
                    observer == null ? NOOP_OBSERVER : observer);
        } finally {
            updateLock.unlock();
        }
    }

    /** Package-private seam used by deterministic transaction-order tests. */
    boolean checkForUpdateTransaction(boolean force) throws Exception {
        return checkForUpdateTransaction(force, NOOP_OBSERVER);
    }

    private boolean checkForUpdateTransaction(boolean force, UpdateObserver observer)
            throws Exception {
        long now = System.currentTimeMillis();
        boolean shouldFetch = withInspectedState(state -> {
            boolean ownedPending = state.pending.valid
                    && CORE_ORIGIN.equals(state.pending.origin)
                    && state.pending.coreApi == CORE_API;
            boolean noUsableCore = !state.active.valid && !state.pending.valid;
            boolean ownedVersionNeedsRepair = state.active.hasInvalidOwnedVersion(family)
                    || state.backup.hasInvalidOwnedVersion(family);
            boolean rejectedCooldown = isRejectedCurrentContract();
            long lastCheck = metadata.optLong("lastCheck", 0L);
            long elapsed = now - lastCheck;
            // A wall-clock rollback or corrupt future timestamp must make the
            // cache stale, not suppress updates until that future date arrives.
            boolean recentlyChecked = lastCheck > 0L && elapsed >= 0L
                    && elapsed < CHECK_INTERVAL_MS;
            return force || !recentlyChecked
                    || ownedVersionNeedsRepair
                    || (noUsableCore && !ownedPending && !rejectedCooldown);
        });
        if (!shouldFetch) return false;

        notifyStage(observer, UpdateStage.PREPARING);
        JSONObject release = fetchRelease();
        validateReleaseAssetSet(release);
        JSONArray assets = release.optJSONArray("assets");
        JSONObject asset = findAsset(assets, assetName());
        if (asset == null) throw new IllegalStateException(
                family.displayName + " asset is missing for " + abi);

        long advertisedSize = asset.optLong("size", 0L);
        if (advertisedSize < MIN_CORE_BYTES || advertisedSize > MAX_CORE_BYTES) {
            throw new IllegalStateException(family.displayName + " asset size is invalid");
        }
        String githubDigest = parseDigest(asset.optString("digest", ""));
        if (!isDigest(githubDigest)) {
            throw new IllegalStateException(family.displayName + " GitHub SHA-256 is missing");
        }

        JSONObject manifestAsset = findAsset(assets, "manifest.json");
        if (manifestAsset == null) throw new IllegalStateException(
                family.displayName + " manifest is missing");
        JSONObject manifest = downloadManifest(release, manifestAsset);
        int manifestCoreApi = manifest.optInt("coreApi", 0);
        JSONObject manifestEntry = manifest.optJSONObject("assets") == null
                ? null : manifest.optJSONObject("assets").optJSONObject(abi);
        if (manifestEntry == null) throw new IllegalStateException(
                family.displayName + " manifest ABI is missing");
        if (!assetName().equals(manifestEntry.optString("name", ""))
                || advertisedSize != manifestEntry.optLong("size", -1L)) {
            throw new IllegalStateException(family.displayName
                    + " manifest asset metadata mismatch");
        }
        String expectedDigest = manifestEntry.optString("sha256", "")
                .toLowerCase(Locale.US);
        if (!isDigest(expectedDigest) || !expectedDigest.equals(githubDigest)) {
            throw new IllegalStateException(family.displayName
                    + " manifest/GitHub digest mismatch");
        }
        JSONArray exports = manifestEntry.optJSONArray("exports");
        if (!hasExactStrings(exports, new String[]{"StartCore", "StopCore"})) {
            throw new IllegalStateException(family.displayName
                    + " manifest exports are incomplete");
        }

        String selectedVersion = release.optString("tag_name", family.id);
        boolean shouldDownload = withInspectedState(state -> {
            repairOwnedInvalidVersions(selectedVersion, expectedDigest, state);
            if (isRejectedCurrentContract()
                    && expectedDigest.equals(metadata.optString("rejectedDigest", ""))) {
                metadata.put("lastCheck", now);
                saveMetadata();
                if (!force) return false;
                throw new IllegalStateException(family.displayName
                        + " release was rejected by loader/self-test");
            }
            if (wouldDowngrade(selectedVersion, state)) {
                metadata.put("lastCheck", now);
                saveMetadata();
                return false;
            }
            boolean activeCurrent = state.active.valid
                    && expectedDigest.equals(state.active.digest)
                    && CORE_ORIGIN.equals(state.active.origin)
                    && state.active.coreApi == manifestCoreApi;
            boolean pendingCurrent = state.pending.valid
                    && expectedDigest.equals(state.pending.digest)
                    && CORE_ORIGIN.equals(state.pending.origin)
                    && state.pending.coreApi == manifestCoreApi;
            if (activeCurrent || pendingCurrent) {
                metadata.put("lastCheck", now);
                saveMetadata();
                return false;
            }
            return true;
        });
        if (!shouldDownload) return false;

        String downloadUrl = asset.optString("browser_download_url", "");
        if (downloadUrl.isEmpty()) throw new IllegalStateException("core download URL is missing");
        notifyStage(observer, UpdateStage.DOWNLOADING);
        File staged = downloadVerified(
                downloadUrl, advertisedSize, expectedDigest, observer);
        final boolean[] stagedMoved = {false};
        try {
            commitHook.beforeFinalCommit();
            return withInspectedState(state -> {
                repairOwnedInvalidVersions(selectedVersion, expectedDigest, state);
                if (isRejectedCurrentContract()
                        && expectedDigest.equals(metadata.optString("rejectedDigest", ""))) {
                    throw new IllegalStateException(family.displayName
                            + " release was rejected by loader/self-test");
                }
                if (wouldDowngrade(selectedVersion, state)) {
                    metadata.put("lastCheck", now);
                    saveMetadata();
                    return false;
                }
                boolean nowActive = state.active.valid
                        && expectedDigest.equals(state.active.digest)
                        && CORE_ORIGIN.equals(state.active.origin)
                        && state.active.coreApi == manifestCoreApi;
                boolean nowPending = state.pending.valid
                        && expectedDigest.equals(state.pending.digest)
                        && CORE_ORIGIN.equals(state.pending.origin)
                        && state.pending.coreApi == manifestCoreApi;
                if (!nowActive && !nowPending) {
                    // The verified download and its metadata become visible as
                    // one state transition. The atomic move/write remain under
                    // transactionLock; expensive ELF/SHA inspection happened before
                    // this critical section and the snapshot was revalidated.
                    moveReplacing(staged, pendingFile());
                    stagedMoved[0] = true;
                    metadata.put("pendingDigest", expectedDigest);
                    metadata.put("pendingVersion", selectedVersion);
                    metadata.put("pendingOrigin", CORE_ORIGIN);
                    metadata.put("pendingCoreApi", manifestCoreApi);
                    metadata.put("pendingManifestSchema", MANIFEST_SCHEMA);
                    metadata.put("pendingMinAndroidApi", MIN_ANDROID_API);
                    metadata.put("pendingAbi", ANDROID_ABI);
                    metadata.remove("requiresNewCore");
                    metadata.put("lastCheck", now);
                    saveMetadata();
                    return true;
                }
                metadata.put("lastCheck", now);
                saveMetadata();
                return false;
            });
        } finally {
            if (!stagedMoved[0] && staged.exists()) {
                //noinspection ResultOfMethodCallIgnored
                staged.delete();
            }
        }
    }

    private JSONObject fetchRelease() throws Exception {
        ReleasePageAccumulator accumulator = new ReleasePageAccumulator(
                family, MAX_RELEASE_BYTES_TOTAL);
        for (int page = 1; page <= MAX_RELEASE_PAGES + 1; page++) {
            String separator = releaseApi.contains("?") ? "&" : "?";
            String url = releaseApi + separator + "page=" + page;
            LimitedHttpClient.Response response = http.get(
                    url, Collections.singletonMap("Accept", "application/vnd.github+json"));
            if (response.status < 200 || response.status >= 300) {
                throw new IllegalStateException(
                        family.displayName + " release HTTP " + response.status);
            }
            int count = accumulator.accept(response.body, page);
            if (count < MAX_RELEASES_PER_PAGE || page > MAX_RELEASE_PAGES) {
                return accumulator.finish();
            }
        }
        throw new IllegalStateException("core release pagination is incomplete");
    }

    static void validateReleasePageShape(String value) {
        if (value == null) throw new IllegalStateException("core release page is missing");
        boolean inString = false;
        boolean escaped = false;
        int depth = 0;
        int separators = 0;
        boolean rootSeen = false;
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (inString) {
                if (escaped) escaped = false;
                else if (current == '\\') escaped = true;
                else if (current == '"') inString = false;
                continue;
            }
            if (current == '"') {
                inString = true;
                continue;
            }
            if (!rootSeen) {
                if (Character.isWhitespace(current)) continue;
                if (current != '[') throw new IllegalStateException(
                        "core release page root is invalid");
                rootSeen = true;
                depth = 1;
                continue;
            }
            if (current == '[' || current == '{') depth++;
            else if (current == ']' || current == '}') depth--;
            else if (current == ',' && depth == 1
                    && ++separators >= MAX_RELEASES_PER_PAGE) {
                throw new IllegalStateException("core release page exceeds 100 entries");
            }
            if (depth < 0) throw new IllegalStateException("core release page is invalid");
        }
        if (!rootSeen) throw new IllegalStateException("core release page root is invalid");
    }

    private void validateReleaseAssetSet(JSONObject release) {
        JSONArray assets = release.optJSONArray("assets");
        Set<String> expected = new HashSet<>();
        expected.add(assetName(ANDROID_ABI));
        expected.add("manifest.json");
        if (family == CoreFamily.SING_BOX) {
            ReleaseVersion version = ReleaseVersion.parse(
                    release.optString("tag_name", ""), family);
            if (version == null) throw new IllegalStateException(
                    "sing-box release tag is invalid");
            expected.add("exitfy-sb-v" + version.major + "." + version.minor + "."
                    + version.patch + "-source.tar.gz");
        }
        if (assets == null || assets.length() != expected.size()) {
            throw new IllegalStateException(family.displayName
                    + " release asset set is incomplete or contains extras");
        }
        Set<String> actual = new HashSet<>();
        for (int index = 0; index < assets.length(); index++) {
            JSONObject asset = assets.optJSONObject(index);
            String name = asset == null ? "" : asset.optString("name", "");
            if (asset == null || !expected.contains(name) || !actual.add(name)
                    || asset.optLong("id", 0L) <= 0L
                    || asset.optLong("size", 0L) <= 0L
                    || !isDigest(parseDigest(asset.optString("digest", "")))
                    || asset.optString("browser_download_url", "").isEmpty()) {
                throw new IllegalStateException(family.displayName
                        + " release asset contract is invalid");
            }
        }
    }

    static JSONObject selectRelease(JSONArray releases, CoreFamily family) {
        if (releases == null || family == null) {
            throw new IllegalStateException("core release list is invalid");
        }
        ReleasePageAccumulator accumulator = new ReleasePageAccumulator(
                family, Integer.MAX_VALUE);
        for (int i = 0; i < releases.length(); i++) {
            accumulator.consider(releases.optJSONObject(i));
        }
        return accumulator.bestOrThrow();
    }

    private JSONObject downloadManifest(JSONObject release, JSONObject asset) throws Exception {
        long size = asset.optLong("size", 0L);
        if (size <= 0 || size > MAX_MANIFEST_BYTES) {
            throw new IllegalStateException(family.displayName + " manifest size is invalid");
        }
        String expected = parseDigest(asset.optString("digest", ""));
        if (!isDigest(expected)) throw new IllegalStateException(
                family.displayName + " manifest digest is missing");
        String url = asset.optString("browser_download_url", "");
        if (url.isEmpty()) throw new IllegalStateException(
                family.displayName + " manifest URL is missing");
        LimitedHttpClient.Response response = null;
        RuntimeException lastFailure = null;
        for (String candidate : downloadCandidates(url)) {
            try {
                LimitedHttpClient.Response attempt = http.getBinary(candidate,
                        Collections.emptyMap(), MAX_MANIFEST_BYTES);
                if (attempt.status < 200 || attempt.status >= 300
                        || attempt.body.length != size) {
                    throw new IllegalStateException(
                            family.displayName + " manifest download failed");
                }
                if (!expected.equals(sha256(attempt.body))) {
                    throw new IllegalStateException(
                            family.displayName + " manifest digest mismatch");
                }
                response = attempt;
                break;
            } catch (RuntimeException failure) {
                lastFailure = failure;
            } catch (Exception failure) {
                lastFailure = new IllegalStateException(
                        family.displayName + " manifest download failed", failure);
            }
        }
        if (response == null) {
            throw lastFailure != null ? lastFailure : new IllegalStateException(
                    family.displayName + " manifest download failed");
        }
        JSONObject manifest = JsonGuard.object(
                new String(response.body, StandardCharsets.UTF_8));
        if (!family.id.equals(manifest.optString("family", ""))
                || manifest.optInt("minAndroidApi", 0) != MIN_ANDROID_API) {
            throw new IllegalStateException("unsupported " + family.displayName + " manifest");
        }
        int schema = manifest.optInt("schema", 0);
        if (schema != MANIFEST_SCHEMA || manifest.optInt("coreApi", 0) != CORE_API
                || manifest.optInt("configContract", 0) != CONFIG_CONTRACT) {
            throw new IllegalStateException("unsupported " + family.displayName
                    + " core contract");
        }
        validateSchemaThreeManifest(release, manifest);
        return manifest;
    }

    private void validateSchemaThreeManifest(JSONObject release, JSONObject manifest) {
        String releaseTag = release.optString("tag_name", "");
        JSONObject upstream = manifest.optJSONObject("upstream");
        JSONObject wrapper = manifest.optJSONObject("wrapper");
        String upstreamTag = upstream == null ? "" : upstream.optString("tag", "");
        boolean xray = family == CoreFamily.XRAY;
        ReleaseVersion parsedRelease = ReleaseVersion.parse(releaseTag, family);
        String revision = parsedRelease == null ? "" : String.valueOf(parsedRelease.wrapper);
        String expectedRelease = xray ? "xray-" + upstreamTag + "-w" + revision
                : "sb-" + upstreamTag + "-w" + revision;
        String expectedRepository = xray ? "XTLS/libXray" : "SagerNet/sing-box";
        if (!hasExactKeys(manifest, new String[]{"schema", "coreApi", "configContract",
                "family", "releaseTag", "upstream", "wrapper", "minAndroidApi",
                "requiredExports", "assets"})
                || !releaseTag.matches(xray
                ? "xray-v[0-9]+\\.[0-9]+\\.[0-9]+-w(?:[2-9]|[1-9][0-9]+)"
                : "sb-v[0-9]+\\.[0-9]+\\.[0-9]+-w(?:[2-9]|[1-9][0-9]+)")
                || !releaseTag.equals(manifest.optString("releaseTag", ""))
                || upstream == null || wrapper == null
                || !expectedRepository.equals(upstream.optString("repository", ""))
                || !"itsv1eds/exitFy".equals(wrapper.optString("repository", ""))
                || !upstreamTag.matches("v[0-9]+\\.[0-9]+\\.[0-9]+")
                || !releaseTag.equals(expectedRelease)
                || !upstream.optString("commit", "").matches("[0-9a-f]{40}")
                || !wrapper.optString("commit", "").matches("[0-9a-f]{40}")
                || !hasExactStrings(manifest.optJSONArray("requiredExports"),
                new String[]{"StartCore", "StopCore"})) {
            throw new IllegalStateException(family.displayName
                    + " manifest release pins are invalid");
        }
        if (xray) {
            if (!hasExactKeys(upstream, new String[]{"repository", "tag", "commit"})
                    || !hasExactKeys(wrapper, new String[]{"repository", "commit"})) {
                throw new IllegalStateException("Xray manifest fields are invalid");
            }
        } else {
            validateSingBoxBuildContract(release, upstream, wrapper, upstreamTag);
        }
        JSONArray releaseAssets = release.optJSONArray("assets");
        JSONObject manifestAssets = manifest.optJSONObject("assets");
        if (manifestAssets == null || !hasExactKeys(manifestAssets,
                new String[]{ANDROID_ABI})) {
            throw new IllegalStateException(family.displayName + " manifest ABI set is invalid");
        }
        JSONObject entry = manifestAssets.optJSONObject(ANDROID_ABI);
        String name = assetName(ANDROID_ABI);
        JSONObject releaseAsset = findAsset(releaseAssets, name);
        long size = entry == null ? -1L : entry.optLong("size", -1L);
        String digest = entry == null ? ""
                : entry.optString("sha256", "").toLowerCase(Locale.US);
        if (entry == null || !hasExactKeys(entry, new String[]{"name", "size", "sha256",
                "elfClass", "elfMachine", "elfMachineName", "exports"})
                || releaseAsset == null || !name.equals(entry.optString("name", ""))
                || size < MIN_CORE_BYTES || size > MAX_CORE_BYTES
                || size != releaseAsset.optLong("size", -1L)
                || !isDigest(digest)
                || !digest.equals(parseDigest(releaseAsset.optString("digest", "")))
                || entry.optInt("elfClass", -1) != 64
                || entry.optInt("elfMachine", -1) != 183
                || !"EM_AARCH64".equals(entry.optString("elfMachineName", ""))
                || !hasExactStrings(entry.optJSONArray("exports"),
                new String[]{"StartCore", "StopCore"})) {
            throw new IllegalStateException(family.displayName
                    + " manifest asset contract mismatch for " + ANDROID_ABI);
        }
    }

    private static void validateSingBoxBuildContract(JSONObject release, JSONObject upstream,
                                                       JSONObject wrapper, String upstreamTag) {
        if (!hasExactKeys(upstream,
                new String[]{"repository", "tag", "commit", "goVersion"})
                || !upstream.optString("goVersion", "")
                .matches("[0-9]+\\.[0-9]+(?:\\.[0-9]+)?")
                || !hasExactKeys(wrapper, new String[]{"repository", "commit", "ndkVersion",
                "buildTags", "sourceBundle"})
                || !SB_NDK_VERSION.equals(wrapper.optString("ndkVersion", ""))
                || !hasExactStrings(wrapper.optJSONArray("buildTags"), SB_BUILD_TAGS)) {
            throw new IllegalStateException("sing-box manifest build contract is invalid");
        }
        JSONObject source = wrapper.optJSONObject("sourceBundle");
        String expectedName = "exitfy-sb-" + upstreamTag + "-source.tar.gz";
        JSONObject releaseAsset = source == null ? null
                : findAsset(release.optJSONArray("assets"), expectedName);
        long size = source == null ? -1L : source.optLong("size", -1L);
        String digest = source == null ? ""
                : source.optString("sha256", "").toLowerCase(Locale.US);
        if (source == null || !hasExactKeys(source, new String[]{"name", "size", "sha256"})
                || !expectedName.equals(source.optString("name", ""))
                || releaseAsset == null || size <= 0L || size > MAX_SOURCE_BUNDLE_BYTES
                || size != releaseAsset.optLong("size", -1L)
                || !isDigest(digest)
                || !digest.equals(parseDigest(releaseAsset.optString("digest", "")))) {
            throw new IllegalStateException("sing-box source bundle contract is invalid");
        }
    }

    private File downloadVerified(String url, long advertisedSize, String expectedDigest,
                                  UpdateObserver observer) throws Exception {
        Exception last = null;
        File staged = store.child(pendingPath() + ".download");
        for (String candidate : downloadCandidates(url)) {
            try {
                //noinspection ResultOfMethodCallIgnored
                staged.delete();
                LimitedHttpClient.StreamResponse response = http.getBinaryToFile(
                        candidate, Collections.emptyMap(), staged, MAX_CORE_BYTES,
                        (downloadedBytes, ignoredTotal) ->
                                notifyProgress(observer, downloadedBytes, advertisedSize));
                notifyStage(observer, UpdateStage.VERIFYING);
                if (response.status < 200 || response.status >= 300) {
                    throw new IllegalStateException("core download HTTP " + response.status);
                }
                if (response.size != advertisedSize || response.size < MIN_CORE_BYTES
                        || response.size > MAX_CORE_BYTES) {
                    throw new IllegalStateException("downloaded core size is invalid");
                }
                if (!expectedDigest.equals(response.sha256)) {
                    throw new IllegalStateException("core digest mismatch");
                }
                ElfInspector.Result inspected = ElfInspector.inspect(staged, abi);
                if (!inspected.valid) throw new IllegalStateException(inspected.error);
                return staged;
            } catch (Exception error) {
                //noinspection ResultOfMethodCallIgnored
                staged.delete();
                last = error;
            }
        }
        if (last != null) throw last;
        throw new IllegalStateException("no core download candidates");
    }

    private static void notifyStage(UpdateObserver observer, UpdateStage stage) {
        try {
            observer.onStage(stage);
        } catch (Throwable ignored) {
        }
    }

    private static void notifyProgress(UpdateObserver observer,
                                       long downloadedBytes, long totalBytes) {
        try {
            observer.onProgress(Math.max(0L, downloadedBytes), Math.max(0L, totalBytes));
        } catch (Throwable ignored) {
        }
    }

    static List<String> downloadCandidates(String url) {
        List<String> values = new ArrayList<>();
        if (url == null || url.trim().isEmpty()) return values;
        String direct = url.trim();
        values.add(direct);
        if (!direct.startsWith("https://")) return values;
        for (String mirror : DOWNLOAD_MIRRORS) {
            String candidate = mirror + direct;
            if (!values.contains(candidate)) values.add(candidate);
        }
        return values;
    }

    void markStartSuccess() {
        transactionLock.lock();
        try {
            reloadMetadata();
            if (!metadata.optBoolean("candidate", false)) return;
            metadata.put("candidate", false);
            metadata.put("rollbackRequested", false);
            saveMetadata();
        } catch (Exception ignored) {
        } finally {
            transactionLock.unlock();
        }
    }

    void markLoaderFailure() {
        transactionLock.lock();
        try {
            reloadMetadata();
            if (!metadata.optBoolean("candidate", false)) return;
            metadata.put("rejectedDigest", metadata.optString("activeDigest", ""));
            metadata.put("rejectedVersion", metadata.optString("activeVersion", ""));
            metadata.put("rejectedCoreApi", metadata.optInt("activeCoreApi", 1));
            metadata.put("rejectedManifestSchema",
                    metadata.optInt("activeManifestSchema", 0));
            metadata.put("rejectedMinAndroidApi",
                    metadata.optInt("activeMinAndroidApi", 0));
            putOrRemove(metadata, "rejectedAbi", metadata.optString("activeAbi", ""));
            metadata.put("rollbackRequested", true);
            saveMetadata();
        } catch (Exception ignored) {
        } finally {
            transactionLock.unlock();
        }
    }

    String version() {
        return readinessSnapshot.version;
    }

    boolean isCandidate() {
        return readinessSnapshot.candidate;
    }

    int activeCoreApi() {
        return readinessSnapshot.coreApi;
    }

    boolean requiresNewCore() {
        return readinessSnapshot.requiresNewCore;
    }

    boolean hasUsableCore() {
        return readinessSnapshot.usable;
    }

    boolean verifyLocalReadiness() throws Exception {
        // Refresh the cheap snapshot only after SHA-256/ELF inspection has
        // reconciled every active, pending and rollback candidate. This is
        // intentionally local-only and can therefore run before the first
        // user-authorized network installation.
        withInspectedState(state -> null);
        return hasUsableCore();
    }

    private void promotePending(InspectedState state, boolean keepBackup) throws Exception {
        if (!state.pending.valid) return;
        String pendingDigest = state.pending.digest;
        String pendingVersion = state.pending.version.isEmpty()
                ? family.id : state.pending.version;
        String pendingOrigin = state.pending.origin;
        int pendingCoreApi = state.pending.coreApi;
        int pendingManifestSchema = state.pending.manifestSchema;
        int pendingMinAndroidApi = state.pending.minAndroidApi;
        String pendingAbi = state.pending.androidAbi;
        String previousDigest = state.active.digest;
        String previousVersion = state.active.version;
        String previousOrigin = state.active.origin;
        int previousCoreApi = state.active.coreApi;
        int previousManifestSchema = state.active.manifestSchema;
        int previousMinAndroidApi = state.active.minAndroidApi;
        String previousAbi = state.active.androidAbi;
        boolean backupExpected = keepBackup && state.active.valid;

        JSONObject transaction = new JSONObject()
                .put("type", "promote")
                .put("pendingDigest", pendingDigest)
                .put("pendingVersion", pendingVersion)
                .put("pendingOrigin", pendingOrigin)
                .put("pendingCoreApi", pendingCoreApi)
                .put("pendingManifestSchema", pendingManifestSchema)
                .put("pendingMinAndroidApi", pendingMinAndroidApi)
                .put("pendingAbi", pendingAbi)
                .put("previousDigest", backupExpected ? previousDigest : "")
                .put("previousVersion", backupExpected ? previousVersion : "")
                .put("previousOrigin", backupExpected ? previousOrigin : "")
                .put("previousCoreApi", backupExpected ? previousCoreApi : 1)
                .put("previousManifestSchema", backupExpected ? previousManifestSchema : 0)
                .put("previousMinAndroidApi", backupExpected ? previousMinAndroidApi : 0)
                .put("previousAbi", backupExpected ? previousAbi : "")
                .put("previousCandidatePresent", backupExpected && metadata.has("candidate"))
                .put("previousCandidate", backupExpected
                        && metadata.optBoolean("candidate", false))
                .put("previousRollbackRequestedPresent", backupExpected
                        && metadata.has("rollbackRequested"))
                .put("previousRollbackRequested", backupExpected
                        && metadata.optBoolean("rollbackRequested", false))
                .put("backupExpected", backupExpected);
        metadata.put("transaction", transaction);
        saveMetadata();

        if (backupExpected) {
            moveReplacing(activeFile(), backupFile());
        } else {
            File backup = backupFile();
            if (!backup.delete() && backup.exists()) {
                throw new IllegalStateException("cannot discard stale core backup");
            }
        }
        moveReplacing(pendingFile(), activeFile());
        finishPromotion(transaction, backupExpected);
    }

    private void restoreBackup(InspectedState state) throws Exception {
        String backupDigest = state.backup.digest;
        String backupVersion = state.backup.version.isEmpty()
                ? "rollback" : state.backup.version;
        String backupOrigin = state.backup.origin;
        int backupCoreApi = state.backup.coreApi;
        int backupManifestSchema = state.backup.manifestSchema;
        int backupMinAndroidApi = state.backup.minAndroidApi;
        String backupAbi = state.backup.androidAbi;
        JSONObject transaction = new JSONObject()
                .put("type", "rollback")
                .put("targetDigest", backupDigest)
                .put("targetVersion", backupVersion)
                .put("targetOrigin", backupOrigin)
                .put("targetCoreApi", backupCoreApi)
                .put("targetManifestSchema", backupManifestSchema)
                .put("targetMinAndroidApi", backupMinAndroidApi)
                .put("targetAbi", backupAbi);
        metadata.put("transaction", transaction);
        saveMetadata();
        moveReplacing(backupFile(), activeFile());
        finishRollback(backupDigest, backupVersion, backupOrigin, backupCoreApi,
                backupManifestSchema, backupMinAndroidApi, backupAbi);
    }

    private void discardRejectedActive() throws Exception {
        File active = activeFile();
        if (!active.delete() && active.exists()) {
            throw new IllegalStateException("cannot discard rejected active core");
        }
        metadata.remove("activeDigest");
        metadata.remove("activeVersion");
        metadata.remove("activeOrigin");
        metadata.remove("activeCoreApi");
        metadata.remove("activeManifestSchema");
        metadata.remove("activeMinAndroidApi");
        metadata.remove("activeAbi");
        metadata.put("requiresNewCore", true);
        metadata.put("candidate", false);
        metadata.put("rollbackRequested", false);
        saveMetadata();
    }

    private void discardPending(String reason) throws Exception {
        File pending = pendingFile();
        if (!pending.delete() && pending.exists()) {
            throw new IllegalStateException("cannot discard pending core");
        }
        removeMetadataFields("pendingDigest", "pendingVersion",
                "pendingOrigin", "pendingCoreApi", "pendingManifestSchema",
                "pendingMinAndroidApi", "pendingAbi");
        saveMetadata();
    }

    /**
     * Completes a durable file transaction left by a process kill. File
     * contents are authenticated outside transactionLock, then their immutable
     * metadata/file-stamp snapshot is revalidated immediately before the
     * journal's short atomic-move commit.
     */
    private void recoverTransaction() throws Exception {
        for (int attempt = 0; attempt < 16; attempt++) {
            CoreStateSnapshot snapshot;
            transactionLock.lockInterruptibly();
            try {
                reloadMetadata();
                if (metadata.optJSONObject("transaction") == null) return;
                snapshot = CoreStateSnapshot.capture(this, metadata);
            } finally {
                transactionLock.unlock();
            }

            InspectedState inspected = inspectSnapshot(snapshot);
            transactionLock.lockInterruptibly();
            try {
                reloadMetadata();
                if (!snapshot.matches(this, metadata)) continue;
                if (inspected.hasInconclusiveFile()) {
                    throw new IllegalStateException("core transaction inspection failed");
                }
                JSONObject transaction = metadata.optJSONObject("transaction");
                if (transaction == null) return;
                String type = transaction.optString("type", "");
                if ("promote".equals(type)) {
                    String pendingDigest = transaction.optString("pendingDigest", "");
                    boolean backupExpected = transaction.optBoolean("backupExpected", false);
                    String previousDigest = transaction.optString("previousDigest", "");
                    if (inspected.active.matchesDigest(pendingDigest)) {
                        finishPromotion(transaction, backupExpected
                                && inspected.backup.matchesDigest(previousDigest));
                        return;
                    }
                    if (inspected.pending.matchesDigest(pendingDigest)) {
                        boolean backupReady = backupExpected
                                && inspected.backup.matchesDigest(previousDigest);
                        if (backupExpected && !backupReady
                                && inspected.active.matchesDigest(previousDigest)) {
                            moveReplacing(activeFile(), backupFile());
                            backupReady = true;
                        }
                        moveReplacing(pendingFile(), activeFile());
                        finishPromotion(transaction, backupReady);
                        return;
                    }
                    if (backupExpected) {
                        if (inspected.active.matchesDigest(previousDigest)
                                || inspected.backup.matchesDigest(previousDigest)) {
                            abortPromotion(transaction, inspected);
                            return;
                        }
                        throw new IllegalStateException(
                                "promotion target and previous core are unavailable");
                    }
                    abortPromotion(transaction, inspected);
                    return;
                } else if ("rollback".equals(type)) {
                    String digest = transaction.optString("targetDigest", "");
                    String version = transaction.optString("targetVersion", "rollback");
                    String origin = transaction.optString("targetOrigin", "");
                    int coreApi = transaction.optInt("targetCoreApi", 1);
                    int manifestSchema = transaction.optInt("targetManifestSchema", 0);
                    int minAndroidApi = transaction.optInt("targetMinAndroidApi", 0);
                    String targetAbi = transaction.optString("targetAbi", "");
                    if (inspected.active.matchesDigest(digest)) {
                        finishRollback(digest, version, origin, coreApi,
                                manifestSchema, minAndroidApi, targetAbi);
                        return;
                    }
                    if (inspected.backup.matchesDigest(digest)) {
                        moveReplacing(backupFile(), activeFile());
                        finishRollback(digest, version, origin, coreApi,
                                manifestSchema, minAndroidApi, targetAbi);
                        return;
                    }
                }
                metadata.remove("transaction");
                saveMetadata();
                return;
            } finally {
                transactionLock.unlock();
            }
        }
        throw new IllegalStateException("core transaction changed repeatedly during recovery");
    }

    private void abortPromotion(JSONObject transaction, InspectedState inspected)
            throws Exception {
        boolean backupExpected = transaction.optBoolean("backupExpected", false);
        String previousDigest = transaction.optString("previousDigest", "");
        if (backupExpected) {
            if (!inspected.active.matchesDigest(previousDigest)) {
                if (!inspected.backup.matchesDigest(previousDigest)) {
                    throw new IllegalStateException("cannot restore previous core promotion state");
                }
                moveReplacing(backupFile(), activeFile());
            }
            metadata.put("activeDigest", previousDigest);
            metadata.put("activeVersion", transaction.optString("previousVersion", ""));
            putOrRemove(metadata, "activeOrigin",
                    transaction.optString("previousOrigin", ""));
            metadata.put("activeCoreApi", transaction.optInt("previousCoreApi", 1));
            metadata.put("activeManifestSchema",
                    transaction.optInt("previousManifestSchema", 0));
            metadata.put("activeMinAndroidApi",
                    transaction.optInt("previousMinAndroidApi", 0));
            putOrRemove(metadata, "activeAbi", transaction.optString("previousAbi", ""));
            if (transaction.has("previousCandidatePresent")) {
                if (transaction.optBoolean("previousCandidatePresent", false)) {
                    metadata.put("candidate",
                            transaction.optBoolean("previousCandidate", false));
                } else {
                    metadata.remove("candidate");
                }
            }
            if (transaction.has("previousRollbackRequestedPresent")) {
                if (transaction.optBoolean("previousRollbackRequestedPresent", false)) {
                    metadata.put("rollbackRequested",
                            transaction.optBoolean("previousRollbackRequested", false));
                } else {
                    metadata.remove("rollbackRequested");
                }
            }
        } else {
            removeMetadataFields("activeDigest", "activeVersion",
                    "activeOrigin", "activeCoreApi", "activeManifestSchema",
                    "activeMinAndroidApi", "activeAbi", "candidate", "rollbackRequested");
        }

        File pending = pendingFile();
        if (!pending.delete() && pending.exists()) {
            throw new IllegalStateException("cannot discard failed promotion target");
        }
        removeMetadataFields("pendingDigest", "pendingVersion",
                "pendingOrigin", "pendingCoreApi", "pendingManifestSchema",
                "pendingMinAndroidApi", "pendingAbi");
        removeMetadataFields("backupDigest", "backupVersion",
                "backupOrigin", "backupCoreApi", "backupManifestSchema",
                "backupMinAndroidApi", "backupAbi");
        metadata.remove("transaction");
        saveMetadata();
    }

    private void finishPromotion(JSONObject transaction, boolean backupReady) throws Exception {
        String pendingDigest = transaction.optString("pendingDigest", "");
        metadata.put("activeDigest", pendingDigest);
        metadata.put("activeVersion", transaction.optString("pendingVersion", family.id));
        putOrRemove(metadata, "activeOrigin", transaction.optString("pendingOrigin", ""));
        metadata.put("activeCoreApi", transaction.optInt("pendingCoreApi", 1));
        metadata.put("activeManifestSchema", transaction.optInt("pendingManifestSchema", 0));
        metadata.put("activeMinAndroidApi", transaction.optInt("pendingMinAndroidApi", 0));
        putOrRemove(metadata, "activeAbi", transaction.optString("pendingAbi", ""));
        metadata.remove("pendingDigest");
        metadata.remove("pendingVersion");
        metadata.remove("pendingOrigin");
        metadata.remove("pendingCoreApi");
        metadata.remove("pendingManifestSchema");
        metadata.remove("pendingMinAndroidApi");
        metadata.remove("pendingAbi");
        if (backupReady) {
            metadata.put("backupDigest", transaction.optString("previousDigest", ""));
            metadata.put("backupVersion", transaction.optString("previousVersion", ""));
            putOrRemove(metadata, "backupOrigin", transaction.optString("previousOrigin", ""));
            metadata.put("backupCoreApi", transaction.optInt("previousCoreApi", 1));
            metadata.put("backupManifestSchema",
                    transaction.optInt("previousManifestSchema", 0));
            metadata.put("backupMinAndroidApi",
                    transaction.optInt("previousMinAndroidApi", 0));
            putOrRemove(metadata, "backupAbi", transaction.optString("previousAbi", ""));
        } else {
            metadata.remove("backupDigest");
            metadata.remove("backupVersion");
            metadata.remove("backupOrigin");
            metadata.remove("backupCoreApi");
            metadata.remove("backupManifestSchema");
            metadata.remove("backupMinAndroidApi");
            metadata.remove("backupAbi");
        }
        metadata.remove("requiresNewCore");
        metadata.put("candidate", true);
        metadata.put("rollbackRequested", false);
        metadata.remove("transaction");
        saveMetadata();
    }

    private void finishRollback(String digest, String version, String origin,
                                int coreApi, int manifestSchema, int minAndroidApi,
                                String targetAbi) throws Exception {
        metadata.put("activeDigest", digest);
        metadata.put("activeVersion", version);
        putOrRemove(metadata, "activeOrigin", origin);
        metadata.put("activeCoreApi", coreApi);
        metadata.put("activeManifestSchema", manifestSchema);
        metadata.put("activeMinAndroidApi", minAndroidApi);
        putOrRemove(metadata, "activeAbi", targetAbi);
        metadata.remove("backupDigest");
        metadata.remove("backupVersion");
        metadata.remove("backupOrigin");
        metadata.remove("backupCoreApi");
        metadata.remove("backupManifestSchema");
        metadata.remove("backupMinAndroidApi");
        metadata.remove("backupAbi");
        metadata.remove("requiresNewCore");
        metadata.put("rollbackRequested", false);
        metadata.put("candidate", false);
        metadata.remove("transaction");
        saveMetadata();
    }

    private static void moveReplacing(File source, File target) throws Exception {
        ensureParent(target);
        try {
            Files.move(source.toPath(), target.toPath(),
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException unsupported) {
            Files.move(source.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private String rootPath() {
        return "core/" + family.id;
    }

    private String metadataPath() {
        return rootPath() + "/core.json";
    }

    private String libraryName() {
        return family == CoreFamily.XRAY ? "libxray.so" : "libvless.so";
    }

    private String assetName() {
        return assetName(abi);
    }

    private String assetName(String candidateAbi) {
        return (family == CoreFamily.XRAY ? "libxray-" : "libexitfy-sb-")
                + candidateAbi + ".so";
    }

    private String pendingPath() {
        return rootPath() + "/pending/" + libraryName();
    }

    private File activeFile() {
        return store.child(rootPath() + "/active/" + libraryName());
    }

    private File pendingFile() {
        return store.child(pendingPath());
    }

    private File backupFile() {
        return store.child(rootPath() + "/backup/" + libraryName());
    }

    /**
     * Runs a short metadata decision while holding transactionLock, but performs the
     * potentially expensive ELF walk and 64 MiB SHA-256 reads outside it. The
     * file stamps and every metadata field used by the decision are checked
     * again after the lock is reacquired. A concurrent first-load promotion
     * therefore causes a retry instead of applying an inspection to a different
     * file revision.
     *
     * Journal writes and atomic moves remain under transactionLock only for their
     * short linearization boundary. Recovery authentication, ELF inspection
     * and SHA-256 reads always happen outside it. UI status reads use the
     * immutable volatile ReadinessSnapshot and never wait for core file I/O.
     */
    private <T> T withInspectedState(InspectedStateOperation<T> operation) throws Exception {
        return withInspectedState(operation, false);
    }

    private <T> T withInspectedState(InspectedStateOperation<T> operation,
                                     boolean failInvalidPending) throws Exception {
        for (int attempt = 0; attempt < 16; attempt++) {
            recoverTransaction();
            CoreStateSnapshot snapshot;
            transactionLock.lockInterruptibly();
            try {
                reloadMetadata();
                if (reconcileMissingFilesLocked()) saveMetadata();
                snapshot = CoreStateSnapshot.capture(this, metadata);
            } finally {
                transactionLock.unlock();
            }

            InspectedState inspected = inspectSnapshot(snapshot);

            transactionLock.lockInterruptibly();
            try {
                reloadMetadata();
                if (metadata.optJSONObject("transaction") != null) continue;
                if (reconcileMissingFilesLocked()) {
                    saveMetadata();
                    continue;
                }
                if (!snapshot.matches(this, metadata)) continue;
                if (inspected.hasInconclusiveFile()) {
                    throw new IllegalStateException("core inspection failed");
                }
                if (reconcileInvalidFilesLocked(snapshot, inspected)) {
                    saveMetadata();
                    if (failInvalidPending && snapshot.pending.fileStamp.regularFile
                            && !inspected.pending.valid) {
                        throw new IllegalStateException(inspected.pending.error);
                    }
                    continue;
                }
                return operation.run(inspected);
            } finally {
                transactionLock.unlock();
            }
        }
        throw new IllegalStateException("core state changed repeatedly during inspection");
    }

    private InspectedState inspectSnapshot(CoreStateSnapshot snapshot) throws Exception {
        return new InspectedState(inspectCandidate(snapshot.active),
                inspectCandidate(snapshot.pending), inspectCandidate(snapshot.backup));
    }

    private CandidateInspection inspectCandidate(CoreCandidateSnapshot candidate)
            throws Exception {
        inspectionHook.beforeInspect(candidate.fileStamp.file);
        if (!candidate.fileStamp.regularFile) {
            return new CandidateInspection(candidate, false, false, true, "",
                    "core file is missing");
        }
        File file = candidate.fileStamp.file;
        if (file.length() < MIN_CORE_BYTES || file.length() > MAX_CORE_BYTES) {
            return new CandidateInspection(candidate, false, false, true, "",
                    "core size is invalid");
        }
        try {
            // Hash first: unlike ElfInspector's intentionally generic
            // "malformed" result, an I/O failure here remains inconclusive
            // and must never cause deletion of a potentially valid core.
            String actualDigest = sha256(file);
            ElfInspector.Result result = ElfInspector.inspect(file, abi);
            if (!result.valid) {
                return new CandidateInspection(candidate, false, false, true,
                        "", result.error);
            }
            boolean metadataValid = candidate.coreApi == CORE_API
                    && candidate.manifestSchema == MANIFEST_SCHEMA
                    && candidate.minAndroidApi == MIN_ANDROID_API
                    && abi.equals(candidate.androidAbi)
                    && CORE_ORIGIN.equals(candidate.origin)
                    && isDigest(candidate.digest) && candidate.digest.equals(actualDigest);
            String error = metadataValid ? ""
                    : candidate.coreApi != CORE_API ? "unsupported core API metadata"
                    : candidate.manifestSchema != MANIFEST_SCHEMA
                    ? "legacy core manifest is unsupported"
                    : candidate.minAndroidApi != MIN_ANDROID_API
                    ? "legacy Android core is unsupported"
                    : !abi.equals(candidate.androidAbi) ? "core ABI metadata is unsupported"
                    : !CORE_ORIGIN.equals(candidate.origin) ? "core origin metadata is unsupported"
                    : !isDigest(candidate.digest) ? "core digest metadata is missing"
                    : "core digest mismatch";
            return new CandidateInspection(candidate, metadataValid, true, true,
                    actualDigest, error);
        } catch (Exception error) {
            return new CandidateInspection(candidate, false, false, false, "",
                    error.getMessage() == null ? error.getClass().getSimpleName()
                            : error.getMessage());
        }
    }

    private boolean reconcileMissingFilesLocked() throws Exception {
        boolean changed = false;
        if (!activeFile().isFile()) {
            changed |= removeMetadataFields("activeDigest", "activeVersion",
                    "activeOrigin", "activeCoreApi", "activeManifestSchema",
                    "activeMinAndroidApi", "activeAbi", "candidate");
            boolean backupExists = backupFile().isFile();
            if (backupExists != metadata.optBoolean("rollbackRequested", false)) {
                if (backupExists) metadata.put("rollbackRequested", true);
                else metadata.remove("rollbackRequested");
                changed = true;
            }
        }
        if (!pendingFile().isFile()) {
            changed |= removeMetadataFields("pendingDigest", "pendingVersion",
                    "pendingOrigin", "pendingCoreApi", "pendingManifestSchema",
                    "pendingMinAndroidApi", "pendingAbi");
        }
        if (!backupFile().isFile()) {
            changed |= removeMetadataFields("backupDigest", "backupVersion",
                    "backupOrigin", "backupCoreApi", "backupManifestSchema",
                    "backupMinAndroidApi", "backupAbi");
        }
        return changed;
    }

    private boolean reconcileInvalidFilesLocked(CoreStateSnapshot snapshot,
                                                InspectedState inspected) throws Exception {
        boolean changed = false;
        if (snapshot.active.fileStamp.regularFile && !inspected.active.valid) {
            File active = activeFile();
            if (!active.delete() && active.exists()) {
                throw new IllegalStateException("cannot discard invalid active core");
            }
            changed |= removeMetadataFields("activeDigest", "activeVersion",
                    "activeOrigin", "activeCoreApi", "activeManifestSchema",
                    "activeMinAndroidApi", "activeAbi", "candidate");
            metadata.put("requiresNewCore", true);
            boolean backupExists = backupFile().isFile();
            if (backupExists) {
                if (!metadata.optBoolean("rollbackRequested", false)) {
                    metadata.put("rollbackRequested", true);
                    changed = true;
                }
            } else if (metadata.has("rollbackRequested")) {
                metadata.remove("rollbackRequested");
                changed = true;
            }
            changed = true;
        }
        if (snapshot.pending.fileStamp.regularFile && !inspected.pending.valid) {
            File pending = pendingFile();
            if (!pending.delete() && pending.exists()) {
                throw new IllegalStateException("cannot discard invalid pending core");
            }
            changed |= removeMetadataFields("pendingDigest", "pendingVersion",
                    "pendingOrigin", "pendingCoreApi", "pendingManifestSchema",
                    "pendingMinAndroidApi", "pendingAbi");
            metadata.put("requiresNewCore", true);
            changed = true;
        }
        if (snapshot.pending.fileStamp.regularFile && inspected.pending.valid
                && inspected.pending.hasInvalidOwnedVersion(family)) {
            File pending = pendingFile();
            if (!pending.delete() && pending.exists()) {
                throw new IllegalStateException("cannot discard invalid-version pending core");
            }
            changed |= removeMetadataFields("pendingDigest", "pendingVersion",
                    "pendingOrigin", "pendingCoreApi", "pendingManifestSchema",
                    "pendingMinAndroidApi", "pendingAbi");
            metadata.put("lastCheck", 0L);
            changed = true;
        }
        if (snapshot.backup.fileStamp.regularFile && !inspected.backup.valid) {
            File backup = backupFile();
            if (!backup.delete() && backup.exists()) {
                throw new IllegalStateException("cannot discard invalid backup core");
            }
            changed |= removeMetadataFields("backupDigest", "backupVersion",
                    "backupOrigin", "backupCoreApi", "backupManifestSchema",
                    "backupMinAndroidApi", "backupAbi");
            metadata.put("requiresNewCore", true);
            changed = true;
        }
        return changed;
    }

    private boolean removeMetadataFields(String... fields) {
        boolean changed = false;
        for (String field : fields) {
            if (metadata.has(field)) {
                metadata.remove(field);
                changed = true;
            }
        }
        return changed;
    }

    private static JSONObject findAsset(JSONArray assets, String name) {
        if (assets == null) return null;
        for (int i = 0; i < assets.length(); i++) {
            JSONObject candidate = assets.optJSONObject(i);
            if (candidate != null && name.equals(candidate.optString("name", ""))) return candidate;
        }
        return null;
    }

    private static boolean hasExactKeys(JSONObject value, String[] expected) {
        if (value == null) return false;
        Set<String> expectedSet = new HashSet<>();
        Collections.addAll(expectedSet, expected);
        Set<String> actual = new HashSet<>();
        java.util.Iterator<String> keys = value.keys();
        while (keys.hasNext()) actual.add(keys.next());
        return actual.equals(expectedSet);
    }

    private static boolean hasExactStrings(JSONArray values, String[] expected) {
        if (values == null || values.length() != expected.length) return false;
        Set<String> expectedSet = new HashSet<>();
        Collections.addAll(expectedSet, expected);
        Set<String> actual = new HashSet<>();
        for (int i = 0; i < values.length(); i++) {
            String value = values.optString(i, "");
            if (value.isEmpty() || !actual.add(value)) return false;
        }
        return actual.equals(expectedSet);
    }

    private static int compareReleaseTags(String left, String right, CoreFamily family) {
        ReleaseVersion leftVersion = ReleaseVersion.parse(left, family);
        ReleaseVersion rightVersion = ReleaseVersion.parse(right, family);
        if (leftVersion == null || rightVersion == null) return 0;
        return leftVersion.compareTo(rightVersion);
    }

    private boolean wouldDowngrade(String selectedVersion, InspectedState state) {
        boolean olderThanActive = state.active.valid && compareReleaseTags(selectedVersion,
                metadata.optString("activeVersion", state.active.version), family) < 0;
        boolean olderThanPending = state.pending.valid && compareReleaseTags(selectedVersion,
                metadata.optString("pendingVersion", state.pending.version), family) < 0;
        boolean olderThanBackup = state.backup.valid && compareReleaseTags(selectedVersion,
                metadata.optString("backupVersion", state.backup.version), family) < 0;
        return olderThanActive || olderThanPending || olderThanBackup;
    }

    private boolean pendingViolatesInstalledFloor(InspectedState state) {
        if (!state.pending.valid) return false;
        if (state.active.hasInvalidOwnedVersion(family)
                || state.backup.hasInvalidOwnedVersion(family)) return true;
        boolean olderThanActive = state.active.valid && compareReleaseTags(
                state.pending.version, state.active.version, family) < 0;
        boolean olderThanBackup = state.backup.valid && compareReleaseTags(
                state.pending.version, state.backup.version, family) < 0;
        return olderThanActive || olderThanBackup;
    }

    private void repairOwnedInvalidVersions(String selectedVersion, String selectedDigest,
                                            InspectedState state) throws Exception {
        if (ReleaseVersion.parse(selectedVersion, family) == null
                || !isDigest(selectedDigest)) {
            throw new IllegalStateException("selected core release metadata is invalid");
        }
        boolean changed = repairOwnedInvalidVersion(
                "active", state.active, selectedVersion, selectedDigest);
        changed |= repairOwnedInvalidVersion(
                "backup", state.backup, selectedVersion, selectedDigest);
        if (changed) saveMetadata();
    }

    private boolean repairOwnedInvalidVersion(String prefix, CandidateInspection candidate,
                                              String selectedVersion,
                                              String selectedDigest) throws Exception {
        if (!candidate.hasInvalidOwnedVersion(family)) return false;
        if (!selectedDigest.equals(candidate.digest)) {
            throw new IllegalStateException(family.displayName + " " + prefix
                    + " version metadata is invalid; exact digest repair is required");
        }
        metadata.put(prefix + "Version", selectedVersion);
        return true;
    }

    static final class ReleasePageAccumulator {
        private final CoreFamily family;
        private final int byteBudget;
        private long totalBytes;
        private int totalEntries;
        private int acceptedPages;
        private boolean complete;
        private JSONObject best;
        private ReleaseVersion bestVersion;

        ReleasePageAccumulator(CoreFamily family, int byteBudget) {
            if (family == null || byteBudget <= 0) {
                throw new IllegalArgumentException("release accumulator contract is invalid");
            }
            this.family = family;
            this.byteBudget = byteBudget;
        }

        int accept(byte[] body, int page) throws Exception {
            if (complete || page != acceptedPages + 1 || page < 1
                    || page > MAX_RELEASE_PAGES + 1) {
                throw new IllegalStateException("core release pagination order is invalid");
            }
            if (body == null || body.length > byteBudget - totalBytes) {
                throw new IllegalStateException("core release pages exceed cumulative byte limit");
            }
            totalBytes += body.length;
            String pageJson = new String(body, StandardCharsets.UTF_8);
            validateReleasePageShape(pageJson);
            JSONArray releases = JsonGuard.array(pageJson);
            int count = releases.length();
            if (count > MAX_RELEASES_PER_PAGE) {
                throw new IllegalStateException("core release page exceeds 100 entries");
            }
            acceptedPages = page;
            if (page > MAX_RELEASE_PAGES) {
                if (count != 0) {
                    throw new IllegalStateException(
                            "core release history exceeds 1000 entries");
                }
                complete = true;
                return 0;
            }
            if (totalEntries > MAX_RELEASES_PER_PAGE * MAX_RELEASE_PAGES - count) {
                throw new IllegalStateException("core release pagination exceeds limits");
            }
            totalEntries += count;
            for (int index = 0; index < count; index++) {
                consider(releases.optJSONObject(index));
            }
            if (count < MAX_RELEASES_PER_PAGE) complete = true;
            return count;
        }

        void consider(JSONObject candidate) {
            if (candidate == null || candidate.optBoolean("draft", false)
                    || candidate.optBoolean("prerelease", false)) return;
            ReleaseVersion parsed = ReleaseVersion.parse(
                    candidate.optString("tag_name", ""), family);
            if (parsed != null && (bestVersion == null || parsed.compareTo(bestVersion) > 0)) {
                best = candidate;
                bestVersion = parsed;
            }
        }

        JSONObject finish() {
            if (!complete) {
                throw new IllegalStateException("core release pagination is truncated");
            }
            return bestOrThrow();
        }

        JSONObject bestOrThrow() {
            if (best != null) return best;
            throw new IllegalStateException(
                    "stable " + family.displayName + " release is missing");
        }

        long totalBytes() {
            return totalBytes;
        }

        int totalEntries() {
            return totalEntries;
        }
    }

    private static final class ReleaseVersion implements Comparable<ReleaseVersion> {
        final int major;
        final int minor;
        final int patch;
        final int wrapper;

        ReleaseVersion(int major, int minor, int patch, int wrapper) {
            this.major = major;
            this.minor = minor;
            this.patch = patch;
            this.wrapper = wrapper;
        }

        static ReleaseVersion parse(String value, CoreFamily family) {
            if (value == null || family == null) return null;
            String prefix = family == CoreFamily.XRAY ? "xray-v" : "sb-v";
            if (!value.startsWith(prefix)) return null;
            int wrapperAt = value.lastIndexOf("-w");
            if (wrapperAt <= prefix.length() || wrapperAt + 2 >= value.length()) return null;
            String[] version = value.substring(prefix.length(), wrapperAt).split("\\.", -1);
            if (version.length != 3) return null;
            try {
                int major = Integer.parseInt(version[0]);
                int minor = Integer.parseInt(version[1]);
                int patch = Integer.parseInt(version[2]);
                int wrapper = Integer.parseInt(value.substring(wrapperAt + 2));
                if (major < 0 || minor < 0 || patch < 0 || wrapper <= 0) return null;
                return new ReleaseVersion(major, minor, patch, wrapper);
            } catch (NumberFormatException invalid) {
                return null;
            }
        }

        @Override
        public int compareTo(ReleaseVersion other) {
            int result = Integer.compare(major, other.major);
            if (result == 0) result = Integer.compare(minor, other.minor);
            if (result == 0) result = Integer.compare(patch, other.patch);
            if (result == 0) result = Integer.compare(wrapper, other.wrapper);
            return result;
        }
    }

    private interface InspectedStateOperation<T> {
        T run(InspectedState state) throws Exception;
    }

    private static final class FileStamp {
        final File file;
        final boolean regularFile;
        final long length;
        final long modified;

        private FileStamp(File file, boolean regularFile, long length, long modified) {
            this.file = file;
            this.regularFile = regularFile;
            this.length = length;
            this.modified = modified;
        }

        static FileStamp capture(File file) {
            boolean regular = file != null && file.isFile();
            return new FileStamp(file, regular, regular ? file.length() : -1L,
                    regular ? file.lastModified() : -1L);
        }

        boolean matches(File current) {
            boolean regular = current != null && current.isFile();
            return regular == regularFile && (!regular
                    || (current.length() == length && current.lastModified() == modified));
        }
    }

    private static final class CoreCandidateSnapshot {
        final FileStamp fileStamp;
        final String digest;
        final String version;
        final String origin;
        final int coreApi;
        final int manifestSchema;
        final int minAndroidApi;
        final String androidAbi;

        CoreCandidateSnapshot(FileStamp fileStamp, String digest, String version,
                              String origin, int coreApi, int manifestSchema,
                              int minAndroidApi, String androidAbi) {
            this.fileStamp = fileStamp;
            this.digest = digest;
            this.version = version;
            this.origin = origin;
            this.coreApi = coreApi;
            this.manifestSchema = manifestSchema;
            this.minAndroidApi = minAndroidApi;
            this.androidAbi = androidAbi;
        }

        boolean metadataMatches(JSONObject current, String prefix, int fallbackApi) {
            return digest.equals(current.optString(prefix + "Digest", ""))
                    && version.equals(current.optString(prefix + "Version", ""))
                    && origin.equals(current.optString(prefix + "Origin", ""))
                    && coreApi == current.optInt(prefix + "CoreApi", fallbackApi)
                    && manifestSchema == current.optInt(prefix + "ManifestSchema", 0)
                    && minAndroidApi == current.optInt(prefix + "MinAndroidApi", 0)
                    && androidAbi.equals(current.optString(prefix + "Abi", ""));
        }
    }

    private static final class CoreStateSnapshot {
        final CoreCandidateSnapshot active;
        final CoreCandidateSnapshot pending;
        final CoreCandidateSnapshot backup;
        final String transaction;

        CoreStateSnapshot(CoreCandidateSnapshot active, CoreCandidateSnapshot pending,
                          CoreCandidateSnapshot backup, String transaction) {
            this.active = active;
            this.pending = pending;
            this.backup = backup;
            this.transaction = transaction;
        }

        static CoreStateSnapshot capture(CoreUpdater updater, JSONObject metadata) {
            JSONObject journal = metadata.optJSONObject("transaction");
            return new CoreStateSnapshot(
                    new CoreCandidateSnapshot(FileStamp.capture(updater.activeFile()),
                            metadata.optString("activeDigest", ""),
                            metadata.optString("activeVersion", ""),
                            metadata.optString("activeOrigin", ""),
                            metadata.optInt("activeCoreApi", 1),
                            metadata.optInt("activeManifestSchema", 0),
                            metadata.optInt("activeMinAndroidApi", 0),
                            metadata.optString("activeAbi", "")),
                    new CoreCandidateSnapshot(FileStamp.capture(updater.pendingFile()),
                            metadata.optString("pendingDigest", ""),
                            metadata.optString("pendingVersion", ""),
                            metadata.optString("pendingOrigin", ""),
                            metadata.optInt("pendingCoreApi", 1),
                            metadata.optInt("pendingManifestSchema", 0),
                            metadata.optInt("pendingMinAndroidApi", 0),
                            metadata.optString("pendingAbi", "")),
                    new CoreCandidateSnapshot(FileStamp.capture(updater.backupFile()),
                            metadata.optString("backupDigest", ""),
                            metadata.optString("backupVersion", ""),
                            metadata.optString("backupOrigin", ""),
                            metadata.optInt("backupCoreApi", 1),
                            metadata.optInt("backupManifestSchema", 0),
                            metadata.optInt("backupMinAndroidApi", 0),
                            metadata.optString("backupAbi", "")),
                    journal == null ? "" : journal.toString());
        }

        boolean matches(CoreUpdater updater, JSONObject current) {
            JSONObject journal = current.optJSONObject("transaction");
            String currentTransaction = journal == null ? "" : journal.toString();
            return active.fileStamp.matches(updater.activeFile())
                    && pending.fileStamp.matches(updater.pendingFile())
                    && backup.fileStamp.matches(updater.backupFile())
                    && active.metadataMatches(current, "active", 1)
                    && pending.metadataMatches(current, "pending", 1)
                    && backup.metadataMatches(current, "backup", 1)
                    && transaction.equals(currentTransaction);
        }
    }

    private static final class CandidateInspection {
        final CoreCandidateSnapshot snapshot;
        final boolean valid;
        final boolean fileValid;
        final boolean conclusive;
        final String actualDigest;
        final String error;
        final String digest;
        final String version;
        final String origin;
        final int coreApi;
        final int manifestSchema;
        final int minAndroidApi;
        final String androidAbi;

        CandidateInspection(CoreCandidateSnapshot snapshot, boolean valid, boolean fileValid,
                            boolean conclusive, String actualDigest, String error) {
            this.snapshot = snapshot;
            this.valid = valid;
            this.fileValid = fileValid;
            this.conclusive = conclusive;
            this.actualDigest = actualDigest == null ? "" : actualDigest;
            this.error = error == null ? "" : error;
            this.digest = snapshot.digest;
            this.version = snapshot.version;
            this.origin = snapshot.origin;
            this.coreApi = snapshot.coreApi;
            this.manifestSchema = snapshot.manifestSchema;
            this.minAndroidApi = snapshot.minAndroidApi;
            this.androidAbi = snapshot.androidAbi;
        }

        boolean matchesDigest(String expected) {
            return fileValid && isDigest(expected) && expected.equals(actualDigest);
        }

        boolean hasInvalidOwnedVersion(CoreFamily family) {
            return valid && coreApi == CORE_API && manifestSchema == MANIFEST_SCHEMA
                    && minAndroidApi == MIN_ANDROID_API && ANDROID_ABI.equals(androidAbi)
                    && CORE_ORIGIN.equals(origin)
                    && ReleaseVersion.parse(version, family) == null;
        }
    }

    private static final class InspectedState {
        final CandidateInspection active;
        final CandidateInspection pending;
        final CandidateInspection backup;

        InspectedState(CandidateInspection active, CandidateInspection pending,
                       CandidateInspection backup) {
            this.active = active;
            this.pending = pending;
            this.backup = backup;
        }

        boolean hasInconclusiveFile() {
            return (active.snapshot.fileStamp.regularFile && !active.conclusive)
                    || (pending.snapshot.fileStamp.regularFile && !pending.conclusive)
                    || (backup.snapshot.fileStamp.regularFile && !backup.conclusive);
        }
    }

    private static void putOrRemove(JSONObject object, String key, String value) throws Exception {
        if (value == null || value.isEmpty()) object.remove(key);
        else object.put(key, value);
    }

    private static String parseDigest(String value) {
        return value != null && value.startsWith("sha256:")
                ? value.substring("sha256:".length()).toLowerCase(Locale.US) : "";
    }

    private static boolean isDigest(String value) {
        return value != null && value.matches("(?i)[0-9a-f]{64}");
    }

    private boolean isRejectedCurrentContract() {
        return isDigest(metadata.optString("rejectedDigest", ""))
                && metadata.optInt("rejectedCoreApi", 0) == CORE_API
                && metadata.optInt("rejectedManifestSchema", 0) == MANIFEST_SCHEMA
                && metadata.optInt("rejectedMinAndroidApi", 0) == MIN_ANDROID_API
                && ANDROID_ABI.equals(metadata.optString("rejectedAbi", ""));
    }

    private static void ensureParent(File value) {
        File parent = value.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs() && !parent.isDirectory()) {
            throw new IllegalStateException("cannot create core directory");
        }
    }

    private void reloadMetadata() throws Exception {
        metadata = store.readJson(metadataPath());
        refreshReadinessSnapshot();
    }

    private void saveMetadata() throws Exception {
        store.writeJson(metadataPath(), metadata);
        refreshReadinessSnapshot();
    }

    private void refreshReadinessSnapshot() {
        boolean activeSupported = activeFile().isFile() && metadataContract("active");
        boolean pendingSupported = pendingFile().isFile() && metadataContract("pending");
        boolean backupSupported = backupFile().isFile() && metadataContract("backup");
        boolean unsupportedPresent = (activeFile().isFile() && !activeSupported)
                || (pendingFile().isFile() && !pendingSupported)
                || (backupFile().isFile() && !backupSupported)
                || metadata.optBoolean("requiresNewCore", false);
        boolean requiresNewCore = !activeSupported && !pendingSupported && unsupportedPresent;
        boolean rollbackRequested = metadata.optBoolean("rollbackRequested", false);
        readinessSnapshot = new ReadinessSnapshot(
                activeSupported ? metadata.optString("activeVersion", "—") : "—",
                activeSupported && metadata.optBoolean("candidate", false),
                activeSupported ? metadata.optInt("activeCoreApi", 0) : 0,
                requiresNewCore,
                (activeSupported && !rollbackRequested)
                        || pendingSupported
                        || (rollbackRequested && backupSupported));
    }

    private boolean metadataContract(String prefix) {
        return metadata.optInt(prefix + "CoreApi", 0) == CORE_API
                && metadata.optInt(prefix + "ManifestSchema", 0) == MANIFEST_SCHEMA
                && metadata.optInt(prefix + "MinAndroidApi", 0) == MIN_ANDROID_API
                && ANDROID_ABI.equals(metadata.optString(prefix + "Abi", ""))
                && CORE_ORIGIN.equals(metadata.optString(prefix + "Origin", ""))
                && isDigest(metadata.optString(prefix + "Digest", ""));
    }

    private static final class ReadinessSnapshot {
        final String version;
        final boolean candidate;
        final int coreApi;
        final boolean requiresNewCore;
        final boolean usable;

        ReadinessSnapshot(String version, boolean candidate, int coreApi,
                          boolean requiresNewCore, boolean usable) {
            this.version = version;
            this.candidate = candidate;
            this.coreApi = coreApi;
            this.requiresNewCore = requiresNewCore;
            this.usable = usable;
        }
    }

    enum UpdateStage {
        PREPARING,
        DOWNLOADING,
        VERIFYING
    }

    interface UpdateObserver {
        void onStage(UpdateStage stage);

        void onProgress(long downloadedBytes, long totalBytes);
    }

    private static final class PrepareResult {
        final boolean retry;
        final LoadTarget target;

        private PrepareResult(boolean retry, LoadTarget target) {
            this.retry = retry;
            this.target = target;
        }

        static PrepareResult retry() {
            return new PrepareResult(true, null);
        }

        static PrepareResult complete(LoadTarget target) {
            return new PrepareResult(false, target);
        }
    }

    static final class LoadTarget {
        final File file;
        final int coreApi;
        final String digest;

        LoadTarget(File file, int coreApi) {
            this(file, coreApi, "");
        }

        LoadTarget(File file, int coreApi, String digest) {
            if (file == null) throw new IllegalArgumentException("core file is missing");
            if (coreApi != 1 && coreApi != 2) {
                throw new IllegalArgumentException("unsupported core API");
            }
            this.file = file;
            this.coreApi = coreApi;
            this.digest = digest == null ? "" : digest.toLowerCase(Locale.US);
        }
    }

    static final class PinnedLoadTarget implements Closeable {
        final File file;
        final int coreApi;
        final String digest;
        private final CoreFileHandle handle;

        private PinnedLoadTarget(File file, int coreApi, String digest,
                                 CoreFileHandle handle) {
            this.file = file;
            this.coreApi = coreApi;
            this.digest = digest == null ? "" : digest;
            this.handle = handle;
        }

        /** Unit-test seam: production preparation always supplies a handle. */
        static PinnedLoadTarget forTests(LoadTarget target) {
            return target == null ? null : new PinnedLoadTarget(
                    target.file, target.coreApi, target.digest, null);
        }

        FileDescriptor descriptor() {
            return handle == null ? null : handle.descriptor();
        }

        boolean isDescriptorPinned() {
            return handle != null;
        }

        @Override
        public void close() throws IOException {
            if (handle != null) handle.close();
        }
    }

    interface CommitHook {
        CommitHook NOOP = () -> {
        };

        void beforeFinalCommit() throws Exception;
    }

    interface InspectionHook {
        InspectionHook NOOP = file -> {
        };

        void beforeInspect(File file) throws Exception;
    }

    private static final class FamilyLocks {
        final ReentrantLock update = new ReentrantLock(true);
        final ReentrantLock transaction = new ReentrantLock(true);
    }

    private static String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                if (read > 0) digest.update(buffer, 0, read);
            }
        }
        return hex(digest.digest());
    }

    private static String sha256(byte[] value) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static String hex(byte[] value) {
        StringBuilder output = new StringBuilder(value.length * 2);
        for (byte item : value) output.append(String.format(Locale.US, "%02x", item & 255));
        return output.toString();
    }
}
