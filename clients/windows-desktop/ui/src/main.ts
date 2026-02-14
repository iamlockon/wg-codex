import { invoke } from "@tauri-apps/api/core";

type UiStatus = {
  authenticated: boolean;
  customer_id: string | null;
  selected_device_id: string | null;
  active_session_key: string | null;
  last_region: string | null;
};

type Device = {
  id: string;
  customer_id: string;
  name: string;
  public_key: string;
  created_at: string;
};

type PendingOAuth = {
  codeVerifier: string;
  nonce: string;
  state: string;
};

const GOOGLE_CLIENT_ID = (import.meta.env.VITE_GOOGLE_OIDC_CLIENT_ID as string | undefined) ?? "";
const GOOGLE_REDIRECT_URI =
  (import.meta.env.VITE_GOOGLE_OIDC_REDIRECT_URI as string | undefined) ?? "";
const PENDING_OAUTH_STORAGE_KEY = "wg.pendingOAuth";

const app = document.getElementById("app")!;

app.innerHTML = `
  <h1>WG Desktop VPN</h1>
  <p class="subtitle">Sign in with Google, select device, choose location, then connect and disconnect VPN.</p>
  <div class="layout">
    <section class="card">
      <h2>1. Google Login</h2>
      <p class="section-note">Continue to Google, sign in, and return to the app automatically.</p>
      <div class="actions">
        <button id="btn-google-start">Sign Up / Log In With Google</button>
        <button id="btn-restore" class="secondary">Restore Session</button>
        <button id="btn-logout" class="danger">Logout</button>
      </div>

      <fieldset id="device-section" class="step-fieldset">
        <h2 style="margin-top:14px">2. Device (Auto)</h2>
        <p class="section-note">This app auto-registers and auto-selects the current device. Use Create New Device if key migration is needed.</p>
        <div class="actions">
          <button id="btn-create-device" class="ok">Create New Device</button>
          <button id="btn-list" class="secondary">Refresh Devices</button>
        </div>
        <ul id="devices" class="device-list"></ul>
      </fieldset>

      <fieldset id="session-section" class="step-fieldset">
        <h2 style="margin-top:14px">3. Location & Connection</h2>
        <p class="section-note">Choose VPN location and connect.</p>
        <div id="connection-banner" class="connection-banner disconnected">Disconnected</div>
        <div class="grid">
          <div>
            <label>Region</label>
            <select id="region">
              <option value="us-west1">US West</option>
              <option value="us-central1">US Central</option>
              <option value="us-east1">US East</option>
              <option value="europe-west1">Europe West</option>
              <option value="asia-east1">Asia East</option>
            </select>
          </div>
          <div><label>Selected device ID</label><input id="selected_device" readonly /></div>
        </div>
        <div class="actions">
          <button id="btn-connect" class="ok">Connect</button>
          <button id="btn-disconnect" class="warn">Disconnect</button>
        </div>
      </fieldset>
    </section>

    <section class="card">
      <h2>Status</h2>
      <div id="status"></div>

      <h2 style="margin-top:14px">Log</h2>
      <div class="log" id="log"></div>
    </section>
  </div>
`;

const logEl = document.getElementById("log")!;
const statusEl = document.getElementById("status")!;
const devicesEl = document.getElementById("devices");

let devices: Device[] = [];
let status: UiStatus | null = null;
let pendingOAuth: PendingOAuth | null = null;

const el = (id: string) => document.getElementById(id) as HTMLInputElement;
const deviceSection = document.getElementById("device-section") as HTMLFieldSetElement;
const sessionSection = document.getElementById("session-section") as HTMLFieldSetElement;
const googleStartBtn = document.getElementById("btn-google-start") as HTMLButtonElement;
const restoreBtn = document.getElementById("btn-restore") as HTMLButtonElement;
const logoutBtn = document.getElementById("btn-logout") as HTMLButtonElement;
const createDeviceBtn = document.getElementById("btn-create-device") as HTMLButtonElement;
const connectBtn = document.getElementById("btn-connect") as HTMLButtonElement;
const disconnectBtn = document.getElementById("btn-disconnect") as HTMLButtonElement;
const connectionBanner = document.getElementById("connection-banner") as HTMLDivElement;

function appendLog(line: string) {
  const ts = new Date().toISOString();
  logEl.textContent = `[${ts}] ${line}\n` + logEl.textContent;
}

function renderStatus() {
  if (!status) {
    statusEl.innerHTML = "<div class='status-row'><span class='key'>state</span><span>unknown</span></div>";
    connectionBanner.textContent = "Disconnected";
    connectionBanner.classList.remove("connected");
    connectionBanner.classList.add("disconnected");
    return;
  }
  const connectionState = status.active_session_key ? "Connected" : "Disconnected";
  const authState = status.authenticated ? "Authenticated" : "Signed out";
  connectionBanner.textContent = connectionState;
  connectionBanner.classList.toggle("connected", Boolean(status.active_session_key));
  connectionBanner.classList.toggle("disconnected", !status.active_session_key);
  statusEl.innerHTML = `
    <div class="status-row"><span class="key">auth</span><span>${authState}</span></div>
    <div class="status-row"><span class="key">connection</span><span>${connectionState}</span></div>
    <div class="status-row"><span class="key">customer_id</span><span>${status.customer_id ?? "-"}</span></div>
    <div class="status-row"><span class="key">selected_device_id</span><span>${status.selected_device_id ?? "-"}</span></div>
    <div class="status-row"><span class="key">session_key</span><span>${status.active_session_key ?? "-"}</span></div>
    <div class="status-row"><span class="key">last_region</span><span>${status.last_region ?? "-"}</span></div>
  `;
}

function syncInteractivity() {
  const hasAuth = Boolean(status?.authenticated);
  const hasDevice = Boolean(status?.selected_device_id);
  const hasSession = Boolean(status?.active_session_key);
  deviceSection.disabled = !hasAuth;
  sessionSection.disabled = !hasAuth || !hasDevice;
  restoreBtn.disabled = !hasAuth;
  logoutBtn.disabled = !hasAuth;
  createDeviceBtn.disabled = !hasAuth;
  connectBtn.disabled = !hasAuth || !hasDevice || hasSession;
  disconnectBtn.disabled = !hasSession;
  googleStartBtn.disabled = hasAuth;
  el("selected_device").value = status?.selected_device_id ?? "";
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function randomUrlSafeString(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

async function sha256Base64Url(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return toBase64Url(new Uint8Array(digest));
}

function parseCodeAndStateFromCallbackUrl(url: URL): { code: string; state: string | null } {
  const code = url.searchParams.get("code");
  if (!code) {
    throw new Error("missing_oauth_code_in_callback");
  }
  return { code, state: url.searchParams.get("state") };
}

function loadPendingOAuthFromStorage(): PendingOAuth | null {
  const raw = sessionStorage.getItem(PENDING_OAUTH_STORAGE_KEY);
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as PendingOAuth;
    if (!parsed.codeVerifier || !parsed.nonce || !parsed.state) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function savePendingOAuthToStorage(value: PendingOAuth): void {
  sessionStorage.setItem(PENDING_OAUTH_STORAGE_KEY, JSON.stringify(value));
}

function clearPendingOAuthFromStorage(): void {
  sessionStorage.removeItem(PENDING_OAUTH_STORAGE_KEY);
}

function cleanupOAuthQueryParams(): void {
  const current = new URL(window.location.href);
  const params = current.searchParams;
  const keys = ["code", "state", "scope", "authuser", "prompt", "hd"];
  let changed = false;
  for (const key of keys) {
    if (params.has(key)) {
      params.delete(key);
      changed = true;
    }
  }
  if (changed) {
    const next = `${current.pathname}${params.toString() ? `?${params.toString()}` : ""}${current.hash}`;
    window.history.replaceState({}, document.title, next);
  }
}

function clearOAuthTransientState(): void {
  clearPendingOAuthFromStorage();
  pendingOAuth = null;
  cleanupOAuthQueryParams();
}

function isValidWireGuardPublicKey(value: string): boolean {
  const raw = value.trim();
  if (!raw) {
    return false;
  }
  try {
    const normalized = raw.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    const decoded = atob(padded);
    return decoded.length === 32;
  } catch {
    return false;
  }
}

async function maybeCompleteOAuthFromReturnUrl() {
  const current = new URL(window.location.href);
  if (!current.searchParams.has("code")) {
    pendingOAuth = loadPendingOAuthFromStorage();
    return;
  }

  const code = current.searchParams.get("code");
  const returnedState = current.searchParams.get("state");
  if (!code || !returnedState) {
    appendLog("google_oauth_complete: ignored (missing code/state)");
    clearOAuthTransientState();
    return;
  }

  const callback = parseCodeAndStateFromCallbackUrl(current);
  const pending = loadPendingOAuthFromStorage();
  if (!pending) {
    appendLog("google_oauth_complete: ignored (oauth_not_started)");
    cleanupOAuthQueryParams();
    return;
  }
  if (callback.state !== pending.state) {
    appendLog("google_oauth_complete: ignored (oauth_state_mismatch)");
    clearOAuthTransientState();
    return;
  }

  try {
    status = await invoke<UiStatus>("oauth_login", {
      input: {
        provider: "google",
        code: callback.code,
        codeVerifier: pending.codeVerifier,
        nonce: pending.nonce,
      },
    });
  } catch (e) {
    appendLog(`google_oauth_complete: ${String(e)}`);
    clearOAuthTransientState();
    return;
  }

  clearOAuthTransientState();
  renderStatus();
  syncInteractivity();
  appendLog("google_oauth_complete: ok");
  await refreshDevices();
}

function renderDevices() {
  if (!devicesEl) {
    return;
  }
  devicesEl.innerHTML = "";
  if (!devices.length) {
    const li = document.createElement("li");
    li.textContent = "No registered devices yet.";
    devicesEl.appendChild(li);
    return;
  }
  for (const d of devices) {
    const li = document.createElement("li");
    li.className = "device-item";
    const selected = status?.selected_device_id === d.id;
    const created = new Date(d.created_at).toLocaleString();
    li.innerHTML = `
      <div class="device-main">
        <strong>${d.name}</strong>
        <span class="device-meta">${selected ? "Auto-selected" : created}</span>
      </div>
      <div class="device-id">${d.id}</div>
    `;
    devicesEl.appendChild(li);
  }
}

async function ensureAutoSelectedDevice() {
  if (!status?.authenticated || !devices.length) {
    return;
  }

  const validDevices = devices.filter((d) => isValidWireGuardPublicKey(d.public_key));
  if (!validDevices.length) {
    const created = await invoke<Device>("register_default_device");
    appendLog(`register_default_device: ${created.id}`);
    devices = [created, ...devices];
    await refreshStatus();
    renderDevices();
    return ensureAutoSelectedDevice();
  }

  const selected = status.selected_device_id
    ? devices.find((d) => d.id === status?.selected_device_id)
    : undefined;
  if (selected && !isValidWireGuardPublicKey(selected.public_key)) {
    appendLog(`selected_device_invalid_key: ${selected.id}`);
  }

  if (
    selected &&
    isValidWireGuardPublicKey(selected.public_key) &&
    status.selected_device_id &&
    devices.some((d) => d.id === status?.selected_device_id)
  ) {
    return;
  }

  const preferred = [...validDevices].sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
  )[0];
  status = await invoke<UiStatus>("select_device", {
    input: { deviceId: preferred.id },
  });
  appendLog(`auto_selected_device: ${preferred.id}`);
  renderStatus();
  syncInteractivity();
  renderDevices();
}

async function refreshStatus() {
  status = await invoke<UiStatus>("get_status");
  renderStatus();
  syncInteractivity();
}

async function refreshDevices() {
  if (!status?.authenticated) {
    devices = [];
    renderDevices();
    return;
  }
  devices = await invoke<Device[]>("list_devices");
  if (!devices.length) {
    const created = await invoke<Device>("register_default_device");
    appendLog(`register_default_device: ${created.id}`);
    devices = [created];
    await refreshStatus();
  }
  await ensureAutoSelectedDevice();
  renderDevices();
}

async function createAndSelectDefaultDevice() {
  const created = await invoke<Device>("register_default_device");
  appendLog(`register_default_device: ${created.id}`);
  await refreshStatus();
  await refreshDevices();
}

async function safe(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    appendLog(`${name}: ok`);
  } catch (e) {
    if (name.startsWith("google_oauth")) {
      clearOAuthTransientState();
    }
    const msg = String(e);
    appendLog(`${name}: ${msg}`);
    if (name === "connect" && msg.includes("missing wireguard private key")) {
      appendLog("hint: click 'Create New Device', then connect again");
    }
  }
}

document.getElementById("btn-google-start")!.addEventListener("click", () =>
  safe("google_oauth_start", async () => {
    if (!GOOGLE_CLIENT_ID || !GOOGLE_REDIRECT_URI) {
      throw new Error(
        "missing_google_oauth_ui_config (set VITE_GOOGLE_OIDC_CLIENT_ID and VITE_GOOGLE_OIDC_REDIRECT_URI)",
      );
    }
    const codeVerifier = randomUrlSafeString(64);
    const codeChallenge = await sha256Base64Url(codeVerifier);
    const nonce = randomUrlSafeString(24);
    const state = randomUrlSafeString(24);
    pendingOAuth = { codeVerifier, nonce, state };
    savePendingOAuthToStorage(pendingOAuth);

    const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    authUrl.searchParams.set("client_id", GOOGLE_CLIENT_ID);
    authUrl.searchParams.set("redirect_uri", GOOGLE_REDIRECT_URI);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("scope", "openid email profile");
    authUrl.searchParams.set("code_challenge", codeChallenge);
    authUrl.searchParams.set("code_challenge_method", "S256");
    authUrl.searchParams.set("nonce", nonce);
    authUrl.searchParams.set("state", state);

    appendLog(`google_oauth_start_url: ${authUrl.toString()}`);
    appendLog("google_oauth_start: redirecting to Google sign in");
    syncInteractivity();
    window.location.assign(authUrl.toString());
  }),
);

document.getElementById("btn-logout")!.addEventListener("click", () =>
  safe("logout", async () => {
    status = await invoke<UiStatus>("logout");
    clearOAuthTransientState();
    devices = [];
    renderStatus();
    renderDevices();
    syncInteractivity();
  }),
);

document.getElementById("btn-restore")!.addEventListener("click", () =>
  safe("restore_and_reconnect", async () => {
    status = await invoke<UiStatus>("restore_and_reconnect");
    renderStatus();
    syncInteractivity();
    await refreshDevices();
  }),
);

document.getElementById("btn-list")!.addEventListener("click", () =>
  safe("list_devices", async () => refreshDevices()),
);

document.getElementById("btn-create-device")!.addEventListener("click", () =>
  safe("register_default_device", async () => createAndSelectDefaultDevice()),
);

document.getElementById("btn-connect")!.addEventListener("click", () =>
  safe("connect", async () => {
    const result = await invoke<{ session_key: string }>("connect", {
      input: { region: el("region").value },
    });
    appendLog(`connected session=${result.session_key}`);
    await refreshStatus();
    await refreshDevices();
  }),
);

document.getElementById("btn-disconnect")!.addEventListener("click", () =>
  safe("disconnect", async () => {
    status = await invoke<UiStatus>("disconnect");
    renderStatus();
    syncInteractivity();
  }),
);

safe("init", async () => {
  await refreshStatus();
  await maybeCompleteOAuthFromReturnUrl();
  await refreshDevices();
});
