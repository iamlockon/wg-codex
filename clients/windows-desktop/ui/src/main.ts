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

const app = document.getElementById("app")!;

app.innerHTML = `
  <h1>WG Windows Client</h1>
  <p class="subtitle">Desktop flow: OAuth callback -> device -> connect -> disconnect/logout</p>
  <div class="layout">
    <section class="card">
      <h2>Auth</h2>
      <div class="grid">
        <div><label>Provider</label><input id="provider" value="google" /></div>
        <div><label>OAuth code</label><input id="code" placeholder="paste callback code" /></div>
        <div><label>Code verifier (optional)</label><input id="code_verifier" /></div>
        <div><label>Nonce (optional)</label><input id="nonce" /></div>
      </div>
      <div class="actions">
        <button id="btn-login">Login</button>
        <button id="btn-restore" class="secondary">Restore+Reconnect</button>
        <button id="btn-logout" class="danger">Logout</button>
      </div>

      <h2 style="margin-top:14px">Device</h2>
      <div class="grid">
        <div><label>Name</label><input id="device_name" value="desktop" /></div>
        <div><label>Public key</label><input id="device_pub" placeholder="base64 WireGuard public key" /></div>
      </div>
      <div class="actions">
        <button id="btn-register" class="ok">Register device</button>
        <button id="btn-list" class="secondary">List devices</button>
      </div>

      <h2 style="margin-top:14px">Session</h2>
      <div class="grid">
        <div><label>Region</label><input id="region" value="us-west1" /></div>
        <div><label>Select device ID</label><input id="selected_device" placeholder="device id" /></div>
      </div>
      <div class="actions">
        <button id="btn-select" class="secondary">Select device</button>
        <button id="btn-connect" class="ok">Connect</button>
        <button id="btn-disconnect" class="warn">Disconnect</button>
      </div>
    </section>

    <section class="card">
      <h2>Status</h2>
      <div id="status"></div>

      <h2 style="margin-top:14px">Devices</h2>
      <ul class="list" id="devices"></ul>

      <h2 style="margin-top:14px">Log</h2>
      <div class="log" id="log"></div>
    </section>
  </div>
`;

const logEl = document.getElementById("log")!;
const statusEl = document.getElementById("status")!;
const devicesEl = document.getElementById("devices")!;

let devices: Device[] = [];
let status: UiStatus | null = null;

const el = (id: string) => document.getElementById(id) as HTMLInputElement;

function appendLog(line: string) {
  const ts = new Date().toISOString();
  logEl.textContent = `[${ts}] ${line}\n` + logEl.textContent;
}

function renderStatus() {
  if (!status) {
    statusEl.innerHTML = "<div class='status-row'><span class='key'>state</span><span>unknown</span></div>";
    return;
  }
  statusEl.innerHTML = `
    <div class="status-row"><span class="key">authenticated</span><span>${String(status.authenticated)}</span></div>
    <div class="status-row"><span class="key">customer_id</span><span>${status.customer_id ?? "-"}</span></div>
    <div class="status-row"><span class="key">selected_device_id</span><span>${status.selected_device_id ?? "-"}</span></div>
    <div class="status-row"><span class="key">active_session_key</span><span>${status.active_session_key ?? "-"}</span></div>
    <div class="status-row"><span class="key">last_region</span><span>${status.last_region ?? "-"}</span></div>
  `;
}

function renderDevices() {
  devicesEl.innerHTML = "";
  for (const d of devices) {
    const li = document.createElement("li");
    li.textContent = `${d.name} | ${d.id} | created=${d.created_at}`;
    devicesEl.appendChild(li);
  }
}

async function refreshStatus() {
  status = await invoke<UiStatus>("get_status");
  renderStatus();
}

async function safe(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    appendLog(`${name}: ok`);
  } catch (e) {
    appendLog(`${name}: ${String(e)}`);
  }
}

document.getElementById("btn-login")!.addEventListener("click", () =>
  safe("oauth_login", async () => {
    status = await invoke<UiStatus>("oauth_login", {
      input: {
        provider: el("provider").value,
        code: el("code").value,
        codeVerifier: el("code_verifier").value || null,
        nonce: el("nonce").value || null,
      },
    });
    renderStatus();
  }),
);

document.getElementById("btn-logout")!.addEventListener("click", () =>
  safe("logout", async () => {
    status = await invoke<UiStatus>("logout");
    devices = [];
    renderStatus();
    renderDevices();
  }),
);

document.getElementById("btn-restore")!.addEventListener("click", () =>
  safe("restore_and_reconnect", async () => {
    status = await invoke<UiStatus>("restore_and_reconnect");
    renderStatus();
  }),
);

document.getElementById("btn-register")!.addEventListener("click", () =>
  safe("register_device", async () => {
    const device = await invoke<Device>("register_device", {
      input: {
        name: el("device_name").value,
        publicKey: el("device_pub").value,
      },
    });
    devices = [device, ...devices.filter((d) => d.id !== device.id)];
    el("selected_device").value = device.id;
    renderDevices();
    await refreshStatus();
  }),
);

document.getElementById("btn-list")!.addEventListener("click", () =>
  safe("list_devices", async () => {
    devices = await invoke<Device[]>("list_devices");
    renderDevices();
  }),
);

document.getElementById("btn-select")!.addEventListener("click", () =>
  safe("select_device", async () => {
    status = await invoke<UiStatus>("select_device", {
      input: { deviceId: el("selected_device").value },
    });
    renderStatus();
  }),
);

document.getElementById("btn-connect")!.addEventListener("click", () =>
  safe("connect", async () => {
    const result = await invoke<{ session_key: string }>("connect", {
      input: { region: el("region").value },
    });
    appendLog(`connected session=${result.session_key}`);
    await refreshStatus();
  }),
);

document.getElementById("btn-disconnect")!.addEventListener("click", () =>
  safe("disconnect", async () => {
    status = await invoke<UiStatus>("disconnect");
    renderStatus();
  }),
);

safe("init", async () => {
  await refreshStatus();
  renderDevices();
});
