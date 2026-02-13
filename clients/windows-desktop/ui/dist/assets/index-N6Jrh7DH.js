(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const s of document.querySelectorAll('link[rel="modulepreload"]'))g(s);new MutationObserver(s=>{for(const o of s)if(o.type==="childList")for(const b of o.addedNodes)b.tagName==="LINK"&&b.rel==="modulepreload"&&g(b)}).observe(document,{childList:!0,subtree:!0});function i(s){const o={};return s.integrity&&(o.integrity=s.integrity),s.referrerPolicy&&(o.referrerPolicy=s.referrerPolicy),s.crossOrigin==="use-credentials"?o.credentials="include":s.crossOrigin==="anonymous"?o.credentials="omit":o.credentials="same-origin",o}function g(s){if(s.ep)return;s.ep=!0;const o=i(s);fetch(s.href,o)}})();async function c(e,t={},i){return window.__TAURI_INTERNALS__.invoke(e,t,i)}const E=document.getElementById("app");E.innerHTML=`
  <h1>WG Desktop VPN</h1>
  <p class="subtitle">Sign in with Google, choose a device, then pick location and connect.</p>
  <div class="layout">
    <section class="card">
      <h2>1. Google Login</h2>
      <p class="section-note">Complete Google sign-in in your browser, then paste the callback code below.</p>
      <div class="grid one-col">
        <div><label>OAuth callback code</label><input id="code" placeholder="paste callback code" /></div>
        <div><label>PKCE code verifier (optional)</label><input id="code_verifier" /></div>
        <div><label>Nonce (optional)</label><input id="nonce" /></div>
      </div>
      <div class="actions">
        <button id="btn-login">Login With Google</button>
        <button id="btn-restore" class="secondary">Restore Session</button>
        <button id="btn-logout" class="danger">Logout</button>
      </div>

      <fieldset id="device-section" class="step-fieldset">
        <h2 style="margin-top:14px">2. Select Device</h2>
        <p class="section-note">Pick an existing device or register this machine.</p>
        <div class="actions">
          <button id="btn-list" class="secondary">Refresh Devices</button>
        </div>
        <div class="grid" style="margin-top:8px">
          <div><label>New device name</label><input id="device_name" value="desktop" /></div>
          <div><label>WireGuard public key</label><input id="device_pub" placeholder="base64 WireGuard public key" /></div>
        </div>
        <div class="actions">
          <button id="btn-register" class="ok">Register Device</button>
        </div>
      </fieldset>

      <fieldset id="session-section" class="step-fieldset">
        <h2 style="margin-top:14px">3. Location & Connection</h2>
        <p class="section-note">Choose VPN location and connect.</p>
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

      <h2 style="margin-top:14px">Devices</h2>
      <ul class="list" id="devices"></ul>

      <h2 style="margin-top:14px">Log</h2>
      <div class="log" id="log"></div>
    </section>
  </div>
`;const h=document.getElementById("log"),_=document.getElementById("status"),y=document.getElementById("devices");let l=[],n=null;const d=e=>document.getElementById(e),w=document.getElementById("device-section"),k=document.getElementById("session-section"),B=document.getElementById("btn-login"),S=document.getElementById("btn-restore"),I=document.getElementById("btn-logout"),L=document.getElementById("btn-connect"),$=document.getElementById("btn-disconnect");function m(e){const t=new Date().toISOString();h.textContent=`[${t}] ${e}
`+h.textContent}function r(){if(!n){_.innerHTML="<div class='status-row'><span class='key'>state</span><span>unknown</span></div>";return}const e=n.active_session_key?"Connected":"Disconnected",t=n.authenticated?"Authenticated":"Signed out";_.innerHTML=`
    <div class="status-row"><span class="key">auth</span><span>${t}</span></div>
    <div class="status-row"><span class="key">connection</span><span>${e}</span></div>
    <div class="status-row"><span class="key">customer_id</span><span>${n.customer_id??"-"}</span></div>
    <div class="status-row"><span class="key">selected_device_id</span><span>${n.selected_device_id??"-"}</span></div>
    <div class="status-row"><span class="key">session_key</span><span>${n.active_session_key??"-"}</span></div>
    <div class="status-row"><span class="key">last_region</span><span>${n.last_region??"-"}</span></div>
  `}function u(){const e=!!n?.authenticated,t=!!n?.selected_device_id,i=!!n?.active_session_key;w.disabled=!e,k.disabled=!e||!t,S.disabled=!e,I.disabled=!e,L.disabled=!e||!t||i,$.disabled=!i,B.disabled=!!n?.authenticated,d("selected_device").value=n?.selected_device_id??""}function p(){if(y.innerHTML="",!l.length){const e=document.createElement("li");e.textContent="No registered devices yet.",y.appendChild(e);return}for(const e of l){const t=document.createElement("li");t.className="device-item";const i=n?.selected_device_id===e.id,g=new Date(e.created_at).toLocaleString();t.innerHTML=`
      <div class="device-main">
        <strong>${e.name}</strong>
        <span class="device-meta">${g}</span>
      </div>
      <div class="device-id">${e.id}</div>
      <div class="actions">
        <button class="${i?"secondary":"ok"}" data-device-id="${e.id}" ${i?"disabled":""}>
          ${i?"Selected":"Select"}
        </button>
      </div>
    `,y.appendChild(t)}y.querySelectorAll("button[data-device-id]").forEach(e=>{e.addEventListener("click",()=>{const t=e.dataset.deviceId;t&&a("select_device",async()=>{n=await c("select_device",{input:{deviceId:t}}),r(),p(),u()})})})}async function f(){n=await c("get_status"),r(),u()}async function v(){if(!n?.authenticated){l=[],p();return}l=await c("list_devices"),p()}async function a(e,t){try{await t(),m(`${e}: ok`)}catch(i){m(`${e}: ${String(i)}`)}}document.getElementById("btn-login").addEventListener("click",()=>a("oauth_login",async()=>{n=await c("oauth_login",{input:{provider:"google",code:d("code").value,codeVerifier:d("code_verifier").value||null,nonce:d("nonce").value||null}}),r(),u(),await v()}));document.getElementById("btn-logout").addEventListener("click",()=>a("logout",async()=>{n=await c("logout"),l=[],r(),p(),u()}));document.getElementById("btn-restore").addEventListener("click",()=>a("restore_and_reconnect",async()=>{n=await c("restore_and_reconnect"),r(),u(),await v()}));document.getElementById("btn-register").addEventListener("click",()=>a("register_device",async()=>{const e=await c("register_device",{input:{name:d("device_name").value,publicKey:d("device_pub").value}});l=[e,...l.filter(t=>t.id!==e.id)],p(),await f(),await v()}));document.getElementById("btn-list").addEventListener("click",()=>a("list_devices",async()=>v()));document.getElementById("btn-connect").addEventListener("click",()=>a("connect",async()=>{const e=await c("connect",{input:{region:d("region").value}});m(`connected session=${e.session_key}`),await f(),await v()}));document.getElementById("btn-disconnect").addEventListener("click",()=>a("disconnect",async()=>{n=await c("disconnect"),r(),u()}));a("init",async()=>{await f(),await v()});
