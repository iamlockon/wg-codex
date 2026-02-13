(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const n of document.querySelectorAll('link[rel="modulepreload"]'))c(n);new MutationObserver(n=>{for(const i of n)if(i.type==="childList")for(const w of i.addedNodes)w.tagName==="LINK"&&w.rel==="modulepreload"&&c(w)}).observe(document,{childList:!0,subtree:!0});function s(n){const i={};return n.integrity&&(i.integrity=n.integrity),n.referrerPolicy&&(i.referrerPolicy=n.referrerPolicy),n.crossOrigin==="use-credentials"?i.credentials="include":n.crossOrigin==="anonymous"?i.credentials="omit":i.credentials="same-origin",i}function c(n){if(n.ep)return;n.ep=!0;const i=s(n);fetch(n.href,i)}})();async function r(e,t={},s){return window.__TAURI_INTERNALS__.invoke(e,t,s)}const I="292809678651-djckf91g47rimbn4lpfrrajr2vuk2t1m.apps.googleusercontent.com",L="http://127.0.0.1:1420",S="wg.pendingOAuth",C=document.getElementById("app");C.innerHTML=`
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

      <h2 style="margin-top:14px">Devices</h2>
      <ul class="list" id="devices"></ul>

      <h2 style="margin-top:14px">Log</h2>
      <div class="log" id="log"></div>
    </section>
  </div>
`;const B=document.getElementById("log"),P=document.getElementById("status"),f=document.getElementById("devices");let u=[],o=null,l=null;const b=e=>document.getElementById(e),A=document.getElementById("device-section"),D=document.getElementById("session-section"),U=document.getElementById("btn-google-start"),N=document.getElementById("btn-restore"),R=document.getElementById("btn-logout"),G=document.getElementById("btn-connect"),x=document.getElementById("btn-disconnect"),p=document.getElementById("connection-banner");function a(e){const t=new Date().toISOString();B.textContent=`[${t}] ${e}
`+B.textContent}function v(){if(!o){P.innerHTML="<div class='status-row'><span class='key'>state</span><span>unknown</span></div>",p.textContent="Disconnected",p.classList.remove("connected"),p.classList.add("disconnected");return}const e=o.active_session_key?"Connected":"Disconnected",t=o.authenticated?"Authenticated":"Signed out";p.textContent=e,p.classList.toggle("connected",!!o.active_session_key),p.classList.toggle("disconnected",!o.active_session_key),P.innerHTML=`
    <div class="status-row"><span class="key">auth</span><span>${t}</span></div>
    <div class="status-row"><span class="key">connection</span><span>${e}</span></div>
    <div class="status-row"><span class="key">customer_id</span><span>${o.customer_id??"-"}</span></div>
    <div class="status-row"><span class="key">selected_device_id</span><span>${o.selected_device_id??"-"}</span></div>
    <div class="status-row"><span class="key">session_key</span><span>${o.active_session_key??"-"}</span></div>
    <div class="status-row"><span class="key">last_region</span><span>${o.last_region??"-"}</span></div>
  `}function g(){const e=!!o?.authenticated,t=!!o?.selected_device_id,s=!!o?.active_session_key;A.disabled=!e,D.disabled=!e||!t,N.disabled=!e,R.disabled=!e,G.disabled=!e||!t||s,x.disabled=!s,U.disabled=e,b("selected_device").value=o?.selected_device_id??""}function O(e){let t="";for(const s of e)t+=String.fromCharCode(s);return btoa(t).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}function E(e){const t=new Uint8Array(e);return crypto.getRandomValues(t),O(t)}async function T(e){const t=new TextEncoder().encode(e),s=await crypto.subtle.digest("SHA-256",t);return O(new Uint8Array(s))}function V(e){const t=e.searchParams.get("code");if(!t)throw new Error("missing_oauth_code_in_callback");return{code:t,state:e.searchParams.get("state")}}function $(){const e=localStorage.getItem(S);if(!e)return null;try{const t=JSON.parse(e);return!t.codeVerifier||!t.nonce||!t.state?null:t}catch{return null}}function H(e){localStorage.setItem(S,JSON.stringify(e))}function _(){localStorage.removeItem(S)}function h(){const e=new URL(window.location.href),t=e.searchParams,s=["code","state","scope","authuser","prompt","hd"];let c=!1;for(const n of s)t.has(n)&&(t.delete(n),c=!0);if(c){const n=`${e.pathname}${t.toString()?`?${t.toString()}`:""}${e.hash}`;window.history.replaceState({},document.title,n)}}async function M(){const e=new URL(window.location.href);if(!e.searchParams.has("code")){l=$();return}const t=e.searchParams.get("code"),s=e.searchParams.get("state");if(!t||!s){a("google_oauth_complete: ignored (missing code/state)"),_(),l=null,h();return}const c=V(e),n=$();if(!n){a("google_oauth_complete: ignored (oauth_not_started)"),h();return}if(c.state!==n.state){a("google_oauth_complete: ignored (oauth_state_mismatch)"),_(),l=null,h();return}try{o=await r("oauth_login",{input:{provider:"google",code:c.code,codeVerifier:n.codeVerifier,nonce:n.nonce}})}catch(i){a(`google_oauth_complete: ${String(i)}`),_(),l=null,h();return}l=null,_(),h(),v(),g(),a("google_oauth_complete: ok"),await m()}function y(){if(f.innerHTML="",!u.length){const e=document.createElement("li");e.textContent="No registered devices yet.",f.appendChild(e);return}for(const e of u){const t=document.createElement("li");t.className="device-item";const s=o?.selected_device_id===e.id,c=new Date(e.created_at).toLocaleString();t.innerHTML=`
      <div class="device-main">
        <strong>${e.name}</strong>
        <span class="device-meta">${c}</span>
      </div>
      <div class="device-id">${e.id}</div>
      <div class="actions">
        <button class="${s?"secondary":"ok"}" data-device-id="${e.id}" ${s?"disabled":""}>
          ${s?"Selected":"Select"}
        </button>
      </div>
    `,f.appendChild(t)}f.querySelectorAll("button[data-device-id]").forEach(e=>{e.addEventListener("click",()=>{const t=e.dataset.deviceId;t&&d("select_device",async()=>{o=await r("select_device",{input:{deviceId:t}}),v(),y(),g()})})})}async function k(){o=await r("get_status"),v(),g()}async function m(){if(!o?.authenticated){u=[],y();return}u=await r("list_devices"),y()}async function d(e,t){try{await t(),a(`${e}: ok`)}catch(s){a(`${e}: ${String(s)}`)}}document.getElementById("btn-google-start").addEventListener("click",()=>d("google_oauth_start",async()=>{const e=E(64),t=await T(e),s=E(24),c=E(24);l={codeVerifier:e,nonce:s,state:c},H(l);const n=new URL("https://accounts.google.com/o/oauth2/v2/auth");n.searchParams.set("client_id",I),n.searchParams.set("redirect_uri",L),n.searchParams.set("response_type","code"),n.searchParams.set("scope","openid email profile"),n.searchParams.set("code_challenge",t),n.searchParams.set("code_challenge_method","S256"),n.searchParams.set("nonce",s),n.searchParams.set("state",c),a("google_oauth_start: redirecting to Google sign in"),g(),window.location.assign(n.toString())}));document.getElementById("btn-logout").addEventListener("click",()=>d("logout",async()=>{o=await r("logout"),u=[],v(),y(),g()}));document.getElementById("btn-restore").addEventListener("click",()=>d("restore_and_reconnect",async()=>{o=await r("restore_and_reconnect"),v(),g(),await m()}));document.getElementById("btn-register").addEventListener("click",()=>d("register_device",async()=>{const e=await r("register_device",{input:{name:b("device_name").value,publicKey:b("device_pub").value}});u=[e,...u.filter(t=>t.id!==e.id)],y(),await k(),await m()}));document.getElementById("btn-list").addEventListener("click",()=>d("list_devices",async()=>m()));document.getElementById("btn-connect").addEventListener("click",()=>d("connect",async()=>{const e=await r("connect",{input:{region:b("region").value}});a(`connected session=${e.session_key}`),await k(),await m()}));document.getElementById("btn-disconnect").addEventListener("click",()=>d("disconnect",async()=>{o=await r("disconnect"),v(),g()}));d("init",async()=>{await k(),await M(),await m()});
