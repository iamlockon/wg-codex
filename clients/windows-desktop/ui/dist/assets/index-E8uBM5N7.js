(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const n of document.querySelectorAll('link[rel="modulepreload"]'))c(n);new MutationObserver(n=>{for(const a of n)if(a.type==="childList")for(const y of a.addedNodes)y.tagName==="LINK"&&y.rel==="modulepreload"&&c(y)}).observe(document,{childList:!0,subtree:!0});function o(n){const a={};return n.integrity&&(a.integrity=n.integrity),n.referrerPolicy&&(a.referrerPolicy=n.referrerPolicy),n.crossOrigin==="use-credentials"?a.credentials="include":n.crossOrigin==="anonymous"?a.credentials="omit":a.credentials="same-origin",a}function c(n){if(n.ep)return;n.ep=!0;const a=o(n);fetch(n.href,a)}})();async function d(e,t={},o){return window.__TAURI_INTERNALS__.invoke(e,t,o)}const E="292809678651-djckf91g47rimbn4lpfrrajr2vuk2t1m.apps.googleusercontent.com",I="http://127.0.0.1:1420",b="wg.pendingOAuth",O=document.getElementById("app");O.innerHTML=`
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
        <p class="section-note">This app auto-registers and auto-selects the current device.</p>
        <div class="actions">
          <button id="btn-list" class="secondary">Refresh Devices</button>
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

      <h2 style="margin-top:14px">Log</h2>
      <div class="log" id="log"></div>
    </section>
  </div>
`;const L=document.getElementById("log"),B=document.getElementById("status"),v=document.getElementById("devices");let r=[],s=null,f=null;const P=e=>document.getElementById(e),C=document.getElementById("device-section"),D=document.getElementById("session-section"),U=document.getElementById("btn-google-start"),T=document.getElementById("btn-restore"),N=document.getElementById("btn-logout"),R=document.getElementById("btn-connect"),G=document.getElementById("btn-disconnect"),g=document.getElementById("connection-banner");function i(e){const t=new Date().toISOString();L.textContent=`[${t}] ${e}
`+L.textContent}function m(){if(!s){B.innerHTML="<div class='status-row'><span class='key'>state</span><span>unknown</span></div>",g.textContent="Disconnected",g.classList.remove("connected"),g.classList.add("disconnected");return}const e=s.active_session_key?"Connected":"Disconnected",t=s.authenticated?"Authenticated":"Signed out";g.textContent=e,g.classList.toggle("connected",!!s.active_session_key),g.classList.toggle("disconnected",!s.active_session_key),B.innerHTML=`
    <div class="status-row"><span class="key">auth</span><span>${t}</span></div>
    <div class="status-row"><span class="key">connection</span><span>${e}</span></div>
    <div class="status-row"><span class="key">customer_id</span><span>${s.customer_id??"-"}</span></div>
    <div class="status-row"><span class="key">selected_device_id</span><span>${s.selected_device_id??"-"}</span></div>
    <div class="status-row"><span class="key">session_key</span><span>${s.active_session_key??"-"}</span></div>
    <div class="status-row"><span class="key">last_region</span><span>${s.last_region??"-"}</span></div>
  `}function l(){const e=!!s?.authenticated,t=!!s?.selected_device_id,o=!!s?.active_session_key;C.disabled=!e,D.disabled=!e||!t,T.disabled=!e,N.disabled=!e,R.disabled=!e||!t||o,G.disabled=!o,U.disabled=e,P("selected_device").value=s?.selected_device_id??""}function $(e){let t="";for(const o of e)t+=String.fromCharCode(o);return btoa(t).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}function w(e){const t=new Uint8Array(e);return crypto.getRandomValues(t),$(t)}async function x(e){const t=new TextEncoder().encode(e),o=await crypto.subtle.digest("SHA-256",t);return $(new Uint8Array(o))}function V(e){const t=e.searchParams.get("code");if(!t)throw new Error("missing_oauth_code_in_callback");return{code:t,state:e.searchParams.get("state")}}function k(){const e=sessionStorage.getItem(b);if(!e)return null;try{const t=JSON.parse(e);return!t.codeVerifier||!t.nonce||!t.state?null:t}catch{return null}}function H(e){sessionStorage.setItem(b,JSON.stringify(e))}function M(){sessionStorage.removeItem(b)}function A(){const e=new URL(window.location.href),t=e.searchParams,o=["code","state","scope","authuser","prompt","hd"];let c=!1;for(const n of o)t.has(n)&&(t.delete(n),c=!0);if(c){const n=`${e.pathname}${t.toString()?`?${t.toString()}`:""}${e.hash}`;window.history.replaceState({},document.title,n)}}function p(){M(),f=null,A()}async function F(){const e=new URL(window.location.href);if(!e.searchParams.has("code")){f=k();return}const t=e.searchParams.get("code"),o=e.searchParams.get("state");if(!t||!o){i("google_oauth_complete: ignored (missing code/state)"),p();return}const c=V(e),n=k();if(!n){i("google_oauth_complete: ignored (oauth_not_started)"),A();return}if(c.state!==n.state){i("google_oauth_complete: ignored (oauth_state_mismatch)"),p();return}try{s=await d("oauth_login",{input:{provider:"google",code:c.code,codeVerifier:n.codeVerifier,nonce:n.nonce}})}catch(a){i(`google_oauth_complete: ${String(a)}`),p();return}p(),m(),l(),i("google_oauth_complete: ok"),await h()}function _(){if(v){if(v.innerHTML="",!r.length){const e=document.createElement("li");e.textContent="No registered devices yet.",v.appendChild(e);return}for(const e of r){const t=document.createElement("li");t.className="device-item";const o=s?.selected_device_id===e.id,c=new Date(e.created_at).toLocaleString();t.innerHTML=`
      <div class="device-main">
        <strong>${e.name}</strong>
        <span class="device-meta">${o?"Auto-selected":c}</span>
      </div>
      <div class="device-id">${e.id}</div>
    `,v.appendChild(t)}}}async function W(){if(!s?.authenticated||!r.length||s.selected_device_id&&r.some(t=>t.id===s?.selected_device_id))return;const e=[...r].sort((t,o)=>new Date(o.created_at).getTime()-new Date(t.created_at).getTime())[0];s=await d("select_device",{input:{deviceId:e.id}}),i(`auto_selected_device: ${e.id}`),m(),l(),_()}async function S(){s=await d("get_status"),m(),l()}async function h(){if(!s?.authenticated){r=[],_();return}if(r=await d("list_devices"),!r.length){const e=await d("register_default_device");i(`register_default_device: ${e.id}`),r=[e],await S()}await W(),_()}async function u(e,t){try{await t(),i(`${e}: ok`)}catch(o){e.startsWith("google_oauth")&&p(),i(`${e}: ${String(o)}`)}}document.getElementById("btn-google-start").addEventListener("click",()=>u("google_oauth_start",async()=>{const e=w(64),t=await x(e),o=w(24),c=w(24);f={codeVerifier:e,nonce:o,state:c},H(f);const n=new URL("https://accounts.google.com/o/oauth2/v2/auth");n.searchParams.set("client_id",E),n.searchParams.set("redirect_uri",I),n.searchParams.set("response_type","code"),n.searchParams.set("scope","openid email profile"),n.searchParams.set("code_challenge",t),n.searchParams.set("code_challenge_method","S256"),n.searchParams.set("nonce",o),n.searchParams.set("state",c),i(`google_oauth_start_url: ${n.toString()}`),i("google_oauth_start: redirecting to Google sign in"),l(),window.location.assign(n.toString())}));document.getElementById("btn-logout").addEventListener("click",()=>u("logout",async()=>{s=await d("logout"),p(),r=[],m(),_(),l()}));document.getElementById("btn-restore").addEventListener("click",()=>u("restore_and_reconnect",async()=>{s=await d("restore_and_reconnect"),m(),l(),await h()}));document.getElementById("btn-list").addEventListener("click",()=>u("list_devices",async()=>h()));document.getElementById("btn-connect").addEventListener("click",()=>u("connect",async()=>{const e=await d("connect",{input:{region:P("region").value}});i(`connected session=${e.session_key}`),await S(),await h()}));document.getElementById("btn-disconnect").addEventListener("click",()=>u("disconnect",async()=>{s=await d("disconnect"),m(),l()}));u("init",async()=>{await S(),await F(),await h()});
