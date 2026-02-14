(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const n of document.querySelectorAll('link[rel="modulepreload"]'))o(n);new MutationObserver(n=>{for(const a of n)if(a.type==="childList")for(const b of a.addedNodes)b.tagName==="LINK"&&b.rel==="modulepreload"&&o(b)}).observe(document,{childList:!0,subtree:!0});function s(n){const a={};return n.integrity&&(a.integrity=n.integrity),n.referrerPolicy&&(a.referrerPolicy=n.referrerPolicy),n.crossOrigin==="use-credentials"?a.credentials="include":n.crossOrigin==="anonymous"?a.credentials="omit":a.credentials="same-origin",a}function o(n){if(n.ep)return;n.ep=!0;const a=s(n);fetch(n.href,a)}})();async function d(e,t={},s){return window.__TAURI_INTERNALS__.invoke(e,t,s)}const I="292809678651-djckf91g47rimbn4lpfrrajr2vuk2t1m.apps.googleusercontent.com",L="http://127.0.0.1:1420",E="wg.pendingOAuth",D=document.getElementById("app");D.innerHTML=`
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
`;const k=document.getElementById("log"),B=document.getElementById("status"),_=document.getElementById("devices");let r=[],c=null,f=null;const $=e=>document.getElementById(e),U=document.getElementById("device-section"),T=document.getElementById("session-section"),N=document.getElementById("btn-google-start"),R=document.getElementById("btn-restore"),G=document.getElementById("btn-logout"),x=document.getElementById("btn-connect"),V=document.getElementById("btn-disconnect"),g=document.getElementById("connection-banner");function i(e){const t=new Date().toISOString();k.textContent=`[${t}] ${e}
`+k.textContent}function m(){if(!c){B.innerHTML="<div class='status-row'><span class='key'>state</span><span>unknown</span></div>",g.textContent="Disconnected",g.classList.remove("connected"),g.classList.add("disconnected");return}const e=c.active_session_key?"Connected":"Disconnected",t=c.authenticated?"Authenticated":"Signed out";g.textContent=e,g.classList.toggle("connected",!!c.active_session_key),g.classList.toggle("disconnected",!c.active_session_key),B.innerHTML=`
    <div class="status-row"><span class="key">auth</span><span>${t}</span></div>
    <div class="status-row"><span class="key">connection</span><span>${e}</span></div>
    <div class="status-row"><span class="key">customer_id</span><span>${c.customer_id??"-"}</span></div>
    <div class="status-row"><span class="key">selected_device_id</span><span>${c.selected_device_id??"-"}</span></div>
    <div class="status-row"><span class="key">session_key</span><span>${c.active_session_key??"-"}</span></div>
    <div class="status-row"><span class="key">last_region</span><span>${c.last_region??"-"}</span></div>
  `}function l(){const e=!!c?.authenticated,t=!!c?.selected_device_id,s=!!c?.active_session_key;U.disabled=!e,T.disabled=!e||!t,R.disabled=!e,G.disabled=!e,x.disabled=!e||!t||s,V.disabled=!s,N.disabled=e,$("selected_device").value=c?.selected_device_id??""}function A(e){let t="";for(const s of e)t+=String.fromCharCode(s);return btoa(t).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}function w(e){const t=new Uint8Array(e);return crypto.getRandomValues(t),A(t)}async function H(e){const t=new TextEncoder().encode(e),s=await crypto.subtle.digest("SHA-256",t);return A(new Uint8Array(s))}function M(e){const t=e.searchParams.get("code");if(!t)throw new Error("missing_oauth_code_in_callback");return{code:t,state:e.searchParams.get("state")}}function P(){const e=sessionStorage.getItem(E);if(!e)return null;try{const t=JSON.parse(e);return!t.codeVerifier||!t.nonce||!t.state?null:t}catch{return null}}function W(e){sessionStorage.setItem(E,JSON.stringify(e))}function F(){sessionStorage.removeItem(E)}function O(){const e=new URL(window.location.href),t=e.searchParams,s=["code","state","scope","authuser","prompt","hd"];let o=!1;for(const n of s)t.has(n)&&(t.delete(n),o=!0);if(o){const n=`${e.pathname}${t.toString()?`?${t.toString()}`:""}${e.hash}`;window.history.replaceState({},document.title,n)}}function p(){F(),f=null,O()}function S(e){const t=e.trim();if(!t)return!1;try{const s=t.replace(/-/g,"+").replace(/_/g,"/"),o=s+"=".repeat((4-s.length%4)%4);return atob(o).length===32}catch{return!1}}async function K(){const e=new URL(window.location.href);if(!e.searchParams.has("code")){f=P();return}const t=e.searchParams.get("code"),s=e.searchParams.get("state");if(!t||!s){i("google_oauth_complete: ignored (missing code/state)"),p();return}const o=M(e),n=P();if(!n){i("google_oauth_complete: ignored (oauth_not_started)"),O();return}if(o.state!==n.state){i("google_oauth_complete: ignored (oauth_state_mismatch)"),p();return}try{c=await d("oauth_login",{input:{provider:"google",code:o.code,codeVerifier:n.codeVerifier,nonce:n.nonce}})}catch(a){i(`google_oauth_complete: ${String(a)}`),p();return}p(),m(),l(),i("google_oauth_complete: ok"),await v()}function h(){if(_){if(_.innerHTML="",!r.length){const e=document.createElement("li");e.textContent="No registered devices yet.",_.appendChild(e);return}for(const e of r){const t=document.createElement("li");t.className="device-item";const s=c?.selected_device_id===e.id,o=new Date(e.created_at).toLocaleString();t.innerHTML=`
      <div class="device-main">
        <strong>${e.name}</strong>
        <span class="device-meta">${s?"Auto-selected":o}</span>
      </div>
      <div class="device-id">${e.id}</div>
    `,_.appendChild(t)}}}async function C(){if(!c?.authenticated||!r.length)return;const e=r.filter(o=>S(o.public_key));if(!e.length){const o=await d("register_default_device");return i(`register_default_device: ${o.id}`),r=[o,...r],await y(),h(),C()}const t=c.selected_device_id?r.find(o=>o.id===c?.selected_device_id):void 0;if(t&&!S(t.public_key)&&i(`selected_device_invalid_key: ${t.id}`),t&&S(t.public_key)&&c.selected_device_id&&r.some(o=>o.id===c?.selected_device_id))return;const s=[...e].sort((o,n)=>new Date(n.created_at).getTime()-new Date(o.created_at).getTime())[0];c=await d("select_device",{input:{deviceId:s.id}}),i(`auto_selected_device: ${s.id}`),m(),l(),h()}async function y(){c=await d("get_status"),m(),l()}async function v(){if(!c?.authenticated){r=[],h();return}if(r=await d("list_devices"),!r.length){const e=await d("register_default_device");i(`register_default_device: ${e.id}`),r=[e],await y()}await C(),h()}async function u(e,t){try{await t(),i(`${e}: ok`)}catch(s){e.startsWith("google_oauth")&&p(),i(`${e}: ${String(s)}`)}}document.getElementById("btn-google-start").addEventListener("click",()=>u("google_oauth_start",async()=>{const e=w(64),t=await H(e),s=w(24),o=w(24);f={codeVerifier:e,nonce:s,state:o},W(f);const n=new URL("https://accounts.google.com/o/oauth2/v2/auth");n.searchParams.set("client_id",I),n.searchParams.set("redirect_uri",L),n.searchParams.set("response_type","code"),n.searchParams.set("scope","openid email profile"),n.searchParams.set("code_challenge",t),n.searchParams.set("code_challenge_method","S256"),n.searchParams.set("nonce",s),n.searchParams.set("state",o),i(`google_oauth_start_url: ${n.toString()}`),i("google_oauth_start: redirecting to Google sign in"),l(),window.location.assign(n.toString())}));document.getElementById("btn-logout").addEventListener("click",()=>u("logout",async()=>{c=await d("logout"),p(),r=[],m(),h(),l()}));document.getElementById("btn-restore").addEventListener("click",()=>u("restore_and_reconnect",async()=>{c=await d("restore_and_reconnect"),m(),l(),await v()}));document.getElementById("btn-list").addEventListener("click",()=>u("list_devices",async()=>v()));document.getElementById("btn-connect").addEventListener("click",()=>u("connect",async()=>{const e=await d("connect",{input:{region:$("region").value}});i(`connected session=${e.session_key}`),await y(),await v()}));document.getElementById("btn-disconnect").addEventListener("click",()=>u("disconnect",async()=>{c=await d("disconnect"),m(),l()}));u("init",async()=>{await y(),await K(),await v()});
