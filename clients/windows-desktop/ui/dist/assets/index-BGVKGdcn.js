(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const n of document.querySelectorAll('link[rel="modulepreload"]'))i(n);new MutationObserver(n=>{for(const c of n)if(c.type==="childList")for(const v of c.addedNodes)v.tagName==="LINK"&&v.rel==="modulepreload"&&i(v)}).observe(document,{childList:!0,subtree:!0});function o(n){const c={};return n.integrity&&(c.integrity=n.integrity),n.referrerPolicy&&(c.referrerPolicy=n.referrerPolicy),n.crossOrigin==="use-credentials"?c.credentials="include":n.crossOrigin==="anonymous"?c.credentials="omit":c.credentials="same-origin",c}function i(n){if(n.ep)return;n.ep=!0;const c=o(n);fetch(n.href,c)}})();async function r(e,t={},o){return window.__TAURI_INTERNALS__.invoke(e,t,o)}let b="",E="";const S="wg.pendingOAuth",$=document.getElementById("app");$.innerHTML=`
  <h1>WG Desktop VPN</h1>
  <p class="subtitle">Sign in with Google, choose location, then connect and disconnect VPN.</p>
  <div class="layout">
    <section class="card">
      <h2>1. Google Login</h2>
      <p class="section-note">Continue to Google, sign in, and return to the app automatically.</p>
      <div id="google-login-identity" class="section-note">Not signed in</div>
      <div class="actions">
        <button id="btn-google-start">Sign Up / Log In With Google</button>
        <button id="btn-restore" class="secondary">Restore Session</button>
        <button id="btn-logout" class="danger">Logout</button>
      </div>

      <fieldset id="session-section" class="step-fieldset">
        <h2 style="margin-top:14px">2. Location & Connection</h2>
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

      <h2 style="margin-top:14px">Settings</h2>
      <p class="section-note">Local values here override entry public config when set.</p>
      <div class="grid one-col">
        <div>
          <label for="cfg-entry-api-base-url">ENTRY_API_BASE_URL</label>
          <input id="cfg-entry-api-base-url" type="text" placeholder="http://127.0.0.1:8080" />
        </div>
        <div>
          <label for="cfg-wireguard-exe">WG_WINDOWS_WIREGUARD_EXE</label>
          <input id="cfg-wireguard-exe" type="text" placeholder="C:\\Program Files\\WireGuard\\wireguard.exe" />
        </div>
        <div>
          <label for="cfg-google-client-id">GOOGLE_OIDC_CLIENT_ID override</label>
          <input id="cfg-google-client-id" type="text" placeholder="optional local override" />
        </div>
        <div>
          <label for="cfg-google-redirect-uri">GOOGLE_OIDC_REDIRECT_URI override</label>
          <input id="cfg-google-redirect-uri" type="text" placeholder="optional local override" />
        </div>
      </div>
      <div class="actions">
        <button id="btn-settings-save" class="secondary">Save Settings</button>
      </div>

      <h2 style="margin-top:14px">Log</h2>
      <div class="log" id="log"></div>
    </section>
  </div>
`;const B=document.getElementById("log"),L=document.getElementById("status");let d=[],s=null,_=null;const R=e=>document.getElementById(e),D=document.getElementById("session-section"),G=document.getElementById("btn-google-start"),T=document.getElementById("btn-restore"),W=document.getElementById("btn-logout"),y=document.getElementById("google-login-identity"),V=document.getElementById("btn-connect"),F=document.getElementById("btn-disconnect"),g=document.getElementById("connection-banner"),H=document.getElementById("btn-settings-save"),P=document.getElementById("cfg-entry-api-base-url"),C=document.getElementById("cfg-wireguard-exe"),A=document.getElementById("cfg-google-client-id"),U=document.getElementById("cfg-google-redirect-uri");function a(e){const t=new Date().toISOString();B.textContent=`[${t}] ${e}
`+B.textContent}function f(){if(!s){L.innerHTML="<div class='status-row'><span class='key'>state</span><span>unknown</span></div>",g.textContent="Disconnected",g.classList.remove("connected"),g.classList.add("disconnected"),y.textContent="Not signed in";return}const e=s.active_session_key?"Connected":"Disconnected",t=s.authenticated?"Authenticated":"Signed out";if(g.textContent=e,g.classList.toggle("connected",!!s.active_session_key),g.classList.toggle("disconnected",!s.active_session_key),L.innerHTML=`
    <div class="status-row"><span class="key">auth</span><span>${t}</span></div>
    <div class="status-row"><span class="key">connection</span><span>${e}</span></div>
    <div class="status-row"><span class="key">session_key</span><span>${s.active_session_key??"-"}</span></div>
    <div class="status-row"><span class="key">last_region</span><span>${s.last_region??"-"}</span></div>
  `,s.authenticated){const o=s.name||s.email||s.customer_id||"unknown user";y.textContent=`Signed in as ${o}`}else y.textContent="Not signed in"}function l(){const e=!!s?.authenticated,t=!!s?.selected_device_id,o=!!s?.active_session_key;D.disabled=!e||!t,T.disabled=!e,W.disabled=!e,V.disabled=!e||!t||o,F.disabled=!o,G.disabled=e}function k(e){let t="";for(const o of e)t+=String.fromCharCode(o);return btoa(t).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}function w(e){const t=new Uint8Array(e);return crypto.getRandomValues(t),k(t)}async function M(e){const t=new TextEncoder().encode(e),o=await crypto.subtle.digest("SHA-256",t);return k(new Uint8Array(o))}function J(e){const t=e.searchParams.get("code");if(!t)throw new Error("missing_oauth_code_in_callback");return{code:t,state:e.searchParams.get("state")}}function O(){const e=sessionStorage.getItem(S);if(!e)return null;try{const t=JSON.parse(e);return!t.codeVerifier||!t.nonce||!t.state?null:t}catch{return null}}function K(e){sessionStorage.setItem(S,JSON.stringify(e))}function Y(){sessionStorage.removeItem(S)}function x(){const e=new URL(window.location.href),t=e.searchParams,o=["code","state","scope","authuser","prompt","hd"];let i=!1;for(const n of o)t.has(n)&&(t.delete(n),i=!0);if(i){const n=`${e.pathname}${t.toString()?`?${t.toString()}`:""}${e.hash}`;window.history.replaceState({},document.title,n)}}function p(){Y(),_=null,x()}async function q(){const e=new URL(window.location.href);if(!e.searchParams.has("code")){_=O();return}const t=e.searchParams.get("code"),o=e.searchParams.get("state");if(!t||!o){a("google_oauth_complete: ignored (missing code/state)"),p();return}const i=J(e),n=O();if(!n){a("google_oauth_complete: ignored (oauth_not_started)"),x();return}if(i.state!==n.state){a("google_oauth_complete: ignored (oauth_state_mismatch)"),p();return}try{s=await r("oauth_login",{input:{provider:"google",code:i.code,codeVerifier:n.codeVerifier,nonce:n.nonce}})}catch(c){a(`google_oauth_complete: ${String(c)}`),p();return}p(),f(),l(),a("google_oauth_complete: ok"),await m()}async function Q(){if(!s?.authenticated)return;if(!d.length){const o=await r("register_default_device");a(`register_default_device: ${o.id}`),d=[o],await h();return}const e=s.selected_device_id?d.find(o=>o.id===s?.selected_device_id):void 0;if(e){d=[e];return}const t=[...d].sort((o,i)=>new Date(i.created_at).getTime()-new Date(o.created_at).getTime())[0];s=await r("select_device",{input:{deviceId:t.id}}),a(`auto_selected_device: ${t.id}`),d=[t],f(),l()}async function h(){s=await r("get_status"),f(),l()}async function m(){if(!s?.authenticated){d=[];return}if(d=await r("list_devices"),!d.length){const e=await r("register_default_device");a(`register_default_device: ${e.id}`),d=[e],await h()}await Q()}async function u(e,t){try{await t(),a(`${e}: ok`)}catch(o){e.startsWith("google_oauth")&&p();const i=String(o);a(`${e}: ${i}`),e==="connect"&&i.includes("missing wireguard private key")&&a("hint: retry connect to auto-register the default device, then connect again"),e==="connect"&&i.includes("wireguard_permission_denied")&&a("hint: run the app as Administrator for real VPN connect, or set WG_WINDOWS_NOOP_TUNNEL=1 for local UI/API testing")}}function N(e){P.value=e.entryApiBaseUrl??"",C.value=e.wireguardExe??"",A.value=e.googleOidcClientId??"",U.value=e.googleOidcRedirectUri??""}async function X(){const e=await r("get_app_config");N(e)}async function I(){const e=await r("get_public_config");b=e.google_oidc_client_id,E=e.google_oidc_redirect_uri}H.addEventListener("click",()=>u("settings_save",async()=>{const e=await r("set_app_config",{input:{entryApiBaseUrl:P.value,wireguardExe:C.value,googleOidcClientId:A.value,googleOidcRedirectUri:U.value}});N(e),await I()}));document.getElementById("btn-google-start").addEventListener("click",()=>u("google_oauth_start",async()=>{if(await I(),!b||!E)throw new Error("missing_google_oauth_ui_config (configure GOOGLE_OIDC_* in entry or set local overrides in Settings)");const e=w(64),t=await M(e),o=w(24),i=w(24);_={codeVerifier:e,nonce:o,state:i},K(_);const n=new URL("https://accounts.google.com/o/oauth2/v2/auth");n.searchParams.set("client_id",b),n.searchParams.set("redirect_uri",E),n.searchParams.set("response_type","code"),n.searchParams.set("scope","openid email profile"),n.searchParams.set("code_challenge",t),n.searchParams.set("code_challenge_method","S256"),n.searchParams.set("nonce",o),n.searchParams.set("state",i),n.searchParams.set("prompt","select_account"),a(`google_oauth_start_url: ${n.toString()}`),a("google_oauth_start: redirecting to Google sign in"),l(),window.location.assign(n.toString())}));document.getElementById("btn-logout").addEventListener("click",()=>u("logout",async()=>{s=await r("logout"),p(),d=[],f(),l()}));document.getElementById("btn-restore").addEventListener("click",()=>u("restore_and_reconnect",async()=>{s=await r("restore_and_reconnect"),f(),l(),await m()}));document.getElementById("btn-connect").addEventListener("click",()=>u("connect",async()=>{const e=await r("connect",{input:{region:R("region").value}});a(`connected session=${e.session_key}`),await h();try{await m()}catch(t){a(`post_connect_device_refresh: non_fatal ${String(t)}`)}}));document.getElementById("btn-disconnect").addEventListener("click",()=>u("disconnect",async()=>{s=await r("disconnect"),f(),l()}));u("init",async()=>{await X(),await I(),await h(),await q(),await m()});
