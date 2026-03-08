(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const o of document.querySelectorAll('link[rel="modulepreload"]'))c(o);new MutationObserver(o=>{for(const s of o)if(s.type==="childList")for(const r of s.addedNodes)r.tagName==="LINK"&&r.rel==="modulepreload"&&c(r)}).observe(document,{childList:!0,subtree:!0});function n(o){const s={};return o.integrity&&(s.integrity=o.integrity),o.referrerPolicy&&(s.referrerPolicy=o.referrerPolicy),o.crossOrigin==="use-credentials"?s.credentials="include":o.crossOrigin==="anonymous"?s.credentials="omit":s.credentials="same-origin",s}function c(o){if(o.ep)return;o.ep=!0;const s=n(o);fetch(o.href,s)}})();async function a(e,t={},n){return window.__TAURI_INTERNALS__.invoke(e,t,n)}let w="",f="";const b="wg.pendingOAuth",$=document.getElementById("app");$.innerHTML=`
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
          <input id="cfg-google-redirect-uri" type="text" placeholder="http://127.0.0.1:53682/oauth/callback" />
        </div>
      </div>
      <div class="actions">
        <button id="btn-settings-save" class="secondary">Save Settings</button>
      </div>

      <h2 style="margin-top:14px">Log</h2>
      <div class="log" id="log"></div>
    </section>
  </div>
`;const B=document.getElementById("log"),L=document.getElementById("status");let l=[],i=null,E=null;const N=e=>document.getElementById(e),D=document.getElementById("session-section"),R=document.getElementById("btn-google-start"),G=document.getElementById("btn-restore"),T=document.getElementById("btn-logout"),y=document.getElementById("google-login-identity"),W=document.getElementById("btn-connect"),V=document.getElementById("btn-disconnect"),p=document.getElementById("connection-banner"),H=document.getElementById("btn-settings-save"),O=document.getElementById("cfg-entry-api-base-url"),k=document.getElementById("cfg-wireguard-exe"),A=document.getElementById("cfg-google-client-id"),C=document.getElementById("cfg-google-redirect-uri");function d(e){const t=new Date().toISOString();B.textContent=`[${t}] ${e}
`+B.textContent}function _(){if(!i){L.innerHTML="<div class='status-row'><span class='key'>state</span><span>unknown</span></div>",p.textContent="Disconnected",p.classList.remove("connected"),p.classList.add("disconnected"),y.textContent="Not signed in";return}const e=i.active_session_key?"Connected":"Disconnected",t=i.authenticated?"Authenticated":"Signed out";if(p.textContent=e,p.classList.toggle("connected",!!i.active_session_key),p.classList.toggle("disconnected",!i.active_session_key),L.innerHTML=`
    <div class="status-row"><span class="key">auth</span><span>${t}</span></div>
    <div class="status-row"><span class="key">connection</span><span>${e}</span></div>
    <div class="status-row"><span class="key">session_key</span><span>${i.active_session_key??"-"}</span></div>
    <div class="status-row"><span class="key">last_region</span><span>${i.last_region??"-"}</span></div>
  `,i.authenticated){const n=i.name||i.email||i.customer_id||"unknown user";y.textContent=`Signed in as ${n}`}else y.textContent="Not signed in"}function u(){const e=!!i?.authenticated,t=!!i?.selected_device_id,n=!!i?.active_session_key;D.disabled=!e||!t,G.disabled=!e,T.disabled=!e,W.disabled=!e||!t||n,V.disabled=!n,R.disabled=e}function P(e){let t="";for(const n of e)t+=String.fromCharCode(n);return btoa(t).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}function m(e){const t=new Uint8Array(e);return crypto.getRandomValues(t),P(t)}async function F(e){const t=new TextEncoder().encode(e),n=await crypto.subtle.digest("SHA-256",t);return P(new Uint8Array(n))}function M(){const e=sessionStorage.getItem(b);if(!e)return null;try{const t=JSON.parse(e);return!t.codeVerifier||!t.nonce||!t.state?null:t}catch{return null}}function J(e){sessionStorage.setItem(b,JSON.stringify(e))}function K(){sessionStorage.removeItem(b)}function Y(){const e=new URL(window.location.href),t=e.searchParams,n=["code","state","scope","authuser","prompt","hd"];let c=!1;for(const o of n)t.has(o)&&(t.delete(o),c=!0);if(c){const o=`${e.pathname}${t.toString()?`?${t.toString()}`:""}${e.hash}`;window.history.replaceState({},document.title,o)}}function I(){K(),E=null,Y()}async function q(){if(!i?.authenticated)return;if(!l.length){const n=await a("register_default_device");d(`register_default_device: ${n.id}`),l=[n],await h();return}const e=i.selected_device_id?l.find(n=>n.id===i?.selected_device_id):void 0;if(e){l=[e];return}const t=[...l].sort((n,c)=>new Date(c.created_at).getTime()-new Date(n.created_at).getTime())[0];i=await a("select_device",{input:{deviceId:t.id}}),d(`auto_selected_device: ${t.id}`),l=[t],_(),u()}async function h(){i=await a("get_status"),_(),u()}async function v(){if(!i?.authenticated){l=[];return}if(l=await a("list_devices"),!l.length){const e=await a("register_default_device");d(`register_default_device: ${e.id}`),l=[e],await h()}await q()}async function g(e,t){try{await t(),d(`${e}: ok`)}catch(n){e.startsWith("google_oauth")&&I();const c=String(n);d(`${e}: ${c}`),e==="connect"&&c.includes("missing wireguard private key")&&d("hint: retry connect to auto-register the default device, then connect again"),e==="connect"&&c.includes("wireguard_permission_denied")&&d("hint: run the app as Administrator for real VPN connect, or set WG_WINDOWS_NOOP_TUNNEL=1 for local UI/API testing")}}function U(e){O.value=e.entryApiBaseUrl??"",k.value=e.wireguardExe??"",A.value=e.googleOidcClientId??"",C.value=e.googleOidcRedirectUri??""}async function Q(){const e=await a("get_app_config");U(e)}async function S(){const e=await a("get_public_config");w=e.google_oidc_client_id,f=e.google_oidc_redirect_uri}H.addEventListener("click",()=>g("settings_save",async()=>{const e=await a("set_app_config",{input:{entryApiBaseUrl:O.value,wireguardExe:k.value,googleOidcClientId:A.value,googleOidcRedirectUri:C.value}});U(e),await S()}));document.getElementById("btn-google-start").addEventListener("click",()=>g("google_oauth_start",async()=>{if(await S(),!w||!f)throw new Error("missing_google_oauth_ui_config (configure GOOGLE_OIDC_* in entry or set local overrides in Settings)");const e=m(64),t=await F(e),n=m(24),c=m(24),o={codeVerifier:e,nonce:n,state:c};E=o,J(o);const s=new URL("https://accounts.google.com/o/oauth2/v2/auth");s.searchParams.set("client_id",w),s.searchParams.set("redirect_uri",f),s.searchParams.set("response_type","code"),s.searchParams.set("scope","openid email profile"),s.searchParams.set("code_challenge",t),s.searchParams.set("code_challenge_method","S256"),s.searchParams.set("nonce",n),s.searchParams.set("state",c),s.searchParams.set("prompt","select_account"),await a("prepare_oauth_callback_listener",{input:{redirectUri:f}}),d(`google_oauth_start_url: ${s.toString()}`),d("google_oauth_start: opening system browser"),u(),await a("open_external_url",{input:{url:s.toString()}});const r=await a("wait_for_oauth_callback",{input:{timeoutSeconds:180}});if(r.error){const x=r.errorDescription?` (${r.errorDescription})`:"";throw new Error(`oauth_callback_error: ${r.error}${x}`)}if(!r.code||!r.state)throw new Error("missing_oauth_code_or_state");if(r.state!==o.state)throw new Error("oauth_state_mismatch");i=await a("oauth_login",{input:{provider:"google",code:r.code,codeVerifier:o.codeVerifier,nonce:o.nonce}}),I(),_(),u(),d("google_oauth_complete: ok"),await v()}));document.getElementById("btn-logout").addEventListener("click",()=>g("logout",async()=>{i=await a("logout"),I(),l=[],_(),u()}));document.getElementById("btn-restore").addEventListener("click",()=>g("restore_and_reconnect",async()=>{i=await a("restore_and_reconnect"),_(),u(),await v()}));document.getElementById("btn-connect").addEventListener("click",()=>g("connect",async()=>{const e=await a("connect",{input:{region:N("region").value}});d(`connected session=${e.session_key}`),await h();try{await v()}catch(t){d(`post_connect_device_refresh: non_fatal ${String(t)}`)}}));document.getElementById("btn-disconnect").addEventListener("click",()=>g("disconnect",async()=>{i=await a("disconnect"),_(),u()}));g("init",async()=>{await Q(),await S(),E=M(),await h(),await v()});
