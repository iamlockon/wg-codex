(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const n of document.querySelectorAll('link[rel="modulepreload"]'))a(n);new MutationObserver(n=>{for(const i of n)if(i.type==="childList")for(const y of i.addedNodes)y.tagName==="LINK"&&y.rel==="modulepreload"&&a(y)}).observe(document,{childList:!0,subtree:!0});function o(n){const i={};return n.integrity&&(i.integrity=n.integrity),n.referrerPolicy&&(i.referrerPolicy=n.referrerPolicy),n.crossOrigin==="use-credentials"?i.credentials="include":n.crossOrigin==="anonymous"?i.credentials="omit":i.credentials="same-origin",i}function a(n){if(n.ep)return;n.ep=!0;const i=o(n);fetch(n.href,i)}})();async function d(e,t={},o){return window.__TAURI_INTERNALS__.invoke(e,t,o)}const S="",b="",E="wg.pendingOAuth",k=document.getElementById("app");k.innerHTML=`
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

      <h2 style="margin-top:14px">Log</h2>
      <div class="log" id="log"></div>
    </section>
  </div>
`;const I=document.getElementById("log"),L=document.getElementById("status");let r=[],s=null,_=null;const C=e=>document.getElementById(e),A=document.getElementById("session-section"),N=document.getElementById("btn-google-start"),$=document.getElementById("btn-restore"),U=document.getElementById("btn-logout"),v=document.getElementById("google-login-identity"),D=document.getElementById("btn-connect"),T=document.getElementById("btn-disconnect"),u=document.getElementById("connection-banner");function c(e){const t=new Date().toISOString();I.textContent=`[${t}] ${e}
`+I.textContent}function p(){if(!s){L.innerHTML="<div class='status-row'><span class='key'>state</span><span>unknown</span></div>",u.textContent="Disconnected",u.classList.remove("connected"),u.classList.add("disconnected"),v.textContent="Not signed in";return}const e=s.active_session_key?"Connected":"Disconnected",t=s.authenticated?"Authenticated":"Signed out";if(u.textContent=e,u.classList.toggle("connected",!!s.active_session_key),u.classList.toggle("disconnected",!s.active_session_key),L.innerHTML=`
    <div class="status-row"><span class="key">auth</span><span>${t}</span></div>
    <div class="status-row"><span class="key">connection</span><span>${e}</span></div>
    <div class="status-row"><span class="key">session_key</span><span>${s.active_session_key??"-"}</span></div>
    <div class="status-row"><span class="key">last_region</span><span>${s.last_region??"-"}</span></div>
  `,s.authenticated){const o=s.name||s.email||s.customer_id||"unknown user";v.textContent=`Signed in as ${o}`}else v.textContent="Not signed in"}function l(){const e=!!s?.authenticated,t=!!s?.selected_device_id,o=!!s?.active_session_key;A.disabled=!e||!t,$.disabled=!e,U.disabled=!e,D.disabled=!e||!t||o,T.disabled=!o,N.disabled=e}function P(e){let t="";for(const o of e)t+=String.fromCharCode(o);return btoa(t).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}function w(e){const t=new Uint8Array(e);return crypto.getRandomValues(t),P(t)}async function G(e){const t=new TextEncoder().encode(e),o=await crypto.subtle.digest("SHA-256",t);return P(new Uint8Array(o))}function R(e){const t=e.searchParams.get("code");if(!t)throw new Error("missing_oauth_code_in_callback");return{code:t,state:e.searchParams.get("state")}}function O(){const e=sessionStorage.getItem(E);if(!e)return null;try{const t=JSON.parse(e);return!t.codeVerifier||!t.nonce||!t.state?null:t}catch{return null}}function x(e){sessionStorage.setItem(E,JSON.stringify(e))}function V(){sessionStorage.removeItem(E)}function B(){const e=new URL(window.location.href),t=e.searchParams,o=["code","state","scope","authuser","prompt","hd"];let a=!1;for(const n of o)t.has(n)&&(t.delete(n),a=!0);if(a){const n=`${e.pathname}${t.toString()?`?${t.toString()}`:""}${e.hash}`;window.history.replaceState({},document.title,n)}}function g(){V(),_=null,B()}async function W(){const e=new URL(window.location.href);if(!e.searchParams.has("code")){_=O();return}const t=e.searchParams.get("code"),o=e.searchParams.get("state");if(!t||!o){c("google_oauth_complete: ignored (missing code/state)"),g();return}const a=R(e),n=O();if(!n){c("google_oauth_complete: ignored (oauth_not_started)"),B();return}if(a.state!==n.state){c("google_oauth_complete: ignored (oauth_state_mismatch)"),g();return}try{s=await d("oauth_login",{input:{provider:"google",code:a.code,codeVerifier:n.codeVerifier,nonce:n.nonce}})}catch(i){c(`google_oauth_complete: ${String(i)}`),g();return}g(),p(),l(),c("google_oauth_complete: ok"),await f()}async function F(){if(!s?.authenticated)return;if(!r.length){const o=await d("register_default_device");c(`register_default_device: ${o.id}`),r=[o],await m();return}const e=s.selected_device_id?r.find(o=>o.id===s?.selected_device_id):void 0;if(e){r=[e];return}const t=[...r].sort((o,a)=>new Date(a.created_at).getTime()-new Date(o.created_at).getTime())[0];s=await d("select_device",{input:{deviceId:t.id}}),c(`auto_selected_device: ${t.id}`),r=[t],p(),l()}async function m(){s=await d("get_status"),p(),l()}async function f(){if(!s?.authenticated){r=[];return}if(r=await d("list_devices"),!r.length){const e=await d("register_default_device");c(`register_default_device: ${e.id}`),r=[e],await m()}await F()}async function h(e,t){try{await t(),c(`${e}: ok`)}catch(o){e.startsWith("google_oauth")&&g();const a=String(o);c(`${e}: ${a}`),e==="connect"&&a.includes("missing wireguard private key")&&c("hint: retry connect to auto-register the default device, then connect again"),e==="connect"&&a.includes("wireguard_permission_denied")&&c("hint: run the app as Administrator for real VPN connect, or set WG_WINDOWS_NOOP_TUNNEL=1 for local UI/API testing")}}document.getElementById("btn-google-start").addEventListener("click",()=>h("google_oauth_start",async()=>{if(!S||!b)throw new Error("missing_google_oauth_ui_config (set VITE_GOOGLE_OIDC_CLIENT_ID and VITE_GOOGLE_OIDC_REDIRECT_URI)");const e=w(64),t=await G(e),o=w(24),a=w(24);_={codeVerifier:e,nonce:o,state:a},x(_);const n=new URL("https://accounts.google.com/o/oauth2/v2/auth");n.searchParams.set("client_id",S),n.searchParams.set("redirect_uri",b),n.searchParams.set("response_type","code"),n.searchParams.set("scope","openid email profile"),n.searchParams.set("code_challenge",t),n.searchParams.set("code_challenge_method","S256"),n.searchParams.set("nonce",o),n.searchParams.set("state",a),n.searchParams.set("prompt","select_account"),c(`google_oauth_start_url: ${n.toString()}`),c("google_oauth_start: redirecting to Google sign in"),l(),window.location.assign(n.toString())}));document.getElementById("btn-logout").addEventListener("click",()=>h("logout",async()=>{s=await d("logout"),g(),r=[],p(),l()}));document.getElementById("btn-restore").addEventListener("click",()=>h("restore_and_reconnect",async()=>{s=await d("restore_and_reconnect"),p(),l(),await f()}));document.getElementById("btn-connect").addEventListener("click",()=>h("connect",async()=>{const e=await d("connect",{input:{region:C("region").value}});c(`connected session=${e.session_key}`),await m();try{await f()}catch(t){c(`post_connect_device_refresh: non_fatal ${String(t)}`)}}));document.getElementById("btn-disconnect").addEventListener("click",()=>h("disconnect",async()=>{s=await d("disconnect"),p(),l()}));h("init",async()=>{await m(),await W(),await f()});
