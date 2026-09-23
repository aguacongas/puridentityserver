"use strict";

/* Demo SPA « sans callback » pour PurIdentityServer.
 *
 * Cette page exerce, depuis le navigateur, tous les flows OIDC/OAuth2 du
 * serveur : Authorization Code + PKCE, Implicit, Hybrid, Pushed
 * Authorization Request, Device Authorization Grant, Client Credentials,
 * Refresh, Introspection, Révocation et RP-Initiated Logout.
 *
 * Le callback est géré ici : le serveur redirige le navigateur vers la
 * racine `redirectUri` (query pour le code, fragment pour les jetons) et
 * cette page détecte le retour à l'initialisation.
 *
 * Note sécurité : il s'agit d'une démo. Un SPA de production doit vérifier
 * la SIGNATURE de l'id_token à l'aide des JWKS du serveur (lib oidc-client-ts
 * ou équivalent) ; ici l'id_token est décodé et son nonce/aud/iss contrôlés,
 * mais pas sa signature.
 */

const SPA_CONFIG = {
  issuer: "http://127.0.0.1:8000",
  clientId: "sample-spa-client",
  redirectUri: `${window.location.origin}/`,
  postLogoutRedirectUri: `${window.location.origin}/`,
  scope: "openid profile email offline_access",
  // Client confidentiel de démo pour introspect / revoke / client_credentials
  // (déclaré dans config.toml — secret EN CLAIR : serveur de démonstration
  // uniquement, jamais à réutiliser en production).
  ccClientId: "sample-cc-client",
  ccClientSecret: "cc-demo-secret",
  // API protégée de démonstration (samples/api-resources-client/api_server.py,
  // port 8120) : valide l'access token (signature JWKS de l'issuer, iss, exp,
  // aud = la ApiResource) et exige le scope api.read.
  apiBaseUrl: "http://127.0.0.1:8120",
  apiResource: "sample-api",
  apiScope: "openid api.read",
  // Démo id_token HS* + JWE : client créé à la volée via /register (RFC 7591)
  // avec le jeton d'inscription de la configuration de démonstration
  // (`registration_initial_access_tokens`, config.toml).
  registerToken: "dev-registrar-token",
  idTokenSigningAlg: "HS256",
  idTokenEncryptionAlg: "RSA-OAEP-256",
  idTokenEncryptionEnc: "A256GCM",
};

// Scopes demandés par le flow id_token HS*/JWE (sans offline_access/api.read,
// pour ne sortir ni refresh token ni audience ApiResource de ce flow).
const IDTOKEN_ALGOS_SCOPE = "openid profile email";

const store = {
  get(key) {
    return sessionStorage.getItem(key);
  },
  set(key, value) {
    sessionStorage.setItem(key, value);
  },
  remove(key) {
    sessionStorage.removeItem(key);
  },
};

let discoveryPromise = null;

function b64url(bytes) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomToken(bytes = 32) {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return b64url(values);
}

async function sha256(urlSafeValue) {
  const data = new TextEncoder().encode(urlSafeValue);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return b64url(new Uint8Array(digest));
}

function b64urlDecode(value) {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function decodeJwt(token) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Jeton non JWT (3 segments attendus)");
  }
  return JSON.parse(b64urlDecode(parts[1]));
}

function buildUrl(base, params) {
  const url = new URL(base);
  Object.entries(params)
    .filter(([, value]) => value !== undefined && value !== null && value !== "")
    .forEach(([key, value]) => url.searchParams.set(key, value));
  return url.toString();
}

function discovery() {
  if (!discoveryPromise) {
    discoveryPromise = fetch(`${SPA_CONFIG.issuer}/.well-known/openid-configuration`).then(
      (response) => {
        if (!response.ok) {
          throw new Error(`Discovery HTTP ${response.status}`);
        }
        return response.json();
      }
    );
    discoveryPromise.catch(() => {
      discoveryPromise = null;
    });
  }
  return discoveryPromise;
}

async function parseJsonResponse(response) {
  const text = await response.text();
  let payload;
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    payload = { raw: text };
  }
  payload._status = response.status;
  payload._ok = response.ok;
  return payload;
}

async function postForm(url, data) {
  const body = new URLSearchParams(data).toString();
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  return parseJsonResponse(response);
}

function basicAuthHeader(username, password) {
  return `Basic ${btoa(`${username}:${password}`)}`;
}

async function postFormBasic(url, data, username, password) {
  const body = new URLSearchParams(data).toString();
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: basicAuthHeader(username, password),
    },
    body,
  });
  return parseJsonResponse(response);
}

async function postJson(url, data, bearerToken) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${bearerToken}`,
    },
    body: JSON.stringify(data),
  });
  return parseJsonResponse(response);
}

async function generateRsaOaepJwk() {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  jwk.use = "enc";
  jwk.alg = "RSA-OAEP-256";
  jwk.kid = randomToken(8);
  return jwk;
}

function issuerOrigin() {
  return new URL(SPA_CONFIG.issuer).origin;
}

function log(message, className = "") {
  const el = document.getElementById("status");
  const line = document.createElement("div");
  line.className = className;
  line.textContent = (el.childNodes.length ? "\n" : "") + message;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
}

function renderResult(title, data) {
  const grid = document.getElementById("results");
  const card = document.createElement("div");
  card.className = "card";
  const heading = document.createElement("h3");
  heading.textContent = title;
  const pre = document.createElement("pre");
  pre.textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2);
  card.append(heading, pre);
  grid.prepend(card);
}

function fail(error, context) {
  log(`${context} : ${error.message}`, "error");
}

function verifyState(received) {
  const expected = store.get("state");
  store.remove("state");
  if (!received || received !== expected) {
    throw new Error(`state invalide (attendu ${expected}, reçu ${received})`);
  }
}

function verifyIdToken(idToken, nonce) {
  const claims = decodeJwt(idToken);
  const checks = [
    [claims.iss === SPA_CONFIG.issuer, `iss="${claims.iss}"`],
    [String(claims.aud) === SPA_CONFIG.clientId || (Array.isArray(claims.aud) && claims.aud.includes(SPA_CONFIG.clientId)), `aud="${claims.aud}"`],
    [!nonce || claims.nonce === nonce, `nonce="${claims.nonce}"`],
  ];
  const failures = checks.filter(([ok]) => !ok).map(([, detail]) => detail);
  if (failures.length) {
    throw new Error(`id_token invalide : ${failures.join(", ")}`);
  }
  return claims;
}

function rememberTokens(flowLabel, tokenResponse, claims, userInfo) {
  if (tokenResponse.access_token) store.set("access_token", tokenResponse.access_token);
  if (tokenResponse.id_token) store.set("id_token", tokenResponse.id_token);
  if (tokenResponse.refresh_token) store.set("refresh_token", tokenResponse.refresh_token);
  renderResult(
    flowLabel,
    {
      access_token: tokenResponse.access_token
        ? `${tokenResponse.access_token.slice(0, 32)}… (expires_in ${tokenResponse.expires_in}s)`
        : undefined,
      id_token: tokenResponse.id_token
        ? `${tokenResponse.id_token.slice(0, 32)}…`
        : undefined,
      refresh_token: tokenResponse.refresh_token
        ? `${tokenResponse.refresh_token.slice(0, 24)}…`
        : undefined,
      token_type: tokenResponse.token_type,
      claims_jwt: claims,
      userinfo: userInfo,
    }
  );
}

function rememberAlgoToken(flowLabel, tokenResponse, jwe, userInfo) {
  if (tokenResponse.access_token) store.set("access_token", tokenResponse.access_token);
  renderResult(flowLabel, {
    access_token: tokenResponse.access_token
      ? `${tokenResponse.access_token.slice(0, 32)}… (expires_in ${tokenResponse.expires_in}s)`
      : undefined,
    id_token_jwe: tokenResponse.id_token ? `${tokenResponse.id_token.slice(0, 64)}…` : undefined,
    jwe,
    userinfo: userInfo,
    token_type: tokenResponse.token_type,
  });
}

function renderJweIdToken(idToken) {
  const parts = idToken.split(".");
  if (parts.length !== 5) {
    throw new Error("id_token non JWE compact (5 segments attendus)");
  }
  return {
    header_jwe: JSON.parse(b64urlDecode(parts[0])),
    payload: "chiffré (JWE) — le déchiffrement et la vérification HS256 sont démontrés "
      + "par samples/id-token-algos-client (Python, WebCrypto non utilisé ici).",
  };
}

async function fetchUserInfo(endpoint, accessToken) {
  const response = await fetch(endpoint, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) {
    throw new Error(`UserInfo HTTP ${response.status}`);
  }
  return response.json();
}

async function completeCodeFlow(search) {
  if (search.get("error")) {
    throw new Error(`${search.get("error")}${search.get("error_description") ? ` — ${search.get("error_description")}` : ""}`);
  }
  verifyState(search.get("state"));
  const verifier = store.get("verifier");
  const nonce = store.get("nonce");
  store.remove("verifier");
  store.remove("nonce");
  const code = search.get("code");
  if (!code || !verifier) {
    throw new Error("code d'autorisation ou code_verifier manquant");
  }
  const config = await discovery();
  const algo = store.get("algo_flow") ? JSON.parse(store.get("algo_flow")) : null;
  if (algo) {
    store.remove("algo_flow");
    const response = await postFormBasic(
      config.token_endpoint,
      {
        grant_type: "authorization_code",
        code,
        redirect_uri: SPA_CONFIG.redirectUri,
        client_id: algo.clientId,
        code_verifier: verifier,
      },
      algo.clientId,
      algo.clientSecret
    );
    if (!response._ok) {
      throw new Error(`/token HTTP ${response._status} : ${JSON.stringify(response)}`);
    }
    if (!response.access_token) {
      throw new Error(`/token sans access_token : ${JSON.stringify(response)}`);
    }
    const userInfo = response.access_token
      ? await fetchUserInfo(config.userinfo_endpoint, response.access_token)
      : null;
    if (!response.id_token) {
      throw new Error(`/token sans id_token : ${JSON.stringify(response)}`);
    }
    log(
      "Code échangé : id_token chiffré (JWE) reçu — signature HS256 et déchiffrement " +
        "démontrés par le sample Python samples/id-token-algos-client",
      "ok"
    );
    rememberAlgoToken("id_token HS* + JWE", response, renderJweIdToken(response.id_token), userInfo);
    return;
  }
  const response = await postForm(config.token_endpoint, {
    grant_type: "authorization_code",
    code,
    redirect_uri: SPA_CONFIG.redirectUri,
    client_id: SPA_CONFIG.clientId,
    code_verifier: verifier,
  });
  if (!response._ok) {
    throw new Error(`/token HTTP ${response._status} : ${JSON.stringify(response)}`);
  }
  const claims = response.id_token ? verifyIdToken(response.id_token, nonce) : null;
  const userInfo = response.access_token
    ? await fetchUserInfo(config.userinfo_endpoint, response.access_token)
    : null;
  log("Code échangé : id_token vérifié (nonce/aud/iss), userinfo récupéré", "ok");
  rememberTokens("Authorization Code + PKCE", response, claims, userInfo);
}

async function completeFragmentFlow(hash) {
  if (hash.get("error")) {
    throw new Error(`${hash.get("error")}${hash.get("error_description") ? ` — ${hash.get("error_description")}` : ""}`);
  }
  verifyState(hash.get("state"));
  const nonce = store.get("nonce");
  store.remove("nonce");
  const config = await discovery();
  let claims = null;
  let response = {
    access_token: hash.get("access_token"),
    id_token: hash.get("id_token"),
    expires_in: Number(hash.get("expires_in") || 0),
    state: hash.get("state"),
    token_type: hash.get("token_type"),
  };
  if (response.id_token) {
    claims = verifyIdToken(response.id_token, nonce);
  }
  const hybridCode = hash.get("code");
  if (hybridCode) {
    const verifier = store.get("verifier");
    store.remove("verifier");
    const exchanged = await postForm(config.token_endpoint, {
      grant_type: "authorization_code",
      code: hybridCode,
      redirect_uri: SPA_CONFIG.redirectUri,
      client_id: SPA_CONFIG.clientId,
      code_verifier: verifier || "",
    });
    if (!exchanged._ok) {
      throw new Error(`/token HTTP ${exchanged._status} : ${JSON.stringify(exchanged)}`);
    }
    response = { ...response, ...exchanged };
    log("Flow hybrid : code échangé au /token (PKCE)", "ok");
  }
  const userInfo = response.access_token
    ? await fetchUserInfo(config.userinfo_endpoint, response.access_token)
    : null;
  log("Jetons reçus dans le fragment : id_token vérifié, userinfo récupéré", "ok");
  const label = hybridCode ? "Hybrid (code id_token token)" : "Implicit (id_token token)";
  rememberTokens(label, response, claims, userInfo);
}

async function beginAuthorizeFlow(responseType, extra, flowLabel) {
  const verifier = randomToken(32);
  const challenge = await sha256(verifier);
  const state = randomToken(16);
  const nonce = randomToken(16);
  store.set("verifier", verifier);
  store.set("state", state);
  store.set("nonce", nonce);
  const config = await discovery();
  const authorize = buildUrl(config.authorization_endpoint, {
    response_type: responseType,
    client_id: SPA_CONFIG.clientId,
    redirect_uri: SPA_CONFIG.redirectUri,
    scope: SPA_CONFIG.scope,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
    ...extra,
  });
  log(`${flowLabel} : redirection vers /login?next=<authorize>`);
  window.location.href = `${issuerOrigin()}/login?next=${encodeURIComponent(authorize)}`;
}

async function flowLogin() {
  try {
    await beginAuthorizeFlow("code", {}, "Authorization Code + PKCE");
  } catch (error) {
    fail(error, "login");
  }
}

async function flowImplicit() {
  try {
    await beginAuthorizeFlow("id_token token", {}, "Implicit");
  } catch (error) {
    fail(error, "implicit");
  }
}

async function flowHybrid() {
  try {
    await beginAuthorizeFlow("code id_token token", {}, "Hybrid");
  } catch (error) {
    fail(error, "hybrid");
  }
}

async function flowPar() {
  try {
    const verifier = randomToken(32);
    const challenge = await sha256(verifier);
    const state = randomToken(16);
    const nonce = randomToken(16);
    store.set("verifier", verifier);
    store.set("state", state);
    store.set("nonce", nonce);
    const config = await discovery();
    if (!config.pushed_authorization_request_endpoint) {
      throw new Error("endpoint /par non publié (par_enabled=false)");
    }
    const pushed = await postForm(config.pushed_authorization_request_endpoint, {
      response_type: "code",
      client_id: SPA_CONFIG.clientId,
      redirect_uri: SPA_CONFIG.redirectUri,
      scope: SPA_CONFIG.scope,
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    if (!pushed._ok) {
      throw new Error(`/par HTTP ${pushed._status} : ${JSON.stringify(pushed)}`);
    }
    log(`PAR : request_uri ${pushed.request_uri} (expires ${pushed.expires_in}s)`, "ok");
    const authorize = buildUrl(config.authorization_endpoint, {
      client_id: SPA_CONFIG.clientId,
      request_uri: pushed.request_uri,
    });
    window.location.href = `${issuerOrigin()}/login?next=${encodeURIComponent(authorize)}`;
  } catch (error) {
    fail(error, "PAR");
  }
}

async function flowDevice() {
  try {
    const config = await discovery();
    const started = await postForm(config.device_authorization_endpoint, {
      client_id: SPA_CONFIG.clientId,
      scope: SPA_CONFIG.scope,
    });
    if (!started._ok) {
      throw new Error(`/device_authorization HTTP ${started._status} : ${JSON.stringify(started)}`);
    }
    log(
      `Appareil enregistré : code ${started.user_code} — allez sur ` +
        `${started.verification_uri} et saisissez ce code (ou suivez ${started.verification_uri_complete})`,
      "ok"
    );
    const startedAt = Date.now();
    const deadline = startedAt + started.expires_in * 1000;
    const interval = Math.max(started.interval || 5, 5);
    const poll = async () => {
      if (Date.now() > deadline) {
        log("device_code expiré : recommencez le flow", "error");
        return;
      }
      const response = await postForm(config.token_endpoint, {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: started.device_code,
        client_id: SPA_CONFIG.clientId,
      });
      if (response._ok) {
        const userInfo = await fetchUserInfo(config.userinfo_endpoint, response.access_token);
        log("Appareil approuvé : jetons reçus", "ok");
        rememberTokens("Device Authorization Grant", response, response.id_token ? decodeJwt(response.id_token) : null, userInfo);
        return;
      }
      if (response.error === "authorization_pending") {
        log(`En attente d'approbation (re-sondage dans ${interval}s)…`);
        setTimeout(poll, interval * 1000);
        return;
      }
      if (response.error === "slow_down") {
        setTimeout(poll, (interval + 5) * 1000);
        return;
      }
      throw new Error(`${response.error}${response.error_description ? ` — ${response.error_description}` : ""}`);
    };
    setTimeout(poll, interval * 1000);
  } catch (error) {
    fail(error, "device");
  }
}

async function flowClientCredentials() {
  try {
    const config = await discovery();
    const response = await postForm(config.token_endpoint, {
      grant_type: "client_credentials",
      client_id: SPA_CONFIG.ccClientId,
      client_secret: SPA_CONFIG.ccClientSecret,
      scope: "openid",
    });
    if (!response._ok) {
      throw new Error(`/token HTTP ${response._status} : ${JSON.stringify(response)}`);
    }
    store.set("access_token", response.access_token);
    log("client_credentials : jeton machine à machine émis", "ok");
    rememberTokens("Client Credentials", response, decodeJwt(response.access_token), null);
  } catch (error) {
    fail(error, "client_credentials");
  }
}

async function flowIdTokenAlgos() {
  try {
    const config = await discovery();
    if (!config.registration_endpoint) {
      throw new Error("endpoint /register non publié (registration_enabled=false)");
    }
    const jwk = await generateRsaOaepJwk();
    const registered = await postJson(
      config.registration_endpoint,
      {
        redirect_uris: [SPA_CONFIG.redirectUri],
        scope: IDTOKEN_ALGOS_SCOPE,
        token_endpoint_auth_method: "client_secret_basic",
        id_token_signed_response_alg: SPA_CONFIG.idTokenSigningAlg,
        id_token_encrypted_response_alg: SPA_CONFIG.idTokenEncryptionAlg,
        id_token_encrypted_response_enc: SPA_CONFIG.idTokenEncryptionEnc,
        jwks: { keys: [jwk] },
      },
      SPA_CONFIG.registerToken
    );
    if (!registered._ok) {
      throw new Error(`/register HTTP ${registered._status} : ${JSON.stringify(registered)}`);
    }
    const state = randomToken(16);
    const nonce = randomToken(16);
    const verifier = randomToken(32);
    const challenge = await sha256(verifier);
    store.set("verifier", verifier);
    store.set("state", state);
    store.set("nonce", nonce);
    store.set(
      "algo_flow",
      JSON.stringify({ clientId: registered.client_id, clientSecret: registered.client_secret })
    );
    const authorize = buildUrl(config.authorization_endpoint, {
      response_type: "code",
      client_id: registered.client_id,
      redirect_uri: SPA_CONFIG.redirectUri,
      scope: IDTOKEN_ALGOS_SCOPE,
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    log(
      `id_token HS*/JWE : client ${registered.client_id} créé (/${SPA_CONFIG.idTokenSigningAlg} ` +
        `+ ${SPA_CONFIG.idTokenEncryptionAlg}/${SPA_CONFIG.idTokenEncryptionEnc}, RSA-2048 ` +
        `use:enc), redirection vers /login`
    );
    window.location.href = `${issuerOrigin()}/login?next=${encodeURIComponent(authorize)}`;
  } catch (error) {
    fail(error, "id_token HS*/JWE");
  }
}

async function flowProtectedApi() {
  try {
    store.set("api_pending", "1");
    await beginAuthorizeFlow("code", { scope: SPA_CONFIG.apiScope }, "API protégée");
  } catch (error) {
    fail(error, "api protégée");
  }
}

async function callProtectedApi() {
  const token = store.get("access_token");
  if (!token) {
    throw new Error("Aucun access_token en session");
  }
  const response = await fetch(`${SPA_CONFIG.apiBaseUrl}/api/data`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const text = await response.text();
  let payload;
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    payload = { raw: text };
  }
  if (!response.ok) {
    throw new Error(`API protégée HTTP ${response.status} : ${JSON.stringify(payload)}`);
  }
  log(
    `API protégée : token valide (signature JWKS de ${SPA_CONFIG.issuer}, ` +
      `iss/exp/aud contrôlés par le resource server) — ` +
      `aud=${payload.aud}, scope=${payload.scope}`,
    "ok"
  );
  renderResult("API protégée (/api/data)", payload);
}

async function flowRefresh() {
  try {
    const refreshToken = store.get("refresh_token");
    if (!refreshToken) {
      log("Aucun refresh_token en session (un flow code avec offline_access est requis)", "error");
      return;
    }
    const config = await discovery();
    const response = await postForm(config.token_endpoint, {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: SPA_CONFIG.clientId,
    });
    if (!response._ok) {
      throw new Error(`/token HTTP ${response._status} : ${JSON.stringify(response)}`);
    }
    log("Refresh : rotation du refresh_token effectuée", "ok");
    rememberTokens("Refresh Token", response, response.id_token ? decodeJwt(response.id_token) : null, null);
  } catch (error) {
    fail(error, "refresh");
  }
}

async function flowIntrospect() {
  try {
    const token = store.get("access_token");
    if (!token) {
      log("Aucun access_token en session : exécutez d'abord un flow de login", "error");
      return;
    }
    const config = await discovery();
    const response = await postForm(config.introspection_endpoint, {
      token,
      client_id: SPA_CONFIG.ccClientId,
      client_secret: SPA_CONFIG.ccClientSecret,
    });
    if (!response._ok) {
      throw new Error(`/introspect HTTP ${response._status} : ${JSON.stringify(response)}`);
    }
    log(`Introspection : active=${response.active}, sub=${response.sub || "-"}`, "ok");
    renderResult("Introspection", response);
  } catch (error) {
    fail(error, "introspect");
  }
}

async function flowRevoke() {
  try {
    const token = store.get("access_token");
    if (!token) {
      log("Aucun access_token en session : exécutez d'abord un flow de login", "error");
      return;
    }
    const config = await discovery();
    const response = await postForm(config.revocation_endpoint, {
      token,
      client_id: SPA_CONFIG.ccClientId,
      client_secret: SPA_CONFIG.ccClientSecret,
    });
    if (!response._ok) {
      throw new Error(`/revoke HTTP ${response._status} : ${JSON.stringify(response)}`);
    }
    store.remove("access_token");
    log("Révocation : access_token révoqué (200)", "ok");
  } catch (error) {
    fail(error, "revoke");
  }
}

async function flowLogout() {
  try {
    const config = await discovery();
    const idTokenHint = store.get("id_token");
    store.remove("id_token");
    const state = randomToken(16);
    store.set("logout_state", state);
    const logoutUrl = buildUrl(config.end_session_endpoint, {
      id_token_hint: idTokenHint || "",
      post_logout_redirect_uri: SPA_CONFIG.postLogoutRedirectUri,
      state,
    });
    log("Logout : redirection vers /end_session");
    window.location.href = logoutUrl;
  } catch (error) {
    fail(error, "logout");
  }
}

function renderFlows() {
  const flows = document.getElementById("flows");
  const buttons = [
    ["Se connecter", "Authorization Code + PKCE (RFC 6749 + 7636)", flowLogin],
    ["Implicit", "OIDC id_token + access_token dans le fragment", flowImplicit],
    ["Hybrid", "OIDC code + id_token + access_token, puis échange", flowHybrid],
    ["PAR", "Pushed Authorization Request (RFC 9126)", flowPar],
    ["Appareil", "Device Authorization Grant (RFC 8628)", flowDevice],
    ["Client Credentials", "RFC 6749 §4.4 (machine à machine)", flowClientCredentials],
    ["API protégée", "Appel de l'API échantillon (scope api.read, aud sample-api)", flowProtectedApi],
    ["id_token HS*/JWE", "Registration RFC 7591 + code flow, id_token chiffré JWE (issue #47)", flowIdTokenAlgos],
    ["Rafraîchir", "Rotation du refresh_token (RFC 6749 §6)", flowRefresh],
    ["Introspection", "RFC 7662 — active/sub", flowIntrospect],
    ["Révoquer", "RFC 7009 — révoque l'access_token", flowRevoke],
    ["Déconnexion", "RP-Initiated Logout (OIDC §5.2)", flowLogout],
  ];
  buttons.forEach(([label, subtitle, handler]) => {
    const button = document.createElement("button");
    button.type = "button";
    button.appendChild(document.createTextNode(label));
    const small = document.createElement("small");
    small.textContent = subtitle;
    button.appendChild(small);
    button.addEventListener("click", handler);
    flows.appendChild(button);
  });
}

function cleanupUrl() {
  const base = window.location.origin + window.location.pathname;
  history.replaceState(null, "", base);
}

async function handleCallback() {
  const search = new URLSearchParams(window.location.search);
  const hash = new URLSearchParams(window.location.hash.slice(1));

  if (search.get("code")) {
    await completeCodeFlow(search);
    cleanupUrl();
    if (store.get("api_pending")) {
      store.remove("api_pending");
      try {
        await callProtectedApi();
      } catch (error) {
        fail(error, "api protégée");
      }
    }
    return;
  }
  if (hash.get("id_token") || hash.get("access_token") || hash.get("code")) {
    await completeFragmentFlow(hash);
    cleanupUrl();
    return;
  }
  if (search.get("state") && store.get("logout_state")) {
    store.remove("logout_state");
    log("Déconnecté : retour de /end_session (session du serveur purgée)", "ok");
    cleanupUrl();
  }
}

async function init() {
  renderFlows();
  try {
    const config = await discovery();
    const summary = document.getElementById("endpoints");
    summary.textContent = `${config.issuer} — ${config.authorization_endpoint} | token ${config.token_endpoint}`;
  } catch (error) {
    log(`Discovery échoué : ${error.message}. Veillez à ce que le serveur PurIdentityServer tourne sur ${SPA_CONFIG.issuer}.`, "error");
    cleanupUrl();
    return;
  }
  await handleCallback();
}

window.addEventListener("DOMContentLoaded", init);