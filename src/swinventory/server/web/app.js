/* swinventory 화면. 빌드 없이 서버가 그대로 서빙한다.
 * 보안: 호스트명·패키지명·오류 메시지는 에이전트가 보낸 신뢰할 수 없는 문자열이다.
 *       그래서 innerHTML 을 쓰지 않고 항상 textContent(h() 헬퍼)로만 렌더링한다. */
(() => {
  "use strict";

  const $app = document.getElementById("app");
  const $top = document.getElementById("top");
  const $role = document.getElementById("role");
  const TOKEN_KEY = "swinv.token";
  let token = sessionStorage.getItem(TOKEN_KEY) || "";
  let role = ""; // /v1/whoami 결과: admin | request | read
  let authKind = ""; // 승인 워크플로는 요청·관리자 개인 세션에 한한다
  let generation = 0; // 느린 응답이 나중 화면을 덮어쓰지 않게 한다
  let enrollTimer = null; // '서버 등록' 화면의 등록 대기 폴링(화면을 벗어나면 정리)
  const expandedServers = new Set();
  let groupPath = "";
  const formDrafts = new Map(); // 비밀번호·발급된 JWT 는 넣지 않는다.
  let currentName = "overview"; // 지금 메뉴 이름 — 문서 제목과 표 정렬 기억의 범위
  let assetDraftGuard = null;

  // 권한 부족(403)과 '관리자 전용 컨트롤을 끈 이유'는 이 문구 하나로 통일한다.
  const ADMIN_ONLY = "관리자 권한으로 로그인해야 합니다";
  const NET_DOWN = "서버에 연결할 수 없습니다(잠시 후 다시 시도).";
  const PAGE_ROWS = 200; // 표는 한 번에 이만큼만 그리고 '더 보기'로 늘린다
  const SCREEN = { overview: "개요", kernels: "커널", software: "소프트웨어", hosts: "호스트", assets: "자산", containers: "컨테이너", network: "네트워크", events: "변경 이력", reports: "AI 리포트", enroll: "서버 등록", settings: "설정", accounts: "내 계정", users: "사용자 관리", tokens: "API 토큰", "business-apps": "업무용 앱", "sw-requests": "SW 사용 승인", cves: "취약점" };

  const EVENT_LABELS = {
    package_installed: ["설치", "ok"], package_removed: ["삭제", "err"],
    package_version_changed: ["버전 변경", "warn"], kernel_changed: ["커널 변경", "warn"],
    os_changed: ["OS 변경", "warn"], ip_added: ["IP 추가", "ok"], ip_removed: ["IP 제거", "err"],
    mac_changed: ["MAC 변경", "warn"], port_opened: ["포트 열림", "warn"], port_closed: ["포트 닫힘", ""],
    container_image_added: ["이미지 추가", "ok"], container_image_removed: ["이미지 제거", ""], container_image_changed: ["이미지 변경", "warn"],
  };
  const EXPOSURE = { any: ["모든 인터페이스", "warn"], specific: ["특정 주소", "neutral"], loopback: ["로컬 전용", "ok"] };
  const STATUS = { ok: ["정상", "ok"], error: ["수집 오류", "warn"], stale: ["수집 끊김", "err"] };
  const STATUS_ORDER = { stale: 0, error: 1, ok: 2 }; // 정렬할 때 문제 있는 쪽이 먼저 오게
  const CONTAINER_STATE = { running: ["실행 중", "ok"], exited: ["종료", ""], created: ["생성됨", ""], paused: ["일시정지", "warn"], unknown: ["알 수 없음", ""] };
  const KIND = { physical: ["물리", "neutral"], virtual: ["VM", "neutral"], container: ["컨테이너", ""], unknown: ["알 수 없음", ""] };
  const ASSET_STATUS = { linked: ["연결됨", "ok"], uncollected: ["미수집", "err"], unregistered: ["자산 미등록", "warn"] };
  const FLAG_LABELS = { kind_mismatch: "구분 불일치", serial_mismatch: "시리얼 불일치", ip_mismatch: "IP 불일치" };
  const MATCH_LABELS = { explicit: "수동 지정", serial: "시리얼", hostname: "호스트명", ip: "IP" };

  // ---------- DOM 헬퍼 ----------
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else if (k === "value") el.value = v;
      else if (k === "checked") el.checked = true;
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
  const enc = encodeURIComponent;
  let uidSeq = 0;
  const uid = (prefix) => `${prefix}-${++uidSeq}`;
  const link = (text, hash, cls) => h("a", { href: hash, class: cls }, text);
  const badge = (text, kind) => h("span", { class: "badge " + (kind || "") }, text);
  const tagsView = (tags) => Object.entries(tags || {}).map(([k, v]) => h("span", { class: "tag" }, `${k}=${v}`));
  const empty = (msg) => h("div", { class: "empty" }, msg);
  const kindLabel = (kind) => (KIND[kind] || [kind])[0];
  const kindBadge = (r) => {
    const [t, k] = KIND[r.kind] || [r.kind, ""];
    const source = r.kind_source === "asset" ? "자산 대장 값" : "에이전트 감지 값";
    return h("span", { class: "badge " + k, title: `${r.virt ? r.virt + " · " : ""}${source}` }, t);
  };
  const flagBadges = (flags) => (flags || []).map((f) => [" ", h("span", { class: "badge warn", title: "자산 대장 값과 수집된 값이 다릅니다" }, FLAG_LABELS[f] || f)]);

  // 자산 화면으로 가는 링크는 '지금 보던 화면'을 return 으로 싣는다 — 저장·삭제 뒤 같은 자리로 돌아오기 위해서다.
  // 검색어 입력으로 주소가 바뀌었을 수 있으므로 클릭하는 순간의 화면으로 다시 계산한다(아래 $app click 핸들러).
  function currentReturn() {
    const raw = location.hash || "#/overview";
    const i = raw.indexOf("?");
    if (i < 0) return raw;
    const q = new URLSearchParams(raw.slice(i + 1));
    q.delete("return"); // 중첩하면 주소가 계속 길어진다
    const s = q.toString();
    return s ? `${raw.slice(0, i)}?${s}` : raw.slice(0, i);
  }
  const withReturn = (path) => `${path}${path.includes("?") ? "&" : "?"}return=${enc(currentReturn())}`;
  // 자산번호(P-1099 처럼 하이픈이 있는 토큰)는 하이픈에서 끊기면 읽을 수 없다 — 링크 자체만 줄바꿈 금지(.nobreak). 칸을 통째로 nowrap 으로 두면 옆의 불일치 배지까지 한 줄로 묶여 열이 넓어진다.
  const assetLink = (path, text) => h("a", { href: withReturn(path), "data-ret": path, class: "nobreak" }, text);
  const returnHash = (q) => { const r = q.get("return"); return r && /^#\//.test(r) ? r : null; };
  $app.addEventListener("click", (e) => {
    const a = e.target.closest && e.target.closest("a[data-ret]");
    if (a) a.setAttribute("href", withReturn(a.dataset.ret));
  });
  const skipLink = document.querySelector(".skip-link");
  if (skipLink) skipLink.addEventListener("click", (event) => {
    event.preventDefault(); $app.focus(); $app.scrollIntoView({ block: "start" });
  });

  // 호스트를 가진 모든 목록이 같은 두 열을 쓴다. 자산이 없어도 수집된 구분(감지)이 보이고 자산번호만 '미등록'이다.
  // 자산번호 칸은 nowrap 이 아니다: 링크만 끊기지 않고 불일치 배지는 아래 줄로 내려갈 수 있어야 한다(cls: "asset" 은 칸의 최소 너비).
  const assetCell = (r) => [r.asset_no ? assetLink(`#/assets/${r.asset_id}`, r.asset_no) : h("span", { class: "muted", title: "자산 대장에 없음" }, "미등록"), flagBadges(r.asset_flags)];
  const assetCols = [
    { title: "자산번호", cls: "asset", sort: (r) => r.asset_no || null, render: assetCell },
    { title: "구분", sort: (r) => kindLabel(r.kind), render: kindBadge },
  ];

  // 시각: 목록은 'YYYY-MM-DD HH:mm' 로 줄이고 전체 시각은 툴팁(title)에 둔다.
  const pad2 = (n) => String(n).padStart(2, "0");
  function fmtTime(iso) {
    if (!iso) return "-";
    const d = new Date(iso);
    if (isNaN(d)) return String(iso);
    return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  }
  function fmtFull(iso) {
    const d = new Date(iso);
    return isNaN(d) ? String(iso) : d.toLocaleString("ko-KR", { hour12: false });
  }
  // 날짜 입력(YYYY-MM-DD)은 '브라우저 로컬 자정'이다 — 표의 시각(fmtTime)도 로컬로 보인다. 시간대 없이 보내면 서버가 UTC 로 읽어(한국은 9시간 어긋남)
  // 로컬 자정~UTC 자정 사이의 이벤트가 빠진다. 그래서 그 순간을 UTC 시각(Z)으로 바꿔 보낸다. 형식이 틀린 값은 그대로 보내 서버가 422 로 알리게 한다.
  function localMidnightUtc(ymd) {
    const d = new Date(`${ymd}T00:00:00`); // 오프셋 없는 날짜-시각 문자열은 로컬 시각으로 해석된다(ES 명세)
    return Number.isNaN(d.getTime()) ? `${ymd}T00:00:00` : d.toISOString().replace(/\.\d{3}Z$/, "Z");
  }
  const timeEl = (iso) => (iso ? h("time", { datetime: iso, title: fmtFull(iso) }, fmtTime(iso)) : "-");
  const stamp = (iso) => { const t = Date.parse(iso); return Number.isNaN(t) ? null : t; };
  function ago(iso) {
    const d = new Date(iso);
    if (isNaN(d)) return "-";
    const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
    if (s < 90) return "방금 전";
    if (s < 5400) return `${Math.round(s / 60)}분 전`;
    if (s < 129600) return `${Math.round(s / 3600)}시간 전`;
    return `${Math.round(s / 86400)}일 전`;
  }
  const agoEl = (iso) => (iso ? h("time", { datetime: iso, title: fmtFull(iso) }, ago(iso)) : "-");
  const statusBadge = (host) => { const [t, k] = STATUS[host.status] || [host.status, ""]; return badge(t, k); };
  const eventBadge = (type) => { const [t, k] = EVENT_LABELS[type] || [type, ""]; return badge(t, k); };

  // ---------- 표 ----------
  const collator = new Intl.Collator("ko", { numeric: true, sensitivity: "base" });
  const tableModule = window.SwinventoryUI?.createTable({ h, pageRows: PAGE_ROWS, empty });
  if (!tableModule) throw new Error("공통 표 모듈을 불러오지 못했습니다.");
  const table = tableModule.table;

  // 분포 막대: 거를 수 있는 항목은 진짜 button 이다(키보드 Tab·Enter·Space). active 를 주면 aria-pressed 로 현재 선택을 알린다.
  function bars(items, { onClick, nameOf = (i) => i.name, countOf = (i) => i.count, active, canClick = () => true, unit = "호스트" } = {}) {
    if (!items.length) return empty("데이터가 없습니다.");
    const max = Math.max(...items.map(countOf), 1);
    return h("div", { class: "bars" }, items.map((it) => {
      const fill = h("span", { class: "fill" });
      fill.style.width = `${(countOf(it) / max) * 100}%`; // CSSOM 대입은 CSP(style-src 'self') 에 걸리지 않는다
      const inner = [h("span", { class: "name", title: nameOf(it) }, nameOf(it)), h("span", { class: "track" }, fill), h("span", { class: "n" }, countOf(it))];
      if (!onClick || !canClick(it)) return h("div", { class: "bar" }, inner);
      const on = active ? active(it) : null;
      return h("button", { type: "button", class: "bar" + (on ? " active" : ""), "aria-pressed": on === null ? null : String(on),
        title: `${nameOf(it)} — ${countOf(it)}${unit} (눌러서 이 항목만 보기)`, onclick: () => onClick(it) }, inner);
    }));
  }

  // 적용 중인 필터를 보여 주고 하나씩 끈다.
  const chip = (text, onRemove, what) => h("span", { class: "chip" }, text,
    h("button", { type: "button", "aria-label": `${what || text} 필터 해제`, title: "필터 해제", onclick: onRemove }, "✕"));

  // 결과·상태 메시지. 진행·성공은 role=status, 오류는 role=alert 영역에 쓴다(보조기기가 바뀐 즉시 읽어 준다).
  function msgBox() {
    const st = h("span", { role: "status" });
    const al = h("span", { role: "alert" });
    const put = (on, cls, text, off) => { off.textContent = ""; on.className = cls; on.textContent = text; };
    return {
      el: h("span", { class: "msg" }, st, al),
      info: (t) => put(st, "muted", t, al),
      ok: (t) => put(st, "result-ok", t, al),
      err: (t) => put(al, "result-err", t, st),
      clear: () => { st.textContent = ""; al.textContent = ""; },
    };
  }

  // ---------- 권한 ----------
  const isAdmin = () => role === "admin";
  const isAdminSession = () => role === "admin" && authKind === "session";
  // 조회 전용 토큰이면 관리자 전용 컨트롤을 끈다 — 폼을 채우고 눌러 본 뒤에야 403 을 만나지 않게 이유를 툴팁으로 남긴다.
  function gate(...els) {
    if (!isAdmin()) for (const el of els) { el.disabled = true; el.title = ADMIN_ONLY; }
    return els[0];
  }
  // 값을 읽을 수 있어야 하는 입력(태그 목록 등)은 disabled 대신 readonly 로 둔다.
  function gateText(el) { if (!isAdmin()) { el.readOnly = true; el.title = ADMIN_ONLY; } return el; }
  const adminNote = () => (isAdmin() ? null : h("p", { class: "hint admin-note" }, `조회 권한으로 접속했습니다. 변경·삭제·생성은 ${ADMIN_ONLY}.`));
  const errMsg = (err, prefix) => (err.status === 403 ? ADMIN_ONLY : prefix ? `${prefix}: ${err.message}` : err.message);

  // ---------- API ----------
  class ApiError extends Error {
    constructor(status, message) { super(message); this.status = status; }
  }
  async function request(path, opts = {}) {
    const headers = { Authorization: `Bearer ${token}` };
    if (opts.body) headers["Content-Type"] = "application/json";
    let res;
    try { res = await fetch(path, { ...opts, headers }); } catch (_) { throw new ApiError(0, NET_DOWN); }
    if (res.status === 401) { logout("토큰이 올바르지 않거나 만료되었습니다. 다시 로그인하세요."); throw new ApiError(401, "인증이 필요합니다."); }
    if (!res.ok) {
      let msg = res.statusText;
      try {
        const j = await res.json();
        msg = typeof j.detail === "string" ? j.detail
          : Array.isArray(j.detail) ? j.detail.map((d) => `${(d.loc || []).slice(1).join(".")}: ${d.msg}`).join("; ") : JSON.stringify(j.detail);
      } catch (_) { /* 본문 없음 */ }
      throw new ApiError(res.status, msg);
    }
    return res;
  }
  const api = async (path, opts) => (await request(path, opts)).json();
  async function download(path, filename) {
    const blob = await (await request(path)).blob();
    const a = h("a", { href: URL.createObjectURL(blob), download: filename });
    document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  // CSV 는 '지금 화면의 조건'을 그대로 서버에 보낸다. 경로를 함수로 받아 누르는 순간의 필터·검색어로 만든다.
  const csvButton = (path, filename) => h("button", { type: "button", onclick: (e) => {
    const btn = e.currentTarget; btn.disabled = true;
    download(typeof path === "function" ? path() : path, filename).catch((err) => alert(`내보내기 실패: ${err.message}`)).finally(() => { btn.disabled = false; });
  } }, "CSV 내보내기");
  const withFormat = (params) => new URLSearchParams([...params, ["format", "csv"]]);

  // ---------- 라우팅 ----------
  const safeDecode = (s) => { try { return decodeURIComponent(s); } catch (_) { return s; } };
  function parseHash() {
    const raw = location.hash || "#/overview";
    const i = raw.indexOf("?");
    const path = i < 0 ? raw.slice(1) : raw.slice(1, i);
    return { segments: path.split("/").filter(Boolean).map(safeDecode), query: new URLSearchParams(i < 0 ? "" : raw.slice(i + 1)) };
  }
  function hashOf(base, params) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v) q.set(k, v);
    const s = q.toString();
    return s ? `${base}?${s}` : base;
  }
  function hashOfExact(base, params, keepEmpty = []) {
    const preserve = new Set(keepEmpty);
    const q = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value === null || value === undefined || value === false) continue;
      if (value === "" && !preserve.has(key)) continue;
      q.set(key, String(value));
    }
    const search = q.toString();
    return search ? `${base}?${search}` : base;
  }
  const replaceQueryExact = (base, params, keepEmpty = []) => history.replaceState(null, "", hashOfExact(base, params, keepEmpty));
  const setQuery = (base, params) => { location.hash = hashOf(base, params); };
  // 입력 중 주소만 갱신(hashchange 를 일으키지 않으므로 화면을 다시 그리지 않고 포커스·커서가 유지된다)
  const replaceQuery = (base, params) => history.replaceState(null, "", hashOf(base, params));

  // 검색 상자: 입력이 멈추면 주소(q)를 갱신하고 서버에서 다시 불러온다 — 화면·주소·CSV 가 같은 조건을 쓴다.
  function liveInput(input, st, base, reload, alive) {
    let timer;
    input.addEventListener("input", () => {
      st.q = input.value;
      clearTimeout(timer);
      timer = setTimeout(() => { if (!alive()) return; replaceQuery(base, { ...st, q: st.q.trim() }); reload(); }, 250);
    });
  }

  // 태그 필터는 `team:infra` 와 `team=infra` 둘 다 받는다(서버 규약은 key:value).
  const normTags = (s) => (s || "").split(",").map((t) => t.trim()).filter(Boolean).map((t) => (t.includes(":") || !t.includes("=") ? t : t.replace("=", ":"))).join(",");
  const tagList = (s) => (s || "").split(",").filter(Boolean);
  function tagFilter(value, apply) {
    const err = h("span", { class: "field-error", role: "alert" });
    const input = h("input", { type: "text", "aria-label": "태그 필터", placeholder: "태그 team:infra 또는 team=infra", value, size: 26, onchange: () => {
      const v = normTags(input.value);
      const bad = tagList(v).find((t) => t.startsWith(":") || !t.includes(":"));
      if (bad) { input.setAttribute("aria-invalid", "true"); err.textContent = `'${bad}' — key:value 형식으로 입력하세요(예: team:infra).`; return; }
      input.removeAttribute("aria-invalid"); err.textContent = "";
      apply(v);
    } });
    return [input, err];
  }

  const VIEWS = { accounts: viewMyAccount, users: viewUsers, tokens: viewTokens, overview: viewOverview, kernels: viewKernels, software: viewSoftware, hosts: viewHosts, assets: viewAssets, containers: viewContainers, events: viewEvents, reports: viewReports, settings: viewSettings, network: viewNetwork, enroll: viewEnroll, "business-apps": viewBusinessSoftware, "sw-requests": viewSoftwareRequests, cves: viewVulnerabilities };

  const titled = (node, sub) => { node.dataset.title = sub; return node; }; // 상세 화면은 대상 이름을 문서 제목에 싣는다
  const documentTitle = (name, sub) => (sub ? `${sub} · ${SCREEN[name]} · swinventory` : `${SCREEN[name]} · swinventory`);

  function showRole() {
    document.querySelectorAll("[data-admin]").forEach((el) => { el.hidden = !isAdmin(); });
    document.querySelectorAll("[data-request]").forEach((el) => { el.hidden = role !== "admin" && !(role === "request" && authKind === "session"); });
    $role.hidden = false;
    $role.textContent = isAdmin() ? "관리자" : role === "request" ? "요청자" : "조회 전용";
    $role.className = "badge " + (isAdmin() ? "ok" : role === "request" ? "warn" : "neutral");
    $role.title = isAdmin() ? "관리자 권한으로 로그인했습니다" : role === "request" ? "요청 범위에서 업무용 SW 사용 승인을 요청할 수 있습니다" : `조회 권한으로 접속했습니다. 변경 기능은 ${ADMIN_ONLY}.`;
  }
  async function loadRole() {
    try {
      role = (await api("/v1/whoami")).role;
      authKind = (await api("/v1/auth/me")).kind;
    } catch (err) {
      if (err.status === 401) return false; // request() 가 이미 로그인 화면으로 보냈다
      if (err.status === 403) { logout("이 토큰으로는 조회할 수 없습니다(수집 전용)."); return false; }
      throw err; // 네트워크·서버 오류는 아래 render 가 '다시 시도' 안내를 띄운다
    }
    return true;
  }

  // 초점: 화면(경로)을 옮기면 제목(h1)으로 보낸다. 같은 화면에서 주소의 query 만 바뀌어 다시 그릴 때(필터 select·체크박스 등)는
  // 사용자가 만지던 컨트롤에 초점을 돌려준다 — 컨트롤은 매번 새로 만들어지므로 '태그|이름(aria-label 또는 글자)'로 짝을 짓는다.
  // 접근 가능한 이름이 같은 컨트롤이 한 화면에 둘이면 첫 번째로 돌아간다(지금 화면에는 그런 필터 컨트롤이 없다).
  let lastPath = "";
  let pendingFocus = null; // 다시 그리기 직전에 초점이 있던 컨트롤의 키(afterRender 가 쓰고 비운다)
  const FOCUSABLE = "a[href], button, input, select, textarea";
  const controlKey = (el) => `${el.localName}|${(el.getAttribute("aria-label") || el.textContent || "").trim()}`;
  const findControl = (key) => [...$app.querySelectorAll(FOCUSABLE)].find((el) => controlKey(el) === key);
  const rememberFocus = () => { const el = document.activeElement; return el && $app.contains(el) && el.matches(FOCUSABLE) ? controlKey(el) : null; };
  function restoreFocus(key) {
    const el = findControl(key);
    if (el) el.focus(); // 화면 밖이면 브라우저가 필요한 만큼만 스크롤한다. 꺼진(disabled) 컨트롤은 초점을 받지 못한다
    return !!el && document.activeElement === el;
  }
  function focusTitle() {
    const title = $app.querySelector("h1");
    if (title) { title.setAttribute("tabindex", "-1"); title.focus({ preventScroll: true }); }
  }
  function afterRender(segments) {
    const key = segments.join("/");
    const moved = key !== lastPath; // 다른 화면으로 옮겼는가(같은 화면에서 필터 query 만 바뀐 것은 아니다)
    const mark = pendingFocus;
    lastPath = key; pendingFocus = null;
    if (moved) window.scrollTo(0, 0);
    // 같은 화면이면 만지던 컨트롤로 돌려보내고, 그 컨트롤이 사라졌을 때(필터 칩 해제 등)만 제목으로 — 초점이 문서 처음으로 떨어지지 않게.
    // 초점이 화면 바깥(메뉴 링크 등)에 있었다면 건드리지 않는다.
    if (moved || (mark && !restoreFocus(mark))) focusTitle();
  }

  async function render() {
    if (assetDraftGuard && location.hash !== assetDraftGuard.hash) {
      if (assetDraftGuard.isDirty() && !confirm("저장하지 않은 자산 변경 내용이 있습니다. 이 화면을 떠날까요?")) {
        // location.hash 로 되돌리면 두 번째 hashchange 가 폼을 다시 읽어 초안을 지운다.
        // 현재 항목만 replaceState 로 복구해 입력 중인 DOM 과 초점을 그대로 둔다.
        history.replaceState(history.state, "", assetDraftGuard.hash);
        return;
      }
      assetDraftGuard = null;
    }
    if (!token) return renderLogin();
    const { segments, query } = parseHash();
    const name = VIEWS[segments[0]] ? segments[0] : "overview";
    if (name !== currentName) { tableModule.clearSortMemory(); currentName = name; }
    $top.hidden = false;
    document.body.classList.add("signed-in");
    setMenu(false);
    const path = segments.join("/");
    if (path !== groupPath) { expandedServers.clear(); groupPath = path; }
    document.getElementById("my-account").setAttribute("aria-current", name === "accounts" ? "page" : "false");
    document.querySelectorAll("#nav a").forEach((a) => {
      const on = a.dataset.route === name;
      a.classList.toggle("active", on);
      if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    });
    document.title = documentTitle(name);
    const mine = ++generation;
    clearInterval(enrollTimer);
    // clear($app) 가 초점을 날리기 전에 기억한다. 아직 그려지는 중(자리표시자만 보임)에 또 시작되면 초점이 이미 body 라서 null 이 되므로 앞선 기록을 유지한다.
    pendingFocus = rememberFocus() || pendingFocus;
    clear($app).append(h("div", { class: "muted", role: "status" }, "불러오는 중…"));
    try {
      if (!role && !(await loadRole())) return;
      if (mine !== generation) return;
      showRole();
      const node = await VIEWS[name](segments.slice(1), query, () => mine === generation);
      if (mine === generation && node) {
        clear($app).append(node);
        document.title = documentTitle(name, node.dataset.title);
        afterRender(segments);
      }
    } catch (err) {
      if (mine !== generation || err.status === 401) return;
      lastPath = ""; // 오류 화면은 어느 화면도 아니다 — 다시 그려지면(원래 보던 화면으로 돌아와도) 새 화면으로 보고 제목으로 초점을 보낸다
      clear($app).append(h("div", { class: "error", role: "alert" }, `불러오지 못했습니다: ${err.message}`),
        h("button", { type: "button", onclick: render }, "다시 시도"));
    }
  }

  function logout(message) {
    if (!message && assetDraftGuard?.isDirty() && !confirm("저장하지 않은 자산 변경 내용이 있습니다. 로그아웃할까요?")) return;
    assetDraftGuard = null;
    generation++; token = ""; role = ""; authKind = ""; sessionStorage.removeItem(TOKEN_KEY);
    formDrafts.clear(); expandedServers.clear(); groupPath = "";
    clearInterval(enrollTimer); renderLogin(message);
  }
  // 로그인 확인은 request() 를 쓰지 않는다(401 일 때 request 가 로그인 화면을 한 번 더 그리지 않게).
  async function probeRole(candidate) {
    // 헤더 값에는 ASCII 만 넣을 수 있다 — 한글 등이 섞이면 fetch 가 TypeError 를 던져 '서버 연결 실패'로 오해하게 된다. 서버에 보내기 전에 잘못된 토큰으로 판정한다.
    if (!/^[\x20-\x7e]+$/.test(candidate)) throw new ApiError(401, "invalid token");
    let res;
    try { res = await fetch("/v1/whoami", { headers: { Authorization: `Bearer ${candidate}` } }); } catch (_) { throw new ApiError(0, NET_DOWN); }
    if (!res.ok) throw new ApiError(res.status, res.statusText);
    const identity = await res.json();
    const principalRes = await fetch("/v1/auth/me", { headers: { Authorization: `Bearer ${candidate}` } });
    if (!principalRes.ok) throw new ApiError(principalRes.status, principalRes.statusText);
    return { role: identity.role, kind: (await principalRes.json()).kind };
  }
  const loginError = (err) => (err.status === 401 ? "토큰이 올바르지 않습니다." : err.status === 403 ? "이 토큰으로는 조회할 수 없습니다(수집 전용)." : NET_DOWN);
  function renderLogin(message) {
    lastPath = ""; // 로그인 화면은 어느 화면도 아니다 — 로그인 뒤에는 어느 화면이든 '새 화면'이다(제목으로 초점)
    $top.hidden = true; $role.hidden = true;
    document.body.classList.remove("signed-in"); setMenu(false);
    document.title = "로그인 · swinventory";
    const input = h("input", { id: "login-token", type: "password", placeholder: "조회 토큰 또는 관리자 토큰", autocomplete: "off", required: true });
    const note = message ? h("div", { class: "error", role: "alert" }, message)
      : h("div", { class: "muted" }, "서버 관리자에게 받은 조회 토큰 또는 관리자 토큰을 입력하세요. 탭을 닫으면 지워집니다.");
    const submit = h("button", { type: "submit" }, "토큰으로 접속");
    const form = h("form", { onsubmit: async (e) => {
      e.preventDefault();
      const candidate = input.value.trim();
      if (!candidate) return;
      submit.disabled = true;
      try {
        const identity = await probeRole(candidate); role = identity.role; authKind = identity.kind;
        token = candidate; sessionStorage.setItem(TOKEN_KEY, token);
        if (location.hash) render(); else location.hash = "#/overview"; // 딥링크로 들어왔다면 원래 페이지로(해시가 바뀌면 hashchange 가 그린다)
      } catch (err) { token = ""; role = ""; authKind = ""; renderLogin(loginError(err)); }
    } }, h("label", { for: "login-token", class: "muted" }, "토큰"), input, submit);
    const username = h("input", { id: "login-id", autocomplete: "username", required: true, maxlength: 64 });
    const password = h("input", { id: "login-password", type: "password", autocomplete: "current-password", required: true, maxlength: 128 });
    const accountMsg = msgBox();
    const accountSubmit = h("button", { class: "primary", type: "submit" }, "로그인");
    const accountForm = h("form", { onsubmit: async (e) => {
      e.preventDefault(); accountSubmit.disabled = true; accountMsg.clear();
      try {
        const res = await fetch("/v1/auth/login", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: username.value.trim(), password: password.value }) });
        let result;
        try { result = await res.json(); } catch (_) { throw new Error(NET_DOWN); }
        if (!res.ok) throw new Error(typeof result.detail === "string" ? result.detail : "로그인에 실패했습니다.");
        password.value = ""; token = result.access_token; role = ""; authKind = "";
        sessionStorage.setItem(TOKEN_KEY, token);
        if (location.hash) render(); else location.hash = "#/overview";
      } catch (err) { password.value = ""; accountMsg.err(err instanceof TypeError ? NET_DOWN : err.message || NET_DOWN); accountSubmit.disabled = false; }
    } }, field("ID", username), field("비밀번호", password), accountSubmit, accountMsg.el);
    clear($app).append(h("div", { class: "login panel" }, h("h1", null, "swinventory"),
      message ? note : h("p", { class: "muted" }, "관리자에게 발급받은 계정으로 로그인하세요."), accountForm,
      h("details", { class: "token-login" }, h("summary", null, "JWT·기존 토큰으로 로그인"), form)));
    username.focus();
  }

  // ---------- 개요 ----------
  async function viewOverview() {
    const o = await api("/v1/overview");
    const pct = (o.healthy_rate * 100).toFixed(o.host_count ? 1 : 0);
    const card = (label, value, sub, cls, href) => h(href ? "a" : "div", { class: `card ${cls || ""}`, href }, h("div", { class: "label" }, label), h("div", { class: "value" }, value), h("div", { class: "sub" }, sub));
    return h("div", null,
      h("h1", null, "개요"),
      o.host_count === 0 ? h("div", { class: "notice" }, "아직 등록된 서버가 없습니다. ", link("서버 등록", "#/enroll"), " 에서 설치 명령을 복사해 대상 서버에서 실행하세요.") : null,
      h("div", { class: "cards stat-strip" },
        card("전체 서버", o.host_count, "", "", "#/hosts"),
        card("수집 정상", `${pct}%`, `${o.healthy_count} / ${o.host_count}대`, "", "#/hosts?status=ok"),
        card("실행 중 컨테이너", o.containers.running_container_count, "", "", "#/containers/list?active=1"),
        card("클러스터", o.containers.cluster_count, `노드 ${o.containers.node_count}대`, "", "#/containers")),
      h("h2", null, "우선 확인"),
      table([
        { title: "항목", render: (r) => r.label },
        { title: "영향", render: (r) => r.detail },
        { title: "건수", sort: (r) => r.count, desc: true, render: (r) => badge(String(r.count), r.level) },
        { title: "확인", render: (r) => link("목록 보기", r.href) },
      ], [
        { label: "IP 충돌", count: o.ip_conflict_count, detail: "같은 IP를 사용하는 서버", level: "err", href: "#/network?conflicts=1" },
        { label: "수집 끊김", count: o.stale_count, detail: `${o.stale_after_hours}시간 이상 수집되지 않음`, level: "err", href: "#/hosts?status=stale" },
        { label: "수집 오류", count: o.error_count, detail: "일부 수집 항목 실패", level: "warn", href: "#/hosts?status=error" },
        { label: "주의 포트", count: o.notable_exposed_host_count, detail: "민감 서비스의 외부 바인딩 확인 필요", level: "warn", href: "#/network/ports?notable=1" },
        { label: "커널 하한선 미달", count: o.noncompliant_count, detail: "최소 커널 버전보다 낮음", level: "warn", href: "#/kernels?compliant=false" },
        { label: "재부팅 필요", count: o.reboot_required_count, detail: "설치한 커널이 아직 적용되지 않음", level: "warn", href: "#/kernels?reboot=1" },
        { label: "자산 미등록", count: o.assets.unregistered, detail: "자산 대장에 없는 서버", level: "", href: "#/assets?status=unregistered" },
        { label: "자산 미수집", count: o.assets.uncollected, detail: "대장에 있지만 수집되지 않은 자산", level: "", href: "#/assets?status=uncollected" },
      ].filter((r) => r.count > 0), "현재 조치가 필요한 항목이 없습니다."),
      h("div", { class: "section-heading" }, h("h2", null, "최근 변경"), link("전체 변경 이력", "#/events")), eventsTable(o.recent_events.slice(0, 8)),
      h("h2", null, "실행 중 커널 분포"),
      h("div", { class: "panel" }, bars(o.kernel_distribution, {
        nameOf: (k) => k.version, countOf: (k) => k.host_count,
        onClick: (k) => { location.hash = `#/kernels?running=${enc(k.version)}`; } })),
      );
  }

  function eventsTable(events, withAsset = true) {
    return table([
      { title: "시각", desc: true, sort: (e) => stamp(e.occurred_at), render: (e) => timeEl(e.occurred_at) },
      { title: "호스트", sort: (e) => e.hostname, render: (e) => link(e.hostname, `#/hosts/${enc(e.host_id)}`) },
      ...(withAsset ? assetCols : []),
      { title: "유형", sort: (e) => (EVENT_LABELS[e.event_type] || [e.event_type])[0], render: (e) => eventBadge(e.event_type) },
      { title: "대상", mono: true, sort: (e) => e.subject_key, render: (e) => e.subject_key },
      { title: "변경", mono: true, render: (e) => `${e.old_value ?? "∅"} → ${e.new_value ?? "∅"}` },
    ], events, "변경 이력이 없습니다.");
  }

  // ---------- 커널 ----------
  async function viewKernels(_, q, alive) {
    const st = { reboot: q.get("reboot") || "", running: q.get("running") || "", compliant: q.get("compliant") || "", tag: normTags(q.get("tag")), q: q.get("q") || "" };
    const params = () => {
      const p = new URLSearchParams();
      if (st.reboot) p.set("reboot_required", "true");
      if (st.running) p.set("running", st.running);
      if (st.compliant) p.set("compliant", st.compliant);
      tagList(st.tag).forEach((t) => p.append("tag", t));
      if (st.q.trim()) p.set("q", st.q.trim());
      return p;
    };
    const [dist, policy, first] = await Promise.all([api("/v1/kernels"), api("/v1/settings/kernel-policy"), api(`/v1/kernels/hosts?${params()}`)]);
    const hasPolicy = policy.rules.length > 0;
    const apply = (patch) => setQuery("#/kernels", { ...st, ...patch });

    const heading = h("h2", null, "");
    const body = h("div");
    const draw = (rows) => {
      heading.textContent = `호스트별 커널 (${rows.length})`;
      clear(body).append(table([
        { title: "호스트", sort: (r) => r.hostname, render: (r) => link(r.hostname, `#/hosts/${enc(r.host_id)}`) },
        ...assetCols,
        { title: "실행 중 커널", mono: true, sort: (r) => r.running, render: (r) => r.running },
        { title: "설치된 최신 커널", mono: true, sort: (r) => r.latest_installed, render: (r) => r.latest_installed },
        { title: "하한선", mono: true, sort: (r) => r.min_kernel, render: (r) => r.min_kernel || "-" },
        { title: "준수", sort: (r) => (r.compliant === null ? null : Number(r.compliant)), render: (r) => (r.compliant === null ? "" : r.compliant ? badge("준수", "ok") : badge("미달", "err")) },
        { title: "재부팅", desc: true, sort: (r) => Number(!!r.reboot_required), render: (r) => (r.reboot_required ? badge("재부팅 필요", "warn") : badge("최신", "ok")) },
        { title: "태그", render: (r) => tagsView(r.tags) },
      ], rows, "조건에 맞는 호스트가 없습니다."));
    };
    let seq = 0;
    const reload = async () => {
      const mine = ++seq;
      try { const rows = await api(`/v1/kernels/hosts?${params()}`); if (mine === seq && alive()) draw(rows); }
      catch (err) { if (mine === seq && alive()) clear(body).append(h("div", { class: "error", role: "alert" }, errMsg(err, "불러오지 못했습니다"))); }
    };
    const search = h("input", { type: "search", placeholder: "호스트·자산번호 검색", "aria-label": "호스트 검색", value: st.q, size: 24 });
    liveInput(search, st, "#/kernels", reload, alive);
    draw(first);

    const runningSel = h("select", { "aria-label": "실행 중 커널", onchange: (e) => apply({ running: e.target.value }) },
      h("option", { value: "" }, "모든 커널"),
      dist.map((k) => h("option", { value: k.version, selected: k.version === st.running }, `${k.version} (${k.host_count})`)));
    // 하한선이 없으면 '미달/준수' 판정 자체가 없다(compliant 는 null) — 고를 수 없게 하고 설정 화면으로 안내한다.
    const complianceSel = h("select", { "aria-label": "하한선 준수 여부", onchange: (e) => apply({ compliant: e.target.value }) },
      h("option", { value: "" }, "하한선: 전체"),
      h("option", { value: "false", selected: st.compliant === "false", disabled: !hasPolicy }, "하한선 미달만"),
      h("option", { value: "true", selected: st.compliant === "true", disabled: !hasPolicy }, "하한선 준수만"));
    return h("div", null, h("h1", null, "커널 버전"),
      h("div", { class: "panel" }, bars(dist, { nameOf: (k) => k.version, countOf: (k) => k.host_count, onClick: (k) => apply({ running: st.running === k.version ? "" : k.version }), active: (k) => k.version === st.running })),
      heading,
      h("div", { class: "toolbar" }, runningSel, complianceSel,
        hasPolicy ? null : h("span", { class: "muted" }, "하한선이 설정되지 않았습니다 — ", link("설정에서 지정", "#/settings")),
        h("label", null, h("input", { type: "checkbox", checked: !!st.reboot, onchange: (e) => apply({ reboot: e.target.checked ? "1" : "" }) }), "재부팅 필요만"),
        tagFilter(st.tag, (v) => apply({ tag: v })), search, h("span", { class: "spacer" }), csvButton(() => `/v1/kernels/hosts?${withFormat(params())}`, "kernels-hosts.csv")),
      body);
  }

  // 이름이 같은 서버도 host_id 로 분리하고, 없는 서버 필터도 임의 해제하지 않는다.
  function serverFilter(hosts, selected, change) {
    const counts = new Map();
    hosts.forEach((r) => counts.set(r.hostname, (counts.get(r.hostname) || 0) + 1));
    return h("select", { "aria-label": "서버 필터", onchange: (e) => change(e.target.value) },
      h("option", { value: "", selected: !selected }, "모든 서버"),
      selected && !hosts.some((r) => r.host_id === selected) ? h("option", { value: selected, selected: true }, `등록되지 않은 서버 (${selected})`) : null,
      hosts.map((r) => h("option", { value: r.host_id, selected: r.host_id === selected }, counts.get(r.hostname) > 1 ? `${r.hostname} (${r.host_id})` : r.hostname)));
  }

  function serverGroups(rows, render, label, countOf = (items) => items.length, lazy = false) {
    if (!rows.length) return empty("조건에 맞는 서버 데이터가 없습니다.");
    const groups = new Map();
    rows.forEach((r) => { if (!groups.has(r.host_id)) groups.set(r.host_id, []); groups.get(r.host_id).push(r); });
    const names = new Map();
    groups.forEach((items) => names.set(items[0].hostname, (names.get(items[0].hostname) || 0) + 1));
    return h("div", { class: "panel server-groups" }, [...groups].map(([id, items]) => {
      const body = h("div", { class: "server-group-body" });
      let loaded = !lazy;
      if (!lazy) body.append(render(items));
      const details = h("details", { class: "server-group", "data-host-id": id, open: expandedServers.has(id) },
        h("summary", { title: `${items[0].hostname || id} · 서버 ID: ${id}` }, h("span", { class: "server-name" }, h("span", { class: "sr-only" }, "서버: "), items[0].hostname || id,
          names.get(items[0].hostname) > 1 ? h("small", { class: "muted" }, ` (${id})`) : null),
          h("span", { class: "server-count" }, `${label} ${countOf(items)}개`)), body);
      details.addEventListener("toggle", async () => {
        if (!details.isConnected) return;
        if (details.open) expandedServers.add(id); else expandedServers.delete(id);
        if (!details.open || loaded) return;
        loaded = true;
        clear(body).append(h("p", { role: "status" }, "불러오는 중…"));
        try { clear(body).append(await render(items)); }
        catch (err) { loaded = false; clear(body).append(h("div", { class: "error", role: "alert" }, errMsg(err, "불러오지 못했습니다. 접었다 다시 펼쳐 재시도하세요."))); }
      });
      return details;
    }));
  }

  function inventorySection(kind, title, ...content) {
    return h("details", { class: "inventory-section", "data-kind": kind }, h("summary", null, h("h2", null, title)), ...content);
  }

  // ---------- 소프트웨어 ----------
  async function viewSoftware(rest, q, alive) {
    if (rest[0]) return softwareDetail(rest.join("/"), q);
    const st = { q: q.get("q") || "", host: q.get("host") || "" };
    const hosts = await api("/v1/hosts");
    const input = h("input", { type: "search", placeholder: "패키지 이름 검색 (예: openssl)", "aria-label": "패키지 이름 검색", value: st.q, size: 36 });
    const out = h("div"); let seq = 0;
    const run = async () => {
      const mine = ++seq;
      const params = new URLSearchParams();
      if (st.q.trim()) params.set("q", st.q.trim());
      if (st.host) params.set("host", st.host);
      try {
        const rows = await api(`/v1/software-hosts?${params}`);
        if (mine !== seq || !alive()) return;
        const term = st.q.trim().toLowerCase();
        clear(out).append(serverGroups(rows, async ([owner]) => {
          const d = await api(`/v1/hosts/${enc(owner.host_id)}`);
          return table([
            { title: "패키지", mono: true, sort: (r) => r.name, render: (r) => link(r.name, `#/software/${enc(r.name)}?host=${enc(owner.host_id)}`) },
            { title: "버전", mono: true, sort: (r) => r.version, render: (r) => r.version || "-" },
            { title: "아키텍처", sort: (r) => r.arch, render: (r) => r.arch || "-" },
            { title: "출처", sort: (r) => r.source, render: (r) => r.source },
          ], d.packages.filter((r) => r.name.toLowerCase().includes(term)));
        }, "소프트웨어", (items) => items[0].package_count, true));
      } catch (err) { if (mine === seq && alive()) clear(out).append(h("div", { class: "error", role: "alert" }, err.message)); }
    };
    liveInput(input, st, "#/software", run, alive);
    run();
    return h("div", null, h("h1", null, "소프트웨어"), h("div", { class: "toolbar" }, serverFilter(hosts, st.host, (host) => setQuery("#/software", { ...st, host })), input), out);
  }

  async function softwareDetail(name, q) {
    const st = { version: q.get("version") || "", below: (q.get("below") || "").trim(), host: q.get("host") || "" };
    const explicitReturn = returnHash(q);
    const back = explicitReturn || `#/software${st.host ? `?host=${enc(st.host)}` : ""}`;
    const params = () => {
      const p = new URLSearchParams();
      if (st.version) p.set("version", st.version);
      if (st.below) p.set("below", st.below);
      if (st.host) p.set("host", st.host);
      return p;
    };
    const [d, hosts] = await Promise.all([api(`/v1/software/${enc(name)}?${params()}`), api("/v1/hosts")]);
    const base = `#/software/${enc(name)}`;
    // 직접 소프트웨어 목록에서 연 경우에는 fallback 뒤로가기만 표시한다. return 쿼리는 링크로
    // 들어와 원래 주소에 명시된 때에만 다음 필터 URL에도 보존한다.
    const apply = (patch) => setQuery(base, { ...st, ...patch, ...(explicitReturn ? { return: explicitReturn } : {}) });
    const belowIn = h("input", { type: "text", id: "below-version", placeholder: "예: 3.0.11", value: st.below, size: 14 });
    const chips = [];
    if (st.version) chips.push(chip(`버전 = ${st.version}`, () => apply({ version: "" }), `버전 ${st.version}`));
    if (st.below) chips.push(chip(`${st.below} 미만`, () => apply({ below: "" }), `${st.below} 미만`));
    return titled(h("div", null,
      h("div", { class: "toolbar" }, link("← 이전 화면", back), serverFilter(hosts, st.host, (host) => apply({ host })), h("span", { class: "spacer" }), csvButton(() => `/v1/software/${enc(name)}?${withFormat(params())}`, `${name}-hosts.csv`)),
      h("h1", { class: "mono" }, d.name),
      h("h2", null, "버전 분포"),
      h("p", { class: "hint" }, "막대를 누르면 그 버전을 쓰는 호스트만 아래 목록에 보입니다. 다시 누르면 해제됩니다."),
      h("div", { class: "panel" }, bars(d.versions, {
        nameOf: (v) => v.version || "(버전 없음)", countOf: (v) => v.host_count,
        canClick: (v) => !!v.version, active: (v) => v.version === st.version,
        onClick: (v) => apply({ version: st.version === v.version ? "" : v.version, below: "" }) })),
      h("form", { class: "toolbar", onsubmit: (e) => { e.preventDefault(); apply({ below: belowIn.value.trim(), version: "" }); } },
        h("label", { for: "below-version" }, "이 버전 미만"), belowIn, h("button", { type: "submit" }, "적용"),
        chips),
      h("h2", null, `설치 호스트 (${new Set(d.hosts.map((host) => host.host_id)).size})`),
      h("p", { class: "muted" }, `설치 항목 ${d.hosts.length}행`),
      serverGroups(d.hosts, (items) => table([
        { title: "호스트", sort: (r) => r.hostname, render: (r) => link(r.hostname, `#/hosts/${enc(r.host_id)}`) },
        ...assetCols,
        { title: "버전", mono: true, sort: (r) => r.version, render: (r) => r.version || "-" },
        { title: "아키텍처", sort: (r) => r.arch, render: (r) => r.arch || "-" },
        { title: "출처", sort: (r) => r.source, render: (r) => r.source },
      ], items), "소프트웨어")), name);
  }

  // ---------- 호스트 ----------
  async function viewHosts(rest, q, alive) {
    if (rest[0]) return hostDetail(rest.join("/"), q);
    const st = { status: q.get("status") || "", tag: normTags(q.get("tag")), q: q.get("q") || "" };
    const params = () => {
      const p = new URLSearchParams();
      tagList(st.tag).forEach((t) => p.append("tag", t));
      if (st.status) p.set("status", st.status);
      if (st.q.trim()) p.set("q", st.q.trim());
      return p;
    };
    const first = await api(`/v1/hosts?${params()}`);
    const apply = (patch) => setQuery("#/hosts", { ...st, ...patch });
    const title = h("h1", null, "");
    const body = h("div");
    const draw = (rows) => {
      title.textContent = `호스트 (${rows.length})`;
      clear(body).append(table([
        { title: "상태", sort: (x) => STATUS_ORDER[x.status] ?? 9, render: statusBadge },
        { title: "호스트", sort: (x) => x.hostname, render: (x) => link(x.hostname, `#/hosts/${enc(x.host_id)}`) },
        ...assetCols,
        { title: "도메인", sort: (x) => x.domain, render: (x) => x.domain || "-" },
        { title: "IP", mono: true, sort: (x) => x.ips[0] || null, render: (x) => (x.ips.length ? [x.ips.slice(0, 2).join(", "), x.ips.length > 2 ? ` +${x.ips.length - 2}` : ""] : "-") },
        { title: "OS", cls: "os", sort: (x) => x.os_name, render: (x) => x.os_name || "-" },
        { title: "실행 중 커널", mono: true, sort: (x) => x.running, render: (x) => [x.running || "-", x.kernel_compliant === false ? " " : null, x.kernel_compliant === false ? badge("하한선 미달", "err") : null] },
        { title: "재부팅", desc: true, sort: (x) => Number(!!x.reboot_required), render: (x) => (x.reboot_required ? badge("필요", "warn") : "") },
        { title: "마지막 수집", sort: (x) => stamp(x.last_seen), render: (x) => agoEl(x.last_seen) },
        { title: "태그", render: (x) => tagsView(x.tags) },
      ], rows, "조건에 맞는 호스트가 없습니다."));
    };
    let seq = 0;
    const reload = async () => {
      const mine = ++seq;
      try { const rows = await api(`/v1/hosts?${params()}`); if (mine === seq && alive()) draw(rows); }
      catch (err) { if (mine === seq && alive()) clear(body).append(h("div", { class: "error", role: "alert" }, errMsg(err, "불러오지 못했습니다"))); }
    };
    const search = h("input", { type: "search", placeholder: "호스트·자산번호·OS·IP 검색", "aria-label": "호스트 검색", value: st.q, size: 24 });
    liveInput(search, st, "#/hosts", reload, alive);
    const statusSel = h("select", { "aria-label": "상태 필터", onchange: () => apply({ status: statusSel.value }) },
      h("option", { value: "" }, "모든 상태"),
      Object.entries(STATUS).map(([k, [t]]) => h("option", { value: k, selected: k === st.status }, t)));
    draw(first);
    return h("div", null, title,
      h("div", { class: "toolbar" }, search, statusSel, tagFilter(st.tag, (v) => apply({ tag: v })), h("span", { class: "spacer" }), csvButton(() => `/v1/hosts?${withFormat(params())}`, "hosts.csv")),
      body);
  }

  async function hostDetail(hostId, q) {
    const saved = q.get("saved") === "1";
    if (saved) history.replaceState(null, "", `${location.pathname}${location.search}#/hosts/${enc(hostId)}`);
    const d = await api(`/v1/hosts/${enc(hostId)}`);
    const host = d.host;
    const errors = Object.entries(host.last_errors || {});
    const tagBox = gateText(h("textarea", { "aria-label": "태그 (key=value, 한 줄에 하나)", placeholder: "key=value (한 줄에 하나)\n예)\nteam=infra\nenv=prod" }));
    tagBox.value = Object.entries(d.tags).map(([k, v]) => `${k}=${v}`).join("\n");
    const tagMsg = msgBox();
    const saveBtn = gate(h("button", { class: "primary", type: "button", onclick: async () => {
      const tags = {};
      for (const line of tagBox.value.split("\n").map((l) => l.trim()).filter(Boolean)) {
        const i = line.indexOf("=");
        if (i < 1) { tagMsg.err(`형식 오류: ${line}`); return; }
        tags[line.slice(0, i).trim()] = line.slice(i + 1).trim();
      }
      saveBtn.disabled = true;
      try { await api(`/v1/hosts/${enc(hostId)}/tags`, { method: "PUT", body: JSON.stringify(tags) }); tagMsg.ok("저장했습니다."); }
      catch (err) { tagMsg.err(errMsg(err, "저장 실패")); }
      saveBtn.disabled = !isAdmin();
    } }, "저장"));
    const removeBtn = gate(h("button", { class: "danger", type: "button", onclick: async () => {
      if (!confirm(`'${host.hostname}' 와(과) 모든 이력을 삭제합니다. 계속할까요?\n(같은 서버가 다시 수집되면 새 호스트로 등록됩니다)`)) return;
      try { await api(`/v1/hosts/${enc(hostId)}`, { method: "DELETE" }); location.hash = "#/hosts"; }
      catch (err) { alert(errMsg(err, "삭제 실패")); }
    } }, "호스트 삭제"));

    const pkgSearch = h("input", { type: "search", placeholder: "패키지 검색", "aria-label": "설치된 패키지 검색", size: 28 });
    const pkgBody = h("div");
    const drawPkgs = () => {
      const term = pkgSearch.value.trim().toLowerCase();
      clear(pkgBody).append(table([
        { title: "패키지", mono: true, sort: (p) => p.name, render: (p) => link(p.name, `#/software/${enc(p.name)}?host=${enc(hostId)}`) },
        { title: "버전", mono: true, sort: (p) => p.version, render: (p) => p.version || "-" },
        { title: "아키텍처", sort: (p) => p.arch, render: (p) => p.arch || "-" },
        { title: "출처", sort: (p) => p.source, render: (p) => p.source },
      ], d.packages.filter((p) => !term || p.name.toLowerCase().includes(term)), "일치하는 패키지가 없습니다."));
    };
    pkgSearch.addEventListener("input", drawPkgs);
    drawPkgs();

    const k = d.kernel;
    return titled(h("div", null, saved ? h("p", { class: "notice", role: "status" }, "자산 정보를 저장했습니다.") : null,
      h("div", { class: "toolbar" }, link("← 호스트 목록", "#/hosts"), h("span", { class: "spacer" }), removeBtn),
      h("h1", null, host.hostname, " ", statusBadge(host)),
      errors.length ? h("div", { class: "notice" }, h("strong", null, "마지막 수집에서 실패한 수집기"), errors.map(([n, m]) => h("div", { class: "mono" }, `${n}: ${m}`))) : null,
      h("div", { class: "grid2" },
        h("div", { class: "panel" }, h("dl", { class: "kv" },
          h("dt", null, "host_id"), h("dd", { class: "mono" }, host.host_id),
          h("dt", null, "OS"), h("dd", null, host.os_name ? `${host.os_name} (${host.os_version})` : "-"),
          h("dt", null, "에이전트"), h("dd", null, host.agent_version),
          h("dt", null, "마지막 수집"), h("dd", null, timeEl(host.last_seen), ` (${ago(host.last_seen)})`),
          h("dt", null, "최초 등록"), h("dd", null, timeEl(host.first_seen)))),
        h("div", { class: "panel" }, k ? h("dl", { class: "kv" },
          h("dt", null, "실행 중 커널"), h("dd", { class: "mono" }, k.running),
          h("dt", null, "설치된 최신"), h("dd", { class: "mono" }, k.latest_installed),
          h("dt", null, "커널 하한선"), h("dd", null, k.min_kernel ? [h("span", { class: "mono" }, k.min_kernel), " ", k.compliant ? badge("준수", "ok") : badge("미달", "err")] : h("span", { class: "muted" }, "미설정")),
          h("dt", null, "재부팅"), h("dd", null, k.reboot_required ? badge("재부팅 필요", "warn") : badge("최신", "ok")),
          h("dt", null, "설치된 커널"), h("dd", { class: "mono" }, d.kernels.map((x) => h("div", null, x.version, x.is_running ? " ← 실행 중" : "")))) : h("span", { class: "muted" }, "커널 정보 없음"))),
      h("h2", null, "장비·자산"),
      h("div", { class: "grid2" }, assetPanel(d), hardwarePanel(d.hardware)),
      inventorySection("containers", `컨테이너 (${d.containers.length})`, containerPanel(d)),
      inventorySection("network", `네트워크 인터페이스 (${d.interfaces.length})`,
      d.interfaces.length ? table([
        { title: "이름", mono: true, sort: (i) => i.name, render: (i) => i.name },
        { title: "MAC", mono: true, sort: (i) => i.mac, render: (i) => i.mac || "-" },
        { title: "상태", sort: (i) => i.state, render: (i) => badge(i.state === "up" ? "up" : i.state === "down" ? "down" : "알 수 없음", i.state === "up" ? "ok" : "") },
        { title: "주소", mono: true, render: (i) => (i.addresses.length ? i.addresses.map((a) => h("div", null, a)) : h("span", { class: "muted" }, "전역 주소 없음")) },
      ], d.interfaces) : empty("네트워크 정보가 아직 수집되지 않았습니다(에이전트 0.2 이상 필요).")),
      inventorySection("ports", `열린 포트 (${d.ports.length})`,
      d.ports.length ? table([
        { title: "포트", mono: true, sort: (p) => p.port, render: (p) => link(`${p.proto}/${p.port}`, `#/network/ports/${p.proto}/${p.port}?host=${enc(hostId)}`) },
        { title: "서비스", sort: (p) => p.service, render: (p) => p.service || "-" },
        { title: "바인딩", mono: true, sort: (p) => p.bind, render: (p) => p.bind },
        { title: "노출", render: (p) => { const [t, kk] = EXPOSURE[p.exposure]; return [badge(t, kk), p.notable ? " " : null, p.notable ? h("span", { class: "badge err", title: p.notable_reason }, "주의") : null]; } },
      ], d.ports) : empty("열린 포트가 없거나 아직 수집되지 않았습니다."),
      h("p", { class: "hint" }, "노출은 바인딩 주소 기준입니다. 방화벽 규칙은 반영되지 않으므로 '외부에서 접근 가능한 후보'로 보세요.")),
      h("h2", null, "태그 (소유팀·환경 등)"),
      h("div", { class: "panel" }, adminNote(), tagBox, h("div", { class: "toolbar" }, saveBtn, tagMsg.el)),
      inventorySection("software", `설치된 소프트웨어 (${d.packages.length})`,
        h("div", { class: "toolbar" }, pkgSearch), pkgBody),
      h("h2", null, "변경 이력"),
      h("p", null, link("이 호스트의 전체 이력 →", `#/events?host=${enc(host.host_id)}`)),
      eventsTable(d.events, false)), host.hostname);
  }

  const assetOwnerValue = (value) => String(value || "").trim();
  const assetOwnerDetails = (asset) => [
    h("dt", null, "담당자(정)"), h("dd", null, assetOwnerValue(asset?.primary_owner) || h("span", { class: "muted" }, "미지정")),
    h("dt", null, "담당자(부)"), h("dd", null, assetOwnerValue(asset?.secondary_owner) || h("span", { class: "muted" }, "미지정")),
  ];
  const assetOwnerCell = (asset) => h("div", { class: "asset-owner-cell" },
    [["정", assetOwnerValue(asset?.primary_owner)], ["부", assetOwnerValue(asset?.secondary_owner)]].map(([label, value]) =>
      h("div", { class: "asset-owner-line" }, h("span", { class: "asset-owner-label" }, label),
        h("span", { class: value ? "asset-owner-value" : "asset-owner-value muted", title: value || "미지정" }, value || "미지정"))));

  function assetPanel(d) {
    const a = d.asset;
    if (!a.asset_id) {
      const register = gate(h("button", { class: "primary", type: "button", onclick: () => { location.hash = `#/assets/new?host=${enc(d.host.host_id)}&return=${enc(currentReturn())}`; } }, "자산으로 등록"));
      return h("div", { class: "panel" }, h("dl", { class: "kv" },
        h("dt", null, "자산번호"), h("dd", null, h("span", { class: "muted" }, "자산 대장에 없음")),
        h("dt", null, "구분"), h("dd", null, [kindBadge(a), " ", h("span", { class: "muted" }, "에이전트가 감지한 값")]),
        ...assetOwnerDetails(a)),
      h("div", { class: "toolbar" }, register));
    }
    return h("div", { class: "panel" }, h("dl", { class: "kv" },
      h("dt", null, "자산번호"), h("dd", null, assetLink(`#/assets/${a.asset_id}`, a.asset_no)),
      h("dt", null, "구분"), h("dd", null, kindBadge(a)),
      h("dt", null, "도메인"), h("dd", null, a.domain || "-"),
      h("dt", null, "시리얼"), h("dd", { class: "mono" }, a.serial || "-"),
      ...assetOwnerDetails(a),
      h("dt", null, "상위 호스트"), h("dd", null, a.parent_asset_no ? [assetLink(`#/assets/${a.parent_asset_id}`, a.parent_asset_no), ` ${a.parent_hostname || ""}`] : "-"),
      h("dt", null, "연결 근거"), h("dd", null, [MATCH_LABELS[a.match_by] || a.match_by, flagBadges(a.flags)])));
  }

  const stateBadge = (st) => { const [t, k] = CONTAINER_STATE[st] || [st, ""]; return badge(t, k); };
  // 이미지·태그 배지는 그 이미지:태그를 쓰는 컨테이너 목록으로 이어진다(cluster 를 알면 그 범위로 좁힌다).
  const imageRef = (repo, tag) => (!tag ? repo : tag.startsWith("sha256:") ? `${repo}@${tag}` : `${repo}:${tag}`);
  const containerListHash = (params) => hashOf("#/containers/list", params);
  const tagBadges = (repo, tags, cluster) => tags.map((t) => [h("a", { class: "badge neutral", title: `호스트 ${t.host_count}대 · 컨테이너 ${t.container_count}개 — 이 이미지를 쓰는 컨테이너 보기`,
    href: containerListHash({ image: imageRef(repo, t.tag), cluster: cluster || "", active: "1" }) }, `${t.tag || "(태그 없음)"} ×${t.host_count}`), " "]);

  function containerPanel(d) {
    const k = d.k8s;
    return h("div", null,
      k ? h("div", { class: "panel" }, h("dl", { class: "kv" },
        h("dt", null, "클러스터"), h("dd", null, link(k.cluster_id ? k.cluster_id.slice(0, 8) : "(클러스터 미확인)", `#/containers/clusters/${enc(k.cluster_id || "unknown")}`)),
        h("dt", null, "쿠버네티스"), h("dd", { class: "mono" }, k.version || "-"),
        h("dt", null, "API 서버"), h("dd", { class: "mono" }, k.api_server || "-"),
        h("dt", null, "런타임"), h("dd", null, k.runtime || "-"))) : null,
      table([
        { title: "컨테이너", mono: true, sort: (c) => c.name, render: (c) => c.name },
        { title: "파드", mono: true, sort: (c) => (c.pod ? `${c.namespace}/${c.pod}` : null), render: (c) => (c.pod ? `${c.namespace}/${c.pod}` : "-") },
        { title: "이미지", mono: true, sort: (c) => c.image, render: (c) => link(c.image, `#/containers/images/${enc(c.image.split("@")[0].replace(/:[^:/]*$/, ""))}`) },
        { title: "상태", sort: (c) => (CONTAINER_STATE[c.state] || [c.state])[0], render: (c) => stateBadge(c.state) },
        { title: "런타임", sort: (c) => c.runtime, render: (c) => c.runtime },
      ], d.containers, "컨테이너가 없습니다."));
  }

  function hardwarePanel(hw) {
    if (!hw) return h("div", { class: "panel" }, h("span", { class: "muted" }, "장비 정보가 아직 수집되지 않았습니다(에이전트 0.2 이상 필요)."));
    return h("div", { class: "panel" }, h("dl", { class: "kv" },
      h("dt", null, "구분(감지)"), h("dd", null, [kindBadge({ kind: hw.kind, virt: hw.virt, kind_source: "detected" }), hw.virt ? ` ${hw.virt}` : ""]),
      h("dt", null, "제조사"), h("dd", null, hw.vendor || "-"),
      h("dt", null, "모델"), h("dd", null, hw.model || "-"),
      h("dt", null, "시리얼"), h("dd", { class: "mono" }, hw.serial || h("span", { class: "muted", title: "Linux 는 root 만 읽을 수 있는 경우가 많습니다" }, "읽지 못함")),
      h("dt", null, "FQDN"), h("dd", { class: "mono" }, hw.fqdn || "-"),
      h("dt", null, "도메인"), h("dd", null, hw.domain || "-")));
  }

  // ---------- 자산 ----------
  async function viewAssets(rest, q, alive) {
    if (rest[0] === "new") return assetForm(null, q);
    if (rest[0] && rest[1] === "edit") return assetForm(rest[0], q);
    if (rest[0]) return assetDetail(rest[0], q, alive);
    const st = { kind: q.get("kind") || "", status: q.get("status") || "", q: q.get("q") || "" };
    const saved = q.get("saved") === "1";
    if (saved) history.replaceState(null, "", `${location.pathname}${location.search}${hashOf("#/assets", st)}`);
    const params = () => {
      const p = new URLSearchParams();
      if (st.kind) p.set("kind", st.kind);
      if (st.status) p.set("status", st.status);
      if (st.q.trim()) p.set("q", st.q.trim());
      return p;
    };
    const [first, sum] = await Promise.all([api(`/v1/assets?${params()}`), api("/v1/assets/summary")]);
    const apply = (patch) => setQuery("#/assets", { ...st, ...patch });
    const card = (label, value, sub, cls, patch) => h("a", { class: `card ${cls || ""}`, href: "#/assets", onclick: (e) => { e.preventDefault(); apply({ kind: "", q: "", ...patch }); } },
      h("div", { class: "label" }, label), h("div", { class: "value" }, value), h("div", { class: "sub" }, sub));
    const title = h("h1", null, "");
    const body = h("div");
    const rowAction = (r) => {
      if (r.asset) return h("span", { class: "row-actions" }, assetLink(`#/assets/${r.asset.id}`, "보기"),
        isAdmin() ? assetLink(`#/assets/${r.asset.id}/edit`, "편집") : null);
      return isAdmin() ? assetLink(`#/assets/new?host=${enc(r.host_id)}`, "등록") : h("span", { class: "muted", title: ADMIN_ONLY, "aria-disabled": "true" }, "등록");
    };
    const draw = (rows) => {
      title.textContent = `자산 (${rows.length})`;
      clear(body).append(table([
        { title: "자산번호", nowrap: true, sort: (r) => (r.asset ? r.asset.asset_no : null), render: (r) => (r.asset ? assetLink(`#/assets/${r.asset.id}`, r.asset.asset_no) : h("span", { class: "muted" }, "-")) },
        { title: "담당자", cls: "asset-owners", sort: (r) => `${r.asset?.primary_owner || ""} ${r.asset?.secondary_owner || ""}`, render: (r) => assetOwnerCell(r.asset) },
        { title: "구분", sort: (r) => kindLabel(r.kind), render: kindBadge },
        { title: "호스트", sort: (r) => r.hostname, render: (r) => (r.host_id ? link(r.hostname, `#/hosts/${enc(r.host_id)}`) : h("span", { class: "muted", title: "에이전트가 아직 수집하지 않음" }, r.hostname || "-")) },
        { title: "도메인", sort: (r) => r.domain, render: (r) => r.domain || "-" },
        { title: "IP", mono: true, nowrap: true, sort: (r) => r.ip, render: (r) => r.ip || "-" },
        { title: "시리얼", mono: true, sort: (r) => r.serial, render: (r) => r.serial || "-" },
        { title: "상위 호스트", sort: (r) => r.parent_asset_no, render: (r) => (r.parent_asset_no ? [assetLink(`#/assets/${r.parent_asset_id}`, r.parent_asset_no), ` ${r.parent_hostname || ""}`] : r.vm_count ? badge(`VM ${r.vm_count}대`, "neutral") : "") },
        { title: "상태", sort: (r) => (ASSET_STATUS[r.status] || [r.status])[0], render: (r) => { const [t, k] = ASSET_STATUS[r.status]; return [badge(t, k), r.match_by ? h("span", { class: "muted", title: "연결 근거" }, ` ${MATCH_LABELS[r.match_by]}`) : null, flagBadges(r.flags)]; } },
        { title: "", srTitle: "작업", nowrap: true, render: rowAction },
      ], rows, "조건에 맞는 자산이 없습니다."));
    };
    let seq = 0;
    const reload = async () => {
      const mine = ++seq;
      try { const rows = await api(`/v1/assets?${params()}`); if (mine === seq && alive()) draw(rows); }
      catch (err) { if (mine === seq && alive()) clear(body).append(h("div", { class: "error", role: "alert" }, errMsg(err, "불러오지 못했습니다"))); }
    };
    const search = h("input", { type: "search", placeholder: "자산번호·호스트·IP·시리얼·도메인·담당자 검색", "aria-label": "자산 검색", value: st.q, size: 32 });
    liveInput(search, st, "#/assets", reload, alive);
    draw(first);
    const sel = (label, name, options) => h("select", { "aria-label": label, onchange: (e) => apply({ [name]: e.target.value }) },
      options.map(([v, t]) => h("option", { value: v, selected: v === st[name] }, t)));
    const addBtn = gate(h("button", { class: "primary", type: "button", onclick: () => { location.hash = `#/assets/new?return=${enc(currentReturn())}`; } }, "자산 추가"));
    return h("div", null, saved ? h("p", { class: "notice", role: "status" }, "자산 정보를 저장했습니다.") : null, title,
      h("div", { class: "cards" },
        card("등록 자산", sum.assets, "자산 대장", "", { status: "registered" }),
        card("연결됨", sum.linked, "수집 호스트와 연결", "ok", { status: "linked" }),
        card("미수집", sum.uncollected, "대장에만 있고 에이전트 수집이 없음", sum.uncollected ? "err" : "ok", { status: "uncollected" }),
        card("자산 미등록", sum.unregistered, "수집됐지만 대장에 없음", sum.unregistered ? "warn" : "ok", { status: "unregistered" }),
        card("물리 / VM", `${sum.physical} / ${sum.virtual}`, "대장 값, 미등록은 감지 값", "", { status: "" })),
      (sum.kind_mismatch || sum.serial_mismatch || sum.ip_mismatch)
        ? h("div", { class: "notice" }, `대장 값과 수집된 값이 다른 자산: 구분 ${sum.kind_mismatch}건 · 시리얼 ${sum.serial_mismatch}건 · IP ${sum.ip_mismatch}건 `, link("현재 조건의 불일치 보기", hashOf("#/assets", { ...st, status: "mismatch" }))) : null,
      adminNote(),
      h("div", { class: "toolbar" },
        sel("구분 필터", "kind", [["", "모든 구분"], ["physical", "물리"], ["virtual", "VM"], ["container", "컨테이너"], ["unknown", "알 수 없음"]]),
        sel("상태 필터", "status", [["", "모든 상태"], ["registered", "등록 자산"], ["linked", "연결됨"], ["uncollected", "미수집"], ["unregistered", "자산 미등록"], ["mismatch", "불일치"]]),
        search, h("span", { class: "spacer" }), csvButton(() => `/v1/assets?${withFormat(params())}`, "assets.csv"), addBtn),
      body,
      h("p", { class: "hint" }, "수집 호스트와의 연결은 시리얼 → 호스트명 → IP 순으로 자동 계산합니다(모호하면 연결하지 않음). 자동 연결이 안 되는 장비는 편집 화면에서 호스트를 직접 지정하세요."));
  }

  // 라벨은 for/id 로 입력과 묶고(스크린리더·클릭 포커스), 힌트·오류는 aria-describedby 로 잇는다.
  function field(label, el, hint) {
    if (!el.id) el.id = uid("fld");
    const labelId = uid("lbl");
    const grouped = el.getAttribute("role") === "group";
    if (grouped) el.setAttribute("aria-labelledby", labelId);
    const err = h("div", { class: "field-error", id: `${el.id}-err`, role: "alert" });
    el.setAttribute("aria-describedby", [hint ? `${el.id}-hint` : null, err.id].filter(Boolean).join(" "));
    el.fieldError = err;
    return [h("label", { id: labelId, for: grouped ? null : el.id }, label), h("div", null, el, err, hint ? h("div", { class: "hint", id: `${el.id}-hint` }, hint) : null)];
  }
  function setFieldError(el, text) {
    if (text) el.setAttribute("aria-invalid", "true"); else el.removeAttribute("aria-invalid");
    el.fieldError.textContent = text || "";
  }

  // 대장 값 ↔ 수집 값 비교표. 각 항목에 '수집값 적용'을 두어 폼 입력란을 수집된 값으로 바꾼다(저장은 따로 누른다).
  function compareTable(items) {
    const norm = (s) => String(s || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    const same = {
      kind: (v, c) => !!v && v === c[0],
      serial: (v, c) => !!norm(v) && norm(v) === norm(c[0]),
      hostname: (v, c) => { const x = v.toLowerCase(); const y = String(c[0] || "").toLowerCase(); return !!x && !!y && (x === y || x.split(".")[0] === y.split(".")[0]); },
      domain: (v, c) => !!v && v.toLowerCase().replace(/\.$/, "") === (c[0] || "").toLowerCase().replace(/\.$/, ""),
      ip: (v, c) => !!v && c.includes(v.trim()),
    };
    const rows = items.map((it) => {
      const cur = h("td", { class: "mono" }); const verdict = h("td"); const acts = h("td");
      const buttons = it.collected.slice(0, 4).map((v) => gate(h("button", { type: "button",
        "aria-label": `${it.label} 수집값 적용${it.collected.length > 1 ? ` (${it.fmt(v)})` : ""}`, onclick: () => { it.set(v); update(); } },
        it.collected.length > 1 ? `${it.fmt(v)} 적용` : "수집값 적용")));
      acts.append(...(buttons.length ? buttons : [h("span", { class: "muted" }, "-")]));
      function update() {
        const v = it.get().trim();
        cur.textContent = v ? it.fmt(v) : "-";
        if (v !== it.saved) cur.append(h("span", { class: "muted" }, " (저장 전)"));
        clear(verdict).append(!it.collected.length ? badge("수집값 없음", "neutral") : same[it.key](v, it.collected) ? badge("일치", "ok") : badge(v ? "다름" : "대장 비어 있음", "warn"));
        buttons.forEach((b, i) => {   // 이미 수집값과 같으면 누를 필요가 없다(조회 전용이면 gate 가 이미 껐다)
          if (!isAdmin()) return;
          const done = v === it.collected[i];
          b.disabled = done;
          if (done) b.title = "대장 값이 이미 수집값과 같습니다"; else b.removeAttribute("title");
        });
      }
      update();
      return { it, update, tr: h("tr", null, h("th", { scope: "row" }, it.label), cur, h("td", { class: "mono" }, it.collected.length ? it.collected.map((v) => it.fmt(v)).join(", ") : h("span", { class: "muted" }, "읽지 못함")), verdict, acts) };
    });
    const node = h("div", { class: "scroll cmp-table" }, h("table", null,
      h("thead", null, h("tr", null, ["항목", "대장 값", "수집 값", "판정", "작업"].map((t) => h("th", { scope: "col" }, t)))),
      h("tbody", null, rows.map((r) => r.tr))));
    return { node, update: () => rows.forEach((r) => r.update()) };
  }

  async function assetDetail(id, q, alive) {
    const detail = await api(`/v1/assets/${enc(id)}`);
    let hostDetail = null, hostError = null;
    if (detail.host_id) {
      try { hostDetail = await api(`/v1/hosts/${enc(detail.host_id)}`); }
      catch (err) { hostError = err; }
    }
    const tabKey = q.get("tab") || "overview";
    const softwareState = {
      q: q.get("software_q") || "", category: q.get("software_category") || "",
      approval: q.get("software_approval") || "", impact: q.get("software_impact") || "",
    };
    const cveState = { q: q.get("asset_cve_q") || "", impact: q.get("asset_cve_impact") || "", page: Math.max(1, Number(q.get("page") || 1)) };
    let softwareSummary = null, softwareSummaryError = null;
    if (tabKey === "software" && detail.host_id && !hostError) {
      try { softwareSummary = await api(`/v1/hosts/${enc(detail.host_id)}/software-summary`); }
      catch (err) { softwareSummaryError = err; }
    }
    const back = returnHash(q) || "#/assets";
    const base = `#/assets/${enc(id)}`;
    const saved = q.get("saved") === "1";
    if (saved) history.replaceState(null, "", `${location.pathname}${location.search}${hashOfExact(base, {
      ...Object.fromEntries(q.entries()), return: back, tab: tabKey,
    })}`);
    const tabHref = (key) => hashOf(base, {
      return: back, tab: key, software_q: softwareState.q, software_category: softwareState.category,
      software_approval: softwareState.approval, software_impact: softwareState.impact,
      asset_cve_q: cveState.q, asset_cve_impact: cveState.impact, page: cveState.page === 1 ? "" : cveState.page,
    });
    const editLink = isAdmin() ? h("a", { class: "button-link", href: hashOf(`${base}/edit`, { return: back, success: location.hash }) }, "자산 정보 편집") : null;
    let content;
    if (tabKey === "overview") {
      content = h("dl", { class: "kv" },
        h("dt", null, "자산번호"), h("dd", null, detail.asset.asset_no),
        h("dt", null, "종류"), h("dd", null, kindLabel(detail.asset.kind)),
        h("dt", null, "시리얼"), h("dd", null, detail.asset.serial || "-"),
        h("dt", null, "호스트명 / 도메인"), h("dd", null, `${detail.asset.hostname || "-"} · ${detail.asset.domain || "-"}`),
        h("dt", null, "대장 관리 IP"), h("dd", { class: "mono" }, detail.asset.ip || "-"),
        ...assetOwnerDetails(detail.asset),
        h("dt", null, "비고"), h("dd", null, detail.asset.note || "-"),
        h("dt", null, "상태 / 연결 근거"), h("dd", null, badge(ASSET_STATUS[detail.status]?.[0] || detail.status, ASSET_STATUS[detail.status]?.[1]), detail.match_by ? ` · ${MATCH_LABELS[detail.match_by]}` : ""),
        h("dt", null, "수집 호스트"), h("dd", null, detail.host_id ? link(detail.hostname, `#/hosts/${enc(detail.host_id)}`) : h("span", { class: "muted" }, "호스트 미수집")),
        h("dt", null, "상위 물리 자산"), h("dd", null, detail.parent_asset_no ? [assetLink(`#/assets/${detail.parent_asset_id}`, detail.parent_asset_no), ` · ${detail.parent_hostname || ""}`] : "없음"),
        h("dt", null, "VM 자산"), h("dd", null, detail.vms.length ? detail.vms.map((v) => h("div", null, assetLink(`#/assets/${v.id}`, `${v.asset_no} · ${v.hostname || "호스트 미수집"}`))) : "없음"),
        h("dt", null, "마지막 수집"), h("dd", null, hostDetail ? timeEl(hostDetail.host.last_seen) : "-"));
      if (hostError) content.append(h("div", { class: "error", role: "alert" }, `호스트 세부 정보를 불러오지 못했습니다. 대장 정보는 표시했으며 호스트 조회 오류: ${hostError.message}`),
        h("button", { type: "button", onclick: () => setQuery(base, { return: back, tab: tabKey, retry: Date.now() }) }, "호스트 정보 다시 시도"));
      else if (hostDetail?.host.last_errors && Object.keys(hostDetail.host.last_errors).length) content.append(h("div", { class: "notice" },
        h("strong", null, "마지막 수집의 항목 오류"), Object.entries(hostDetail.host.last_errors).map(([src, error]) => h("div", null, `${src}: ${error}`))));
    } else if (!detail.host_id) {
      content = h("div", { class: "notice" }, "수집 호스트가 연결되지 않아 설치 소프트웨어·취약점·네트워크·수집 이력을 조회할 수 없습니다. 자산 대장 정보는 계속 확인할 수 있습니다.");
    } else if (hostError) {
      content = h("div", { class: "error", role: "alert" }, `연결된 호스트 ${detail.hostname} 정보를 불러오지 못했습니다: ${hostError.message} `,
        h("button", { type: "button", onclick: () => setQuery(base, { return: back, tab: tabKey, retry: Date.now() }) }, "다시 시도"));
    } else if (tabKey === "software") {
      const rows = softwareSummary?.items || [];
      const categories = [["", "전체"], ["business_app", "업무용 앱"], ["os_package", "OS 패키지"],
        ["development_dependency", "개발 라이브러리·의존성"], ["needs_review", "분류 확인 필요"]];
      const categoryCount = (value) => value ? rows.filter((row) => row.category === value).length : rows.length;
      const categoryTabs = h("nav", { class: "view-tabs", "aria-label": "설치 소프트웨어 분류" }, categories.map(([value, label]) => {
        const anchor = h("a", { href: hashOf(base, { return: back, tab: "software", software_q: softwareState.q,
          software_category: value, software_approval: softwareState.approval, software_impact: softwareState.impact }),
          class: value === softwareState.category ? "active" : null, "aria-current": value === softwareState.category ? "page" : null,
          "data-category": value }, `${label} ${categoryCount(value)}`);
        anchor.addEventListener("click", (event) => {
          event.preventDefault(); softwareState.category = value;
          for (const tabAnchor of categoryTabs.querySelectorAll("a")) {
            const active = tabAnchor.dataset.category === value;
            tabAnchor.classList.toggle("active", active);
            if (active) tabAnchor.setAttribute("aria-current", "page"); else tabAnchor.removeAttribute("aria-current");
          }
          persistSoftwareState(); drawSoftware();
        });
        return anchor;
      }));
      const approval = h("select", { "aria-label": "사용 승인 필터" }, [["", "모든 승인 상태"], ["active", "승인됨"], ["not_active", "미승인"], ["not_required", "대상 제외"], ["classification_required", "분류 확인 필요"]].map(([value, label]) => h("option", { value, selected: value === softwareState.approval }, label)));
      const impact = h("select", { "aria-label": "취약점 영향 필터" }, [["", "모든 영향 판정"], ...Object.entries(IMPACT_STATUS).map(([value, [label]]) => [value, label])].map(([value, label]) => h("option", { value, selected: value === softwareState.impact }, label)));
      const search = h("input", { type: "search", value: softwareState.q, placeholder: "이름·버전·출처 검색", "aria-label": "설치 소프트웨어 검색" });
      const resultCount = h("span", { class: "table-toolbar-result", role: "status", "aria-live": "polite" }, `전체 ${rows.length}개`);
      const tableHost = h("div");
      const persistSoftwareState = () => replaceQuery(base, { return: back, tab: "software", software_q: softwareState.q.trim(),
        software_category: softwareState.category, software_approval: softwareState.approval, software_impact: softwareState.impact,
        asset_cve_q: cveState.q, asset_cve_impact: cveState.impact, page: "" });
      const drawSoftware = () => {
        const needle = softwareState.q.trim().toLocaleLowerCase("ko-KR");
        const visibleRows = rows.filter((row) => {
          const values = [row.name, row.product_name, row.publisher, row.source, row.arch, row.version, row.category];
          return (!needle || values.some((value) => String(value || "").toLocaleLowerCase("ko-KR").includes(needle)))
            && (!softwareState.category || row.category === softwareState.category)
            && (!softwareState.approval || row.approval_status === softwareState.approval)
            && (!softwareState.impact || row.impact_status === softwareState.impact);
        });
        resultCount.textContent = `${visibleRows.length}개 표시 · 전체 ${rows.length}개`;
        clear(tableHost).append(workflowModule.softwareTable(visibleRows, {
          hostId: detail.host_id, role,
          detailHref: (row) => hashOf(`#/software/${enc(row.name)}`, { host: detail.host_id, version: row.version, return: location.hash }),
        }));
      };
      search.addEventListener("input", () => {
        softwareState.q = search.value; persistSoftwareState(); drawSoftware();
      });
      [approval, impact].forEach((element) => element.addEventListener("change", () => {
        softwareState.approval = approval.value; softwareState.impact = impact.value;
        persistSoftwareState(); drawSoftware();
      }));
      const reset = h("button", { type: "button", class: "link table-filter-reset", onclick: () => {
        softwareState.q = ""; softwareState.category = ""; softwareState.approval = ""; softwareState.impact = "";
        search.value = ""; approval.value = ""; impact.value = "";
        for (const tabAnchor of categoryTabs.querySelectorAll("a")) {
          const active = tabAnchor.dataset.category === ""; tabAnchor.classList.toggle("active", active);
          if (active) tabAnchor.setAttribute("aria-current", "page"); else tabAnchor.removeAttribute("aria-current");
        }
        persistSoftwareState(); drawSoftware(); search.focus();
      } }, "초기화");
      const sourceRows = (hostDetail.source_freshness || []).filter((row) => row.source.startsWith("software."));
      const freshness = sourceRows.length ? table([
        { title: "수집기", render: (row) => row.source },
        { title: "상태", render: (row) => badge(row.state === "ok" ? "성공" : "실패", row.state === "ok" ? "ok" : "err") },
        { title: "마지막 성공", render: (row) => timeEl(row.last_success_at) },
        { title: "마지막 시도 / 오류", render: (row) => [timeEl(row.last_attempt_at), row.last_error ? h("span", { class: "error-text" }, ` · ${row.last_error}`) : null] },
      ], sourceRows) : h("p", { class: "muted" }, "소프트웨어 수집기별 성공 시각이 아직 없습니다. 다음 정상 수집 후 표시됩니다.");
      drawSoftware();
      content = softwareSummaryError ? h("div", { class: "error", role: "alert" }, `설치 소프트웨어 요약을 불러오지 못했습니다: ${errMsg(softwareSummaryError)}`)
        : h("div", null,
          categoryTabs, workflowModule.toolbar(search, approval, impact, resultCount, reset), tableHost,
          h("p", { class: "table-note" }, "업무용 앱만 사용 승인 대상입니다. OS 패키지와 개발 의존성은 승인에서 제외되지만, 모든 설치 항목은 보안 조회에 포함됩니다."),
          h("details", { class: "asset-collection-details" }, h("summary", null, "소프트웨어 수집기 상태"), freshness));
    } else if (tabKey === "cves") {
      try {
        let result = { items: [], total: 0 }, seq = 0;
        const search = h("input", { type: "search", value: cveState.q, placeholder: "CVE ID·설명·제품 검색", "aria-label": "자산 CVE 검색" });
        const impact = h("select", { "aria-label": "자산 CVE 영향 판정 필터" }, [["", "모든 영향 판정"], ...Object.entries(IMPACT_STATUS).map(([value, [label]]) => [value, label])].map(([value, label]) => h("option", { value, selected: value === cveState.impact }, label)));
        const count = h("span", { class: "table-toolbar-result", role: "status", "aria-live": "polite" }, "CVE 자료를 불러오는 중…");
        const tableHost = h("div");
        const persistCveState = () => replaceQuery(base, { return: back, tab: "cves", software_q: softwareState.q,
          software_category: softwareState.category, software_approval: softwareState.approval, software_impact: softwareState.impact,
          asset_cve_q: cveState.q.trim(), asset_cve_impact: cveState.impact, page: cveState.page === 1 ? "" : cveState.page });
        const refreshCves = async () => {
          const run = ++seq; const params = new URLSearchParams({ host: detail.host_id, page: String(cveState.page), page_size: "50" });
          if (cveState.q.trim()) params.set("q", cveState.q.trim()); if (cveState.impact) params.set("impact", cveState.impact);
          count.textContent = "CVE 자료를 불러오는 중…";
          try {
            result = await api(`/v1/vulnerabilities?${params}`); if (!alive() || run !== seq) return;
            count.textContent = `전체 ${result.total}건`;
            const detailHref = (row, impactStatus) => hashOf(`#/cves/${enc(row.cve_id)}`, {
              return: location.hash, host: detail.host_id, impact: impactStatus || "",
            });
            clear(tableHost).append(workflowModule.vulnerabilityTable(result.items, { detailHref, serverPage: true }),
              pageControls(base, { return: back, tab: "cves", software_q: softwareState.q, software_category: softwareState.category,
                software_approval: softwareState.approval, software_impact: softwareState.impact,
                asset_cve_q: cveState.q, asset_cve_impact: cveState.impact }, cveState.page, 50, result.total));
          } catch (err) { if (alive() && run === seq) { count.textContent = "조회 실패"; clear(tableHost).append(h("div", { class: "error", role: "alert" }, `취약점 조회 실패: ${errMsg(err)}`)); } }
        };
        let timer; search.addEventListener("input", () => { cveState.q = search.value; cveState.page = 1; persistCveState(); clearTimeout(timer); timer = setTimeout(refreshCves, 220); });
        impact.addEventListener("change", () => { cveState.impact = impact.value; cveState.page = 1; persistCveState(); refreshCves(); });
        const reset = h("button", { type: "button", class: "link table-filter-reset", onclick: () => {
          cveState.q = ""; cveState.impact = ""; cveState.page = 1; search.value = ""; impact.value = ""; persistCveState(); refreshCves(); search.focus();
        } }, "초기화");
        await refreshCves();
        content = h("div", null, workflowModule.toolbar(search, impact, count, reset), tableHost,
          h("p", { class: "table-note" }, "판정별 호스트 수는 설치 제품 매핑 기준입니다. 여러 제품이 설치된 호스트는 상태 간 중복될 수 있으며, 확인되지 않은 매칭은 영향 없음 판정이 아닙니다."));
      } catch (err) { content = h("div", { class: "error", role: "alert" }, `취약점 조회 실패: ${err.message}`); }
    } else if (tabKey === "network") {
      content = h("div", null, h("p", null, link("호스트 상세에서 모든 네트워크 정보 보기 →", `#/hosts/${enc(detail.host_id)}`)),
        h("h2", null, `네트워크 인터페이스 (${hostDetail.interfaces.length})`), hostDetail.interfaces.length ? table([
          { title: "인터페이스", mono: true, render: (r) => r.name }, { title: "MAC", mono: true, render: (r) => r.mac || "-" },
          { title: "상태", render: (r) => r.state }, { title: "주소", mono: true, render: (r) => r.addresses.join(", ") || "전역 주소 없음" },
        ], hostDetail.interfaces) : empty("수집된 네트워크 인터페이스가 없습니다."),
        h("h2", null, `열린 포트 (${hostDetail.ports.length})`), hostDetail.ports.length ? table([
          { title: "프로토콜 / 포트", sort: (r) => r.port, render: (r) => `${r.proto}/${r.port}` },
          { title: "바인딩", mono: true, render: (r) => r.bind }, { title: "노출", render: (r) => exposureBadge(r.exposure) },
        ], hostDetail.ports) : empty("수집된 열린 포트가 없습니다."));
    } else if (tabKey === "history") {
      try {
        const page = Math.max(1, Number(q.get("page") || 1));
        const result = await api(`/v1/events?host=${enc(detail.host_id)}&page=${page}&page_size=100`);
        content = h("div", null, h("p", { class: "muted", role: "status" }, `전체 ${result.total}건 · ${result.items.length}건 표시`), table([
          { title: "시각", sort: (r) => r.occurred_at, render: (r) => timeEl(r.occurred_at) },
          { title: "변경", render: (r) => eventBadge(r.event_type) }, { title: "대상", render: (r) => r.subject_key },
          { title: "이전 / 이후", render: (r) => `${r.old_value || "-"} → ${r.new_value || "-"}` },
        ], result.items, "이 호스트의 변경 이력이 없습니다."),
        pageControls(base, { return: back, tab: tabKey, page }, page, 100, result.total));
      } catch (err) { content = h("div", { class: "error", role: "alert" }, `이력 조회 실패: ${err.message}`); }
    } else content = empty("알 수 없는 자산 상세 탭입니다.");
    const asset = detail.asset;
    const osName = hostDetail?.host?.os_name ? `${hostDetail.host.os_name}${hostDetail.host.os_version ? ` ${hostDetail.host.os_version}` : ""}` : "OS 미기록";
    const context = h("div", { class: "asset-context-strip", "aria-label": "자산 요약 정보" },
      h("span", null, h("b", null, "호스트"), detail.hostname || asset.hostname || "호스트 미연결"),
      h("span", null, h("b", null, "관리 IP"), asset.ip || "미기록"),
      h("span", null, h("b", null, "OS"), osName),
      h("span", null, h("b", null, "담당자"), `정 ${assetOwnerValue(asset.primary_owner) || "미지정"} · 부 ${assetOwnerValue(asset.secondary_owner) || "미지정"}`),
      h("span", null, h("b", null, "연결"), ASSET_STATUS[detail.status]?.[0] || detail.status),
      h("span", null, h("b", null, "마지막 수집"), hostDetail ? compactKstTime(hostDetail.host.last_seen) : h("span", { class: "muted" }, "미수집")));
    const tabs = workflowModule.tabs([
      { label: "기본 정보", active: tabKey === "overview", href: tabHref("overview") },
      { label: "설치 소프트웨어", active: tabKey === "software", href: tabHref("software") },
      { label: "취약점", active: tabKey === "cves", href: tabHref("cves") },
      { label: "네트워크", active: tabKey === "network", href: tabHref("network") },
      { label: "변경 이력", active: tabKey === "history", href: tabHref("history") },
    ], "자산 상세 보기");
    const tabKeys = ["overview", "software", "cves", "network", "history"];
    tabs.querySelectorAll("a").forEach((anchor, index) => anchor.addEventListener("click", (event) => {
      event.preventDefault(); location.hash = tabHref(tabKeys[index]);
    }));
    const pageActions = h("div", { class: "page-actions" }, link("← 이전 화면", back), editLink);
    return titled(h("div", null, saved ? h("p", { class: "notice", role: "status" }, "자산 정보를 저장했습니다.") : null,
      pageHeader(`자산 ${asset.asset_no}`, pageActions, `${asset.hostname || detail.hostname || "호스트 미연결"} · ${kindLabel(asset.kind)}`),
      context, tabs, h("section", { class: "panel" }, content)), `자산 ${asset.asset_no}`);
  }

  async function assetForm(idOrNull, q) {
    const id = idOrNull;
    const back = returnHash(q) || "#/assets";
    const [physical, hosts] = await Promise.all([api("/v1/assets?kind=physical"), api("/v1/hosts")]);
    let row = null; let prefill = {}; let kindUnclear = false; let hostError = null;
    if (id) row = await api(`/v1/assets/${enc(id)}`);
    else if (q.get("host")) {   // 호스트 화면에서 '자산으로 등록' — 수집된 값으로 미리 채운다
      const d = await api(`/v1/hosts/${enc(q.get("host"))}`);
      const hw = d.hardware || {};
      const v4 = d.interfaces.flatMap((i) => i.addresses).map((x) => x.split("/")[0]).find((x) => !x.includes(":")) || "";
      // 감지가 물리/VM 이 아니면(알 수 없음·컨테이너) '물리'로 단정하지 않고 직접 고르게 한다
      kindUnclear = !["physical", "virtual"].includes(hw.kind);
      prefill = { kind: kindUnclear ? "" : hw.kind, serial: hw.serial || "", hostname: d.host.hostname, domain: hw.domain || "", ip: v4, host_id: d.host.host_id };
    }
    const a = row ? row.asset : { asset_no: "", kind: "", serial: "", hostname: "", domain: "", ip: "", parent_asset_id: null, host_id: null,
      primary_owner: "", secondary_owner: "", note: "", ...prefill };
    let expectedRevision = row?.asset.revision ?? null;
    const f = {
      asset_no: h("input", { type: "text", value: a.asset_no, maxlength: 64, required: true, "aria-required": "true" }),
      kind: h("select", { required: true, "aria-required": "true" }, h("option", { value: "", disabled: true, selected: !a.kind }, "선택하세요"),
        [["physical", "물리"], ["virtual", "VM"]].map(([v, t]) => h("option", { value: v, selected: v === a.kind }, t))),
      serial: h("input", { type: "text", value: a.serial, maxlength: 128 }),
      hostname: h("input", { type: "text", value: a.hostname, maxlength: 255 }),
      domain: h("input", { type: "text", value: a.domain, maxlength: 255, placeholder: "corp.example.com" }),
      ip: h("input", { type: "text", value: a.ip, maxlength: 45, placeholder: "관리 IP" }),
      parent: h("select", null, h("option", { value: "" }, "없음"),
        physical.filter((r) => r.asset && String(r.asset.id) !== String(id)).map((r) => h("option", { value: r.asset.id, selected: r.asset.id === a.parent_asset_id }, `${r.asset.asset_no} · ${r.hostname || "-"}`))),
      host: h("select", null, h("option", { value: "" }, "자동 연결(시리얼·호스트명·IP)"),
        hosts.map((x) => h("option", { value: x.host_id, selected: x.host_id === a.host_id }, `${x.hostname} (${x.ips[0] || x.host_id.slice(0, 8)})`))),
      primary_owner: h("input", { type: "text", value: a.primary_owner || "", maxlength: 128, placeholder: "이름 또는 식별정보" }),
      secondary_owner: h("input", { type: "text", value: a.secondary_owner || "", maxlength: 128, placeholder: "이름 또는 식별정보" }),
      note: h("input", { type: "text", value: a.note, maxlength: 500 }),
    };
    f.asset_no.id = "asset-no"; f.kind.id = "asset-kind";
    if (!isAdmin()) Object.values(f).forEach((el) => { el.disabled = true; el.title = ADMIN_ONLY; }); // 조회 전용: 채워도 저장할 수 없으니 입력 자체를 막는다
    const msg = msgBox();
    const syncParent = () => { f.parent.disabled = !isAdmin() || f.kind.value !== "virtual"; if (f.kind.value !== "virtual") f.parent.value = ""; };
    f.kind.addEventListener("change", syncParent); syncParent();
    f.asset_no.addEventListener("input", () => setFieldError(f.asset_no, ""));
    f.kind.addEventListener("change", () => setFieldError(f.kind, ""));
    const body = () => ({
      asset_no: f.asset_no.value.trim(), kind: f.kind.value, serial: f.serial.value.trim(), hostname: f.hostname.value.trim(), domain: f.domain.value.trim(),
      ip: f.ip.value.trim(), parent_asset_id: f.parent.value ? Number(f.parent.value) : null, host_id: f.host.value || null,
      primary_owner: f.primary_owner.value.trim(), secondary_owner: f.secondary_owner.value.trim(), note: f.note.value.trim(),
    });
    const inputs = { asset_no: f.asset_no, kind: f.kind, serial: f.serial, hostname: f.hostname, domain: f.domain, ip: f.ip,
      parent_asset_id: f.parent, host_id: f.host, primary_owner: f.primary_owner, secondary_owner: f.secondary_owner, note: f.note };
    const readValues = (asset) => ({ asset_no: asset.asset_no || "", kind: asset.kind || "", serial: asset.serial || "", hostname: asset.hostname || "",
      domain: asset.domain || "", ip: asset.ip || "", parent_asset_id: asset.parent_asset_id ?? null, host_id: asset.host_id || null,
      primary_owner: asset.primary_owner || "", secondary_owner: asset.secondary_owner || "", note: asset.note || "" });
    let baselineValues = body();
    let draftBaseline = JSON.stringify(baselineValues);
    assetDraftGuard = { hash: location.hash, isDirty: () => JSON.stringify(body()) !== draftBaseline };
    const updateBaseline = (values) => { baselineValues = readValues(values); draftBaseline = JSON.stringify(baselineValues); };
    const applyValues = (values) => {
      for (const [key, el] of Object.entries(inputs)) el.value = values[key] ?? "";
      f.kind.dispatchEvent(new Event("change", { bubbles: true }));
      f.parent.value = values.parent_asset_id == null ? "" : String(values.parent_asset_id);
      f.host.value = values.host_id || "";
      for (const el of Object.values(inputs)) if (el.fieldError) setFieldError(el, "");
    };
    // 제출 전에 필수 항목을 그 자리에서 알려 준다(서버 422 를 받고서야 아는 일이 없게)
    const validate = () => {
      let first = null;
      const need = (el, text) => { setFieldError(el, text); if (text && !first) first = el; };
      need(f.asset_no, f.asset_no.value.trim() ? "" : "자산번호를 입력하세요.");
      need(f.kind, f.kind.value ? "" : "구분(물리/VM)을 선택하세요.");
      if (first) first.focus();
      return !first;
    };
    let busy = false; // 저장 중 다시 눌러 같은 자산이 두 번 만들어지지 않게
    const saveBtn = gate(h("button", { class: "primary", type: "submit" }, "저장"));
    const showConflict = async () => {
      let latest;
      try { latest = await api(`/v1/assets/${enc(id)}`); }
      catch (err) { msg.err(`최신 자산을 불러오지 못했습니다: ${err.message}`); return; }
      const latestValues = readValues(latest.asset);
      const openedValues = { ...baselineValues };
      const currentValues = body();
      const labels = { asset_no: "자산번호", kind: "구분", serial: "시리얼", hostname: "호스트명", domain: "도메인", ip: "IP",
        parent_asset_id: "상위 자산", host_id: "수집 호스트", primary_owner: "담당자(정)", secondary_owner: "담당자(부)", note: "비고" };
      const rows = Object.keys(inputs).map((key) => {
        const localChanged = currentValues[key] !== openedValues[key];
        const remoteChanged = latestValues[key] !== openedValues[key];
        const collision = localChanged && remoteChanged && currentValues[key] !== latestValues[key];
        const choice = collision ? h("select", { "aria-label": `${labels[key]} 충돌 해결` },
          h("option", { value: "latest" }, "최신값 사용"), h("option", { value: "mine" }, "내 입력 유지")) : null;
        if (choice) choice.dataset.assetField = key;
        const printable = (value) => value === null || value === "" ? "-" : String(value);
        return h("tr", null, h("th", { scope: "row" }, labels[key]), h("td", null, printable(openedValues[key])),
          h("td", null, printable(latestValues[key])), h("td", null, printable(currentValues[key])),
          h("td", null, choice || (remoteChanged ? "최신값 유지" : localChanged ? "내 입력 유지" : "변경 없음")));
      });
      const compare = h("div", { class: "scroll" }, h("table", null,
        h("thead", null, h("tr", null, ["항목", "열었을 때", "최신값", "내 입력", "저장할 값"].map((label) => h("th", { scope: "col" }, label)))),
        h("tbody", null, rows)));
      let dialog;
      const useLatest = h("button", { type: "button", onclick: () => {
        applyValues(latestValues); expectedRevision = latest.asset.revision; updateBaseline(latestValues);
        dialog.close("latest"); msg.info("최신값을 불러왔습니다. 필요한 변경을 다시 적용하세요.");
      } }, "최신값 불러오기");
      const merge = h("button", { type: "button", class: "primary", onclick: async () => {
        const merged = { ...latestValues };
        for (const key of Object.keys(inputs)) {
          const localChanged = currentValues[key] !== openedValues[key];
          const remoteChanged = latestValues[key] !== openedValues[key];
          if (localChanged && !remoteChanged) merged[key] = currentValues[key];
          else if (localChanged && remoteChanged && currentValues[key] !== latestValues[key]) {
            const select = [...dialog.querySelectorAll("select[data-asset-field]")].find((el) => el.dataset.assetField === key);
            if (!select) { alert(`${labels[key]} 변경 충돌을 선택하세요.`); return; }
            if (select.value === "mine") merged[key] = currentValues[key];
          }
        }
        applyValues(merged); expectedRevision = latest.asset.revision; updateBaseline(latestValues);
        dialog.close("merged"); await save();
      } }, "선택한 값으로 저장");
      dialog = editorDialog("자산이 다른 사용자에 의해 변경됨", h("div", null,
        h("p", { class: "notice" }, "서로 다른 항목에서 생긴 변경은 함께 보존합니다. 같은 항목을 둘 다 바꿨으면 저장할 값을 선택하세요."),
        compare, h("div", { class: "toolbar" }, useLatest, merge, cancelDialog(() => dialog.close("cancel")))), saveBtn);
    };
    const showApiErrors = (err) => {
      const parts = err.message.split(/;\s*(?=[a-z_]+:\s)/i);
      const first = [];
      for (const part of parts) {
        const match = part.match(/^(asset_no|kind|serial|hostname|domain|ip|parent_asset_id|host_id|primary_owner|secondary_owner|note):\s*(.+)$/i);
        if (!match) continue;
        const el = inputs[match[1]];
        if (!el) continue;
        setFieldError(el, match[2]); first.push(el);
      }
      if (first.length) first[0].focus(); else msg.err(errMsg(err));
    };
    const save = async () => {
      if (busy || !isAdmin() || !validate()) return;
      busy = true; saveBtn.disabled = true; msg.info("저장 중…");
      try {
        await api(id ? `/v1/assets/${enc(id)}` : "/v1/assets", { method: id ? "PUT" : "POST", body: JSON.stringify({ ...body(), ...(id ? { expected_revision: expectedRevision } : {}) }) });
        assetDraftGuard = null;
        const requestedSuccess = q.get("success");
        const successTarget = requestedSuccess && /^#\//.test(requestedSuccess) ? requestedSuccess : back;
        const params = new URLSearchParams(successTarget.includes("?") ? successTarget.slice(successTarget.indexOf("?") + 1) : ""); params.set("saved", "1");
        location.hash = `${successTarget.split("?")[0]}?${params}`;
      } catch (err) {
        busy = false; saveBtn.disabled = false;
        msg.clear();
        if (id && err.status === 409 && /다른 사용자|revision changed/i.test(err.message)) { await showConflict(); return; }
        showApiErrors(err);
      }
    };
    const removeBtn = id ? gate(h("button", { class: "danger", type: "button", onclick: async () => {
      if (!confirm(`자산 '${a.asset_no}' 을(를) 대장에서 삭제합니다. 수집된 호스트와 이력은 그대로 남습니다. 계속할까요?`)) return;
      try { await api(`/v1/assets/${enc(id)}`, { method: "DELETE" }); location.hash = back; } catch (err) { msg.err(errMsg(err)); }
    } }, "삭제")) : null;

    let hostD = null;
    if (row && row.host_id) { try { hostD = await api(`/v1/hosts/${enc(row.host_id)}`); } catch (err) { hostError = err; } }
    const detected = hostD ? hostD.hardware : null;
    let compare = null;
    if (hostD) {
      const ips = [...new Set(hostD.interfaces.flatMap((i) => i.addresses).map((x) => x.split("/")[0]))].sort((x, y) => Number(x.includes(":")) - Number(y.includes(":")));
      const fireInput = (el) => el.dispatchEvent(new Event("input", { bubbles: true }));
      const setInput = (el) => (v) => { el.value = v; fireInput(el); };
      const textItem = (key, label, el, collected) => ({ key, label, saved: String(a[key] || ""), collected: collected ? [collected] : [], fmt: (v) => v, get: () => el.value, set: setInput(el) });
      compare = compareTable([
        { key: "kind", label: "구분", saved: a.kind, collected: detected && ["physical", "virtual"].includes(detected.kind) ? [detected.kind] : [], fmt: kindLabel,
          get: () => f.kind.value, set: (v) => { f.kind.value = v; f.kind.dispatchEvent(new Event("change", { bubbles: true })); } },
        textItem("serial", "시리얼", f.serial, detected && detected.serial),
        textItem("hostname", "호스트명", f.hostname, hostD.host.hostname),
        textItem("domain", "도메인", f.domain, detected && detected.domain),
        { key: "ip", label: "IP", saved: String(a.ip || ""), collected: ips, fmt: (v) => v, get: () => f.ip.value, set: setInput(f.ip) },
      ]);
      for (const el of [f.serial, f.hostname, f.domain, f.ip]) el.addEventListener("input", compare.update);
      f.kind.addEventListener("change", compare.update);
    }
    const form = h("form", { class: "form", novalidate: true, onsubmit: (e) => { e.preventDefault(); save(); } },
      field("자산번호 *", f.asset_no, "대소문자를 구분하지 않고 유일해야 합니다."),
      field("구분 *", f.kind, kindUnclear ? "수집된 구분을 알 수 없어(컨테이너·미확인) 물리/VM 을 직접 골라야 합니다." : null),
      field("시리얼", f.serial, "비워 두면 수집된 시리얼을 씁니다. 자리표시자 값(To Be Filled…)은 연결에 쓰지 않습니다."),
      field("호스트명", f.hostname, "수집된 호스트명과 같으면 자동으로 연결됩니다."), field("도메인", f.domain),
      field("관리 IP", f.ip, "수집된 IP 와 다르면 '불일치'로 표시합니다."),
      field("상위 호스트", f.parent, "VM 이 올라간 물리 장비(구분이 VM 일 때만)."),
      field("수집 호스트 지정", f.host, "자동 연결이 안 될 때만 직접 지정합니다."),
      field("담당자(정)", f.primary_owner, "로그인 계정과 관계없이 이름이나 식별정보를 자유롭게 입력합니다."),
      field("담당자(부)", f.secondary_owner, "로그인 계정과 관계없이 이름이나 식별정보를 자유롭게 입력합니다."),
      field("비고", f.note),
      h("div", { class: "full toolbar" }, saveBtn, removeBtn, msg.el));
    for (const el of Object.values(inputs)) {
      el.addEventListener("input", () => { if (el.fieldError) setFieldError(el, ""); });
      el.addEventListener("change", () => { if (el.fieldError) setFieldError(el, ""); });
    }
    return titled(h("div", null,
      h("div", { class: "toolbar" }, link(returnHash(q) ? "← 돌아가기" : "← 자산 목록", back)),
      h("h1", null, id ? `자산 ${a.asset_no}` : "자산 추가"),
      adminNote(),
      kindUnclear ? h("div", { class: "notice" }, "이 호스트의 구분을 수집값으로 알 수 없습니다(컨테이너·미확인). 물리/VM 을 직접 선택하세요.") : null,
      row ? h("div", { class: "panel" }, h("dl", { class: "kv" },
        h("dt", null, "상태"), h("dd", null, [badge(...ASSET_STATUS[row.status]), flagBadges(row.flags)]),
        h("dt", null, "수집 호스트"), h("dd", null, row.host_id ? [link(row.hostname, `#/hosts/${enc(row.host_id)}`), ` · 연결 근거: ${MATCH_LABELS[row.match_by]}`] : h("span", { class: "muted" }, "아직 연결된 수집 호스트가 없습니다")),
        detected ? [h("dt", null, "수집된 장비"), h("dd", null, `${kindLabel(detected.kind)}${detected.virt ? ` (${detected.virt})` : ""} · ${detected.vendor} ${detected.model} · 시리얼 ${detected.serial || "읽지 못함"}`)] : null,
        hostError ? h("div", { class: "error full", role: "alert" }, `연결된 호스트의 비교 정보를 불러오지 못했습니다: ${hostError.message}. 자산 대장 입력과 저장은 계속할 수 있습니다.`) : null,
        row.vms && row.vms.length ? [h("dt", null, "올라간 VM"), h("dd", null, row.vms.map((v) => h("div", null, link(v.asset_no, `#/assets/${v.id}`), ` ${v.hostname || ""}`)))] : null)) : null,
      compare ? [h("h2", null, "대장 값 ↔ 수집 값"), compare.node, h("p", { class: "hint" }, "'수집값 적용'은 아래 입력란만 바꿉니다. 저장을 눌러야 대장에 반영됩니다.")] : null,
      h("h2", null, "대장 정보"),
      h("div", { class: "panel" }, form)), id ? `자산 ${a.asset_no}` : "자산 추가");
  }

  // ---------- 컨테이너·쿠버네티스 ----------
  const tab = (text, hash, on) => h("a", { href: hash, class: "tab" + (on ? " active" : ""), "aria-current": on ? "page" : null }, text);
  const containerTabs = (active) => h("nav", { class: "toolbar", "aria-label": "컨테이너 보기" },
    tab("클러스터", "#/containers", active === "clusters"),
    tab("이미지", "#/containers/images", active === "images"),
    tab("컨테이너", "#/containers/list", active === "list"));
  const clusterLabel = (id) => (id === "unknown" ? "미확인" : String(id).slice(0, 8));

  async function viewContainers(rest, q, alive) {
    if (rest[0] === "images") return rest[1] ? imageDetail(rest.slice(1).join("/"), q) : imagesView(q, alive);
    if (rest[0] === "list") return containersList(q, alive);
    if (rest[0] === "clusters" && rest[1]) return clusterDetail(rest[1]);
    return clustersView();
  }

  async function clustersView() {
    const [clusters, o] = await Promise.all([api("/v1/k8s/clusters"), api("/v1/overview")]);
    const c = o.containers;
    return h("div", null, h("h1", null, "컨테이너·쿠버네티스"), containerTabs("clusters"),
      h("div", { class: "cards" },
        h("div", { class: "card" }, h("div", { class: "label" }, "클러스터"), h("div", { class: "value" }, c.cluster_count), h("div", { class: "sub" }, "노드의 CA 인증서로 구분")),
        h("div", { class: "card" }, h("div", { class: "label" }, "쿠버네티스 노드"), h("div", { class: "value" }, c.node_count), h("div", { class: "sub" }, "에이전트가 설치된 노드")),
        h("a", { class: "card", href: "#/containers/list?active=1" }, h("div", { class: "label" }, "실행 중 컨테이너"), h("div", { class: "value" }, c.running_container_count), h("div", { class: "sub" }, "서버 위 도커 포함")),
        h("a", { class: "card", href: "#/containers/images" }, h("div", { class: "label" }, "이미지"), h("div", { class: "value" }, c.image_count), h("div", { class: "sub" }, "실행 중인 이미지 종류"))),
      clusters.some((x) => !x.cluster_id) ? h("div", { class: "notice" }, "클러스터를 알아내지 못한 노드가 있습니다(클러스터 CA 인증서를 읽지 못함). 노드 설치를 다시 실행하면 식별됩니다.") : null,
      table([
        { title: "클러스터", sort: (x) => x.name, render: (x) => link(x.name, `#/containers/clusters/${enc(x.cluster_id || "unknown")}`) },
        { title: "API 서버", mono: true, sort: (x) => x.api_servers[0] || null, render: (x) => x.api_servers.join(", ") || "-" },
        { title: "버전", mono: true, sort: (x) => x.versions[0] || null, render: (x) => [x.versions.join(", ") || "-", x.versions.length > 1 ? " " : null, x.versions.length > 1 ? badge("버전 혼재", "warn") : null] },
        { title: "노드", desc: true, sort: (x) => x.node_count, render: (x) => x.node_count }, { title: "파드", desc: true, sort: (x) => x.pod_count, render: (x) => x.pod_count },
        { title: "네임스페이스", desc: true, sort: (x) => x.namespace_count, render: (x) => x.namespace_count }, { title: "컨테이너", desc: true, sort: (x) => x.container_count, render: (x) => x.container_count },
        { title: "이미지", desc: true, sort: (x) => x.image_count, render: (x) => x.image_count },
      ], clusters, "쿠버네티스 노드가 없습니다. 노드에 에이전트를 설치하세요(crictl 이 있으면 컨테이너 헬퍼가 함께 설치됩니다)."),
      h("p", { class: "hint" }, "파드·컨테이너는 에이전트가 설치된 노드만 보입니다. 쿠버네티스 API 는 사용하지 않아 Deployment 같은 워크로드 단위는 알 수 없습니다."));
  }

  async function clusterDetail(id) {
    const d = await api(`/v1/k8s/clusters/${enc(id)}`);
    const nameIn = gate(h("input", { id: "cluster-name", type: "text", value: d.cluster_id ? d.name : "", placeholder: d.name, maxlength: 64, size: 28 }));
    const msg = msgBox();
    const saveBtn = gate(h("button", { class: "primary", type: "button", onclick: async () => {
      saveBtn.disabled = true;
      try { await api(`/v1/k8s/clusters/${enc(id)}/name`, { method: "PUT", body: JSON.stringify({ name: nameIn.value.trim() }) }); msg.ok("저장했습니다."); }
      catch (err) { msg.err(errMsg(err)); }
      saveBtn.disabled = !isAdmin();
    } }, "저장"));
    return titled(h("div", null, h("div", { class: "toolbar" }, link("← 클러스터", "#/containers")),
      h("h1", null, d.name),
      d.cluster_id ? [adminNote(), h("div", { class: "toolbar" }, h("label", { for: "cluster-name" }, "이름"), nameIn, saveBtn, msg.el)] : null,
      h("p", { class: "hint mono" }, d.cluster_id ? `CA 해시 ${d.cluster_id}` : "CA 인증서를 읽지 못한 노드들입니다."),
      h("p", null, link(`이 클러스터의 컨테이너 ${d.containers.length}개 보기 →`, containerListHash({ cluster: id, active: "1" }))),
      h("h2", null, `노드 (${d.nodes.length})`),
      table([
        { title: "노드", sort: (n) => n.hostname, render: (n) => link(n.hostname, `#/hosts/${enc(n.host_id)}`) }, ...assetCols,
        { title: "버전", mono: true, sort: (n) => n.version, render: (n) => n.version || "-" }, { title: "런타임", sort: (n) => n.runtime, render: (n) => n.runtime || "-" },
        { title: "파드", desc: true, sort: (n) => n.pod_count, render: (n) => n.pod_count }, { title: "컨테이너", desc: true, sort: (n) => n.container_count, render: (n) => n.container_count },
      ], d.nodes),
      h("h2", null, "네임스페이스"),
      table([
        { title: "네임스페이스", mono: true, sort: (n) => n.namespace, render: (n) => link(n.namespace, containerListHash({ cluster: id, namespace: n.namespace, active: "1" })) },
        { title: "파드", desc: true, sort: (n) => n.pod_count, render: (n) => n.pod_count }, { title: "컨테이너", desc: true, sort: (n) => n.container_count, render: (n) => n.container_count },
      ], d.namespaces, "실행 중인 파드가 없습니다."),
      h("h2", null, "이미지"), imageTable(d.images, id)), d.name);
  }

  // cluster 를 주면 이미지 링크·태그 배지가 그 클러스터 범위로 이어진다.
  function imageTable(images, cluster) {
    return table([
      { title: "이미지", mono: true, sort: (i) => i.repo, render: (i) => link(i.repo, hashOf(`#/containers/images/${enc(i.repo)}`, { cluster: cluster || "" })) },
      { title: "호스트", desc: true, sort: (i) => i.host_count, render: (i) => i.host_count }, { title: "컨테이너", desc: true, sort: (i) => i.container_count, render: (i) => i.container_count },
      { title: "태그(호스트 수)", sort: (i) => i.tag_count, render: (i) => [tagBadges(i.repo, i.tags, cluster), i.tag_count > 1 ? badge("버전 혼재", "warn") : null] },
    ], images, "이미지가 없습니다.");
  }

  async function imagesView(q, alive) {
    const st = { all: q.get("all") || "", q: q.get("q") || "" };
    const all = h("input", { type: "checkbox", checked: !!st.all, onchange: () => setQuery("#/containers/images", { all: all.checked ? "1" : "", q: st.q.trim() }) });
    const search = h("input", { type: "search", placeholder: "이미지 검색 (예: nginx)", "aria-label": "이미지 검색", size: 28, value: st.q });
    const body = h("div");
    let seq = 0;
    const run = async () => {
      const mine = ++seq;
      const p = new URLSearchParams({ active: st.all ? "false" : "true" }); if (st.q.trim()) p.set("q", st.q.trim().toLowerCase());
      try { const rows = await api(`/v1/images?${p}`); if (mine === seq && alive()) clear(body).append(imageTable(rows)); }
      catch (err) { if (mine === seq && alive()) clear(body).append(h("div", { class: "error", role: "alert" }, err.message)); }
    };
    liveInput(search, st, "#/containers/images", run, alive);
    run();
    return h("div", null, h("h1", null, "컨테이너·쿠버네티스"), containerTabs("images"),
      h("div", { class: "toolbar" }, search, h("label", null, all, "종료된 컨테이너 포함")), body,
      h("p", { class: "hint" }, "같은 이미지의 태그가 호스트마다 갈라져 있으면 '버전 혼재'로 표시합니다. 태그를 누르면 그 이미지를 쓰는 컨테이너 목록으로 이동합니다."));
  }

  async function imageDetail(repo, q) {
    const cluster = q.get("cluster") || "";
    const path = `/v1/images/${repo.split("/").map(enc).join("/")}`;
    const base = `#/containers/images/${enc(repo)}`;
    const scope = cluster ? chip(`클러스터: ${clusterLabel(cluster)}`, () => setQuery(base, {}), "클러스터 범위") : null;
    let d;
    try { d = await api(cluster ? `${path}?cluster=${enc(cluster)}` : path); }
    catch (err) {
      if (err.status !== 404 || !cluster) throw err;
      return titled(h("div", null, h("div", { class: "toolbar" }, link("← 이미지", "#/containers/images")),
        h("h1", { class: "mono" }, repo),
        h("div", { class: "toolbar" }, scope),
        empty("이 클러스터에는 이 이미지를 쓰는 컨테이너가 없습니다. 범위를 해제하면 전체를 볼 수 있습니다.")), repo);
    }
    return titled(h("div", null, h("div", { class: "toolbar" }, link("← 이미지", "#/containers/images")),
      h("h1", { class: "mono" }, d.repo),
      scope ? h("div", { class: "toolbar" }, scope, h("span", { class: "muted" }, "이 클러스터에서 쓰는 태그·컨테이너만 보입니다")) : null,
      h("h2", null, "태그 분포"),
      h("div", { class: "panel" }, bars(d.tags, { nameOf: (t) => t.tag || "(태그 없음)", countOf: (t) => t.host_count,
        onClick: (t) => { location.hash = containerListHash({ image: imageRef(d.repo, t.tag), cluster, active: "1" }); } })),
      h("h2", null, `이 이미지를 쓰는 컨테이너 (${d.containers.length})`),
      h("p", null, link("목록 화면에서 보기(검색·CSV) →", containerListHash({ image: d.repo, cluster, active: "1" }))),
      containersTable(d.containers)), d.repo);
  }

  function containersTable(rows) {
    return serverGroups(rows, (items) => table([
      { title: "호스트", sort: (r) => r.hostname, render: (r) => link(r.hostname, `#/hosts/${enc(r.host_id)}`) }, ...assetCols,
      { title: "클러스터", sort: (r) => (r.cluster_id === null ? null : r.cluster_id || "미확인"), render: (r) => (r.cluster_id === null ? h("span", { class: "muted" }, "-") : link((r.cluster_id || "미확인").slice(0, 8), `#/containers/clusters/${enc(r.cluster_id || "unknown")}`)) },
      { title: "파드", mono: true, sort: (r) => (r.pod ? `${r.namespace}/${r.pod}` : null), render: (r) => (r.pod ? `${r.namespace}/${r.pod}` : "-") },
      { title: "컨테이너", mono: true, sort: (r) => r.name, render: (r) => r.name }, { title: "이미지", mono: true, sort: (r) => r.image, render: (r) => r.image },
      { title: "상태", sort: (r) => (CONTAINER_STATE[r.state] || [r.state])[0], render: (r) => stateBadge(r.state) },
    ], items), "컨테이너");
  }

  async function containersList(q, alive) {
    const st = { cluster: "", namespace: "", runtime: "", state: "", active: "", host: "", image: "", q: "" };
    for (const k of Object.keys(st)) st[k] = q.get(k) || "";
    const params = () => {
      const p = new URLSearchParams();
      for (const k of ["cluster", "namespace", "runtime", "state", "active", "host", "image"]) if (st[k]) p.set(k, st[k]);
      if (st.q.trim()) p.set("q", st.q.trim());
      return p;
    };
    const [first, hosts] = await Promise.all([api(`/v1/containers?${params()}`), api("/v1/hosts")]);
    const apply = (patch) => setQuery("#/containers/list", { ...st, ...patch });
    const hostName = (first.find((r) => r.host_id === st.host) || {}).hostname || st.host.slice(0, 8);
    const chips = [];   // URL 로 걸린 필터는 화면에 보이지 않으면 결과가 비어 보이는 이유를 알 수 없다 — 칩으로 드러내고 하나씩 끈다
    if (st.cluster) chips.push(chip(`클러스터: ${clusterLabel(st.cluster)}`, () => apply({ cluster: "" }), "클러스터"));
    if (st.namespace) chips.push(chip(`네임스페이스: ${st.namespace}`, () => apply({ namespace: "" }), "네임스페이스"));
    if (st.host) chips.push(chip(`호스트: ${hostName}`, () => apply({ host: "" }), "호스트"));
    if (st.image) chips.push(chip(`이미지: ${st.image}`, () => apply({ image: "" }), "이미지"));
    const count = h("p", { class: "muted", role: "status" });
    const body = h("div");
    const draw = (rows) => { count.textContent = `${rows.length}개`; clear(body).append(containersTable(rows)); };
    let seq = 0;
    const reload = async () => {
      const mine = ++seq;
      try { const rows = await api(`/v1/containers?${params()}`); if (mine === seq && alive()) draw(rows); }
      catch (err) { if (mine === seq && alive()) clear(body).append(h("div", { class: "error", role: "alert" }, errMsg(err, "불러오지 못했습니다"))); }
    };
    const search = h("input", { type: "search", placeholder: "컨테이너·이미지·파드·호스트 검색", "aria-label": "컨테이너 검색", value: st.q, size: 32 });
    liveInput(search, st, "#/containers/list", reload, alive);
    draw(first);
    const sel = (label, name, options) => h("select", { "aria-label": label, onchange: (e) => apply({ [name]: e.target.value }) }, options.map(([v, t]) => h("option", { value: v, selected: v === st[name] }, t)));
    return h("div", null, h("h1", null, "컨테이너·쿠버네티스"), containerTabs("list"),
      h("div", { class: "toolbar" },
        h("label", null, h("input", { type: "checkbox", checked: !!st.active, onchange: (e) => apply({ active: e.target.checked ? "1" : "" }) }), "종료된 컨테이너 제외"),
        serverFilter(hosts, st.host, (host) => apply({ host })),
        sel("런타임 필터", "runtime", [["", "모든 런타임"], ["docker", "docker"], ["containerd", "containerd"], ["cri-o", "cri-o"]]),
        sel("상태 필터", "state", [["", "모든 상태"], ["running", "실행 중"], ["exited", "종료"], ["created", "생성됨"], ["paused", "일시정지"]]),
        chips,
        search, h("span", { class: "spacer" }), csvButton(() => `/v1/containers?${withFormat(params())}`, "containers.csv")),
      count, body);
  }

  // ---------- 변경 이력 ----------
  async function viewEvents(_, q) {
    const st = { type: q.get("type") || "", host: q.get("host") || "", since: q.get("since") || "",
      page: Math.max(1, Number(q.get("page") || 1)), page_size: q.get("page_size") || q.get("limit") || "200" };
    if (!["50", "100", "200"].includes(st.page_size)) st.page_size = "200";
    const params = () => {
      const p = new URLSearchParams({ page: String(st.page), page_size: st.page_size });
      if (st.type) p.set("type", st.type);
      if (st.host) p.set("host", st.host);
      if (st.since) p.set("since", localMidnightUtc(st.since));
      return p;
    };
    const csvParams = () => {
      const p = new URLSearchParams();
      if (st.type) p.set("type", st.type);
      if (st.host) p.set("host", st.host);
      if (st.since) p.set("since", localMidnightUtc(st.since));
      return p;
    };
    const [result, hosts] = await Promise.all([api(`/v1/events?${params()}`), api("/v1/hosts").catch(() => [])]);
    const apply = (patch) => setQuery("#/events", { ...st, ...patch, page: patch.page ?? 1 });
    // host_id 대신 호스트 이름으로 고른다(이름이 겹치면 host_id 앞 8자를 덧붙인다). 주소에는 host_id 가 그대로 남는다.
    const count = new Map(); hosts.forEach((x) => count.set(x.hostname, (count.get(x.hostname) || 0) + 1));
    const labelOf = new Map(hosts.map((x) => [x.host_id, count.get(x.hostname) > 1 ? `${x.hostname} (${x.host_id.slice(0, 8)})` : x.hostname]));
    const idOf = new Map([...labelOf].map(([id, label]) => [label, id]));
    const listId = uid("event-hosts");
    const hostErr = h("span", { class: "field-error", role: "alert" });
    const hostIn = h("input", { type: "text", list: listId, "aria-label": "호스트 (이름으로 선택)", placeholder: "호스트 이름", size: 26, value: st.host ? labelOf.get(st.host) || st.host : "",
      onchange: () => {
        const v = hostIn.value.trim();
        if (!v) { apply({ host: "" }); return; }
        const id = idOf.get(v) || (labelOf.has(v) ? v : "");
        if (!id) { hostIn.setAttribute("aria-invalid", "true"); hostErr.textContent = "목록에 없는 호스트입니다. 이름을 목록에서 고르세요."; return; }
        apply({ host: id });
      } });
    const typeSel = h("select", { "aria-label": "이벤트 유형", onchange: (e) => apply({ type: e.target.value }) }, h("option", { value: "" }, "모든 유형"),
      Object.entries(EVENT_LABELS).map(([k, [t]]) => h("option", { value: k, selected: k === st.type }, t)));
    const sinceIn = h("input", { type: "date", value: st.since, onchange: (e) => apply({ since: e.target.value }) });
    const limitSel = h("select", { "aria-label": "페이지 크기", onchange: (e) => apply({ page_size: e.target.value }) },
      ["50", "100", "200"].map((n) => h("option", { value: n, selected: n === st.page_size }, `${n}건`)));
    return h("div", null, h("h1", null, "변경 이력"),
      h("div", { class: "toolbar" }, typeSel, hostIn, h("datalist", { id: listId }, [...idOf.keys()].map((label) => h("option", { value: label }))), hostErr,
        h("label", null, "이후", sinceIn), limitSel, h("span", { class: "spacer" }), csvButton(() => `/v1/events?${withFormat(csvParams())}`, "events.csv")),
      h("p", { class: "muted", role: "status" }, `전체 ${result.total}건 · ${result.items.length}건 표시`), eventsTable(result.items),
      pageControls("#/events", st, st.page, Number(st.page_size), result.total));
  }


  // ---------- 안전한 마크다운 렌더러 (LLM 출력도 신뢰하지 않는다: 요소는 직접 만들고 링크·HTML 은 텍스트로만 표시) ----------
  function inlineMd(text) {
    const out = [];
    for (const part of text.split(/(`[^`]+`|\*\*[^*]+\*\*)/)) {
      if (!part) continue;
      if (part.startsWith("`") && part.endsWith("`") && part.length > 2) out.push(h("code", null, part.slice(1, -1)));
      else if (part.startsWith("**") && part.endsWith("**") && part.length > 4) out.push(h("strong", null, part.slice(2, -2)));
      else out.push(part.replace(/\[([^\]]*)\]\(([^)]*)\)/g, "$1")); // [텍스트](url) → 텍스트만. 링크 요소를 만들지 않는다
    }
    return out;
  }
  function mdToDom(text) {
    const root = h("div", { class: "md" });
    const lines = text.replace(/\r\n?/g, "\n").split("\n");
    const splitRow = (l) => l.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
    for (let i = 0; i < lines.length;) {
      const line = lines[i];
      if (/^```/.test(line)) {
        const buf = []; i++;
        while (i < lines.length && !/^```/.test(lines[i])) buf.push(lines[i++]);
        i++; root.append(h("pre", null, h("code", null, buf.join("\n")))); continue;
      }
      const hd = /^(#{1,4})\s+(.*)$/.exec(line);
      if (hd) { root.append(h(["h2", "h2", "h3", "h4"][hd[1].length - 1], null, inlineMd(hd[2]))); i++; continue; }
      if (/^\s*([-*_])\1{2,}\s*$/.test(line)) { root.append(h("hr")); i++; continue; }
      if (/^\s*\|/.test(line) && i + 1 < lines.length && /^\s*\|?[\s:|-]+\|?\s*$/.test(lines[i + 1]) && lines[i + 1].includes("-")) {
        const head = splitRow(line); i += 2; const body = [];
        while (i < lines.length && /^\s*\|/.test(lines[i])) body.push(splitRow(lines[i++]));
        root.append(h("div", { class: "scroll", tabindex: "0" }, h("table", null, h("thead", null, h("tr", null, head.map((c) => h("th", { scope: "col" }, inlineMd(c))))),
          h("tbody", null, body.map((r) => h("tr", null, r.map((c) => h("td", null, inlineMd(c)))))))));
        continue;
      }
      const li = /^\s*([-*+]|\d+\.)\s+(.*)$/.exec(line);
      if (li) {
        const ordered = /\d/.test(li[1]); const items = [];
        while (i < lines.length) {
          const m = /^\s*([-*+]|\d+\.)\s+(.*)$/.exec(lines[i]);
          if (!m) break; items.push(h("li", null, inlineMd(m[2]))); i++;
        }
        root.append(h(ordered ? "ol" : "ul", null, items)); continue;
      }
      if (!line.trim()) { i++; continue; }
      const para = [];
      while (i < lines.length && lines[i].trim() && !/^(#{1,4}\s|```|\s*([-*+]|\d+\.)\s|\s*\|)/.test(lines[i])) para.push(lines[i++]);
      root.append(h("p", null, inlineMd(para.join(" "))));
    }
    return root;
  }


  // ---------- 네트워크 ----------
  const netTabs = (active) => h("nav", { class: "toolbar", "aria-label": "네트워크 보기" }, tab("IP·MAC", "#/network", active === "ips"), tab("열린 포트", "#/network/ports", active === "ports"));
  const exposureBadge = (e) => { const [t, k] = EXPOSURE[e] || [e, ""]; return badge(t, k); };

  async function viewNetwork(rest, q, alive) {
    if (rest[0] === "ports") return rest[2] ? portDetail(rest[1], rest[2], q) : portsView(q, alive);
    return ipsView(q, alive);
  }

  async function ipsView(q, alive) {
    const st = { q: q.get("q") || "", host: q.get("host") || "", conflicts: q.get("conflicts") ? "1" : "" };
    const params = () => {
      const p = new URLSearchParams();
      if (st.q.trim()) p.set("q", st.q.trim());
      if (st.host) p.set("host", st.host);
      if (st.conflicts) p.set("conflicts", "true");
      return p;
    };
    const hosts = await api("/v1/hosts");
    const input = h("input", { type: "search", placeholder: "IP·MAC·호스트·자산번호·인터페이스 검색", "aria-label": "IP·MAC 검색", value: st.q, size: 36 });
    // '충돌만'은 서버가 거른다(CSV 도 같은 조건) — 주소에 남겨 새로 고침·공유에도 유지된다. 다시 그리지 않으므로 포커스도 유지된다.
    const conflictsOnly = h("input", { type: "checkbox", checked: !!st.conflicts, onchange: () => { st.conflicts = conflictsOnly.checked ? "1" : ""; replaceQuery("#/network", { ...st, q: st.q.trim() }); run(); } });
    const out = h("div"); const banner = h("div"); let seq = 0;
    const run = async () => {
      const mine = ++seq;
      try {
        const rows = await api(`/v1/network/ips?${params()}`);
        if (mine !== seq || !alive()) return;
        const dupIps = new Set(rows.filter((r) => r.duplicate).map((r) => r.ip));
        clear(banner); if (dupIps.size) banner.append(h("div", { class: "notice" }, `IP 충돌 ${dupIps.size}건: 같은 IP 를 둘 이상의 호스트가 사용합니다. (${[...dupIps].slice(0, 5).join(", ")}${dupIps.size > 5 ? " …" : ""})`));
        clear(out).append(serverGroups(rows, (items) => table([
          { title: "IP", mono: true, sort: (r) => r.cidr, render: (r) => r.cidr },
          { title: "호스트", sort: (r) => r.hostname, render: (r) => link(r.hostname, `#/hosts/${enc(r.host_id)}`) },
          ...assetCols,
          { title: "인터페이스", mono: true, sort: (r) => r.interface, render: (r) => r.interface },
          { title: "MAC", mono: true, sort: (r) => r.mac, render: (r) => r.mac || "-" },
          { title: "상태", sort: (r) => r.state, render: (r) => badge(r.state === "up" ? "up" : r.state === "down" ? "down" : "?", r.state === "up" ? "ok" : "") },
          { title: "", srTitle: "충돌", sort: (r) => Number(!!r.duplicate), desc: true, render: (r) => (r.duplicate ? badge("IP 충돌", "err") : "") },
        ], items), "네트워크 주소"));
      } catch (err) { if (mine === seq && alive()) clear(out).append(h("div", { class: "error", role: "alert" }, err.message)); }
    };
    liveInput(input, st, "#/network", run, alive);
    run();
    return h("div", null, h("h1", null, "네트워크"), netTabs("ips"),
      h("div", { class: "toolbar" }, serverFilter(hosts, st.host, (host) => setQuery("#/network", { ...st, host })), input, h("label", null, conflictsOnly, "충돌만"), h("span", { class: "spacer" }), csvButton(() => `/v1/network/ips?${withFormat(params())}`, "ips.csv")), banner, out);
  }

  function listeningTable(rows) {
    return table([
      { title: "포트", mono: true, sort: (r) => r.port, render: (r) => link(`${r.proto}/${r.port}`, `#/network/ports/${r.proto}/${r.port}?host=${enc(r.host_id)}`) },
      { title: "호스트", sort: (r) => r.hostname, render: (r) => link(r.hostname, `#/hosts/${enc(r.host_id)}`) },
      ...assetCols,
      { title: "서비스", sort: (r) => r.service, render: (r) => r.service || "-" },
      { title: "바인딩", mono: true, sort: (r) => r.bind, render: (r) => r.bind },
      { title: "노출", sort: (r) => r.exposure, render: (r) => [exposureBadge(r.exposure), r.notable ? h("span", { class: "badge err", title: r.notable_reason }, "주의") : null] },
    ], rows);
  }

  async function portsView(q, alive) {
    const st = { proto: q.get("proto") || "", exposure: q.get("exposure") || "", notable: q.get("notable") || "", q: q.get("q") || "", host: q.get("host") || "" };
    const params = () => {
      const p = new URLSearchParams();
      for (const k of ["proto", "exposure", "host"]) if (st[k]) p.set(k, st[k]);
      if (st.notable) p.set("notable", "true");
      if (st.q.trim()) p.set("q", st.q.trim());
      return p;
    };
    const hosts = await api("/v1/hosts");
    const apply = (patch) => setQuery("#/network/ports", { ...st, ...patch });
    const body = h("div"); let seq = 0;
    const run = async () => {
      const mine = ++seq;
      try {
        const rows = await api(`/v1/network/listening?${params()}`);
        if (mine === seq && alive()) clear(body).append(serverGroups(rows, listeningTable, "열린 포트"));
      } catch (err) { if (mine === seq && alive()) clear(body).append(h("div", { class: "error", role: "alert" }, err.message)); }
    };
    const search = h("input", { type: "search", placeholder: "포트·서비스 검색 (예: 22, ssh)", "aria-label": "포트·서비스 검색", size: 26, value: st.q });
    liveInput(search, st, "#/network/ports", run, alive);
    run();
    const sel = (label, name, options) => h("select", { "aria-label": label, onchange: (e) => apply({ [name]: e.target.value }) },
      options.map(([v, t]) => h("option", { value: v, selected: v === st[name] }, t)));
    return h("div", null, h("h1", null, "네트워크"), netTabs("ports"),
      h("div", { class: "toolbar" }, serverFilter(hosts, st.host, (host) => apply({ host })),
        sel("프로토콜 필터", "proto", [["", "tcp·udp"], ["tcp", "tcp"], ["udp", "udp"]]),
        sel("노출 필터", "exposure", [["", "모든 바인딩"], ["exposed", "외부 바인딩(루프백 제외)"], ["any", "모든 인터페이스(0.0.0.0/::)"], ["specific", "특정 주소"], ["loopback", "로컬 전용"]]),
        h("label", null, h("input", { type: "checkbox", checked: !!st.notable, onchange: (e) => apply({ notable: e.target.checked ? "1" : "" }) }), "주의 포트만"),
        search, h("span", { class: "spacer" }), csvButton(() => `/v1/network/listening?${withFormat(params())}`, "listening-ports.csv")), body,
      h("p", { class: "hint" }, "노출은 바인딩 주소 기준입니다. 방화벽 규칙은 반영되지 않습니다."));
  }

  async function portDetail(proto, port, q) {
    const host = q.get("host") || "";
    const params = new URLSearchParams({ proto, port });
    if (host) params.set("host", host);
    const [rows, hosts] = await Promise.all([api(`/v1/network/listening?${params}`), api("/v1/hosts")]);
    const base = `#/network/ports/${enc(proto)}/${enc(port)}`;
    return titled(h("div", null,
      h("div", { class: "toolbar" }, link("← 포트 목록", `#/network/ports${host ? `?host=${enc(host)}` : ""}`),
        serverFilter(hosts, host, (value) => setQuery(base, { host: value })), h("span", { class: "spacer" }),
        csvButton(() => `/v1/network/listening?${withFormat(params)}`, `ports-${proto}-${port}.csv`)),
      h("h1", { class: "mono" }, `${proto}/${port}`, rows[0] && rows[0].service ? ` · ${rows[0].service}` : ""),
      serverGroups(rows, listeningTable, "열린 포트")), `${proto}/${port}`);
  }


  // ---------- 서버 등록 ----------
  const fmtSize = (n) => (n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`);

  // 복사 결과는 role=status 영역(status)에 적어 보조기기가 읽게 한다(버튼 글자만 바뀌면 알려지지 않는다).
  async function copyText(text, button, status) {
    try { await navigator.clipboard.writeText(text); button.textContent = "복사됨"; status.textContent = "명령을 클립보드에 복사했습니다."; }
    catch (_) { // http(비보안 컨텍스트)에서는 Clipboard API 가 막힌다 — 선택만 해 두고 직접 복사하게 한다
      const pre = button.closest(".panel").querySelector("pre.cmd");
      const range = document.createRange(); range.selectNodeContents(pre);
      const sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(range);
      button.textContent = "선택됨 — Ctrl+C"; status.textContent = "복사하지 못해 명령을 선택해 두었습니다. Ctrl+C 로 복사하세요.";
    }
    setTimeout(() => { button.textContent = "복사"; status.textContent = ""; }, 2500);
  }

  async function viewEnroll(_, __, alive) {
    // 화면을 연 시점의 호스트 ID 를 기억해 두고, 그 뒤에 새로 나타난 호스트만 '방금 등록'으로 보여 준다(브라우저·서버 시계 차이에 의존하지 않는다)
    let known = null;
    try { known = new Set((await api("/v1/hosts")).map((x) => x.host_id)); } catch (_e) { /* 폴링에서 다시 시도 */ }
    const baseIn = h("input", { id: "enroll-base", type: "text", value: location.origin, size: 40, title: "대상 서버가 접근할 수 있는 이 서버의 주소" });
    const caIn = h("input", { type: "checkbox" });
    const tokenIn = gate(h("input", { type: "checkbox" }));
    const out = h("div"); const msg = msgBox();
    let agentsOk = true; // 배포할 에이전트 파일이 하나도 없으면 등록 대기 폴링이 의미가 없다

    const card = (title, hint, info, command) => {
      const status = h("span", { class: "muted", role: "status" });
      const copy = h("button", { class: "primary", type: "button", onclick: (e) => copyText(command, e.currentTarget, status) }, "복사");
      return h("div", { class: "panel" },
        h("h2", null, title, " ", badge(info.available ? "배포 가능" : "서버에 없음", info.available ? "ok" : "err")),
        h("p", { class: "hint" }, hint),
        info.available ? h("dl", { class: "kv" },
          h("dt", null, "파일"), h("dd", { class: "mono" }, `${info.file} (${fmtSize(info.size)})`),
          h("dt", null, "sha256"), h("dd", { class: "mono", title: info.sha256 }, info.sha256)) : null,
        command ? [h("pre", { class: "cmd" }, command), h("div", { class: "toolbar" }, copy, status)] : empty("이 서버에는 배포용 파일이 없습니다."));
    };

    const waiting = h("div");
    const load = async () => {
      msg.info("불러오는 중…");
      const params = new URLSearchParams({ base_url: baseIn.value.trim(), ca: String(caIn.checked), include_token: String(tokenIn.checked) });
      try {
        const e = await api(`/v1/enrollment?${params}`);
        msg.clear();
        agentsOk = !!(e.agents.linux.available || e.agents.windows.available);
        clear(out).append(...[
          agentsOk ? null : h("div", { class: "error", role: "alert" }, "이 서버에는 배포용 에이전트 파일이 하나도 없어 서버를 등록할 수 없습니다. 서버 관리자가 에이전트 디렉터리(SWINV_AGENT_DIR)를 확인해야 합니다."),
          e.notes.length ? h("div", { class: "notice" }, e.notes.map((n) => h("div", null, n))) : null,
          tokenIn.checked ? (e.token_included
            ? h("div", { class: "notice" }, "이 명령에는 수집 전용 토큰이 들어 있습니다. 터미널 기록·화면 공유에 남지 않게 주의하세요. 필요 없으면 '토큰 포함'을 끄고 직접 입력하세요.")
            : h("div", { class: "notice" }, "서버에 설정된 수집 토큰이 없어 자리표시자(<수집 토큰>)로 남겼습니다.")) : null,
          // 네이티브 append(null) 은 'null' 글자를 붙인다 — h() 와 달리 거르지 않으므로 직접 거른다
          agentsOk ? h("div", { class: "enroll-grid" },
            card("Linux", "Debian/Ubuntu·RHEL 계열. 대상: python3 3.9+, sudo 권한(설치만 root, 에이전트는 전용 비특권 계정으로 실행). IP·MAC 수집은 iproute2(ip) 필요. curl 이 없어도 python3 로 내려받는다.",
              e.agents.linux, e.commands.linux),
            card("Windows Server", "관리자 PowerShell 5.1+. 설치만 관리자이고 에이전트는 저권한 LOCAL SERVICE 예약 작업(60분마다)으로 실행된다. .NET 설치 불필요(단일 exe).",
              e.agents.windows, e.commands.windows)) : null].filter(Boolean));
        if (!agentsOk) { clearInterval(enrollTimer); clear(waiting); }
      } catch (err) {
        clear(out); msg.err(err.status === 403 ? `'토큰 포함'은 ${ADMIN_ONLY}.` : `명령을 만들지 못했습니다: ${err.message}`);
      }
    };
    for (const el of [caIn, tokenIn]) el.addEventListener("change", load);
    baseIn.addEventListener("change", load);

    // 등록 대기: 명령을 실행하면 서버가 나타나는 것을 바로 보여 준다. 일시 오류는 넘기되 3회 연속이면 화면에 알린다.
    // 오류가 나도 '대기 중' 제목은 남긴다(아무것도 안 보이면 폴링이 멈춘 것으로 오해한다).
    let failures = 0; let fresh = [];
    const drawWaiting = (failure) => clear(waiting).append(h("div", null,
      h("h2", null, h("span", { class: fresh.length ? "" : "pulse" }), fresh.length ? `방금 등록된 서버 (${fresh.length})` : "등록 대기 중… (5초마다 확인)"),
      failure ? h("div", { class: "error", role: "alert" }, failure) : null,
      fresh.length ? table([
        { title: "호스트", sort: (x) => x.hostname, render: (x) => link(x.hostname, `#/hosts/${enc(x.host_id)}`) },
        { title: "OS", cls: "os", sort: (x) => x.os_name, render: (x) => x.os_name || "-" },
        { title: "IP", mono: true, render: (x) => x.ips.slice(0, 2).join(", ") || "-" },
        { title: "등록 시각", sort: (x) => stamp(x.first_seen), render: (x) => timeEl(x.first_seen) },
      ], fresh) : h("div", { class: "muted" }, "대상 서버에서 위 명령을 실행하면 첫 수집이 끝나는 즉시 여기에 나타납니다.")));
    const poll = async () => {
      if (!agentsOk) return;
      try {
        const all = await api("/v1/hosts");
        failures = 0;
        if (known === null) known = new Set(all.map((x) => x.host_id));
        fresh = all.filter((x) => !known.has(x.host_id));
        drawWaiting(null);
      } catch (err) {
        failures += 1;
        if (failures >= 3) drawWaiting(`등록 대기 확인이 ${failures}회 연속 실패했습니다: ${err.message} 서버 연결을 확인하세요(계속 다시 시도합니다).`);
      }
    };
    load().then(() => {
      if (!alive() || !agentsOk) return;
      drawWaiting(null);
      enrollTimer = setInterval(poll, 5000);
      poll();
    });

    return h("div", null, h("h1", null, "서버 등록"),
      h("p", { class: "muted" }, "대상 서버에서 한 줄만 실행하면 에이전트를 내려받아(sha256 고정) 설치하고 첫 수집까지 확인합니다."),
      h("div", { class: "toolbar" }, h("label", { for: "enroll-base" }, "서버 주소"), baseIn, h("label", null, caIn, "사설 CA 사용"), h("label", null, tokenIn, "토큰 포함(관리자)")),
      isAdmin() ? null : h("p", { class: "hint" }, `'토큰 포함'은 ${ADMIN_ONLY}.`),
      msg.el, out, waiting);
  }

  // ---------- AI 리포트 ----------
  async function viewReports(rest) {
    if (rest[0] === "facts") return reportFacts();
    if (rest[0]) return reportDetail(rest[0]);
    const list = await api("/v1/reports");
    const status = msgBox();
    const btn = gate(h("button", { class: "primary", type: "button", onclick: async () => {
      btn.disabled = true;
      status.info("생성 중… 집계를 AI 에 보내 분석하는 데 수십 초에서 수 분이 걸릴 수 있습니다.");
      try { const r = await api("/v1/reports", { method: "POST" }); location.hash = `#/reports/${r.id}`; }
      catch (err) {
        btn.disabled = !isAdmin();
        status.err(err.status === 409 ? `${err.message} (설정 화면에서 AI 연결을 입력하세요)` : errMsg(err));
      }
    } }, "AI 리포트 생성"));
    return h("div", null, h("h1", null, "AI 종합 분석 리포트"),
      h("div", { class: "notice" }, "리포트를 생성하면 호스트명·태그·커널/패키지 집계가 설정한 AI 엔드포인트로 전송됩니다. 외부(external) 엔드포인트를 쓰면 사내 인벤토리가 외부로 나가므로 설정에서 신뢰 영역을 확인하세요."),
      adminNote(),
      h("div", { class: "toolbar" }, btn, link("근거 집계(facts) 보기", "#/reports/facts"), status.el),
      table([
        { title: "생성 시각", desc: true, sort: (r) => stamp(r.created_at), render: (r) => h("a", { href: `#/reports/${r.id}`, title: fmtFull(r.created_at) }, fmtTime(r.created_at)) },
        { title: "모델", mono: true, sort: (r) => r.model, render: (r) => r.model },
        { title: "토큰(입력/출력)", desc: true, sort: (r) => r.prompt_tokens, render: (r) => (r.prompt_tokens == null ? "-" : `${r.prompt_tokens} / ${r.completion_tokens ?? "-"}`) },
      ], list, "생성된 리포트가 없습니다. 위 버튼으로 첫 리포트를 만드세요."));
  }

  async function reportDetail(id) {
    const r = await api(`/v1/reports/${enc(id)}`);
    const delBtn = gate(h("button", { class: "danger", type: "button", onclick: async () => {
      if (!confirm("이 리포트를 삭제할까요?")) return;
      try { await api(`/v1/reports/${enc(id)}`, { method: "DELETE" }); location.hash = "#/reports"; }
      catch (err) { alert(errMsg(err)); }
    } }, "삭제"));
    const save = () => {
      const a = h("a", { href: URL.createObjectURL(new Blob([r.markdown], { type: "text/markdown;charset=utf-8" })), download: `inventory-report-${r.id}.md` });
      document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    };
    return titled(h("div", null,
      h("div", { class: "toolbar" }, link("← 리포트 목록", "#/reports"), h("span", { class: "spacer" }),
        h("button", { type: "button", onclick: save }, "마크다운 저장"), delBtn),
      h("h1", null, `리포트 #${r.id}`),
      h("div", { class: "muted" }, `${fmtTime(r.created_at)} · 모델 ${r.model} · 토큰 ${r.prompt_tokens ?? "-"}/${r.completion_tokens ?? "-"} · AI 가 작성한 내용이므로 아래 근거 집계와 대조해 확인하세요.`),
      h("div", { class: "panel md-panel" }, mdToDom(r.markdown)),
      h("details", null, h("summary", null, "근거 집계(facts) — 리포트 작성 시점에 AI 에 전달한 데이터"), h("pre", { class: "json" }, JSON.stringify(r.facts, null, 2)))), `리포트 #${r.id}`);
  }

  async function reportFacts() {
    const f = await api("/v1/reports/facts");
    return titled(h("div", null, h("div", { class: "toolbar" }, link("← 리포트 목록", "#/reports")),
      h("h1", null, "근거 집계(현재)"), h("div", { class: "muted" }, "리포트 생성 시 AI 에 전달되는 집계입니다. AI 설정 없이도 볼 수 있습니다."),
      h("pre", { class: "json", tabindex: "0" }, JSON.stringify(f, null, 2))), "근거 집계");
  }

  // ---------- 계정·권한·API 토큰 ----------
  const roleLabel = (r) => ({ read: "조회", request: "요청자", admin: "관리자", ingest: "수집 전용" })[r] || r;
  function pageHeader(title, action, hint) {
    return h("div", { class: "page-heading" }, h("div", null, h("h1", null, title), hint ? h("p", { class: "muted" }, hint) : null), action);
  }
  function feedback() {
    const message = h("span"); let timer;
    const node = h("div", { class: "feedback", role: "status", hidden: true }, message,
      h("button", { type: "button", "aria-label": "알림 닫기", onclick: () => { node.hidden = true; } }, "닫기"));
    return { node, ok(text) { message.textContent = text; node.hidden = false; clearTimeout(timer); timer = setTimeout(() => { node.hidden = true; }, 8000); } };
  }
  function editorDialog(title, body, opener, onCancel) {
    const titleId = uid("dialog-title");
    const dialog = h("dialog", { class: "editor-dialog", "aria-labelledby": titleId }, h("h2", { id: titleId }, title), body);
    dialog.addEventListener("close", () => {
      if (dialog.returnValue !== "saved" && onCancel) onCancel();
      dialog.remove();
      if (opener && opener.isConnected) opener.focus(); else focusTitle();
    });
    $app.append(dialog); dialog.showModal();
    return dialog;
  }
  const cancelDialog = (close) => h("button", { type: "button", onclick: close }, "취소");
  const userRoleSelect = (value = "read") => h("select", null,
    ["read", "request", "admin"].map((r) => h("option", { value: r, selected: value === r }, roleLabel(r))));

  async function viewMyAccount() {
    const me = await api("/v1/auth/me");
    if (me.kind !== "session") return h("div", null, pageHeader("내 계정"),
      h("div", { class: "panel" }, "토큰으로 접속했습니다. 비밀번호 변경은 ID·비밀번호로 로그인한 계정에서 사용할 수 있습니다."));
    const msg = msgBox();
    const current = h("input", { type: "password", autocomplete: "current-password", required: true, maxlength: 128 });
    const next = h("input", { type: "password", autocomplete: "new-password", required: true, minlength: 12, maxlength: 128 });
    const change = h("button", { type: "submit", class: "primary" }, "비밀번호 변경");
    const form = h("form", { class: "panel form personal-form", onsubmit: async (e) => {
      e.preventDefault(); change.disabled = true;
      try { await api("/v1/auth/password", { method: "POST", body: JSON.stringify({ current_password: current.value, new_password: next.value }) });
        current.value = ""; next.value = ""; logout("비밀번호를 변경했습니다. 새 비밀번호로 로그인하세요.");
      } catch (err) { current.value = ""; msg.err(errMsg(err)); change.disabled = false; }
    } }, field("현재 비밀번호", current), field("새 비밀번호", next, "12~128자"),
      h("div", { class: "full form-actions" }, change, msg.el));
    return h("div", null, pageHeader("내 계정", null, me.username), h("h2", null, "내 비밀번호 변경"),
      h("p", { class: "hint section-hint" }, "변경하면 이 계정의 기존 로그인과 API 토큰이 해제됩니다."), form);
  }

  async function viewUsers(_, q, alive) {
    if (!isAdmin()) return h("div", null, pageHeader("사용자 관리"), h("div", { class: "panel" }, ADMIN_ONLY));
    let users = await api("/v1/users");
    const notice = feedback(); const body = h("div");
    const search = h("input", { type: "search", "aria-label": "사용자 검색", placeholder: "ID 검색", value: q.get("q") || "" });
    const draw = () => {
      const term = search.value.trim().toLowerCase();
      clear(body).append(table([
        { title: "ID", sort: (u) => u.username, render: (u) => u.username },
        { title: "권한", render: (u) => roleLabel(u.role) },
        { title: "상태", render: (u) => u.active ? badge("활성", "ok") : badge("비활성") },
        { title: "작업", render: (u) => h("span", { class: "row-actions" },
          h("button", { type: "button", onclick: (e) => edit(u, e.currentTarget) }, "권한·계정 변경"),
          u.role === "request" && isAdminSession() ? h("button", { type: "button", onclick: (e) => manageScope(u, e.currentTarget) }, "요청 호스트 범위") : null) },
      ], users.filter((u) => !term || u.username.toLowerCase().includes(term)), "일치하는 사용자가 없습니다."));
    };
    const refresh = async () => { const rows = await api("/v1/users"); if (alive()) { users = rows; draw(); } };
    function edit(user, opener) {
      const key = `user:${user.id}`; const draft = formDrafts.get(key) || { role: user.role, active: user.active };
      const selectedRole = userRoleSelect(draft.role);
      const active = h("input", { type: "checkbox", checked: draft.active });
      const reset = h("input", { type: "password", autocomplete: "new-password", minlength: 12, maxlength: 128 });
      const msg = msgBox(); let dialog;
      const save = h("button", { type: "submit", class: "primary", disabled: true }, "변경 적용");
      const changed = () => {
        formDrafts.set(key, { role: selectedRole.value, active: active.checked });
        save.disabled = selectedRole.value === user.role && active.checked === user.active && !reset.value;
      };
      [selectedRole, active].forEach((el) => el.addEventListener("change", changed)); reset.addEventListener("input", changed);
      const form = h("form", { class: "form", onsubmit: async (e) => {
        e.preventDefault(); if (save.disabled) return; save.disabled = true;
        const patch = {};
        if (selectedRole.value !== user.role) patch.role = selectedRole.value;
        if (active.checked !== user.active) patch.active = active.checked;
        if (reset.value) patch.password = reset.value;
        try {
          await api(`/v1/users/${enc(user.id)}`, { method: "PATCH", body: JSON.stringify(patch) }); reset.value = ""; formDrafts.delete(key);
          await refresh(); if (alive()) { dialog.close("saved"); notice.ok(`${user.username} 계정을 변경했습니다.`); }
        } catch (err) { reset.value = ""; msg.err(errMsg(err)); changed(); }
      } }, field("사용자 권한", selectedRole), field("계정 활성", active), field("비밀번호 초기화", reset, "비워 두면 유지합니다."),
        h("p", { class: "hint full" }, "변경하면 이 사용자의 기존 로그인과 API 토큰이 해제됩니다."),
        h("div", { class: "full" }, msg.el), h("div", { class: "dialog-actions full" }, cancelDialog(() => dialog.close()), save));
      dialog = editorDialog(`${user.username} 계정 변경`, form, opener, () => formDrafts.delete(key)); changed();
    }
    function create(opener) {
      const draft = formDrafts.get("new-user") || { username: "", role: "read" };
      const id = h("input", { type: "text", autocomplete: "off", required: true, minlength: 3, maxlength: 64, value: draft.username });
      const pw = h("input", { type: "password", autocomplete: "new-password", required: true, minlength: 12, maxlength: 128 });
      const selectedRole = userRoleSelect(draft.role); const msg = msgBox(); let dialog;
      const remember = () => formDrafts.set("new-user", { username: id.value, role: selectedRole.value });
      id.addEventListener("input", remember); selectedRole.addEventListener("change", remember);
      const save = h("button", { type: "submit", class: "primary" }, "사용자 생성");
      const form = h("form", { class: "form", onsubmit: async (e) => {
        e.preventDefault(); save.disabled = true;
        try { const u = await api("/v1/users", { method: "POST", body: JSON.stringify({ username: id.value.trim(), password: pw.value, role: selectedRole.value }) });
          pw.value = ""; formDrafts.delete("new-user"); await refresh(); if (alive()) { dialog.close("saved"); notice.ok(`${u.username} 사용자를 생성했습니다.`); }
        } catch (err) { pw.value = ""; msg.err(errMsg(err)); save.disabled = false; }
      } }, field("새 사용자 ID", id, "영문·숫자·점·밑줄·하이픈, 3~64자"), field("초기 비밀번호", pw, "12~128자"), field("초기 권한", selectedRole),
        h("div", { class: "full" }, msg.el), h("div", { class: "dialog-actions full" }, cancelDialog(() => dialog.close()), save));
      dialog = editorDialog("사용자 추가", form, opener, () => formDrafts.delete("new-user"));
    }
    async function manageScope(user, opener) {
      const [hosts, current, history] = await Promise.all([
        api("/v1/hosts"), api(`/v1/software-request-scopes/${enc(user.id)}`),
        api(`/v1/software-request-scopes/${enc(user.id)}/history`),
      ]);
      const selected = new Set(current.host_ids); const searchHost = h("input", { type: "search", "aria-label": "호스트 범위 검색", placeholder: "호스트명·호스트 ID·자산번호·IP 검색" });
      const list = h("div", { class: "scope-list", role: "group", "aria-label": "요청 가능 호스트" });
      const msg = msgBox(); let dialog;
      const drawHosts = () => {
        const term = searchHost.value.trim().toLowerCase();
        clear(list);
        const rows = hosts.filter((host) => !term || [host.hostname, host.host_id, host.asset_no, ...(host.ips || [])].join(" ").toLowerCase().includes(term));
        if (!rows.length) list.append(empty("조건에 맞는 호스트가 없습니다."));
        for (const host of rows) {
          const cb = h("input", { type: "checkbox", checked: selected.has(host.host_id), "aria-label": `${host.hostname} (${host.host_id})`, onchange: (e) => {
            if (e.target.checked) selected.add(host.host_id); else selected.delete(host.host_id);
            count.textContent = `선택 ${selected.size}대`;
          } });
          list.append(h("label", { class: "scope-row" }, cb, h("span", null, h("strong", null, host.hostname),
            h("span", { class: "muted" }, `${host.asset_no ? ` · ${host.asset_no}` : " · 미등록 자산"} · ${host.host_id} · ${(host.ips || []).join(", ")}`))));
        }
      };
      const count = h("p", { class: "hint" }, `선택 ${selected.size}대`);
      const historyNode = h("details", { class: "scope-history" }, h("summary", null, "권한 변경 이력 보기"),
        history.length ? table([
          { title: "시각", sort: (r) => r.occurred_at, render: (r) => timeEl(r.occurred_at) },
          { title: "변경자", render: (r) => r.actor_name },
          { title: "이전 범위", render: (r) => `${r.old_host_ids.length}대` },
          { title: "새 범위", render: (r) => `${r.new_host_ids.length}대` },
        ], history, "범위 변경 이력이 없습니다.") : empty("범위 변경 이력이 없습니다."));
      searchHost.addEventListener("input", drawHosts); drawHosts();
      const save = h("button", { type: "button", class: "primary", onclick: async () => {
        save.disabled = true; msg.clear();
        try {
          await api(`/v1/software-request-scopes/${enc(user.id)}`, { method: "PUT", body: JSON.stringify({ host_ids: [...selected] }) });
          await refresh(); if (alive()) { dialog.close("saved"); notice.ok(`${user.username} 요청 가능 호스트 범위를 저장했습니다.`); }
        } catch (err) { msg.err(errMsg(err)); save.disabled = false; }
      } }, "범위 저장");
      dialog = editorDialog(`${user.username} · 요청 호스트 범위`, h("div", null,
        h("p", { class: "hint" }, "관리자가 명시적으로 지정한 호스트에 한해 업무용 앱 승인을 요청할 수 있습니다. OS 패키지와 개발 의존성은 승인 대상이 아닙니다."),
        searchHost, count, list, historyNode, msg.el, h("div", { class: "dialog-actions" }, cancelDialog(() => dialog.close()), save)), opener);
    }
    search.addEventListener("input", () => { replaceQuery("#/users", { q: search.value.trim() }); draw(); });
    draw();
    return h("div", null, pageHeader("사용자 관리", h("button", { class: "primary", type: "button", onclick: (e) => create(e.currentTarget) }, "사용자 추가")),
      h("div", { class: "toolbar" }, search), body, notice.node);
  }

  async function viewTokens(_, q, alive) {
    if (!isAdmin()) return h("div", null, pageHeader("API 토큰"), h("div", { class: "panel" }, ADMIN_ONLY));
    const users = await api("/v1/users"); let tokens = await api("/v1/tokens");
    const notice = feedback(); const body = h("div");
    const search = h("input", { type: "search", "aria-label": "토큰 검색", placeholder: "이름·사용자 검색", value: q.get("q") || "" });
    const status = h("select", { "aria-label": "토큰 상태" }, ["전체", "유효", "회수됨", "만료", "계정 변경으로 무효"].map((v) => h("option", { value: v, selected: v === (q.get("status") || "전체") }, v)));
    const ownerName = (r) => (users.find((u) => u.id === r.user_id) || {}).username || "수집기";
    const draw = () => {
      const term = search.value.trim().toLowerCase();
      clear(body).append(table([
        { title: "이름", sort: (r) => r.name, render: (r) => r.name }, { title: "사용자", sort: ownerName, render: ownerName },
        { title: "권한", render: (r) => roleLabel(r.role) }, { title: "만료", sort: (r) => r.expires_at, render: (r) => timeEl(new Date(r.expires_at * 1000).toISOString()) },
        { title: "상태", render: (r) => badge(r.status, r.status === "유효" ? "ok" : "") },
        { title: "작업", render: (r) => h("button", { type: "button", disabled: r.status !== "유효", onclick: (e) => revoke(r, e.currentTarget) }, "회수") },
      ], tokens.filter((r) => (status.value === "전체" || r.status === status.value) && (!term || `${r.name} ${ownerName(r)}`.toLowerCase().includes(term))), "조건에 맞는 API 토큰이 없습니다."));
    };
    const refresh = async () => { const rows = await api("/v1/tokens"); if (alive()) { tokens = rows; draw(); } };
    function revoke(token, opener) {
      const msg = msgBox(); let dialog;
      const confirm = h("button", { type: "button", class: "danger", onclick: async () => {
        confirm.disabled = true; msg.clear();
        try { await api(`/v1/tokens/${enc(token.id)}`, { method: "DELETE" }); await refresh(); if (alive()) { dialog.close("saved"); notice.ok(`${token.name} 토큰을 회수했습니다.`); } }
        catch (err) { msg.err(errMsg(err)); confirm.disabled = false; }
      } }, "토큰 회수");
      const cancel = cancelDialog(() => dialog.close()); cancel.autofocus = true;
      dialog = editorDialog("API 토큰 회수", h("div", null, h("p", null, h("strong", null, token.name)),
        h("p", { class: "muted" }, `${ownerName(token)} · ${roleLabel(token.role)}`),
        h("p", null, token.role === "ingest" ? "이 토큰을 사용하는 수집기의 전송이 즉시 중단됩니다. 새 토큰으로 수집기 설정을 변경해야 합니다." : "이 토큰을 사용하는 API 연결이 즉시 차단됩니다. 회수한 토큰은 다시 사용할 수 없습니다."),
        msg.el, h("div", { class: "dialog-actions" }, cancel, confirm)), opener);
    }
    function issue(opener) {
      const key = "new-token"; const draft = formDrafts.get(key) || { name: "", role: "read", owner: "", hours: "24" };
      const name = h("input", { type: "text", required: true, maxlength: 100, value: draft.name });
      const selectedRole = h("select", null, ["read", "ingest", "admin"].map((r) => h("option", { value: r, selected: r === draft.role }, roleLabel(r))));
      const owner = h("select", { required: true }, h("option", { value: "" }, "사용자 선택"), users.filter((u) => u.active).map((u) => h("option", { value: u.id, selected: u.id === draft.owner }, u.username)));
      const hours = h("select", null, [["24", "1일"], ["168", "7일"], ["720", "30일"], ["custom", "직접 입력"]].map(([v, label]) => h("option", { value: v, selected: draft.hours === v }, label)));
      const custom = h("input", { type: "number", "aria-label": "유효 시간(시간)", min: 1, max: 720, value: draft.custom || 24, hidden: draft.hours !== "custom" });
      const explanation = h("p", { class: "hint full" }); const expiry = h("p", { class: "hint full" }); const msg = msgBox(); let dialog;
      const remember = () => {
        const ingest = selectedRole.value === "ingest";
        owner.disabled = ingest; owner.required = !ingest;
        if (ingest) owner.value = "";
        const canAdmin = users.some((u) => u.id === owner.value && u.role === "admin");
        selectedRole.querySelector('option[value="admin"]').disabled = !canAdmin;
        if (selectedRole.value === "admin" && !canAdmin) selectedRole.value = "read";
        custom.hidden = hours.value !== "custom"; custom.required = !custom.hidden;
        explanation.textContent = { read: "서버·소프트웨어·네트워크 정보를 조회합니다.", admin: "사용자·권한·설정 변경과 데이터 삭제를 포함한 관리 작업을 허용합니다.", ingest: "수집 정보 전송만 허용합니다. 사용자 없이 발급합니다." }[selectedRole.value];
        const duration = Number(hours.value === "custom" ? custom.value : hours.value);
        expiry.textContent = duration >= 1 && duration <= 720 ? `만료 예정: ${fmtTime(new Date(Date.now() + duration * 3600000).toISOString())}` : "유효 시간은 1~720시간입니다.";
        formDrafts.set(key, { name: name.value, role: selectedRole.value, owner: owner.value, hours: hours.value, custom: custom.value });
      };
      [selectedRole, owner, hours].forEach((el) => el.addEventListener("change", remember)); [name, custom].forEach((el) => el.addEventListener("input", remember));
      const save = h("button", { type: "submit", class: "primary" }, "JWT 발급");
      const form = h("form", { class: "form", onsubmit: async (e) => {
        e.preventDefault(); save.disabled = true; msg.clear();
        try {
          const result = await api("/v1/tokens", { method: "POST", body: JSON.stringify({ name: name.value.trim(), role: selectedRole.value,
            user_id: selectedRole.value === "ingest" ? null : owner.value, expires_hours: Number(hours.value === "custom" ? custom.value : hours.value) }) });
          formDrafts.delete(key); await refresh(); if (!alive()) return;
          const secret = h("textarea", { readonly: true, "aria-label": "발급된 JWT", rows: 5 }); secret.value = result.access_token;
          const copyMsg = msgBox();
          const copy = h("button", { class: "primary", type: "button", onclick: async () => {
            try { await navigator.clipboard.writeText(secret.value); copyMsg.ok("복사했습니다."); }
            catch (_) { secret.focus(); secret.select(); copyMsg.info("토큰을 선택했습니다. 직접 복사하세요."); }
          } }, "토큰 복사");
          clear(form).append(h("p", { class: "full" }, "발급된 JWT는 이 화면에서만 확인할 수 있습니다. 닫기 전에 복사하세요."), h("div", { class: "full" }, secret),
            h("div", { class: "full" }, copyMsg.el), h("div", { class: "dialog-actions full" }, copy, h("button", { type: "button", onclick: () => dialog.close("saved") }, "닫기")));
          notice.ok(`${name.value.trim()} 토큰을 발급했습니다.`); copy.focus();
        } catch (err) { msg.err(errMsg(err)); save.disabled = false; }
      } }, field("토큰 이름", name), field("토큰 사용자", owner), field("발급 권한", selectedRole), explanation,
        field("만료 기간", hours), h("div", { class: "full" }, custom), expiry, h("div", { class: "full" }, msg.el),
        h("div", { class: "dialog-actions full" }, cancelDialog(() => dialog.close()), save));
      dialog = editorDialog("API 토큰 발급", form, opener, () => formDrafts.delete(key)); remember();
    }
    const filter = () => { replaceQuery("#/tokens", { q: search.value.trim(), status: status.value === "전체" ? "" : status.value }); draw(); };
    search.addEventListener("input", filter); status.addEventListener("change", filter); draw();
    return h("div", null, pageHeader("API 토큰", h("button", { type: "button", class: "primary", onclick: (e) => issue(e.currentTarget) }, "API 토큰 발급")),
      h("div", { class: "toolbar" }, search, status), body, notice.node);
  }

  // ---------- 업무용 앱 분류·사용 승인 ----------
  const PRODUCT_CATEGORIES = {
    business_app: "업무용 앱", os_package: "OS 패키지",
    development_dependency: "개발 라이브러리·의존성", needs_review: "분류 확인 필요",
  };
  const REQUEST_STATUS = {
    submitted: ["접수", "neutral"], reviewing: ["검토 중", "warn"],
    needs_changes: ["보완 요청", "warn"], approved: ["승인", "ok"],
    rejected: ["반려", "err"], withdrawn: ["철회", ""],
  };
  const IMPACT_STATUS = {
    confirmed: ["영향 확인", "err"], needs_review: ["확인 필요", "warn"],
    no_observed_match: ["확정 일치 없음", "neutral"], not_assessed: ["미평가", ""],
    not_affected: ["영향 없음 판정", "ok"],
  };
  const productLabel = (v) => PRODUCT_CATEGORIES[v] || v || "분류 확인 필요";
  const requestBadge = (v) => { const [label, kind] = REQUEST_STATUS[v] || [v, ""]; return badge(label, kind); };
  const impactBadge = (v) => { const [label, kind] = IMPACT_STATUS[v] || [v, ""]; return badge(label, kind); };
  const workflowRequestLabel = (value) => REQUEST_STATUS[value]?.[0] || (value ? String(value) : "요청 없음");
  const workflowImpactLabel = (value) => IMPACT_STATUS[value]?.[0] || (value ? String(value) : "판정 정보 없음");
  const compactKstTime = (iso) => {
    if (!iso) return h("span", { class: "muted" }, "미지정");
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return h("time", { datetime: iso, title: String(iso) }, String(iso));
    const parts = new Map(new Intl.DateTimeFormat("en-CA", {
      timeZone: "Asia/Seoul", year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", hourCycle: "h23",
    }).formatToParts(date).map((part) => [part.type, part.value]));
    const full = `${parts.get("year")}-${parts.get("month")}-${parts.get("day")} ${parts.get("hour")}:${parts.get("minute")} KST`;
    return h("time", { datetime: iso, title: full }, `${parts.get("month")}-${parts.get("day")} ${parts.get("hour")}:${parts.get("minute")}`);
  };
  const workflowModule = window.SwinventoryUI?.createWorkflow({
    h, table, link, compactTime: compactKstTime,
    requestLabel: workflowRequestLabel, impactLabel: workflowImpactLabel,
  });
  if (!workflowModule) throw new Error("업무 흐름 표 모듈을 불러오지 못했습니다.");
  const pageControls = (base, query, page, pageSize, total, keepEmpty = []) => h("div", { class: "pagination", role: "group", "aria-label": "페이지 이동" },
    h("span", { class: "muted", role: "status" }, `전체 ${total}건 · ${Math.min(total, (page - 1) * pageSize + 1)}–${Math.min(total, page * pageSize)}건 · ${page}페이지`),
    h("button", { type: "button", disabled: page <= 1, onclick: () => {
      const retained = keepEmpty.filter((key) => Object.prototype.hasOwnProperty.call(query, key) && query[key] === "");
      location.hash = hashOfExact(base, { ...query, page: page - 1 }, retained);
    } }, "이전"),
    h("button", { type: "button", disabled: page * pageSize >= total, onclick: () => {
      const retained = keepEmpty.filter((key) => Object.prototype.hasOwnProperty.call(query, key) && query[key] === "");
      location.hash = hashOfExact(base, { ...query, page: page + 1 }, retained);
    } }, "다음"));
  const categorySelect = (value, onChange) => h("select", { "aria-label": "업무용 앱 분류", value, onchange: (e) => onChange(e.target.value) },
    [["", "모든 분류"], ...Object.entries(PRODUCT_CATEGORIES)].map(([v, t]) => h("option", { value: v, selected: v === value }, t)));

  async function viewBusinessSoftware(_, q, alive) {
    const st = { q: q.get("q") || "", category: q.get("category") || "", page: Math.max(1, Number(q.get("page") || 1)) };
    const base = "#/business-apps"; const body = h("div");
    const search = h("input", { type: "search", "aria-label": "업무용 앱 검색", placeholder: "패키지 이름 검색", value: st.q, size: 30 });
    const category = categorySelect(st.category, (value) => setQuery(base, { ...st, category: value, page: 1 }));
    let products = [], total = 0, seq = 0;
    const refresh = async () => {
      const run = ++seq; const params = new URLSearchParams({ page: String(st.page), page_size: "50" });
      if (st.q.trim()) params.set("q", st.q.trim()); if (st.category) params.set("category", st.category);
      clear(body).append(h("p", { class: "muted", role: "status" }, "제품 분류를 불러오는 중…"));
      try {
        const result = await api(`/v1/software-products?${params}`);
        if (!alive() || run !== seq) return;
        products = result.items; total = result.total;
        clear(body).append(table([
          { title: "제품", sort: (p) => p.product_name || p.name, render: (p) => h("span", null,
            link(p.product_name || p.name, `#/software/${enc(p.name)}`), h("span", { class: "muted" }, ` · ${p.name}`)) },
          { title: "출처 / 아키텍처", render: (p) => `${p.source} · ${p.arch || "-"}` },
          { title: "분류", render: (p) => badge(productLabel(p.category), p.category === "business_app" ? "ok" : p.category === "needs_review" ? "warn" : "neutral") },
          { title: "설치 / 호스트 / 버전", sort: (p) => p.install_count, render: (p) => `${p.install_count}설치 · ${p.host_count}대 · ${p.version_count}개 버전` },
          { title: "게시자 / 근거", render: (p) => h("span", { title: p.classification_evidence || "분류 이력이 없습니다." },
            [p.publisher || "게시자 미기록", p.classification_evidence || "분류 근거 없음"].join(" · ")) },
          { title: "작업", render: (p) => h("span", { class: "row-actions" },
            isAdminSession() ? h("button", { type: "button", onclick: (e) => editClassification(p, e.currentTarget) }, "분류 편집") : null,
            isAdminSession() ? h("button", { type: "button", onclick: (e) => classificationHistory(p, e.currentTarget) }, "분류 이력") : null,
            role === "request" && authKind === "session" && p.category === "business_app" ? h("button", { type: "button", class: "primary", onclick: (e) => requestProduct(p, e.currentTarget) }, "사용 승인 요청") : null,
            p.category !== "business_app" ? h("span", { class: "muted" }, "승인 요청 대상 아님") : null) },
        ], products, "검색 결과가 없습니다."), pageControls(base, st, st.page, 50, total));
      } catch (err) { if (alive() && run === seq) clear(body).append(h("div", { class: "error", role: "alert" }, err.message)); }
    };
    const applySearch = () => { st.q = search.value; st.page = 1; replaceQuery(base, { ...st, q: st.q.trim() }); refresh(); };
    let timer; search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(applySearch, 250); });
    async function editClassification(product, opener) {
      const current = await api(`/v1/software-classification-history?source=${enc(product.source)}&name=${enc(product.name)}&arch=${enc(product.arch)}`);
      const categoryInput = h("select", null, Object.entries(PRODUCT_CATEGORIES).map(([v, t]) => h("option", { value: v, selected: product.category === v }, t)));
      const productName = h("input", { type: "text", maxlength: 512, value: product.product_name || product.name });
      const publisher = h("input", { type: "text", maxlength: 255, value: product.publisher || "" });
      const evidence = h("textarea", { required: true, maxlength: 1000, rows: 4, placeholder: "패키지 메타데이터·게시자·업무 소유자 확인 등 분류 근거" }, product.classification_evidence || "");
      const msg = msgBox(); let dialog;
      const save = h("button", { type: "submit", class: "primary" }, "분류 저장");
      const form = h("form", { class: "form", onsubmit: async (e) => {
        e.preventDefault(); if (evidence.value.trim().length < 1) { evidence.focus(); return; }
        save.disabled = true; msg.clear();
        try {
          await api("/v1/software-products/classification", { method: "PUT", body: JSON.stringify({
            source: product.source, name: product.name, arch: product.arch, category: categoryInput.value,
            product_name: productName.value.trim(), publisher: publisher.value.trim(), evidence: evidence.value.trim(),
            expected_revision: product.revision ?? null,
          }) });
          await refresh(); if (alive()) { dialog.close("saved"); notice.ok(`${product.name} 분류를 저장했습니다.`); }
        } catch (err) { msg.err(errMsg(err)); save.disabled = false; }
      } }, field("분류", categoryInput), field("제품 표시명", productName), field("게시자", publisher),
        field("관리자 분류 근거", evidence, "소스 이름만으로 분류하지 않습니다. 분류 확인 필요로 두면 요청 대상이 되지 않습니다."),
        current.length ? h("p", { class: "hint full" }, `최근 변경 ${current[0].changed_by_name} · ${fmtTime(current[0].changed_at)}`) : null,
        h("div", { class: "full" }, msg.el), h("div", { class: "dialog-actions full" }, cancelDialog(() => dialog.close()), save));
      dialog = editorDialog(`${product.product_name || product.name} 분류`, form, opener);
    }
    async function classificationHistory(product, opener) {
      const history = await api(`/v1/software-classification-history?source=${enc(product.source)}&name=${enc(product.name)}&arch=${enc(product.arch)}`);
      const rows = table([
        { title: "시각", sort: (r) => r.changed_at, render: (r) => timeEl(r.changed_at) },
        { title: "변경자", render: (r) => r.changed_by_name },
        { title: "이전 분류", render: (r) => productLabel(r.old_category || "미분류") },
        { title: "새 분류", render: (r) => productLabel(r.new_category) },
        { title: "근거", render: (r) => r.evidence },
      ], history, "분류 변경 이력이 없습니다.");
      let dialog; dialog = editorDialog(`${product.name} 분류 이력`, h("div", null, rows,
        h("div", { class: "dialog-actions" }, h("button", { type: "button", onclick: () => dialog.close() }, "닫기"))), opener);
    }
    async function requestProduct(product, opener) {
      const [detail, hostRows, scope] = await Promise.all([
        api(`/v1/software/${enc(product.name)}`), api("/v1/hosts"), api("/v1/software-request-scopes/me"),
      ]);
      const scoped = new Set(scope.host_ids);
      const installs = detail.hosts.filter((i) => i.source === product.source && i.arch === product.arch && scoped.has(i.host_id));
      const versions = [...new Set(installs.map((i) => i.version).filter(Boolean))].sort((a, b) => collator.compare(b, a));
      if (!installs.length || !versions.length) { alert("관리자가 요청할 호스트 범위를 지정하지 않았거나, 해당 범위에 설치된 버전이 없습니다."); return; }
      const version = h("select", { "aria-label": "설치 버전", required: true }, versions.map((v) => h("option", { value: v }, v)));
      const hostChoices = h("div", { class: "scope-list", role: "group", "aria-label": "승인 요청 대상 호스트" });
      const purpose = h("textarea", { required: true, minlength: 5, maxlength: 2000, rows: 4, placeholder: "업무에서 이 제품이 필요한 이유" });
      const license = h("textarea", { required: true, minlength: 3, maxlength: 2000, rows: 3, placeholder: "사용권·계약·오픈소스 라이선스 확인 근거" });
      const msg = msgBox(); let dialog;
      const drawHosts = () => {
        const allowed = new Set(installs.filter((i) => i.version === version.value).map((i) => i.host_id));
        clear(hostChoices);
        const rows = hostRows.filter((host) => allowed.has(host.host_id));
        rows.forEach((host) => hostChoices.append(h("label", { class: "scope-row" },
          h("input", { type: "checkbox", value: host.host_id, "aria-label": `${host.hostname} (${host.host_id})` }),
          h("span", null, h("strong", null, host.hostname), h("span", { class: "muted" }, ` · ${host.asset_no || "자산 미등록"} · ${host.host_id}`)))));
      };
      version.addEventListener("change", drawHosts); drawHosts();
      const save = h("button", { type: "submit", class: "primary" }, "승인 요청 제출");
      const form = h("form", { class: "form", onsubmit: async (e) => {
        e.preventDefault();
        const host_ids = [...hostChoices.querySelectorAll('input[type="checkbox"]:checked')].map((el) => el.value);
        if (!host_ids.length) { msg.err("대상 호스트를 한 대 이상 선택하세요."); return; }
        save.disabled = true; msg.clear();
        try {
          const result = await api("/v1/software-requests", { method: "POST", body: JSON.stringify({
            source: product.source, name: product.name, arch: product.arch, version: version.value,
            purpose: purpose.value.trim(), license_evidence: license.value.trim(), host_ids,
          }) });
          dialog.close("saved"); location.hash = `#/sw-requests/${result.id}?return=${enc(currentReturn())}`;
        } catch (err) { msg.err(err.status === 409 && err.message.includes("duplicate_request")
          ? "같은 제품·버전·대상 호스트의 진행 요청이 이미 있습니다. 기존 요청을 열어 확인하세요."
          : err.status === 409 ? `${err.message} 이미 유효한 승인 범위를 확인하세요.` : errMsg(err)); save.disabled = false; }
      } }, field("제품", h("p", { class: "read-value" }, `${product.product_name || product.name} · ${product.source} · ${product.arch}`)),
        field("설치 버전", version), field("대상 호스트", hostChoices, "선택한 버전이 설치된 허용 범위의 호스트만 표시합니다. 최대 100대."),
        field("업무 목적", purpose), field("사용권 근거", license),
        h("p", { class: "hint full" }, "업무용 앱의 조직 내 사용 승인 요청입니다. 설치 실행 승인·신규 목록 등록 요청이 아니며 OS 패키지와 개발 의존성은 대상에서 제외됩니다."),
        h("div", { class: "full" }, msg.el), h("div", { class: "dialog-actions full" }, cancelDialog(() => dialog.close()), save));
      dialog = editorDialog("업무용 앱 사용 승인 요청", form, opener);
    }
    const notice = feedback();
    await refresh();
    return h("div", null, pageHeader("업무용 앱", isAdmin() ? h("span", { class: "muted" }, "관리자 분류 근거와 변경 이력을 관리합니다.") : null,
      "설치 인벤토리의 전체 소프트웨어를 분류합니다. OS 패키지와 개발 의존성은 계속 조회·CVE 분석에 포함하며 승인 요청 대상에서만 제외합니다."),
      h("div", { class: "toolbar" }, search, category), body, notice.node);
  }

  async function viewSoftwareRequests(rest, q, alive) {
    if (role !== "admin" && role !== "request") return h("div", null, pageHeader("SW 사용 승인"), h("div", { class: "panel" }, "조회 전용 계정에는 승인 요청 권한이 없습니다."));
    if (role === "request" && authKind !== "session") return h("div", null, pageHeader("SW 사용 승인"), h("div", { class: "panel" }, "요청자는 개인 세션으로 로그인해야 요청·상세·상태 변경을 할 수 있습니다."));
    if (rest[0]) return softwareRequestDetail(Number(rest[0]), q, alive);
    const defaultScope = role === "admin" ? (q.get("overdue") === "true" ? "overdue" : q.has("mine") ? "all" : "pending") : "mine";
    const st = {
      q: q.get("q") || "", status: q.get("status") || "", security: q.get("security") || "", scope: q.get("scope") || defaultScope,
      mine: q.get("mine") === "true", unassigned: q.get("unassigned") === "true",
      sort: q.get("sort") || "", direction: q.get("direction") || "asc", page: Math.max(1, Number(q.get("page") || 1)),
    };
    if (st.scope === "pending" && st.status) st.scope = "all";
    if (st.scope === "assigned" && (st.mine || st.unassigned)) { st.mine = false; st.unassigned = false; }
    const base = "#/sw-requests"; let result = { items: [], total: 0 }; let seq = 0; const body = h("div");
    const search = h("input", { type: "search", "aria-label": "승인 요청 검색", placeholder: "요청 번호·제품·요청자", value: st.q });
    const statusOptions = [["", "모든 상태"], ...Object.entries(REQUEST_STATUS).map(([value, [label]]) => [value, label])];
    const status = h("select", { "aria-label": "요청 상태 필터" }, statusOptions.map(([v, label]) => h("option", { value: v, selected: v === st.status }, label)));
    const securityOptions = [["", "모든 보안 판정"], ...Object.entries(IMPACT_STATUS).map(([value, [label]]) => [value, label])];
    const security = h("select", { "aria-label": "보안 영향 판정 필터" }, securityOptions.map(([v, label]) => h("option", { value: v, selected: v === st.security }, label)));
    const mine = h("input", { type: "checkbox", checked: st.mine, "aria-label": "내가 제출한 요청만" });
    const unassigned = h("input", { type: "checkbox", checked: st.unassigned, "aria-label": "미배정" });
    const queryState = () => ({
      q: st.q.trim(), status: st.status, security: st.security, scope: st.scope,
      mine: st.mine ? "true" : "", unassigned: st.unassigned ? "true" : "",
      sort: st.sort, direction: st.direction, page: st.page === 1 ? "" : st.page,
    });
    let scopes = null;
    const syncScopeNav = () => {
      if (!scopes) return;
      for (const anchor of scopes.querySelectorAll("a")) {
        const scope = anchor.dataset.scope;
        const active = scope === st.scope;
        anchor.classList.toggle("active", active);
        if (active) anchor.setAttribute("aria-current", "page"); else anchor.removeAttribute("aria-current");
        anchor.href = hashOf(base, { ...queryState(), scope, status: "",
          mine: scope === "assigned" ? "" : queryState().mine,
          unassigned: scope === "assigned" ? "" : queryState().unassigned, page: "" });
      }
    };
    const sortState = () => ({ key: st.sort || "due", direction: st.sort ? st.direction : "asc" });
    const resultCount = h("span", { class: "table-toolbar-result", role: "status", "aria-live": "polite" }, `전체 ${result.total}건`);
    const refresh = async () => {
      const run = ++seq;
      const params = new URLSearchParams({ page: String(st.page), page_size: "50" });
      if (st.q.trim()) params.set("q", st.q.trim()); if (st.status) params.set("status", st.status);
      if (st.security) params.set("security_impact", st.security);
      if (st.mine && role === "admin" && st.scope !== "assigned") params.set("mine", "true");
      if (st.unassigned && role === "admin" && st.scope !== "assigned") params.set("unassigned", "true");
      if (st.scope === "pending" && role === "admin") params.set("pending", "true");
      if (st.scope === "assigned" && isAdminSession()) params.set("assigned_to_me", "true");
      if (st.scope === "overdue" && role === "admin") params.set("overdue", "true");
      if (st.sort) { params.set("sort", st.sort); params.set("direction", st.direction); }
      clear(body).append(h("p", { class: "muted", role: "status" }, "요청을 불러오는 중…"));
      try {
        result = await api(`/v1/software-requests?${params}`); if (!alive() || run !== seq) return;
        resultCount.textContent = `전체 ${result.total}건`;
        const requestUrl = (row) => withReturn(`#/sw-requests/${row.id}`);
        clear(body).append(workflowModule.approvalTable(result.items, {
          openRequest: requestUrl, serverSort: sortState(),
          onServerSort: (key, direction) => {
            st.sort = key; st.direction = direction; st.page = 1;
            replaceQuery(base, queryState()); refresh();
          },
        }), pageControls(base, st, st.page, 50, result.total));
      } catch (err) { if (alive() && run === seq) clear(body).append(h("div", { class: "error", role: "alert" }, errMsg(err))); }
    };
    const apply = () => {
      st.q = search.value; st.status = status.value; st.security = security.value;
      if (st.scope === "pending" && st.status) st.scope = "all";
      st.mine = isAdminSession() && st.scope !== "assigned" && mine.checked;
      st.unassigned = role === "admin" && st.scope !== "assigned" && unassigned.checked; st.page = 1;
      mine.checked = st.mine; unassigned.checked = st.unassigned;
      syncScopeNav();
      replaceQuery(base, queryState()); refresh();
    };
    let timer; search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(apply, 250); });
    [status, security, mine, unassigned].forEach((el) => el.addEventListener("change", apply));
    await refresh();
    const scopeItems = role === "admin" ? [
      { key: "pending", label: "검토 대기" }, { key: "all", label: "전체" },
      ...(isAdminSession() ? [{ key: "assigned", label: "내 검토" }] : []), { key: "overdue", label: "기한 초과" },
    ] : [];
    if (scopeItems.length) {
      scopes = workflowModule.tabs(scopeItems.map((item) => ({
        label: item.label, active: item.key === st.scope,
        href: hashOf(base, { ...queryState(), scope: item.key, status: "", mine: "", unassigned: "", page: "" }),
      })), "승인 요청 범위");
      scopes.querySelectorAll("a").forEach((anchor, index) => { anchor.dataset.scope = scopeItems[index].key; });
    }
    const filters = workflowModule.toolbar(search, status, security,
      isAdminSession() && st.scope !== "assigned" ? h("label", { class: "table-toolbar-check" }, mine, "내가 제출한 요청") : null,
      role === "admin" && st.scope !== "assigned" ? h("label", { class: "table-toolbar-check" }, unassigned, "미배정") : null,
      resultCount,
      h("button", { type: "button", class: "link table-filter-reset", onclick: () => {
        st.q = ""; st.status = ""; st.security = ""; st.mine = false; st.unassigned = false; st.page = 1;
        search.value = ""; status.value = ""; security.value = ""; mine.checked = false; unassigned.checked = false;
        syncScopeNav();
        replaceQuery(base, queryState()); refresh(); search.focus();
      } }, "초기화"));
    return h("div", { class: "workflow-page" },
      pageHeader("SW 사용 승인 요청", h("a", { href: "#/business-apps", class: "button-link" }, "업무용 앱 찾기")),
      scopes, filters, body);
  }

  async function softwareRequestDetail(requestId, q, alive) {
    if (!Number.isSafeInteger(requestId) || requestId < 1) throw new ApiError(404, "요청을 찾을 수 없습니다.");
    const item = await api(`/v1/software-requests/${requestId}`);
    const base = returnHash(q) || "#/sw-requests"; const root = h("div");
    const admins = isAdminSession() ? (await api("/v1/users")).filter((u) => u.active && u.role === "admin") : [];
    const dateLocal = (iso) => {
      if (!iso) return ""; const d = new Date(iso); const local = new Date(d.getTime() - d.getTimezoneOffset() * 60000); return local.toISOString().slice(0, 16);
    };
    const localIso = (value) => {
      const d = new Date(value); return Number.isNaN(d.getTime()) ? "" : d.toISOString().replace(/\.\d{3}Z$/, "Z");
    };
    const runAction = async (action, payload, dialog, save, msg) => {
      save.disabled = true; msg.clear();
      try {
        const updated = await api(`/v1/software-requests/${requestId}/actions`, { method: "POST", body: JSON.stringify({ action, expected_revision: item.revision, ...payload }) });
        Object.assign(item, updated); dialog.close("saved"); if (alive()) clear(root).append(draw());
      } catch (err) { msg.err(err.status === 409 ? `${err.message} 최신 요청을 다시 불러와 확인하세요.` : errMsg(err)); save.disabled = false; }
    };
    function actionForm(title, action, fields, payload, opener) {
      const msg = msgBox(); let dialog;
      const save = h("button", { type: "submit", class: action === "reject" || action === "revoke_approval" ? "danger" : "primary" }, title);
      const form = h("form", { class: "form", onsubmit: (e) => { e.preventDefault(); runAction(action, payload(), dialog, save, msg); } },
        ...fields, h("div", { class: "full" }, msg.el), h("div", { class: "dialog-actions full" }, cancelDialog(() => dialog.close()), save));
      dialog = editorDialog(title, form, opener); return dialog;
    }
    const reasonField = (label = "사유") => h("textarea", { required: true, maxlength: 2000, rows: 3, placeholder: `${label}를 구체적으로 입력하세요.` });
    const datetimeField = (label, value) => h("input", { type: "datetime-local", required: true, value: dateLocal(value) });
    function draw() {
      const status = item.status; const canDecide = isAdminSession();
      const actions = [];
      if (canDecide && ["submitted", "reviewing", "needs_changes"].includes(status)) actions.push(h("button", { type: "button", class: "primary", onclick: (e) => {
        const assignee = h("select", { required: true }, h("option", { value: "" }, "담당 관리자 선택"), admins.map((u) => h("option", { value: u.id, selected: u.id === item.assignee_id }, u.username)));
        const due = datetimeField("처리 기한", item.due_at);
        actionForm(item.assignee_id ? "담당 재배정" : "담당 배정", "assign", [field("담당자", assignee), field("처리 기한", due, "브라우저 지역 시각을 UTC 시각으로 변환해 저장합니다.")], () => ({ assignee_id: assignee.value, due_at: localIso(due.value) }), e.currentTarget);
      } }, item.assignee_id ? "담당 재배정" : "담당 배정"));
      if (canDecide && ["submitted", "reviewing"].includes(status)) actions.push(h("button", { type: "button", onclick: (e) => {
        const reason = reasonField("보완 사유"); actionForm("보완 요청", "request_changes", [field("보완 사유", reason)], () => ({ reason: reason.value.trim() }), e.currentTarget);
      } }, "보완 요청"));
      if (canDecide && status === "reviewing") actions.push(h("button", { type: "button", class: "primary", onclick: (e) => {
        const reason = reasonField("승인 사유"), until = datetimeField("승인 유효 기한", item.approval_until);
        actionForm("승인", "approve", [field("승인 사유", reason), field("승인 유효 기한", until, "이 기한은 내부 승인 효력 기한입니다. 시간대는 UTC로 정규화합니다.")],
          () => ({ reason: reason.value.trim(), approval_until: localIso(until.value) }), e.currentTarget);
      } }, "승인"));
      if (canDecide && ["submitted", "reviewing", "needs_changes"].includes(status)) actions.push(h("button", { type: "button", class: "danger", onclick: (e) => {
        const reason = reasonField("반려 사유"); actionForm("반려", "reject", [field("반려 사유", reason)], () => ({ reason: reason.value.trim() }), e.currentTarget);
      } }, "반려"));
      if (role === "request" && status === "needs_changes") actions.push(h("button", { type: "button", class: "primary", onclick: (e) => {
        const purpose = h("textarea", { required: true, minlength: 5, maxlength: 2000, rows: 3, value: item.purpose });
        const license = h("textarea", { required: true, minlength: 3, maxlength: 2000, rows: 3, value: item.license_evidence });
        actionForm("보완 후 재제출", "resubmit", [field("업무 목적", purpose), field("사용권 근거", license)],
          () => ({ purpose: purpose.value.trim(), license_evidence: license.value.trim() }), e.currentTarget);
      } }, "같은 요청 번호로 재제출"));
      if (role === "request" && ["submitted", "reviewing", "needs_changes"].includes(status)) actions.push(h("button", { type: "button", onclick: (e) => {
        const reason = h("textarea", { maxlength: 2000, rows: 3, placeholder: "철회 사유(선택)" });
        actionForm("요청 철회", "withdraw", [field("철회 사유", reason)], () => ({ reason: reason.value.trim() }), e.currentTarget);
      } }, "요청 철회"));
      if (canDecide && status === "approved" && item.approvals.some((a) => a.effective_state === "active")) actions.push(h("button", { type: "button", class: "danger", onclick: (e) => {
        const reason = reasonField("승인 취소 사유"); actionForm("승인 범위 취소", "revoke_approval", [field("취소 사유", reason)], () => ({ reason: reason.value.trim() }), e.currentTarget);
      } }, "현재 승인 취소"));
      return h("div", null,
        pageHeader(item.request_no, h("a", { href: base, class: "button-link" }, "← 요청함"), `${productLabel("business_app")} · revision ${item.revision}`),
        h("div", { class: "action-bar" }, requestBadge(status), ...actions),
        h("div", { class: "request-grid" },
          h("section", { class: "panel" }, h("h2", null, "요청 내용"),
            h("dl", { class: "detail-list" }, h("dt", null, "제품"), h("dd", null, link(item.product_name, `#/software/${enc(item.name)}`), ` · ${item.source} · ${item.arch}`),
              h("dt", null, "버전"), h("dd", null, item.version), h("dt", null, "요청자"), h("dd", null, item.requester_name),
              h("dt", null, "대상 호스트"), h("dd", null, item.hosts.map((host) => link(host.hostname, `#/hosts/${enc(host.host_id)}`))),
              h("dt", null, "업무 목적"), h("dd", null, item.purpose), h("dt", null, "사용권 근거"), h("dd", null, item.license_evidence),
              h("dt", null, "담당 / 처리 기한"), h("dd", null, `${item.assignee_name || "미배정"} · `, timeEl(item.due_at)),
              h("dt", null, "승인 유효 기한"), h("dd", null, timeEl(item.approval_until)),
              h("dt", null, "최근 판정 사유"), h("dd", null, item.decision_reason || "-"),
              h("dt", null, "생성 / 갱신"), h("dd", null, timeEl(item.created_at), " · ", timeEl(item.updated_at)))),
          h("section", { class: "panel" }, h("h2", null, "유효 승인 범위"),
            item.approvals.length ? table([
              { title: "호스트", render: (a) => link(a.host_id, `#/hosts/${enc(a.host_id)}`) },
              { title: "승인 버전", render: (a) => a.version },
              { title: "유효 기간", render: (a) => h("span", null, timeEl(a.valid_from), " – ", timeEl(a.valid_until)) },
              { title: "상태", render: (a) => badge(a.effective_state, a.effective_state === "active" ? "ok" : "neutral") },
              { title: "결정자 / 사유", render: (a) => `${a.decided_by_name} · ${a.reason}` },
            ], item.approvals, "승인 기록이 없습니다.") : empty("승인 기록이 없습니다."))),
        h("section", { class: "panel" }, h("h2", null, "변경 이력"), table([
          { title: "시각", sort: (e) => e.occurred_at, render: (e) => timeEl(e.occurred_at) },
          { title: "변경자", render: (e) => e.actor_name },
          { title: "작업", render: (e) => e.action },
          { title: "상태", render: (e) => `${e.from_status || "-"} → ${e.to_status}` },
          { title: "사유 / 세부 내용", render: (e) => h("span", null, e.reason || "-", h("details", null, h("summary", null, "세부 내용"), h("pre", { class: "json" }, JSON.stringify(e.detail, null, 2)))) },
          { title: "revision", render: (e) => e.revision },
        ], item.history, "요청 이력이 없습니다.")));
    }
    clear(root).append(draw()); return root;
  }

  // ---------- CVE / KEV ----------
  async function viewVulnerabilities(rest, q, alive) {
    if (rest[0]) return vulnerabilityDetail(rest[0], q, alive);
    const exactProductKeys = ["product_source", "product_name", "product_arch", "product_version"];
    const st = {
      q: q.get("q") || "", kev: q.get("kev") === "true", impact: q.get("impact") || "", host: q.get("host") || "",
      product_source: q.has("product_source") ? q.get("product_source") : null,
      product_name: q.has("product_name") ? q.get("product_name") : null,
      product_arch: q.has("product_arch") ? q.get("product_arch") : null,
      product_version: q.has("product_version") ? q.get("product_version") : null,
      page: Math.max(1, Number(q.get("page") || 1)),
    };
    const base = "#/cves", body = h("div"), feedBox = h("div"), msg = feedback(); let seq = 0;
    const search = h("input", { type: "search", "aria-label": "CVE 검색", placeholder: "CVE ID·설명·KEV 제품", value: st.q });
    const kev = h("input", { type: "checkbox", checked: st.kev, "aria-label": "CISA KEV만 보기" });
    const impactOptions = [["", "모든 영향 상태"], ...Object.entries(IMPACT_STATUS).map(([value, [label]]) => [value, label])];
    const impact = h("select", { "aria-label": "CVE 영향 판정" }, impactOptions.map(([v, label]) => h("option", { value: v, selected: v === st.impact }, label)));
    const productScope = h("div"); const hostScope = h("div");
    let hostScopeLabel = st.host;
    const resultCount = h("span", { class: "table-toolbar-result", role: "status" }, "CVE 목록");
    const drawScopes = () => {
      clear(productScope); clear(hostScope);
      if (st.product_name !== null) productScope.append(h("span", { class: "table-filter-context" },
        `제품: ${st.product_name} ${st.product_version || ""} · ${st.product_source || ""} · ${st.product_arch || ""}`,
        h("button", { type: "button", class: "link", onclick: () => {
          st.product_source = null; st.product_name = null; st.product_arch = null; st.product_version = null; st.page = 1;
          replaceQueryExact(base, queryState(), exactProductKeys); drawScopes(); refresh();
        }, "aria-label": "제품 영향 범위 해제" }, "해제")));
      if (st.host) hostScope.append(h("span", { class: "table-filter-context", title: `호스트 ID: ${st.host}` }, `호스트: ${hostScopeLabel}`,
        h("button", { type: "button", class: "link", onclick: () => {
          st.host = ""; st.page = 1; replaceQueryExact(base, queryState(), exactProductKeys); drawScopes(); refresh();
        }, "aria-label": "호스트 필터 해제" }, "해제")));
    };
    const loadHostScope = async () => {
      if (!st.host) return;
      const selectedHost = st.host;
      try {
        const detail = await api(`/v1/hosts/${enc(selectedHost)}`);
        if (!alive() || st.host !== selectedHost) return;
        const hostname = detail.host?.hostname;
        const assetNo = detail.asset?.asset_no;
        hostScopeLabel = [hostname || selectedHost, assetNo ? `자산 ${assetNo}` : ""].filter(Boolean).join(" · ");
      } catch (_) { /* 읽기 메타데이터가 없으면 호스트 ID를 그대로 보여 준다 */ }
    };
    const queryState = () => ({
      q: st.q.trim(), kev: st.kev ? "true" : "", impact: st.impact, host: st.host,
      product_source: st.product_source, product_name: st.product_name, product_arch: st.product_arch, product_version: st.product_version,
      page: st.page === 1 ? "" : st.page,
    });
    const refresh = async () => {
      const run = ++seq; const params = new URLSearchParams({ page: String(st.page), page_size: "50" });
      if (st.q.trim()) params.set("q", st.q.trim()); if (st.kev) params.set("kev", "true"); if (st.impact) params.set("impact", st.impact); if (st.host) params.set("host", st.host);
      for (const key of exactProductKeys) if (st[key] !== null) params.set(key, st[key]);
      clear(body).append(h("p", { class: "muted", role: "status" }, "CVE 자료를 불러오는 중…"));
      try {
        const result = await api(`/v1/vulnerabilities?${params}`);
        if (!alive() || run !== seq) return;
        resultCount.textContent = `전체 ${result.total}건`;
        const items = result.items; const feeds = result.feeds || []; clear(feedBox).append(h("details", { class: "feed-details" }, h("summary", null, "KEV·NVD 피드 상태"),
          h("div", { class: "feed-grid" }, feeds.length ? feeds.map((f) => h("div", { class: "feed-status" },
          h("strong", null, f.source === "cisa_kev" ? "CISA KEV" : "NVD"), badge(f.state, f.state === "ok" ? "ok" : f.state === "failed" ? "err" : "warn"),
          h("span", null, `항목 ${f.records} · 데이터 버전 ${f.data_version || "-"}`),
          h("span", null, "마지막 성공 ", timeEl(f.last_success_at), " · 시도 ", timeEl(f.last_attempt_at)),
          f.last_error ? h("span", { class: "error-text" }, f.last_error) : null)) : empty("피드 동기화를 실행하지 않았습니다."))));
        const detailHref = (row, impactStatus) => hashOfExact(`#/cves/${enc(row.cve_id)}`, {
          return: location.hash, impact: impactStatus || "", host: st.host,
          product_source: st.product_source, product_name: st.product_name,
          product_arch: st.product_arch, product_version: st.product_version,
        }, exactProductKeys);
        clear(body).append(workflowModule.vulnerabilityTable(items, { detailHref, serverPage: true }),
          pageControls(base, st, st.page, 50, result.total, exactProductKeys),
          h("p", { class: "table-note" }, "판정별 수는 설치 제품 매핑 기준입니다. 여러 제품이 설치된 호스트는 서로 다른 상태에 중복 집계될 수 있습니다. 확인 필요·확정 일치 없음은 영향 없음 판정이 아닙니다."));
      } catch (err) { if (alive() && run === seq) clear(body).append(h("div", { class: "error", role: "alert" }, err.message)); }
    };
    const apply = () => { st.q = search.value; st.kev = kev.checked; st.impact = impact.value; st.page = 1; replaceQueryExact(base, queryState(), exactProductKeys); refresh(); };
    let timer; search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(apply, 250); }); [kev, impact].forEach((el) => el.addEventListener("change", apply));
    const syncButton = isAdminSession() ? h("button", { type: "button", class: "primary", onclick: async (e) => {
      const button = e.currentTarget; button.disabled = true; button.textContent = "피드 갱신 중…";
      try { const r = await api("/v1/vulnerabilities/sync", { method: "POST" });
        const failed = r.feeds.filter((f) => f.state === "failed").length;
        msg.ok(failed ? "일부 피드 갱신이 실패했습니다. 마지막 성공 자료는 유지했습니다." : "CISA KEV 및 NVD 피드 갱신을 처리했습니다."); await refresh();
      } catch (err) { msg.ok(errMsg(err)); } finally { button.disabled = false; button.textContent = "KEV·NVD 갱신"; }
    } }, "KEV·NVD 갱신") : null;
    const hostScopeTask = loadHostScope();
    await refresh();
    await hostScopeTask;
    drawScopes();
    const toolbar = workflowModule.toolbar(search, impact, h("label", { class: "table-toolbar-check" }, kev, "CISA KEV만"), resultCount);
    return h("div", { class: "workflow-page" }, pageHeader("취약점 영향 조회", syncButton),
      hostScope, productScope, toolbar, body, feedBox, msg.node);
  }

  async function vulnerabilityDetail(cveId, q, alive) {
    const item = await api(`/v1/vulnerabilities/${enc(cveId)}`); const root = h("div");
    const kev = item.kev;
    const matches = item.matches || [];
    const selectedImpact = q.get("impact") || "";
    const observedInstallations = matches.flatMap((match) => {
      const statusFallback = ({ affected_confirmed: "confirmed", needs_review: "needs_review", not_affected: "not_affected" })[match.status];
      const sourceRows = Array.isArray(match.observed_installations) ? match.observed_installations : (match.installations || []);
      return sourceRows.map((row) => ({
        ...row, name: row.name || match.name, source: row.source || match.source, arch: row.arch || match.arch,
        evidence: row.evidence || match.evidence || "", impact_status: row.impact_status || statusFallback || "needs_review",
      }));
    });
    const installationScope = (row) => {
      if (selectedImpact && row.impact_status !== selectedImpact) return false;
      if (q.has("host") && row.host_id !== q.get("host")) return false;
      const productFields = { product_source: "source", product_name: "name", product_arch: "arch", product_version: "version" };
      for (const [queryKey, rowKey] of Object.entries(productFields)) {
        if (q.has(queryKey) && String(row[rowKey] ?? "") !== q.get(queryKey)) return false;
      }
      return true;
    };
    const scopedInstallations = observedInstallations.filter(installationScope);
    const admin = isAdminSession();
    const notice = feedback();
    const referenceList = (item.references || []).map((r) => h("li", null, h("a", { href: r.url, target: "_blank", rel: "noopener noreferrer" }, r.url), r.source ? ` · ${r.source}` : ""));
    const draw = () => h("div", null,
      pageHeader(cveId, h("a", { href: returnHash(q) || "#/cves", class: "button-link" }, "← 취약점 목록"),
        h("span", null, `NVD 상태 ${item.nvd_status || "-"} · 발행 `, timeEl(item.published_at), " · 갱신 ", timeEl(item.modified_at))),
      kev ? h("section", { class: "kev-banner" }, h("div", null, badge("CISA KEV", "err"), h("strong", null, `${kev.vendor} · ${kev.product}`)),
        h("p", null, kev.vulnerability_name), h("p", null, `추가일 ${kev.date_added} · CISA 조치 기한 ${kev.due_date || "없음"} · 랜섬웨어 사용 ${kev.ransomware_use || "알 수 없음"}`),
        h("p", null, kev.required_action || ""), kev.notes ? h("p", { class: "muted" }, kev.notes) : null) : null,
      h("div", { class: "request-grid" },
        h("section", { class: "panel" }, h("h2", null, "NVD 취약점 정보"), h("p", null, item.description || "설명이 없습니다."),
          h("dl", { class: "detail-list" }, h("dt", null, "CVSS"), h("dd", null, item.cvss_score ? `${item.cvss_score} · ${item.cvss_severity || ""}` : "점수 없음"),
            h("dt", null, "NVD 기준 수정"), h("dd", null, timeEl(item.modified_at)), h("dt", null, "피드 수집"), h("dd", null, timeEl(item.nvd_fetched_at))),
          referenceList.length ? h("details", null, h("summary", null, `참고 자료 ${referenceList.length}건`), h("ul", null, referenceList)) : empty("참고 링크가 없습니다."),
          h("details", { class: "raw-json" }, h("summary", null, "NVD CVSS 메트릭과 CPE 적용 조건"), h("pre", { class: "json" }, JSON.stringify({ cvss_metrics: item.cvss_metrics, configurations: item.configurations }, null, 2)))),
        h("section", { class: "panel" }, h("h2", null, "제품 영향 판정"),
          matches.length ? matches.map((match) => h("article", { class: "match-card" },
            h("div", { class: "section-heading" }, h("strong", null, link(`${match.name} · ${match.source} · ${match.arch}`, `#/software/${enc(match.name)}`)),
              impactBadge(match.status === "affected_confirmed" ? "confirmed" : match.status === "needs_review" ? "needs_review" : "not_affected")),
            h("p", null, match.evidence), match.conditions ? h("p", { class: "muted" }, `적용 조건: ${match.conditions}`) : null,
            match.affected_versions?.length ? h("p", null, `영향 확정 버전: ${match.affected_versions.join(", ")}`) : null,
            h("p", { class: "muted" }, `근거 갱신 ${match.updated_by} · `, timeEl(match.updated_at), ` · revision ${match.revision}`),
            admin ? h("button", { type: "button", onclick: (e) => editMatch(match, e.currentTarget) }, "판정 근거 편집") : null))
            : empty("제품 영향 판정이 없습니다. 미평가를 영향 없음으로 간주하지 않습니다."),
          admin ? h("button", { type: "button", class: "primary", onclick: (e) => editMatch(null, e.currentTarget) }, "제품 영향 판정 추가") : null)),
      h("section", { class: "panel" },
        h("h2", null, `설치 호스트 영향 판정 (${scopedInstallations.length})`),
        q.has("host") || q.has("product_name") ? h("p", { class: "muted" }, [
          q.has("host") ? `호스트 ${q.get("host")}` : "",
          q.has("product_name") ? `제품 ${q.get("product_name")} ${q.get("product_version") || "(버전 미기록)"}` : "",
          selectedImpact ? workflowImpactLabel(selectedImpact) : "",
        ].filter(Boolean).join(" · ")) : null,
        table([
          { title: "호스트", render: (r) => link(r.hostname || r.host_id, `#/hosts/${enc(r.host_id)}`) },
          { title: "자산", render: (r) => r.asset_no ? assetLink(`#/assets/${r.asset_id}`, r.asset_no) : "미등록" },
          { title: "영향 판정", render: (r) => impactBadge(r.impact_status) },
          { title: "소프트웨어 · 설치 버전", render: (r) => `${r.product_name || r.name || "제품명 미기록"} · ${r.version || "버전 미기록"}` },
          { title: "담당자(정/부)", render: (r) => assetOwnerCell(r) },
          { title: "마지막 수집", render: (r) => timeEl(r.last_seen) },
          { title: "근거", render: (r) => r.evidence
            ? h("details", { class: "evidence-disclosure" }, h("summary", null, "근거 보기"), h("p", null, r.evidence))
            : h("span", { class: "muted" }, "근거 미기록") },
        ], scopedInstallations, selectedImpact ? "선택한 판정의 설치행이 없습니다." : "이 CVE와 연결된 관측 설치행이 없습니다."),
        h("p", { class: "table-note" }, "버전이 정확히 일치하지 않는 설치는 영향 없음으로 간주하지 않고 ‘확정 일치 없음’으로 구분합니다.")),
      h("section", { class: "panel" }, h("h2", null, "피드 상태"), item.feed_status?.length ? table([
        { title: "출처", render: (r) => r.source }, { title: "상태", render: (r) => badge(r.state, r.state === "ok" ? "ok" : r.state === "failed" ? "err" : "warn") },
        { title: "마지막 성공", render: (r) => timeEl(r.last_success_at) }, { title: "마지막 시도", render: (r) => timeEl(r.last_attempt_at) },
        { title: "데이터 버전 / 오류", render: (r) => `${r.data_version || "-"}${r.last_error ? ` · ${r.last_error}` : ""}` },
      ], item.feed_status) : empty("피드 수집을 실행하지 않았습니다.")), notice.node);
    function editMatch(match, opener) {
      const currentRevision = match?.revision ?? null;
      const productSearch = h("input", { type: "search", "aria-label": "영향 제품 검색", placeholder: "패키지명 검색", value: match?.name || "" });
      const product = h("select", { required: true, "aria-label": "영향 제품" });
      const state = h("select", null, [["needs_review", "확인 필요"], ["affected_confirmed", "영향 확인"], ["not_affected", "영향 없음 판정"]].map(([v, label]) => h("option", { value: v, selected: v === (match?.status || "needs_review") }, label)));
      const evidence = h("textarea", { required: true, minlength: 8, maxlength: 2000, rows: 4, placeholder: "공식 보안 공지, CVE 적용 조건, 패키지 공급자 확인 등 근거" }, match?.evidence || "");
      const conditions = h("textarea", { maxlength: 1000, rows: 2, placeholder: "제품·빌드·환경·완화 조건" }, match?.conditions || "");
      const versions = h("textarea", { rows: 3, placeholder: "영향 확정 시 정확한 설치 버전을 쉼표로 입력" }, (match?.affected_versions || []).join(", "));
      const versionField = field("영향 확정 버전", versions, "문자열 버전 비교로 자동 판단하지 않습니다. 설치 행과 정확히 일치하는 버전만 확정에 사용합니다.");
      const msg = msgBox(); let dialog; let products = [];
      const loadProducts = async () => {
        const params = new URLSearchParams({ page: "1", page_size: "100" }); if (productSearch.value.trim()) params.set("q", productSearch.value.trim());
        try {
          const result = await api(`/v1/software-products?${params}`); products = result.items; clear(product).append(...products.map((p) => {
            const key = `${p.source}\u001f${p.name}\u001f${p.arch}`;
            return h("option", { value: key, selected: key === (match ? `${match.source}\u001f${match.name}\u001f${match.arch}` : "") }, `${p.product_name || p.name} · ${p.source} · ${p.arch || "-"}`);
          }));
        } catch (err) { msg.err(errMsg(err)); }
      };
      let timer; productSearch.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(loadProducts, 250); });
      const syncVersions = () => { versionField[0].hidden = state.value !== "affected_confirmed"; versionField[1].hidden = state.value !== "affected_confirmed"; };
      state.addEventListener("change", syncVersions); syncVersions();
      const save = h("button", { type: "submit", class: "primary" }, "판정 저장");
      const form = h("form", { class: "form", onsubmit: async (e) => {
        e.preventDefault(); save.disabled = true; msg.clear();
        const [source, name, arch] = product.value.split("\u001f");
        const affected_versions = state.value === "affected_confirmed" ? [...new Set(versions.value.split(",").map((v) => v.trim()).filter(Boolean))] : [];
        try {
          await api("/v1/vulnerabilities/matches", { method: "PUT", body: JSON.stringify({ cve_id: cveId, source, name, arch, status: state.value,
            evidence: evidence.value.trim(), conditions: conditions.value.trim(), affected_versions, expected_revision: currentRevision }) });
          const refreshed = await api(`/v1/vulnerabilities/${enc(cveId)}`); Object.assign(item, refreshed); dialog.close("saved"); if (alive()) clear(root).append(draw());
        } catch (err) { msg.err(err.status === 409 ? `${err.message} 최신 판정을 다시 불러오세요.` : errMsg(err)); save.disabled = false; }
      } }, field("제품 검색", productSearch), field("설치 제품", product), field("판정", state), field("근거", evidence), field("적용 조건", conditions), versionField,
        h("p", { class: "hint full" }, "정확한 설치 제품·아키텍처·버전과 근거를 관리자가 확인합니다. 이름 유사도만으로는 영향 확정하지 않습니다."),
        h("div", { class: "full" }, msg.el), h("div", { class: "dialog-actions full" }, cancelDialog(() => dialog.close()), save));
      dialog = editorDialog(match ? "CVE 제품 영향 판정 편집" : "CVE 제품 영향 판정 추가", form, opener);
      loadProducts();
    }
    clear(root).append(draw()); return root;
  }

  // ---------- 설정 ----------
  const FAMILY_LABELS = { "*": "* 전체(기본)", debian: "Debian / Ubuntu", rhel: "RHEL 계열", windows: "Windows" };

  async function viewSettings() {
    const policy = await api("/v1/settings/kernel-policy");
    const ai = isAdmin() ? await api("/v1/settings/ai") : null; // AI 연결 설정은 관리자만 읽을 수 있다 — 조회 토큰으로는 요청하지 않는다
    return h("div", null, h("h1", null, "설정"), adminNote(), policyPanel(policy.rules), aiPanel(ai));
  }

  function policyPanel(initial) {
    let rules = initial.map((r) => ({ ...r }));
    const box = h("div", { class: "rules" }); const msg = msgBox();
    const draw = () => {
      clear(box);
      if (!rules.length) box.append(h("div", { class: "muted" }, "하한선이 없습니다. 규칙을 추가하면 실행 중 커널이 그 값보다 낮은 호스트가 '미달'로 표시됩니다."));
      rules.forEach((r, i) => box.append(h("div", { class: "rule" },
        gate(h("select", { "aria-label": `규칙 ${i + 1} OS 계열`, onchange: (e) => { r.os_family = e.target.value; } },
          Object.entries(FAMILY_LABELS).map(([k, t]) => h("option", { value: k, selected: k === r.os_family }, t)))),
        gate(h("input", { type: "text", "aria-label": `규칙 ${i + 1} 최소 커널`, placeholder: "최소 커널 (예: 5.15.0-100)", value: r.min_kernel, oninput: (e) => { r.min_kernel = e.target.value; } })),
        gate(h("button", { type: "button", "aria-label": `규칙 ${i + 1} 삭제`, onclick: () => { rules.splice(i, 1); draw(); } }, "삭제")))));
    };
    draw();
    const saveBtn = gate(h("button", { class: "primary", type: "button", onclick: async () => {
      saveBtn.disabled = true; msg.info("저장 중…");
      try {
        const out = await api("/v1/settings/kernel-policy", { method: "PUT", body: JSON.stringify({ rules: rules.map((r) => ({ os_family: r.os_family, min_kernel: r.min_kernel.trim() })) }) });
        rules = out.rules.map((r) => ({ ...r })); draw();
        const o = await api("/v1/overview");
        msg.ok(out.rules.length ? `저장했습니다. 현재 하한선 미달 호스트: ${o.noncompliant_count}대` : "저장했습니다. 하한선이 해제됐습니다.");
      } catch (err) { msg.err(errMsg(err)); }
      saveBtn.disabled = !isAdmin();
    } }, "저장"));
    const addBtn = gate(h("button", { type: "button", onclick: () => {
      const unused = Object.keys(FAMILY_LABELS).filter((k) => k !== "*").concat("*").find((k) => !rules.some((r) => r.os_family === k));
      rules.push({ os_family: unused || "*", min_kernel: "" }); draw(); // 아직 규칙이 없는 계열을 기본으로 — 처음부터 중복을 만들지 않는다
    } }, "+ 규칙 추가"));
    return h("div", null, h("h2", null, "커널 하한선"),
      h("div", { class: "panel" },
        h("p", { class: "hint" }, "OS 계열별 최소 허용 커널(실행 중 커널 기준). 숫자 단위로 비교하며(5.15.0-91 < 5.15.0-100) 계열 규칙이 '*' 규칙보다 우선합니다. 예) Debian 5.15.0-100 · RHEL 5.14.0-427 · Windows 10.0.22631.3155. 저장 즉시 모든 화면·리포트에 반영됩니다."),
        box,
        h("div", { class: "toolbar" }, addBtn, saveBtn, msg.el)));
  }

  function aiPanel(ai) {
    if (ai === null) return h("div", null, h("h2", null, "AI 연결"), h("div", { class: "notice" }, `AI 연결 설정을 보려면 ${ADMIN_ONLY}.`));
    const f = (k, d = "") => (ai[k] ?? d);
    const baseUrl = h("input", { type: "text", value: f("base_url"), placeholder: "https://llm.corp.example/v1" });
    const model = h("input", { type: "text", value: f("model"), placeholder: "모델명 (예: gpt-oss)" });
    const zone = h("select", null, h("option", { value: "internal", selected: f("trust_zone", "internal") === "internal" }, "internal — 사내 게이트웨이"),
      h("option", { value: "external", selected: f("trust_zone") === "external" }, "external — 외부 서비스(https 필수)"));
    const key = h("input", { type: "password", autocomplete: "off", placeholder: ai.has_api_key ? `저장됨(${ai.api_key_source === "env" ? "환경변수 OPENAI_API_KEY" : "설정"}) — 바꾸려면 입력` : "API 키 (사내 게이트웨이는 비워도 됨)" });
    const clearKey = h("input", { type: "checkbox" });
    const verify = h("select", null, h("option", { value: "default", selected: ai.verify_ssl !== false }, "검증함(기본)"),
      h("option", { value: "off", selected: ai.verify_ssl === false }, "검증 안 함 — 자가서명 사내 게이트웨이 전용"));
    const ca = h("input", { type: "text", value: f("ca_file"), placeholder: "사설 CA 번들 경로 (검증을 끄는 것보다 권장)" });
    const timeout = h("input", { type: "number", value: f("timeout", 120), min: 1, max: 600 });
    const maxTokens = h("input", { type: "number", value: f("max_tokens", 4000), min: 256, max: 16000 });
    const msg = msgBox();
    const headerRows = [];
    const headerList = h("div", { class: "ai-header-list", "aria-label": "추가 HTTP 헤더 목록" });
    const authHeader = h("select", { id: "ai-auth-header", "aria-label": "사용자 인증 헤더", onchange: () => msg.clear() },
      h("option", { value: "" }, "사용 안 함"));
    const originNotice = h("p", { class: "notice ai-origin-notice", role: "status", hidden: true });
    const initialBaseUrl = String(f("base_url") || "");
    let savedBaseUrl = initialBaseUrl;
    let busy = false;
    let saveButton;
    let addHeaderButton;
    const normalizedName = (v) => String(v || "").trim().toLowerCase();
    const headerToken = /^[!#$%&'*+\-.^_\x60|~0-9A-Za-z]+$/;
    const reservedHeaders = new Set(["accept", "connection", "content-length", "content-type", "expect", "host", "keep-alive",
      "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"]);
    const originOf = (value) => {
      try { return new URL(String(value || "").trim()).origin; } catch (_) { return ""; }
    };
    const updateOriginNotice = () => {
      const changed = !!savedBaseUrl && !!baseUrl.value.trim() && originOf(savedBaseUrl) !== originOf(baseUrl.value);
      const preserved = headerRows.some((row) => row.hasValue && !row.valueInput.value);
      originNotice.hidden = !(changed && preserved);
      originNotice.textContent = "엔드포인트의 scheme·호스트·포트가 바뀌었습니다. 저장된 헤더 비밀값은 새 주소로 옮기지 않으므로, 유지할 각 행에 새 값을 입력하거나 해당 행을 삭제하세요.";
    };
    const updateAuthOptions = () => {
      const wanted = authHeader.value;
      const seen = new Set();
      const options = [h("option", { value: "" }, "사용 안 함")];
      for (const row of headerRows) {
        const name = row.nameInput.value.trim();
        const keyName = normalizedName(name);
        if (!keyName || seen.has(keyName)) continue;
        seen.add(keyName);
        options.push(h("option", { value: name }, name));
      }
      clear(authHeader).append(...options);
      authHeader.value = options.some((option) => option.value && normalizedName(option.value) === normalizedName(wanted))
        ? options.find((option) => option.value && normalizedName(option.value) === normalizedName(wanted)).value : "";
    };
    const updateHeaderLabels = () => {
      headerRows.forEach((row, index) => {
        const name = row.nameInput.value.trim();
        row.removeButton.setAttribute("aria-label", `${name || `추가 헤더 ${index + 1}`} 삭제`);
      });
    };
    const makeHeaderRow = (item = {}) => {
      const rowId = uid("ai-header");
      const nameInput = h("input", { id: `${rowId}-name`, type: "text", autocomplete: "off", spellcheck: "false", maxlength: 128,
        value: item.name || "", placeholder: "예: X-Organization-Key", "aria-describedby": `${rowId}-name-hint ${rowId}-name-error` });
      const valueInput = h("input", { id: `${rowId}-value`, type: "password", autocomplete: "new-password", spellcheck: "false", maxlength: 4096,
        placeholder: item.has_value ? "저장된 값 유지 — 교체할 때만 입력" : "헤더 값", "aria-describedby": `${rowId}-value-hint ${rowId}-value-error` });
      const nameError = h("div", { class: "field-error", id: `${rowId}-name-error`, role: "alert" });
      const valueError = h("div", { class: "field-error", id: `${rowId}-value-error`, role: "alert" });
      const saved = h("span", { class: "ai-header-state" }, item.has_value ? "저장됨 · 값은 다시 표시되지 않습니다" : "값 미설정");
      const removeButton = gate(h("button", { type: "button", class: "danger", "aria-label": "추가 헤더 삭제" }, "삭제"));
      const row = { element: null, nameInput, valueInput, nameError, valueError, removeButton,
        originalName: String(item.name || ""), hasValue: item.has_value === true, saved };
      const nameField = h("div", { class: "ai-header-field" },
        h("label", { for: nameInput.id }, "헤더 이름"), nameInput, nameError,
        h("span", { class: "hint", id: `${rowId}-name-hint` }, "공백 없이 헤더 이름을 입력하세요."));
      const valueField = h("div", { class: "ai-header-field" },
        h("label", { for: valueInput.id }, "헤더 값"), valueInput, valueError,
        h("span", { class: "hint", id: `${rowId}-value-hint` }, item.has_value ? "비워두면 같은 이름의 저장값을 유지합니다." : "빈 값도 저장할 수 있습니다."));
      row.element = h("div", { class: "ai-header-row" }, h("div", { class: "ai-header-fields" }, nameField, valueField),
        h("div", { class: "ai-header-actions" }, saved, removeButton));
      removeButton.addEventListener("click", () => {
        const index = headerRows.indexOf(row);
        if (index >= 0) headerRows.splice(index, 1);
        row.element.remove(); updateAuthOptions(); updateHeaderLabels(); updateOriginNotice(); msg.clear();
      });
      nameInput.addEventListener("input", () => { nameError.textContent = ""; nameInput.removeAttribute("aria-invalid"); updateAuthOptions(); updateHeaderLabels(); updateOriginNotice(); msg.clear(); });
      valueInput.addEventListener("input", () => { valueError.textContent = ""; valueInput.removeAttribute("aria-invalid"); updateOriginNotice(); msg.clear(); });
      headerRows.push(row);
      headerList.append(row.element);
      return row;
    };
    for (const row of (Array.isArray(ai.extra_headers) ? ai.extra_headers : [])) makeHeaderRow(row);
    updateAuthOptions(); updateHeaderLabels();
    authHeader.value = ai.auth_header || "";
    updateOriginNotice();
    addHeaderButton = gate(h("button", { type: "button", onclick: () => {
      if (headerRows.length >= 32) { msg.err("추가 HTTP 헤더는 최대 32개까지 설정할 수 있습니다."); return; }
      const row = makeHeaderRow(); updateAuthOptions(); updateHeaderLabels(); row.nameInput.focus(); msg.clear();
    } }, "+ 헤더 추가"));
    baseUrl.addEventListener("input", updateOriginNotice);
    const save = async () => {
      if (busy) return;
      const seenHeaders = new Set();
      for (const row of headerRows) {
        row.nameError.textContent = ""; row.nameInput.removeAttribute("aria-invalid");
        row.valueError.textContent = ""; row.valueInput.removeAttribute("aria-invalid");
        const rawName = row.nameInput.value;
        const currentName = rawName.trim();
        const keyName = normalizedName(currentName);
        let nameError = "";
        if (!currentName) nameError = "헤더 이름을 입력하세요.";
        else if (rawName !== currentName) nameError = "헤더 이름 앞뒤에 공백을 넣을 수 없습니다.";
        else if (currentName.length > 128 || !headerToken.test(currentName)) nameError = "공백 없이 영문·숫자와 HTTP 헤더에 허용된 기호를 입력하세요.";
        else if (reservedHeaders.has(keyName)) nameError = "요청 전송에 예약된 헤더 이름은 사용할 수 없습니다.";
        else if (seenHeaders.has(keyName)) nameError = "헤더 이름은 대소문자를 구분하지 않고 중복할 수 없습니다.";
        if (nameError) {
          row.nameError.textContent = nameError; row.nameInput.setAttribute("aria-invalid", "true"); row.nameInput.focus();
          msg.err("헤더 이름을 확인하세요."); return;
        }
        seenHeaders.add(keyName);
        if (row.hasValue && normalizedName(currentName) !== normalizedName(row.originalName) && !row.valueInput.value) {
          row.valueError.textContent = "저장된 비밀값은 다른 헤더 이름으로 이동할 수 없습니다. 새 이름에 사용할 값을 입력하세요.";
          row.valueInput.setAttribute("aria-invalid", "true"); row.valueInput.focus();
          msg.err("헤더 이름을 바꾼 행에는 새 값을 입력해야 합니다.");
          return;
        }
      }
      busy = true; saveButton.disabled = true; addHeaderButton.disabled = true;
      headerRows.forEach((row) => { row.removeButton.disabled = true; });
      msg.info("저장 중…");
      const body = { base_url: baseUrl.value.trim(), model: model.value.trim(), trust_zone: zone.value, api_key: key.value || null,
        clear_api_key: clearKey.checked, verify_ssl: verify.value === "off" ? false : null, ca_file: ca.value.trim() || null,
        timeout: Number(timeout.value), max_tokens: Number(maxTokens.value), auth_header: authHeader.value || null,
        extra_headers: headerRows.map((row) => ({ name: row.nameInput.value.trim(),
          value: row.valueInput.value || (row.hasValue ? null : "") })) };
      try {
        const savedConfig = await api("/v1/settings/ai", { method: "PUT", body: JSON.stringify(body) });
        key.value = ""; clearKey.checked = false;
        savedBaseUrl = String(savedConfig.base_url || baseUrl.value.trim());
        if (Array.isArray(savedConfig.extra_headers)) {
          headerRows.splice(0, headerRows.length);
          clear(headerList);
          for (const row of savedConfig.extra_headers) makeHeaderRow(row);
          updateAuthOptions(); updateHeaderLabels();
          authHeader.value = savedConfig.auth_header || "";
        }
        updateOriginNotice(); msg.ok("저장했습니다. 비밀 입력란은 비웠습니다. 연결 테스트는 저장된 설정을 사용합니다.");
      }
      catch (err) { msg.err(errMsg(err)); }
      finally { busy = false; saveButton.disabled = !isAdmin(); addHeaderButton.disabled = !isAdmin(); headerRows.forEach((row) => { row.removeButton.disabled = !isAdmin(); }); }
    };
    const test = async () => {
      msg.info("테스트 중…");
      try { const r = await api("/v1/settings/ai/test", { method: "POST" }); if (r.ok) msg.ok(`연결 성공 — 모델 ${r.model}, ${r.latency_ms}ms`); else msg.err(`연결 실패: ${r.error}`); }
      catch (err) { msg.err(errMsg(err)); }
    };
    return h("div", null, h("h2", null, "AI 연결 (OpenAI 호환 API)"),
      h("div", { class: "panel" },
        h("p", { class: "hint" }, "tclient 의 사내 AI 엔드포인트와 같은 방식입니다. API 키는 쓰기 전용이며 암호화되어 저장되고 화면·API 응답에 다시 나오지 않습니다. 키를 비워 두고 저장하면 기존 키를 유지합니다."),
        h("div", { class: "form" },
          field("엔드포인트(base_url)", baseUrl), field("모델", model), field("신뢰 영역", zone),
          field("API 키", key), field("저장된 키 삭제", clearKey, "체크하고 저장하면 저장된 API 키를 지웁니다."),
          field("TLS 검증", verify), field("사설 CA 파일", ca),
          field("타임아웃(초)", timeout), field("최대 출력 토큰", maxTokens),
          h("section", { class: "ai-extra-headers full", "aria-labelledby": "ai-extra-headers-title" },
            h("div", { class: "ai-extra-heading" }, h("div", null, h("h3", { id: "ai-extra-headers-title" }, "추가 HTTP 헤더"),
              h("p", { class: "hint" }, "프록시·사내 게이트웨이용 헤더를 최대 32개까지 설정합니다. 값은 암호화 저장되며 다시 표시되지 않습니다.")), addHeaderButton),
            headerList,
            h("div", { class: "ai-auth-row" }, h("label", { for: "ai-auth-header" }, "사용자 인증 헤더"),
              authHeader),
            h("p", { class: "hint" }, "외부 엔드포인트는 API 키 또는 여기서 선택한 비어 있지 않은 헤더 값이 필요합니다. 추가 Authorization 헤더는 API 키와 함께 사용할 수 없습니다."),
            originNotice)),
        h("p", { class: "hint" }, "external 은 https 만 허용되고 TLS 검증을 끌 수 없습니다. 엔드포인트 URL 에 자격증명(user:pw@, ?api_key=)을 넣을 수 없습니다."),
        h("p", { class: "hint" }, "연결 테스트는 현재 저장된 설정만 사용합니다. 변경사항은 먼저 저장하세요."),
        h("div", { class: "toolbar" }, saveButton = gate(h("button", { class: "primary", type: "button", onclick: save }, "저장")), gate(h("button", { type: "button", onclick: test }, "연결 테스트")), msg.el)));
  }

  function setMenu(open) {
    $top.classList.toggle("nav-open", open);
    document.getElementById("nav-toggle").setAttribute("aria-expanded", String(open));
  }
  document.getElementById("nav-toggle").addEventListener("click", () => setMenu(!$top.classList.contains("nav-open")));
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && $top.classList.contains("nav-open")) { setMenu(false); document.getElementById("nav-toggle").focus(); }
  });
  document.addEventListener("click", (e) => { if (!$top.contains(e.target)) setMenu(false); });

  window.addEventListener("beforeunload", (e) => {
    if (!assetDraftGuard?.isDirty()) return;
    e.preventDefault(); e.returnValue = "";
  });
  document.getElementById("logout").addEventListener("click", async (e) => {
    e.currentTarget.disabled = true;
    try { await api("/v1/auth/logout", { method: "POST" }); logout(); }
    catch (err) { if (err.status !== 401) alert(`로그아웃 실패: ${err.message}. 다시 시도하세요.`); }
    finally { document.getElementById("logout").disabled = false; }
  });
  window.addEventListener("hashchange", render);
  render();
})();
