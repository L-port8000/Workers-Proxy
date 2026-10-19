// Cloudflare Workers: ブログ風フロント + CGIプロキシ (v2 / X.com対応強化版)
//
// 【v2の方針】
//  ・JS本文は書き換えない(ストリーム素通し)。URLの付け替えはブラウザ側のパッチで実行時に行う
//  ・ページ表示後に URLバーを "/go/https/x.com/home" → "/home" に置き換える(clean-path mode)
//    → SPAのルーターが location.pathname を正しく読める
//  ・直接 "/home" を開き直した場合は、Cookie pxo(最後に開いたトップレベルのorigin)で振り分ける
//  ・document.cookie をパッチして、プレフィックス付きCookieを素のCookieに見せる(ct0対策)
//  ・リクエストヘッダは原則すべて転送(x-csrf-token / x-twitter-* / authorization など)
//
// ルート:
//   "/"                              : ブログ
//   "/go/<scheme>/<host>/<path>"     : プロキシ本体 (scheme = http|https|ws|wss)
//                                      "/go/https://host/path" や "/go/host/path" も自動で正しい形に直す
//   "/api/status" "/api/unlock"      : 合言葉
//   "/api/cookies" "/cookies"        : Cookie管理
// Secret ACCESS_KEY を設定すると、合言葉を入れた人だけが使える(必ず設定推奨)

const CLICKS_TO_OPEN = 3;

const enc = new TextEncoder();
const DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

// ---- 設定フラグ ----
// iframe(クロスサイト)内でもCookieが保存・送信されるよう SameSite=None を使う。
// Safari / Firefox(ETP) 等で iframe 内ログインが保持されない場合は true にすると Partitioned を付ける
// (ただし iframe 用と通常表示用でCookieの保存領域が分かれる)
const COOKIE_PARTITIONED = false;
const COOKIE_FLAGS = 'Path=/; Secure; SameSite=None' + (COOKIE_PARTITIONED ? '; Partitioned' : '');
// true: プロキシを素通りする通信(書き換え漏れのURL)をCSPで遮断する(実IPでの直接通信を防ぐ)。サイトが壊れる場合は false に
const STRICT_CSP = false; // 既定OFF (Worker内の通信などを遮断しうるため)。設定ページで切り替え可
// true: 画像・動画・フォントだけは https: を許可する。書き換え漏れ(CSSOM経由の background-image など)で画像が
// 表示されなくなるのを防ぐ。ただし漏れた分は実IPで直接接続される。DevToolsのNetworkで /go/ を経由しない
// リクエストが無いと確認できたら false にすると厳格モードになる
const CSP_ALLOW_REMOTE_MEDIA = true;
// true: WebRTC を無効化(STUN経由の実IP漏れ防止)
const BLOCK_WEBRTC = true;
// true: 画像・JS・CSSをCloudflareのエッジにキャッシュ (既定OFF)。設定ページで切り替え可
const EDGE_CACHE = false;
// true: Web Worker 内の通信もプロキシ経由にする (DM等がWorker内でfetchする場合に必要)
const WORKER_PATCH = true;
// true: ブラウザ/OSを Firefox on Windows 11 に見せる (HTTPヘッダ + navigator)
// ※ Windows 11 の Firefox も UA 上は "Windows NT 10.0" と報告される(Windows 10と同じ)
const SPOOF_UA = true;
// 現行の安定版に合わせて時々更新(1〜2世代古い程度なら問題になりにくい)
const FF_VERSION = '155';
const FAKE_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:' + FF_VERSION + '.0) Gecko/20100101 Firefox/' + FF_VERSION + '.0';
// true: 通常の Web Worker 内の navigator も偽装する(classic workerのみ)。
// 一部サイトのWorkerが壊れる場合があるので既定は false
const SPOOF_WORKERS = false;
const FP_PROFILE = {
  ua: FAKE_UA,
  appVersion: '5.0 (Windows)',
  platform: 'Win32',
  oscpu: 'Windows NT 10.0; Win64; x64',
  buildID: '20181001000000',
  workers: SPOOF_WORKERS,
};
// Twitter UI モード用: 青い鳥のロゴ(24x24)
const TW_BIRD = 'M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z';
const isXHost = h => /(^|\.)(x|twitter)\.com$/i.test(h);
const FF_ACCEPT_DOC = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8';
const FF_ACCEPT_IMG = 'image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5';

// ---- 静的ファイル(画像・JS・CSS・フォント)の高速化 ----
// Cloudflareのエッジキャッシュに載せる秒数 (0で無効)。Cookie/Authorization/Range が無い GET のみ対象
const STATIC_CACHE_TTL = 86400;
const STATIC_DESTS = new Set(['image', 'font', 'style', 'script', 'audio', 'video', 'track']);
const CACHE_DESTS = new Set(['image', 'font', 'style', 'script']);

async function sha256Hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function parseCookies(h) {
  const o = {};
  (h || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return o;
}

// 認証トークンはisolate内で使い回す(画像1枚ごとにSHA-256を計算しない)
let _tokKey = null, _tok = null;
async function authToken(env) {
  if (_tokKey !== env.ACCESS_KEY) {
    _tok = await sha256Hex('pxa:' + env.ACCESS_KEY);
    _tokKey = env.ACCESS_KEY;
  }
  return _tok;
}

async function isAuthed(req, env, cookies) {
  if (!env.ACCESS_KEY) return true;
  const c = cookies || parseCookies(req.headers.get('cookie'));
  return c.pxa === (await authToken(env));
}

function htmlRes(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      'content-type': 'text/html;charset=utf-8',
      'x-robots-tag': 'noindex',
      'cache-control': 'no-store',
    },
  });
}

// ---------- 設定 (設定ページが Cookie pxs に保存。無ければ上の定数が既定) ----------
function getCfg(cookies) {
  const c = {
    twitterUi: false,
    spoofUa: SPOOF_UA,
    blockWebrtc: BLOCK_WEBRTC,
    strictCsp: STRICT_CSP,
    edgeCache: EDGE_CACHE,
    workerPatch: WORKER_PATCH,
  };
  try {
    if (cookies && cookies.pxs) {
      const o = JSON.parse(decodeURIComponent(cookies.pxs));
      for (const k in c) if (typeof o[k] === 'boolean') c[k] = o[k];
    }
  } catch (e) {}
  return c;
}

// Web Worker 内の fetch / XHR / WebSocket / EventSource / importScripts をプロキシ経由にする
// (Workerはページのパッチが効かないため、スクリプトの先頭にこれを付ける)
const WORKER_PATCH_SRC = String.raw`(function(T){
try{
  var O=self.location.origin;
  function px(u){
    if(u==null||u==='')return u;
    if(typeof u!=='string')u=String(u);
    if(/^(#|data:|blob:|javascript:|mailto:|tel:|about:)/i.test(u))return u;
    try{
      var a=new URL(u,T);
      if(a.origin===O){
        if(/^\/go\//.test(a.pathname))return O+a.pathname+a.search+a.hash;
        a=new URL(a.pathname+a.search+a.hash,T);
      }
      var p=a.protocol.slice(0,-1);
      if(p!=='http'&&p!=='https'&&p!=='ws'&&p!=='wss')return u;
      return O+'/go/'+p+'/'+a.host+a.pathname+a.search+a.hash;
    }catch(e){return u}
  }
  var f=self.fetch;
  if(f)self.fetch=function(i,n){
    try{
      if(typeof Request!=='undefined'&&i instanceof Request){var nu=px(i.url);if(nu!==i.url)i=new Request(nu,i)}
      else i=px(i instanceof URL?i.href:String(i));
    }catch(e){}
    return f.call(this,i,n);
  };
  if(self.XMLHttpRequest){
    var xo=XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open=function(m,u){try{arguments[1]=px(u)}catch(e){}return xo.apply(this,arguments)};
  }
  if(self.WebSocket){
    var WSO=self.WebSocket;
    var WS=function(u,p){
      try{
        var a=new URL(String(u),T);
        var pr=a.protocol==='https:'?'wss':a.protocol==='http:'?'ws':a.protocol.slice(0,-1);
        if(pr==='ws'||pr==='wss')u=O.replace(/^http/,'ws')+'/go/'+pr+'/'+a.host+a.pathname+a.search;
      }catch(e){}
      return p===undefined?new WSO(u):new WSO(u,p);
    };
    WS.prototype=WSO.prototype;WS.CONNECTING=0;WS.OPEN=1;WS.CLOSING=2;WS.CLOSED=3;
    self.WebSocket=WS;
  }
  if(self.EventSource){
    var ESO=self.EventSource;
    var ES=function(u,o){return new ESO(px(u),o)};
    ES.prototype=ESO.prototype;self.EventSource=ES;
  }
  if(typeof importScripts==='function'){
    var is=importScripts;
    self.importScripts=function(){return is.apply(self,[].map.call(arguments,function(u){return px(u)}))};
  }
}catch(e){}
})(__T__);
`;

function workerPatchFor(base) {
  return WORKER_PATCH_SRC.replace('__T__', () => JSON.stringify(base)) + '\n';
}

// ---------- URL helpers ----------
function proxify(u, base) {
  try {
    if (!u) return u;
    const s = u.trim();
    if (/^(#|data:|blob:|javascript:|mailto:|tel:|about:)/i.test(s)) return u;
    const a = new URL(s, base);
    if (a.protocol !== 'http:' && a.protocol !== 'https:' && a.protocol !== 'ws:' && a.protocol !== 'wss:') return u;
    return '/go/' + a.protocol.slice(0, -1) + '/' + a.host + a.pathname + a.search + a.hash;
  } catch (e) {
    return u;
  }
}

function isBlocked(t, self, allowSelf) {
  const h = t.hostname.toLowerCase();
  if (t.host === self.host && !allowSelf) return true;
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')) return true;
  if (h.startsWith('[')) return true; // IPv6リテラルは全面拒否
  if (/^(0|10|127)\./.test(h)) return true;
  if (/^192\.168\./.test(h) || /^169\.254\./.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  if (h === '0.0.0.0' || h === 'metadata.google.internal') return true;
  return false;
}

// ---------- cookie prefixes ----------
// host-only : x<host>__<name>
// domain    : xd_<domain>__<name>
function cookiePrefix(host) {
  return 'x' + host.replace(/[^a-z0-9]/gi, '_') + '__';
}

const MULTI_TLD = new Set(['uk','jp','au','nz','za','br','mx','cn','kr','tw','hk','in','ru','tr','pl','ua','cz','hr','fi','gr','pt','ro','sk','es','se','no','dk','at','be','ch','it','fr','de','nl','ie','ar','cl','pe','ve','ph','th','id','vn','my','sg']);
const MULTI_2ND = new Set(['co','com','org','net','gov','edu','ac','go','ne','or','gr','mil','mod','nic','hs','lg','ed','in']);

function registrableDomain(host) {
  const parts = host.toLowerCase().replace(/^\[|\]$/g, '').split('.');
  if (parts.length <= 2) return host;
  const last = parts[parts.length - 1];
  const second = parts[parts.length - 2];
  if (MULTI_TLD.has(last) && MULTI_2ND.has(second) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

function cookieDomainPrefix(host) {
  return 'xd_' + registrableDomain(host).replace(/[^a-z0-9]/gi, '_') + '__';
}

// target に送るべきCookieを "name=value" の配列で返す
// domain Cookie は「ホスト名がそのドメインのサフィックスに一致するか」で判定
function cookiesFor(target, incoming) {
  const hostPre = cookiePrefix(target.host);
  const hn = target.hostname.toLowerCase().replace(/[^a-z0-9]/g, '_');
  const out = [];
  for (const k in incoming) {
    if (k.startsWith('xd_')) {
      const i = k.indexOf('__');
      if (i < 4) continue;
      const d = k.slice(3, i);
      if (hn === d || hn.endsWith('_' + d)) out.push(k.slice(i + 2) + '=' + incoming[k]);
    } else if (k.startsWith(hostPre)) {
      out.push(k.slice(hostPre.length) + '=' + incoming[k]);
    }
  }
  return out;
}

// ---------- rewriting (HTML / CSS のみ) ----------
function rewriteCss(css, base) {
  return css
    .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/g, (m, q, u) => 'url(' + q + proxify(u, base) + q + ')')
    .replace(/@import\s+(['"])(.*?)\1/g, (m, q, u) => '@import ' + q + proxify(u, base) + q)
    .replace(/image-set\(([^)]+)\)/g, (m, inner) => {
      return 'image-set(' + inner.split(',').map(p => {
        const t = p.trim().split(/\s+/);
        if (t[0]) t[0] = proxify(t[0].replace(/^['"]|['"]$/g, ''), base);
        return t.join(' ');
      }).join(', ') + ')';
    });
}

function rewriteSrcset(v, base) {
  return v
    .split(',')
    .map(part => {
      const t = part.trim().split(/\s+/);
      if (!t[0]) return part;
      t[0] = proxify(t[0], base);
      return t.join(' ');
    })
    .join(', ');
}

function rewriteM3u8(text, base) {
  return text.split(/\r?\n/).map(line => {
    if (!line.trim()) return line;
    if (line.startsWith('#')) {
      return line.replace(/URI="([^"]*)"/g, (m, u) => 'URI="' + proxify(u, base) + '"');
    }
    return proxify(line.trim(), base);
  }).join('\n');
}

class Attr {
  constructor(attr, fn) { this.attr = attr; this.fn = fn; }
  element(e) {
    const v = e.getAttribute(this.attr);
    if (v !== null) e.setAttribute(this.attr, this.fn(v));
  }
}

class StyleText {
  constructor(base) { this.base = base; this.buf = ''; }
  text(t) {
    this.buf += t.text;
    if (t.lastInTextNode) {
      t.replace(rewriteCss(this.buf, this.base), { html: true });
      this.buf = '';
    } else {
      t.remove();
    }
  }
}

// ---------- ブラウザ側パッチ ----------
// 注意: String.raw 内なのでバッククォートと ${ は使わないこと
const CLIENT_JS = String.raw`(function(){
  if(window.__pxInit)return;window.__pxInit=1;
  var T=__T__,O=location.origin,CK=__CK__,BLOCK_RTC=__RTC__,FP=__FP__,TWUI=__TWUI__,WP=__WP__;

  // ---- ブラウザ/OSの偽装 (Firefox on Windows 11): navigator を書き換える
  //      この関数は Worker 用にソース文字列としても使うので、外側の変数を参照しないこと
  function applyNav(g,P){
    try{
      var np=Object.getPrototypeOf(g.navigator);
      var def=function(k,v){try{Object.defineProperty(np,k,{get:function(){return v},configurable:true,enumerable:true})}catch(e){}};
      var del=function(k){try{delete np[k]}catch(e){}};
      def('userAgent',P.ua);def('appVersion',P.appVersion);def('platform',P.platform);
      if(g.document){
        def('oscpu',P.oscpu);def('buildID',P.buildID);
        def('vendor','');def('vendorSub','');def('productSub','20100101');
        try{delete g.chrome}catch(e){}
      }
      ['userAgentData','deviceMemory','connection','getBattery','webkitTemporaryStorage','webkitPersistentStorage',
       'bluetooth','usb','hid','serial','presentation','getInstalledRelatedApps','cookieDeprecationLabel','login',
       'scheduling','ink','managed','windowControlsOverlay','virtualKeyboard','setAppBadge','clearAppBadge'].forEach(del);
    }catch(e){}
  }
  if(FP){
    applyNav(window,FP);
    // iframe.contentWindow 経由で「未加工のnavigator」を覗く検査への対策
    try{
      var cwD=Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype,'contentWindow');
      var cdD=Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype,'contentDocument');
      var fixWin=function(w){try{if(w&&w.navigator&&!w.__pxNav){w.__pxNav=1;applyNav(w,FP)}}catch(e){}};
      if(cwD&&cwD.get)Object.defineProperty(HTMLIFrameElement.prototype,'contentWindow',{get:function(){var w=cwD.get.call(this);fixWin(w);return w},configurable:true,enumerable:true});
      if(cdD&&cdD.get)Object.defineProperty(HTMLIFrameElement.prototype,'contentDocument',{get:function(){var d=cdD.get.call(this);try{if(d)fixWin(d.defaultView)}catch(e){}return d},configurable:true,enumerable:true});
    }catch(e){}
  }

  // ---- このウィンドウが「プロキシページの最上位」か判定する
  //  ・通常のタブ                              → ROOT
  //  ・自分のサイトの iframe に直接埋め込まれた → ROOT (親がクロスオリジンで __pxInit を読めない)
  //  ・プロキシ済みページの中の iframe          → ROOT ではない (親が __pxInit を持つ)
  //  ※ 下の parent 隠しパッチより前に判定すること
  var ROOT=(function(){
    try{
      if(window===window.top)return true;
      return !window.parent.__pxInit;
    }catch(e){return true}
  })();

  // ---- WebRTC無効化 (STUN経由で実IPが漏れるのを防ぐ)
  if(BLOCK_RTC){
    ['RTCPeerConnection','webkitRTCPeerConnection','mozRTCPeerConnection','RTCDataChannel'].forEach(function(n){
      try{Object.defineProperty(window,n,{value:undefined,configurable:true,writable:true})}catch(e){}
    });
  }

  // ---- 外側のサイトに埋め込まれていることを隠す (window.top はブラウザ仕様で上書き不可)
  //      プロキシ済みページ内の子iframe(認証ウィジェット等)は親との postMessage が必要なので触らない
  try{
    if(ROOT&&window!==window.top){
      var SELF=window.self;
      var hide=function(name,val){try{Object.defineProperty(window,name,{get:function(){return val},set:function(){},configurable:true})}catch(e){}};
      hide('parent',SELF);
      hide('frameElement',null);
      // 埋め込み元ページのURLが document.referrer に出るので空にする
      try{Object.defineProperty(document,'referrer',{get:function(){return ''},configurable:true})}catch(e){}
    }
  }catch(e){}

  // ---- URLバーを素のパスに戻す (ROOTのみ。iframe埋め込みでもSPAのルーターが正しいパスを読めるように)
  try{
    if(ROOT){
      var m0=location.pathname.match(/^\/go\/(https?)\/([^\/]+)(\/.*)?$/);
      if(m0)history.replaceState(history.state,'',(m0[3]||'/')+location.search+location.hash);
    }
  }catch(e){}

  // ---- URL変換: 任意のURL(相対/絶対/自オリジン)を /go/... に変換
  function px(u){
    if(u==null||u==='')return u;
    if(typeof u!=='string')u=String(u);
    if(/^(#|data:|blob:|javascript:|mailto:|tel:|about:|chrome:|chrome-extension:|moz-extension:|safari-extension:)/i.test(u))return u;
    if(/^\/go\//.test(u))return u;
    try{
      var a=new URL(u,T);
      if(a.origin===O){
        if(/^\/go\//.test(a.pathname))return a.pathname+a.search+a.hash;
        a=new URL(a.pathname+a.search+a.hash,T);
      }
      var p=a.protocol.slice(0,-1);
      if(p!=='http'&&p!=='https'&&p!=='ws'&&p!=='wss')return u;
      return '/go/'+p+'/'+a.host+a.pathname+a.search+a.hash;
    }catch(e){return u}
  }
  function unpx(u){
    var m=u.match(/^(?:https?:\/\/[^\/]+)?\/go\/(https?)\/([^\/?#]+)([^]*)$/);
    if(m)return m[1]+'://'+m[2]+(m[3]||'/');
    var a=new URL(u,T);
    if(a.origin===O)a=new URL(a.pathname+a.search+a.hash,T);
    return a.href;
  }
  function pxWs(u){
    try{
      var a=new URL(String(u),T);
      if(a.host===location.host)a=new URL(a.pathname+a.search,T);
      var p=a.protocol==='https:'?'wss':a.protocol==='http:'?'ws':a.protocol.slice(0,-1);
      if(p!=='ws'&&p!=='wss')return u;
      return O.replace(/^http/,'ws')+'/go/'+p+'/'+a.host+a.pathname+a.search;
    }catch(e){return u}
  }
  function rs(v){return String(v).split(',').map(function(p){var t=p.trim().split(/\s+/);if(t[0])t[0]=px(t[0]);return t.join(' ')}).join(', ')}

  // ---- fetch / XHR / beacon / EventSource / window.open
  function PO(){try{return new URL(T).origin}catch(e){return ''}}
  var f=window.fetch;
  window.fetch=function(i,n){
    try{
      var base=null;
      if(typeof Request!=='undefined'&&i instanceof Request){
        base=i.headers;
        var nu=px(i.url);
        if(nu!==i.url)i=new Request(nu,i);
      }else{
        i=px(i instanceof URL?i.href:String(i));
      }
      // 今のページのoriginをサーバーに伝える (Origin/Referer の組み立て用。上流には転送されない)
      var n2=Object.assign({},n||{});
      var hh=new Headers(n2.headers||base||undefined);
      hh.set('x-px-page',PO());
      n2.headers=hh;
      n=n2;
    }catch(e){}
    return f.call(this,i,n);
  };
  var xo=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){try{arguments[1]=px(u)}catch(e){}return xo.apply(this,arguments)};
  var xs=XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send=function(b){try{this.setRequestHeader('x-px-page',PO())}catch(e){}return xs.apply(this,arguments)};
  try{var sb=navigator.sendBeacon;if(sb)navigator.sendBeacon=function(u,d){return sb.call(navigator,px(u),d)}}catch(e){}
  try{
    var ESO=window.EventSource;
    if(ESO){var ES=function(u,o){return new ESO(px(u),o)};ES.prototype=ESO.prototype;window.EventSource=ES}
  }catch(e){}
  var wo=window.open;
  window.open=function(u){try{if(u)arguments[0]=px(u)}catch(e){}return wo.apply(this,arguments)};

  // ---- 属性 / プロパティ
  var sa=Element.prototype.setAttribute;
  Element.prototype.setAttribute=function(k,v){
    try{
      var kl=String(k).toLowerCase();
      if(typeof v==='string'){
        if(kl==='srcset'||kl==='imagesrcset')v=rs(v);
        else if(/^(src|href|action|formaction|poster|xlink:href)$/.test(kl))v=px(v);
        else if(kl==='data'&&this.tagName==='OBJECT')v=px(v);
        else if(kl==='style')v=rc(v);
      }
    }catch(e){}
    return sa.call(this,k,v);
  };
  [[HTMLScriptElement,'src'],[HTMLImageElement,'src'],[HTMLAnchorElement,'href'],
   [HTMLLinkElement,'href'],[HTMLIFrameElement,'src'],[HTMLFormElement,'action'],
   [HTMLSourceElement,'src'],[HTMLMediaElement,'src'],[HTMLInputElement,'formaction'],
   [HTMLButtonElement,'formaction'],[HTMLAreaElement,'href'],[HTMLVideoElement,'poster'],
   [HTMLEmbedElement,'src'],[HTMLTrackElement,'src']].forEach(function(p){
    try{
      var d=Object.getOwnPropertyDescriptor(p[0].prototype,p[1]);
      if(d&&d.set)Object.defineProperty(p[0].prototype,p[1],{get:d.get,set:function(v){d.set.call(this,px(v))},configurable:true,enumerable:d.enumerable});
    }catch(e){}
  });
  [[HTMLImageElement,'srcset'],[HTMLSourceElement,'srcset'],[HTMLLinkElement,'imagesrcset']].forEach(function(p){
    try{
      var d=Object.getOwnPropertyDescriptor(p[0].prototype,p[1]);
      if(d&&d.set)Object.defineProperty(p[0].prototype,p[1],{get:d.get,set:function(v){d.set.call(this,rs(v))},configurable:true,enumerable:d.enumerable});
    }catch(e){}
  });

  // ---- CSS内の url() / image-set() を /go/ 形式にする (X のアイコンや画像タイルは background-image で描画される)
  function rc(v){
    if(typeof v!=='string')return v;
    if(v.indexOf('url(')<0&&v.indexOf('image-set(')<0)return v;
    return v
      .replace(/url\(\s*(['"]?)([^'")]*)\1\s*\)/g,function(m,q,u){return 'url('+q+px(u)+q+')'})
      .replace(/image-set\(([^)]*)\)/g,function(m,inner){return 'image-set('+inner.replace(/(["'])([^"']+)\1/g,function(mm,q,u){return q+px(u)+q})+')'});
  }
  // HTML文字列 (innerHTML など) 内の src / href / srcset / style も同様に
  function rh(h){
    if(typeof h!=='string'||h.length<12)return h;
    if(h.indexOf('http')<0&&h.indexOf('//')<0&&h.indexOf('url(')<0)return h;
    h=h.replace(/(\s(?:src|poster|href|action|data)\s*=\s*)(["'])([^"']*)\2/gi,function(m,a,q,u){return a+q+px(u)+q});
    h=h.replace(/(\ssrcset\s*=\s*)(["'])([^"']*)\2/gi,function(m,a,q,u){return a+q+rs(u)+q});
    return rc(h);
  }
  try{
    var CSS_PROPS=['backgroundImage','background','mask','maskImage','webkitMask','webkitMaskImage','borderImage','borderImageSource','listStyle','listStyleImage','content','cursor'];
    [CSSStyleDeclaration.prototype,(window.CSS2Properties&&CSS2Properties.prototype)].forEach(function(P){
      if(!P)return;
      CSS_PROPS.concat(['cssText']).forEach(function(k){
        var d=Object.getOwnPropertyDescriptor(P,k);
        if(d&&d.get&&d.set)Object.defineProperty(P,k,{get:d.get,set:function(v){d.set.call(this,rc(v))},configurable:true,enumerable:d.enumerable});
      });
      var sp=P.setProperty;
      if(sp)P.setProperty=function(n,v,pr){return sp.call(this,n,rc(v),pr)};
    });
  }catch(e){}
  try{
    var ir=CSSStyleSheet.prototype.insertRule;
    CSSStyleSheet.prototype.insertRule=function(r,i){return ir.call(this,rc(r),i)};
    ['replace','replaceSync'].forEach(function(n){
      var o=CSSStyleSheet.prototype[n];
      if(o)CSSStyleSheet.prototype[n]=function(t){return o.call(this,rc(t))};
    });
  }catch(e){}
  try{
    [Element.prototype,(window.ShadowRoot&&ShadowRoot.prototype)].forEach(function(P){
      if(!P)return;
      ['innerHTML','outerHTML'].forEach(function(k){
        var d=Object.getOwnPropertyDescriptor(P,k);
        if(d&&d.get&&d.set)Object.defineProperty(P,k,{get:d.get,set:function(v){d.set.call(this,rh(v))},configurable:true,enumerable:d.enumerable});
      });
    });
    var iah=Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML=function(pos,h){return iah.call(this,pos,rh(h))};
  }catch(e){}
  try{
    var FF0=window.FontFace;
    if(FF0){var FFp=function(f,src,d){return new FF0(f,typeof src==='string'?rc(src):src,d)};FFp.prototype=FF0.prototype;window.FontFace=FFp}
  }catch(e){}

  // ---- document.cookie: プレフィックス付きCookieを素の名前で見せる
  try{
    var CD=Object.getOwnPropertyDescriptor(Document.prototype,'cookie');
    // 「今見ているサイト」を覚える (素のパスでのリロード・相対リンクの振り分け用)
    if(ROOT){try{CD.set.call(document,'pxo='+new URL(T).origin+'; '+CK)}catch(e){}}
    Object.defineProperty(Document.prototype,'cookie',{
      get:function(){
        var u=new URL(T);
        var hp='x'+u.host.replace(/[^a-z0-9]/gi,'_')+'__';
        var hn=u.hostname.toLowerCase().replace(/[^a-z0-9]/g,'_');
        var out=[];
        CD.get.call(document).split(';').forEach(function(p){
          p=p.trim();if(!p)return;
          var i=p.indexOf('=');if(i<1)return;
          var k=p.slice(0,i),v=p.slice(i+1);
          if(k.indexOf('xd_')===0){
            var j=k.indexOf('__');
            if(j>3){var d=k.slice(3,j);if(hn===d||hn.slice(-(d.length+1))==='_'+d)out.push(k.slice(j+2)+'='+v)}
          }else if(k.indexOf(hp)===0){
            out.push(k.slice(hp.length)+'='+v);
          }
        });
        return out.join('; ');
      },
      set:function(s){
        s=String(s);
        var parts=s.split(';'),first=parts[0],i=first.indexOf('=');
        if(i<1)return;
        var name=first.slice(0,i).trim(),val=first.slice(i+1),keep=[],dom=null;
        parts.slice(1).forEach(function(a){
          a=a.trim();
          if(/^(expires|max-age)\s*=/i.test(a))keep.push(a);
          var m=a.match(/^domain\s*=\s*(.+)$/i);
          if(m)dom=m[1].trim().toLowerCase().replace(/^\./,'');
        });
        var u=new URL(T),pre;
        if(dom&&(u.hostname===dom||u.hostname.slice(-(dom.length+1))==='.'+dom))pre='xd_'+dom.replace(/[^a-z0-9]/gi,'_')+'__';
        else pre='x'+u.host.replace(/[^a-z0-9]/gi,'_')+'__';
        CD.set.call(document,[pre+name+'='+val,CK].concat(keep).join('; '));
      },
      configurable:true
    });
  }catch(e){}

  // ---- History: SPAのpushStateでもURLバーは素のパスを維持
  try{
    var hp0=History.prototype.pushState,hr0=History.prototype.replaceState;
    var wrap=function(orig){
      return function(s,t,u){
        try{
          if(u!=null){
            var abs=unpx(String(u)),a=new URL(abs);
            if(a.host===new URL(T).host){T=abs;u=a.pathname+a.search+a.hash}
            else{T=abs;u=px(abs)}
          }
        }catch(e){}
        return orig.call(this,s,t,u);
      };
    };
    History.prototype.pushState=wrap(hp0);
    History.prototype.replaceState=wrap(hr0);
    var sync=function(){
      try{
        if(/^\/go\//.test(location.pathname))return;
        T=new URL(location.pathname+location.search+location.hash,T).href;
      }catch(e){}
    };
    window.addEventListener('popstate',sync,true);
    window.addEventListener('hashchange',sync,true);
  }catch(e){}

  // ---- 生の絶対URLリンク(innerHTML等で作られたもの)を拾う
  document.addEventListener('click',function(e){
    try{
      if(e.defaultPrevented||e.button!==0||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey)return;
      var a=e.target&&e.target.closest?e.target.closest('a[href]'):null;
      if(!a)return;
      var h=a.getAttribute('href');
      if(!h||!/^https?:\/\//i.test(h))return;
      if(new URL(h).origin===O)return;
      e.preventDefault();
      if(a.target==='_blank')window.open(h);else location.href=px(h);
    }catch(err){}
  },true);

  // ---- Navigation API: location.href = "https://..." などプロキシを外れる遷移を /go/ に差し替える (Chromium系)
  try{
    if(window.navigation&&navigation.addEventListener){
      navigation.addEventListener('navigate',function(e){
        try{
          if(!e.cancelable)return;
          var d=new URL(e.destination.url);
          if(d.origin===O||(d.protocol!=='http:'&&d.protocol!=='https:'))return;
          e.preventDefault();
          location.href=px(d.href);
        }catch(err){}
      });
    }
  }catch(e){}

  // ---- Twitter UI モード: x.com / twitter.com のとき、見た目を Twitter 風にする (通信には影響しない)
  //  ・ロゴ(青い鳥) ・タイトル/ファビコン ・「ポスト」→「ツイート」等の用語 ・Grok / Premium など X 固有のメニューを隠す
  //  DOMの変化を監視して、画面が書き換わるたびに適用する。有効なときは <html data-px-twui="1"> が付く
  if(TWUI){
    try{
      if(/(^|\.)(x|twitter)\.com$/.test(new URL(T).hostname)){
        var BIRD='M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z';
        var BLUE='#1d9bf0';
        var TWICON='data:image/svg+xml,'+encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="'+BLUE+'" d="'+BIRD+'"/></svg>');
        var EXACT={'Post':'Tweet','Posts':'Tweets','Repost':'Retweet','Reposts':'Retweets','Post all':'Tweet all','Post your reply':'Tweet your reply'};
        var SKIP='[data-testid="tweetText"],[data-testid="UserDescription"],[data-testid="User-Name"],[data-testid="UserName"],[data-testid="card.wrapper"]';
        var ja=function(t){return t.replace(/リポスト/g,'リツイート').replace(/ポスト/g,'ツイート')};
        document.documentElement.setAttribute('data-px-twui','1');
        var twCss=document.createElement('style');
        twCss.textContent='a[href="/i/grok"],a[href="/i/premium_sign_up"],a[href="/i/verified-orgs-signup"]{display:none!important}';
        (document.head||document.documentElement).appendChild(twCss);

        var fixLogo=function(p){if(p.getAttribute('d')!==BIRD){p.setAttribute('d',BIRD);p.style.fill=BLUE}};
        var fixText=function(nd){
          var tx=nd.nodeValue;
          if(!tx||tx.length>30)return;
          var isEx=EXACT.hasOwnProperty(tx);
          if(!isEx&&tx.indexOf('ポスト')<0)return;
          var pe=nd.parentElement;
          if(pe&&pe.closest&&pe.closest(SKIP))return;
          nd.nodeValue=isEx?EXACT[tx]:ja(tx);
        };
        var twFix=function(root){
          try{
            if(root.nodeType===3){fixText(root);return}
            if(root.nodeType!==1)return;
            if(root.tagName==='path'||root.tagName==='PATH'){
              if((root.getAttribute('d')||'').indexOf('M18.244')===0)fixLogo(root);
              return;
            }
            var ps=root.querySelectorAll('path[d^="M18.244"]');
            for(var j=0;j<ps.length;j++)fixLogo(ps[j]);
            var ls=root.querySelectorAll('[aria-label*="ポスト"]');
            for(var k=0;k<ls.length;k++)ls[k].setAttribute('aria-label',ja(ls[k].getAttribute('aria-label')));
            var wk=document.createTreeWalker(root,NodeFilter.SHOW_TEXT,null),nd;
            while((nd=wk.nextNode()))fixText(nd);
          }catch(e){}
        };
        var fixMeta=function(){
          try{
            var t=document.title,n=(t==='X')?'Twitter':t.replace(/(\s\/\s)X$/,'$1Twitter');
            if(n!==t)document.title=n;
            var lk=document.querySelectorAll('link[rel~="icon"],link[rel="apple-touch-icon"]');
            if(!lk.length&&document.head){var nl=document.createElement('link');nl.rel='icon';document.head.appendChild(nl);lk=[nl]}
            for(var i=0;i<lk.length;i++){if(lk[i].getAttribute('href')!==TWICON){lk[i].removeAttribute('type');lk[i].removeAttribute('sizes');lk[i].setAttribute('href',TWICON)}}
          }catch(e){}
        };
        var metaPending=false;
        var mo=new MutationObserver(function(ms){
          for(var i=0;i<ms.length;i++){
            var m=ms[i];
            if(m.type==='childList'){for(var j=0;j<m.addedNodes.length;j++)twFix(m.addedNodes[j])}
            else if(m.type==='characterData'){fixText(m.target)}
            else if(m.type==='attributes'){twFix(m.target)}
          }
          if(!metaPending){metaPending=true;(window.requestAnimationFrame||setTimeout)(function(){metaPending=false;fixMeta()})}
        });
        mo.observe(document.documentElement,{childList:true,subtree:true,characterData:true,attributes:true,attributeFilter:['d']});
        document.addEventListener('DOMContentLoaded',function(){twFix(document.body);fixMeta()});
        fixMeta();
      }
    }catch(e){}
  }

  // ---- Service Worker / Cache 無効化
  try{
    if(navigator.serviceWorker){
      navigator.serviceWorker.register=function(){return Promise.reject(new Error('disabled by proxy'))};
      navigator.serviceWorker.getRegistration=function(){return Promise.resolve(undefined)};
      navigator.serviceWorker.getRegistrations=function(){return Promise.resolve([])};
      try{Object.defineProperty(navigator.serviceWorker,'ready',{get:function(){return new Promise(function(){})}})}catch(e){}
    }
  }catch(e){}

  // ---- WebSocket / Worker / SharedWorker
  try{
    var WSO=window.WebSocket;
    var WS=function(u,p){return p===undefined?new WSO(pxWs(u)):new WSO(pxWs(u),p)};
    WS.prototype=WSO.prototype;
    WS.CONNECTING=0;WS.OPEN=1;WS.CLOSING=2;WS.CLOSED=3;
    window.WebSocket=WS;
  }catch(e){}
  try{
    var WO=window.Worker;
    if(WO){
      var W=function(u,o){
        var src=px(String(u));
        try{
          var mod=!!(o&&o.type==='module');
          if(WP&&/^blob:/i.test(src)){
            // ページが作った blob worker: 先にパッチを読み込ませてから本来のスクリプトを実行する
            var pu=URL.createObjectURL(new Blob([WP.replace('__T__',function(){return JSON.stringify(T)})],{type:'text/javascript'}));
            var wcode=mod?('import '+JSON.stringify(pu)+';import '+JSON.stringify(src)+';'):('importScripts('+JSON.stringify(pu)+','+JSON.stringify(src)+');');
            src=URL.createObjectURL(new Blob([wcode],{type:'text/javascript'}));
          }else if(FP&&FP.workers&&!mod&&!/^(blob:|data:)/i.test(src)){
            // classic worker の先頭で navigator を偽装してから本来のスクリプトを読み込む
            var code='('+applyNav.toString()+')(self,'+JSON.stringify(FP)+');importScripts('+JSON.stringify(new URL(src,O).href)+');';
            src=URL.createObjectURL(new Blob([code],{type:'text/javascript'}));
          }
        }catch(e){}
        return new WO(src,o);
      };
      W.prototype=WO.prototype;window.Worker=W;
    }
  }catch(e){}
  try{
    var SWO=window.SharedWorker;
    if(SWO){var SW=function(u,o){return new SWO(px(String(u)),o)};SW.prototype=SWO.prototype;window.SharedWorker=SW}
  }catch(e){}

  // ---- document の各種URL (相対解決の基準を対象サイトに)
  try{Object.defineProperty(document,'baseURI',{get:function(){return T},configurable:true})}catch(e){}
  try{Object.defineProperty(document,'URL',{get:function(){return T},configurable:true})}catch(e){}
  try{Object.defineProperty(document,'documentURI',{get:function(){return T},configurable:true})}catch(e){}
})();`;

// ---------- WebSocket ----------
async function handleWebSocket(req, env, url) {
  const m = url.pathname.match(/^\/go\/(wss?)\/([^\/]+)(\/.*)?$/);
  if (!m) return new Response('Bad WS URL', { status: 400 });

  const targetProto = m[1] === 'wss' ? 'https' : 'http';
  let target;
  try {
    target = new URL(`${targetProto}://${m[2]}${m[3] || '/'}${url.search}`);
  } catch (e) {
    return new Response('Bad target URL', { status: 400 });
  }
  if (isBlocked(target, url)) return new Response('Blocked target', { status: 403 });

  const incoming = parseCookies(req.headers.get('cookie'));
  const h = new Headers();
  h.set('upgrade', 'websocket'); // Workersからのfetchで必須
  h.set('user-agent', getCfg(incoming).spoofUa ? FAKE_UA : (req.headers.get('user-agent') || DEFAULT_UA));
  const lang = req.headers.get('accept-language');
  if (lang) h.set('accept-language', lang);
  const proto = req.headers.get('sec-websocket-protocol');
  if (proto) h.set('sec-websocket-protocol', proto);
  let pageOrigin = target.origin;
  try { if (incoming.pxo) pageOrigin = new URL(incoming.pxo).origin; } catch (e) {}
  h.set('origin', pageOrigin);
  const ck = cookiesFor(target, incoming);
  if (ck.length) h.set('cookie', ck.join('; '));

  let upstreamRes;
  try {
    upstreamRes = await fetch(target.toString(), { method: 'GET', headers: h });
  } catch (e) {
    return new Response('Upstream connect failed: ' + String(e.message || e), { status: 502 });
  }

  if (upstreamRes.status !== 101 || !upstreamRes.webSocket) {
    return new Response('Upstream did not upgrade WebSocket (status=' + upstreamRes.status + ')', { status: 502 });
  }

  const upstreamWs = upstreamRes.webSocket;
  upstreamWs.accept();

  const pair = new WebSocketPair();
  const [client, server] = [pair[0], pair[1]];
  server.accept();

  server.addEventListener('message', e => { try { upstreamWs.send(e.data); } catch (_) {} });
  upstreamWs.addEventListener('message', e => { try { server.send(e.data); } catch (_) {} });
  server.addEventListener('close', e => { try { upstreamWs.close(e.code, e.reason); } catch (_) {} });
  upstreamWs.addEventListener('close', e => { try { server.close(e.code, e.reason); } catch (_) {} });
  server.addEventListener('error', () => { try { upstreamWs.close(); } catch (_) {} });
  upstreamWs.addEventListener('error', () => { try { server.close(); } catch (_) {} });

  const respInit = { status: 101, webSocket: client };
  return new Response(null, respInit);
}

// ---------- proxy ----------
const DENY_REQ = new Set([
  'host', 'cookie', 'origin', 'referer', 'content-length', 'connection', 'upgrade',
  'accept-encoding', 'x-real-ip', 'true-client-ip', 'cdn-loop', 'forwarded', 'via',
  'te', 'keep-alive', 'proxy-authorization', 'x-px-page',
]);

const DROP_RES = new Set([
  'set-cookie', 'content-security-policy', 'content-security-policy-report-only',
  'x-frame-options', 'content-length', 'content-encoding', 'transfer-encoding',
  'strict-transport-security', 'report-to', 'nel', 'permissions-policy',
  'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy',
  'alt-svc', 'link', 'vary', 'accept-ch', 'critical-ch',
]);

// fallbackBase: "/go/" 以外のパスが来た時に使う origin (Cookie pxo)
async function handleProxy(req, env, url, fallbackBase) {
  const incoming0 = parseCookies(req.headers.get('cookie'));
  if (!(await isAuthed(req, env, incoming0))) return new Response('Unauthorized', { status: 401 });
  const cfg = getCfg(incoming0);

  const isWsUpgrade = req.headers.get('upgrade') === 'websocket';
  let target;

  if (fallbackBase) {
    if (isWsUpgrade) return new Response('Bad request', { status: 400 });
    try {
      const b = new URL(fallbackBase);
      if (b.protocol !== 'http:' && b.protocol !== 'https:') return new Response('Bad target', { status: 400 });
      target = new URL(b.origin + url.pathname + url.search); // 文字列連結で host すり替えを防ぐ
    } catch (e) {
      return new Response('Bad target', { status: 400 });
    }
  } else {
    if (isWsUpgrade) return handleWebSocket(req, env, url);
    const m = url.pathname.match(/^\/go\/(https?)\/([^\/]+)(\/.*)?$/);
    if (!m) return new Response('Bad proxy URL', { status: 400 });
    try {
      target = new URL(`${m[1]}://${m[2]}${m[3] || '/'}${url.search}`);
    } catch (e) {
      return new Response('Bad target URL', { status: 400 });
    }
  }
  if (isBlocked(target, url, true)) return new Response('Blocked target', { status: 403 });

  const incoming = incoming0;
  const realDest = req.headers.get('sec-fetch-dest') || 'empty';
  // iframe / frame / embed / object 由来のナビゲーションは、上流には通常のページ遷移(document)として見せる
  const framed = realDest === 'iframe' || realDest === 'frame' || realDest === 'embed' || realDest === 'object';
  const dest = framed ? 'document' : realDest;
  const hasBody = req.method !== 'GET' && req.method !== 'HEAD';

  // ページ側のorigin (Origin / Referer / Sec-Fetch-Site の判定用)
  // fetch/XHR はブラウザ側パッチが x-px-page でページのoriginを毎回伝えてくる(別タブで別サイトを開いていても混ざらない)。
  // 画像やスクリプトなど素のリクエストは Cookie pxo(最後に開いたサイト)で代用する
  let pageOrigin = target.origin;
  try {
    const ph = req.headers.get('x-px-page');
    const po = ph || incoming.pxo;
    if (po) {
      const pu = new URL(po);
      if (pu.protocol === 'http:' || pu.protocol === 'https:') pageOrigin = pu.origin;
    }
  } catch (e) {}

  // ---- リクエストヘッダ: 原則すべて転送 (x-csrf-token, x-twitter-*, authorization 等)
  const h = new Headers();
  for (const [k, v] of req.headers) {
    const kl = k.toLowerCase();
    if (DENY_REQ.has(kl) || kl.startsWith('cf-') || kl.startsWith('x-forwarded-') || kl.startsWith('sec-fetch-')) continue;
    // Firefox は Client Hints(sec-ch-ua*) を送らない。Chromium固有の x-client-data も落とす
    if (cfg.spoofUa && (kl.startsWith('sec-ch-') || kl === 'x-client-data')) continue;
    h.set(k, v);
  }
  if (cfg.spoofUa) {
    h.set('user-agent', FAKE_UA);
    if (dest === 'document') h.set('accept', FF_ACCEPT_DOC);
    else if (dest === 'image') h.set('accept', FF_ACCEPT_IMG);
  } else if (!h.get('user-agent')) {
    h.set('user-agent', DEFAULT_UA);
  }
  if (hasBody || req.headers.get('origin')) h.set('origin', pageOrigin);
  h.set('referer', pageOrigin + '/');

  let site = 'same-origin';
  if (realDest === 'document') site = 'none';
  else if (new URL(pageOrigin).host !== target.host) {
    site = registrableDomain(new URL(pageOrigin).hostname) === registrableDomain(target.hostname) ? 'same-site' : 'cross-site';
  }
  h.set('sec-fetch-site', site);
  h.set('sec-fetch-mode', req.headers.get('sec-fetch-mode') || 'cors');
  h.set('sec-fetch-dest', dest);
  if (framed) h.set('sec-fetch-user', '?1');

  if (target.username || target.password) {
    try {
      const creds = decodeURIComponent(target.username || '') + ':' + decodeURIComponent(target.password || '');
      h.set('authorization', 'Basic ' + btoa(creds));
    } catch (e) {}
  }

  // CDN上の静的ファイルにCookieを付けると、キャッシュが効かず遅くなる。クロスサイトの静的GETには付けない
  // (同一サイトの ton.x.com 等のDM画像のように認証が要るものは site が same-site なので従来どおり送る)
  const isStaticGet = req.method === 'GET' && STATIC_DESTS.has(dest);
  // URLが「静的ファイルらしい」場合だけキャッシュ対象にする (js_inst のようなセッション毎に変わるスクリプトを除外)
  const looksStatic = /twimg\.com$/i.test(target.hostname) ||
    /\.(js|mjs|css|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf)$/i.test(target.pathname);
  const ck = cookiesFor(target, incoming);
  if (ck.length) h.set('cookie', ck.join('; '));

  // 本文(画像アップロードのmultipartなど)は、サイズが分かる場合はバッファして Content-Length 付きで送る
  // (ストリーム転送だと chunked になり、upload系のAPIが拒否することがある)
  let reqBody;
  if (hasBody) {
    const cl = parseInt(req.headers.get('content-length') || '', 10);
    reqBody = (Number.isFinite(cl) && cl <= 90 * 1024 * 1024) ? await req.arrayBuffer() : req.body;
  }

  // 公開の静的ファイルだけエッジにキャッシュ (個人宛の応答は混ざらないよう Cookie等が付く場合は除外)
  const cacheable = cfg.edgeCache && STATIC_CACHE_TTL > 0 && isStaticGet && looksStatic && CACHE_DESTS.has(dest) &&
    !ck.length && !h.has('range') && !h.has('authorization');
  let res;
  if (target.host === url.host) {
    // 同一オリジン(このWorker自身のページ)は外へ出ず、内部のルーターで処理する (無限ループ防止に深さを制限)
    const depth = parseInt(req.headers.get('x-px-depth') || '0', 10);
    if (depth >= 2) return new Response('Too many nested requests', { status: 508 });
    const lh = new Headers(req.headers);
    lh.delete('x-px-page');
    lh.set('x-px-depth', String(depth + 1));
    try {
      res = await router(new Request(url.origin + target.pathname + target.search, { method: req.method, headers: lh, body: reqBody }), env);
    } catch (e) {
      return htmlRes('<h3>内部処理に失敗しました</h3><p>' + String(e.message || e).replace(/</g, '&lt;') + '</p>', 502);
    }
  } else {
    try {
      res = await fetch(target.toString(), {
        method: req.method,
        headers: h,
        body: reqBody,
        redirect: 'manual',
        cf: cacheable ? {
          cacheEverything: true,
          cacheTtlByStatus: { '200-299': STATIC_CACHE_TTL, '404': 60, '500-599': 0 },
        } : undefined,
      });
    } catch (e) {
      return htmlRes('<h3>接続に失敗しました</h3><p>' + String(e.message || e).replace(/</g, '&lt;') + '</p>', 502);
    }
  }

  // Cloudflareの制限: 同じアカウントの *.workers.dev(同一ゾーン)の別Workerへは、互換性フラグ無しでは fetch できない(エラー 1042)
  if (res.status >= 400 && /\.workers\.dev$/i.test(target.hostname) && target.host !== url.host) {
    try {
      const cl = parseInt(res.headers.get('content-length') || '0', 10);
      if (!cl || cl < 2000) {
        const et = await res.clone().text();
        if (/error code:?\s*1042/i.test(et.slice(0, 400))) {
          return htmlRes('<!doctype html><meta charset="utf-8"><title>接続できません</title><div style="font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 20px;line-height:1.8">' +
            '<h3>同じアカウントの別Workerには、そのままでは接続できません (Cloudflare エラー 1042)</h3>' +
            '<p>このプロキシ用Workerに、互換性フラグ <code>global_fetch_strictly_public</code> を追加してください。</p>' +
            '<p>wrangler: <code>compatibility_flags = ["global_fetch_strictly_public"]</code><br>' +
            'ダッシュボード: Workers &amp; Pages → このWorker → 設定 → ランタイム → 互換性フラグ</p></div>', 502);
        }
      }
    } catch (e) {}
  }

  const out = new Headers();
  res.headers.forEach((v, k) => { if (!DROP_RES.has(k.toLowerCase())) out.set(k, v); });

  const loc = res.headers.get('location');
  if (loc) out.set('location', proxify(loc, target.toString()));

  // ---- Set-Cookie をプレフィックス付きに付け替え
  const setCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  for (const c of setCookies) {
    const parts = c.split(';');
    const eq = parts[0].indexOf('=');
    if (eq < 1) continue;
    const name = parts[0].slice(0, eq).trim();
    const value = parts[0].slice(eq + 1);
    const attrs = parts.slice(1).map(p => p.trim());
    const keep = attrs.filter(p => /^(expires|max-age)\s*=/i.test(p));

    let domainAttr = null;
    for (const a of attrs) {
      const dm = a.match(/^domain\s*=\s*(.+)$/i);
      if (dm) { domainAttr = dm[1].trim().toLowerCase().replace(/^\./, ''); break; }
    }

    const hostLower = target.hostname.toLowerCase();
    let pre;
    if (domainAttr && (hostLower === domainAttr || hostLower.endsWith('.' + domainAttr))) {
      pre = 'xd_' + domainAttr.replace(/[^a-z0-9]/gi, '_') + '__';
    } else {
      pre = cookiePrefix(target.host);
    }
    out.append('set-cookie', [pre + name + '=' + value, COOKIE_FLAGS, ...keep].join('; '));
  }

  const ct = (res.headers.get('content-type') || '').toLowerCase();
  const base = target.toString();
  const isHtml = ct.includes('text/html');

  out.set('x-robots-tag', 'noindex');
  // "/go/<url>" は URL が一意なので静的ファイルは上流のcache-controlを尊重。
  // HTML と fallback(パスだけのURL、ホストが変わりうる) は no-store
  if (isHtml || fallbackBase) out.set('cache-control', 'no-store');

  // トップレベル遷移のHTMLなら「今どのサイトを見ているか」を覚える
  if (isHtml && realDest === 'document') { // iframe内の遷移ではサーバー側では更新しない(クライアントJSが設定する)
    out.append('set-cookie', 'pxo=' + target.origin + '; ' + COOKIE_FLAGS);
  }

  // Web Worker / SharedWorker のスクリプトには、通信をプロキシへ向けるパッチを先頭に付ける
  if (cfg.workerPatch && (dest === 'worker' || dest === 'sharedworker') && res.status === 200) {
    const wtext = await res.text();
    return new Response(workerPatchFor(base) + wtext, { status: res.status, headers: out });
  }

  if (isHtml) {
    if (cfg.strictCsp) {
      // 書き換え漏れのURLがあっても、ブラウザがプロキシを通さず直接接続しないように遮断する
      const hh = url.host;
      out.set('content-security-policy', [
        "default-src 'self' data: blob:",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: data:",
        "style-src 'self' 'unsafe-inline' data:",
        "img-src 'self' data: blob:" + (CSP_ALLOW_REMOTE_MEDIA ? ' https:' : ''),
        "media-src 'self' data: blob:" + (CSP_ALLOW_REMOTE_MEDIA ? ' https:' : ''),
        "font-src 'self' data:" + (CSP_ALLOW_REMOTE_MEDIA ? ' https:' : ''),
        "connect-src 'self' data: blob: ws://" + hh + " wss://" + hh,
        "frame-src 'self' data: blob:",
        "worker-src 'self' blob: data:",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
      ].join('; '));
    }
    let injected = false;
    const inject = {
      element(e) {
        if (injected) return;
        injected = true;
        const tJson = JSON.stringify(base).replace(/</g, '\\u003c').replace(/-->/g, '--\\u003e');
        const js = CLIENT_JS
          .replace('__T__', () => tJson)
          .replace('__CK__', () => JSON.stringify(COOKIE_FLAGS))
          .replace('__RTC__', () => (cfg.blockWebrtc ? 'true' : 'false'))
          .replace('__FP__', () => JSON.stringify(cfg.spoofUa ? FP_PROFILE : null))
          .replace('__TWUI__', () => (cfg.twitterUi ? 'true' : 'false'))
          .replace('__WP__', () => (cfg.workerPatch ? JSON.stringify(WORKER_PATCH_SRC).replace(/</g, '\u003c') : 'null'));
        e.prepend('<script>' + js + '</script>', { html: true });
      },
    };
    const U = a => new Attr(a, v => proxify(v, base));
    const rw = new HTMLRewriter()
      .on('head', inject)
      .on('html', inject)
      .on('base', { element(e) { e.remove(); } })
      .on('a[href],link[href],area[href]', U('href'))
      .on('img[src],script[src],iframe[src],frame[src],source[src],video[src],audio[src],embed[src],track[src],input[src]', U('src'))
      .on('video[poster]', U('poster'))
      .on('form[action]', U('action'))
      .on('button[formaction],input[formaction]', U('formaction'))
      .on('img[srcset],source[srcset]', new Attr('srcset', v => rewriteSrcset(v, base)))
      .on('link[imagesrcset]', new Attr('imagesrcset', v => rewriteSrcset(v, base)))
      .on('[style]', new Attr('style', v => rewriteCss(v, base)))
      .on('style', new StyleText(base))
      .on('script[integrity],link[integrity]', { element(e) { e.removeAttribute('integrity'); } })
      .on('meta[http-equiv]', {
        element(e) {
          const eq = (e.getAttribute('http-equiv') || '').toLowerCase();
          if (eq === 'refresh') {
            const c = e.getAttribute('content') || '';
            e.setAttribute('content', c.replace(/(url\s*=\s*)(['"]?)([^'";]+)\2/i, (mm, a, q, u) => a + q + proxify(u, base) + q));
          } else if (eq === 'content-security-policy') {
            e.remove();
          }
        },
      })
      .on('link[rel~=manifest]', { element(e) { e.remove(); } })
      .on('link[rel~=serviceworker]', { element(e) { e.remove(); } });
    if (cfg.twitterUi && isXHost(target.hostname)) {
      rw.on('path', { element(e) { const d = e.getAttribute('d'); if (d && d.startsWith('M18.244')) e.setAttribute('d', TW_BIRD); } });
      rw.on('html', { element(e) { e.setAttribute('data-px-twui', '1'); } });
    }
    return rw.transform(new Response(res.body, { status: res.status, headers: out }));
  }

  if (ct.includes('text/css')) {
    const css = await res.text();
    return new Response(rewriteCss(css, base), { status: res.status, headers: out });
  }

  // HLS プレイリスト: 中のURL(特に "/ext_tw_video/..." のようなルート相対パス)を /go/ 形式にする
  if (ct.includes('mpegurl') || /\.m3u8$/i.test(target.pathname)) {
    const text = await res.text();
    return new Response(rewriteM3u8(text, base), { status: res.status, headers: out });
  }

  // JS・画像・動画・JSON などは本文に触れずストリームでそのまま返す
  // (URLの付け替えはブラウザ側の fetch / setAttribute / WebSocket パッチが実行時に行う)
  const clen = res.headers.get('content-length');
  if (clen && !res.headers.get('content-encoding') && (res.status === 200 || res.status === 206) &&
      /^(image|video|audio|font)\//.test(ct)) {
    out.set('content-length', clen); // 動画のシーク・Range再生に必要
  }
  return new Response(res.body, { status: res.status, headers: out });
}

// ---------- Cookie API (元のまま) ----------
async function handleCookieApi(req, env, url) {
  if (!(await isAuthed(req, env))) return new Response('Unauthorized', { status: 401 });

  if (req.method === 'GET') {
    const all = parseCookies(req.headers.get('cookie'));
    const list = [];
    for (const k in all) {
      let type = 'host', scope = '';
      if (k.startsWith('xd_')) {
        type = 'domain';
        const m = k.match(/^xd_(.+?)__(.+)$/);
        if (m) scope = m[1].replace(/_/g, '.');
      } else if (k.startsWith('x')) {
        const m = k.match(/^x(.+?)__(.+)$/);
        if (m) {
          type = 'host';
          scope = m[1].replace(/_/g, '.');
        }
      }
      if (type === 'host' || type === 'domain') {
        const nameStart = k.indexOf('__') + 2;
        if (nameStart < 2) continue;
        list.push({ type, scope, name: k.slice(nameStart), value: all[k] });
      }
    }
    return Response.json({ cookies: list });
  }

  if (req.method === 'POST') {
    let body;
    try { body = await req.json(); } catch (e) { return Response.json({ error: 'bad json' }, { status: 400 }); }
    const { host, cookies } = body;
    if (host != null && typeof host !== 'string') return Response.json({ error: 'invalid host' }, { status: 400 });
    if (!cookies || typeof cookies !== 'string') return Response.json({ error: 'cookies required' }, { status: 400 });

    const setHeaders = [];
    let parsed = [];
    try {
      const j = JSON.parse(cookies);
      if (Array.isArray(j)) parsed = j;
    } catch (e) {
      cookies.split(';').forEach(p => {
        const i = p.indexOf('=');
        if (i > 0) parsed.push({ name: p.slice(0, i).trim(), value: p.slice(i + 1).trim() });
      });
    }

    // host は省略可。JSONの各Cookieに domain があれば、それを使う(エクスポートしたJSONをそのまま戻せる)
    let targetHost = '';
    let hostLower = '';
    if (host && host.trim()) {
      try {
        const hh = host.trim();
        const u = new URL(/^https?:\/\//.test(hh) ? hh : 'https://' + hh);
        targetHost = u.host;
        hostLower = u.hostname.toLowerCase();
      } catch (e) {
        return Response.json({ error: 'invalid host' }, { status: 400 });
      }
    }

    // ブラウザのDevToolsから取ったCookieは通常「.x.com」のドメインCookie。
    // ホスト限定で保存すると upload.x.com / api.x.com に認証Cookieが届かず、画像投稿などが失敗する。
    // → hostOnly:true のものだけホスト限定、それ以外はドメインCookieとして保存する
    parsed.forEach(c => {
      if (!c || !c.name) return;
      const v = c.value != null ? String(c.value) : '';
      const dom = c.domain ? String(c.domain).toLowerCase().replace(/^\./, '') : '';
      let usePre = null;
      if (c.hostOnly === true) {
        if (dom || targetHost) usePre = cookiePrefix(dom || targetHost);
      } else if (dom && (!hostLower || hostLower === dom || hostLower.endsWith('.' + dom))) {
        usePre = 'xd_' + dom.replace(/[^a-z0-9]/gi, '_') + '__';
      } else if (hostLower) {
        usePre = 'xd_' + registrableDomain(hostLower).replace(/[^a-z0-9]/gi, '_') + '__';
      }
      if (!usePre) return;
      setHeaders.push([usePre + c.name + '=' + v, COOKIE_FLAGS, 'Max-Age=2592000'].join('; '));
    });
    if (!setHeaders.length) {
      return Response.json({ error: '対象ホストを入力してください(または domain 付きのJSONを貼ってください)' }, { status: 400 });
    }

    const respHeaders = new Headers({ 'content-type': 'application/json' });
    setHeaders.forEach(s => respHeaders.append('set-cookie', s));
    return new Response(JSON.stringify({ ok: true, count: setHeaders.length, host: targetHost || '' }), { headers: respHeaders });
  }

  if (req.method === 'DELETE') {
    let body = {};
    try { body = await req.json(); } catch (e) {}
    const host = body.host;
    const incoming = parseCookies(req.headers.get('cookie'));
    const respHeaders = new Headers({ 'content-type': 'application/json' });
    for (const k in incoming) {
      if (k.startsWith('x') || k.startsWith('xd_')) {
        if (host) {
          const hostPre = cookiePrefix(host);
          const domPre = cookieDomainPrefix(host);
          if (!k.startsWith(hostPre) && !k.startsWith(domPre)) continue;
        }
        respHeaders.append('set-cookie', k + '=; Path=/; Max-Age=0');
      }
    }
    return new Response(JSON.stringify({ ok: true }), { headers: respHeaders });
  }

  return new Response('Method not allowed', { status: 405 });
}

// ---------- ページ本体 ----------
const COOKIE_PAGE = String.raw`<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cookie管理</title>
<style>
:root{--bg:#faf7f2;--card:#fff;--ink:#3b3631;--sub:#8a8178;--accent:#c98a5b;--line:#eee7dc}
@media(prefers-color-scheme:dark){:root{--bg:#1d1b19;--card:#262320;--ink:#e9e3da;--sub:#9d958b;--accent:#d9a074;--line:#37322d}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.7 "Hiragino Sans","Yu Gothic",system-ui,sans-serif;padding:20px}
.wrap{max-width:760px;margin:0 auto}
h1{font-size:1.3rem;color:var(--accent);margin:0 0 6px}
p.sub{color:var(--sub);font-size:.85rem;margin:0 0 18px}
a{color:var(--accent)}
.box{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:18px}
.box h2{margin:0 0 10px;font-size:1rem;color:var(--ink)}
label{display:block;font-size:.85rem;color:var(--sub);margin:8px 0 4px}
input,textarea{width:100%;padding:9px 12px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--ink);font:inherit}
textarea{min-height:120px;resize:vertical;font-family:ui-monospace,Consolas,monospace;font-size:13px}
button{padding:9px 18px;border-radius:8px;border:0;cursor:pointer;font:inherit;background:var(--accent);color:#fff;margin-top:8px}
button.sec{background:var(--bg);color:var(--sub);border:1px solid var(--line)}
.row{display:flex;gap:8px}
#msg{color:#c0504d;font-size:.85rem;min-height:1.2em;margin-top:8px}
#ok{color:#3a8a3a;font-size:.85rem;min-height:1.2em;margin-top:8px}
ul{margin:8px 0;padding-left:1.2em}
ul li{margin:4px 0;font-size:.85rem;color:var(--sub);word-break:break-all}
.tbl{width:100%;border-collapse:collapse;font-size:.8rem;margin-top:8px}
.tbl th,.tbl td{border:1px solid var(--line);padding:6px 8px;text-align:left}
.tbl th{background:var(--bg);color:var(--sub);font-weight:500}
code{background:var(--bg);padding:1px 5px;border-radius:4px;font-size:.85em}
</style>
</head>
<body>
<div class="wrap">
<h1>Cookie管理</h1>
<p class="sub">プロキシ経由で保持しているCookieの一覧とインポートができます。ブラウザからエクスポートしたCookieを貼り付けることで、ログイン状態をプロキシに引き継げます。</p>

<div class="box">
<h2>現在のCookie一覧</h2>
<div id="list"><p style="color:var(--sub);font-size:.85rem">読み込み中…</p></div>
<div class="row" style="margin-top:10px"><button class="sec" id="del">選択hostを削除</button> <button class="sec" id="delall">全削除</button> <button class="sec" id="ref">再読込</button></div>
</div>

<div class="box">
<h2>Cookie をインポート</h2>
<label>対象ホスト (例: twitter.com)</label>
<input id="host" placeholder="twitter.com" autocomplete="off" spellcheck="false">
<label>Cookie文字列 または JSON配列</label>
<textarea id="ck" placeholder='auth_token=abc123; ct0=xyz456; ...&#10;または&#10;[{"name":"auth_token","value":"abc123"},{"name":"ct0","value":"xyz456","domain":".twitter.com"}]'></textarea>
<button id="imp">インポート</button>
<div id="msg"></div><div id="ok"></div>
</div>

<div class="box">
<h2>使い方</h2>
<ul>
<li>ブラウザの DevTools (F12) → Application → Cookies から対象サイトの Cookie をコピーし、<code>name=value; name2=value2</code> 形式で貼り付けます。</li>
<li>ブラウザ拡張 (Cookie-Editor 等) から JSON 形式でエクスポートした内容もそのまま貼り付けられます。</li>
<li>X (Twitter) でログイン状態にするには <code>auth_token</code> と <code>ct0</code> があれば足ります。CSRF トークン <code>ct0</code> はAPIリクエスト時に必須です。</li>
<li>インポート後は <a href="/go/https/x.com/">/go/https/x.com/</a> のように直接プロキシURLを開けばログイン済み状態で表示されます。</li>
</ul>
</div>
<p style="text-align:center"><a href="/">← ブログに戻る</a></p>
</div>
<script>
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
async function load(){
  var r=await fetch('/api/cookies',{cache:'no-store'});
  var d=await r.json();
  var el=document.getElementById('list');
  if(!d.cookies||!d.cookies.length){el.innerHTML='<p style="color:var(--sub);font-size:.85rem">Cookieはありません</p>';return}
  var byHost={};
  d.cookies.forEach(function(c){
    var key=c.type==='domain'?'*.'+c.scope:c.scope||'(unknown)';
    (byHost[key]=byHost[key]||[]).push(c);
  });
  var h='<table class="tbl"><thead><tr><th>Host</th><th>Name</th><th>Value (先頭20文字)</th><th>Type</th></tr></thead><tbody>';
  Object.keys(byHost).sort().forEach(function(k){
    byHost[k].forEach(function(c,i){
      h+='<tr><td>'+(i===0?'<input type="checkbox" class="hk" data-host="'+esc(c.scope)+'"> '+esc(k):'')+'</td><td><code>'+esc(c.name)+'</code></td><td><code>'+esc((c.value||'').slice(0,20))+'</code></td><td>'+esc(c.type)+'</td></tr>';
    });
  });
  h+='</tbody></table>';
  el.innerHTML=h;
}
document.getElementById('ref').onclick=load;
document.getElementById('del').onclick=async function(){
  var hs=Array.prototype.slice.call(document.querySelectorAll('.hk:checked')).map(function(c){return c.dataset.host});
  if(!hs.length){alert('行を選択してください');return}
  for(var i=0;i<hs.length;i++){
    await fetch('/api/cookies',{method:'DELETE',headers:{'content-type':'application/json'},body:JSON.stringify({host:hs[i]})});
  }
  load();
};
document.getElementById('delall').onclick=async function(){
  if(!confirm('すべてのプロキシCookieを削除しますか？'))return;
  await fetch('/api/cookies',{method:'DELETE',headers:{'content-type':'application/json'},body:JSON.stringify({})});
  load();
};
document.getElementById('imp').onclick=async function(){
  var msg=document.getElementById('msg'),ok=document.getElementById('ok');
  msg.textContent='';ok.textContent='';
  var host=document.getElementById('host').value.trim();
  var ck=document.getElementById('ck').value;
  if(!host){msg.textContent='hostを入力してください';return}
  if(!ck.trim()){msg.textContent='Cookieを入力してください';return}
  try{
    var r=await fetch('/api/cookies',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({host:host,cookies:ck})});
    var d=await r.json();
    if(!r.ok){msg.textContent=d.error||('HTTP '+r.status);return}
    ok.textContent=d.count+' 個のCookieを '+d.host+' に保存しました';
    document.getElementById('ck').value='';
    load();
  }catch(e){msg.textContent=String(e)}
};
load();
</script>
</body>
</html>`;

const BLOG = String.raw`<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ひだまりノート | 日々のささやかな記録</title>
<style>
:root{--bg:#faf7f2;--card:#fff;--ink:#3b3631;--sub:#8a8178;--accent:#c98a5b;--line:#eee7dc}
@media(prefers-color-scheme:dark){:root{--bg:#1d1b19;--card:#262320;--ink:#e9e3da;--sub:#9d958b;--accent:#d9a074;--line:#37322d}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.85 "Hiragino Sans","Yu Gothic",system-ui,sans-serif}
header{border-bottom:1px solid var(--line);background:var(--card)}
.wrap{max-width:960px;margin:0 auto;padding:0 20px}
.hd{display:flex;align-items:center;justify-content:space-between;padding:22px 0}
.logo{font-size:1.4rem;font-weight:700;letter-spacing:.08em;color:var(--accent);text-decoration:none}
.logo small{display:block;font-size:.7rem;font-weight:400;color:var(--sub);letter-spacing:.15em}
nav a{margin-left:20px;color:var(--sub);text-decoration:none;font-size:.9rem}
nav a:hover{color:var(--accent)}
.grid{display:grid;grid-template-columns:1fr 260px;gap:32px;padding:36px 0}
@media(max-width:760px){.grid{grid-template-columns:1fr}}
article{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:26px 28px;margin-bottom:24px}
article h2{margin:.2em 0 .3em;font-size:1.25rem}
.meta{font-size:.8rem;color:var(--sub)}
.tag{display:inline-block;font-size:.72rem;padding:1px 10px;border-radius:99px;background:var(--bg);border:1px solid var(--line);margin-right:6px;color:var(--sub)}
aside .box{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;margin-bottom:20px;font-size:.9rem}
aside h3{margin:0 0 .6em;font-size:.95rem;color:var(--accent)}
aside ul{margin:0;padding-left:1.1em;color:var(--sub)}
footer{border-top:1px solid var(--line);padding:30px 0 50px;text-align:center;color:var(--sub);font-size:.82rem}
#ov{position:fixed;inset:0;background:rgba(0,0,0,.45);display:none;align-items:center;justify-content:center;z-index:50;padding:20px}
#ov.on{display:flex}
#box{background:var(--card);border-radius:16px;padding:26px;width:100%;max-width:460px;max-height:92vh;overflow:auto;box-shadow:0 20px 60px rgba(0,0,0,.35)}
#ov.on #box{animation:pop .2s ease-out}
@keyframes pop{from{opacity:0}to{opacity:1}}
#box h3{margin:0 0 4px;color:var(--accent)}
#box p{margin:0 0 14px;font-size:.82rem;color:var(--sub)}
#box input{width:100%;padding:11px 14px;border-radius:10px;border:1px solid var(--line);background:var(--bg);color:var(--ink);font:inherit;margin-bottom:10px}
#box .row{display:flex;gap:8px;justify-content:space-between}
#box .row .btns{display:flex;gap:8px}
#box button{padding:9px 18px;border-radius:10px;border:0;cursor:pointer;font:inherit}
#go{background:var(--accent);color:#fff}
#cl,#ck{background:var(--bg);color:var(--sub)}
#ck{border:1px solid var(--line)}
#msg{color:#c0504d;font-size:.82rem;min-height:1.2em;margin:0 0 6px}
#recents{margin-top:14px;font-size:.8rem;color:var(--sub);max-height:140px;overflow:auto}
#recents a{display:block;color:var(--sub);text-decoration:none;padding:5px 8px;border-radius:6px}
#recents a:hover{background:var(--bg)}
#box textarea{width:100%;min-height:120px;resize:vertical;padding:10px 12px;border-radius:10px;border:1px solid var(--line);background:var(--bg);color:var(--ink);font:12px/1.5 ui-monospace,Consolas,monospace;margin-bottom:10px}
#cp{margin-top:12px;padding-top:12px;border-top:1px solid var(--line)}
#cp .row2{display:flex;gap:6px;flex-wrap:wrap}
#cp .row2 button{padding:7px 12px;font-size:.8rem;background:var(--bg);color:var(--sub);border:1px solid var(--line)}
#cp .row2 #ci{background:var(--accent);color:#fff;border-color:var(--accent)}
#cm{font-size:.8rem;min-height:1.2em;margin-top:8px;word-break:break-all}
</style>
</head>
<body>
<header><div class="wrap hd">
<a class="logo" href="/">ひだまりノート<small>HIDAMARI NOTE</small></a>
<nav><a href="#">ホーム</a><a href="#">記事一覧</a><a href="#">about</a></nav>
</div></header>

<div class="wrap grid">
<main>
<article>
<div class="meta"><span class="tag">日常</span>2026.10.03</div>
<h2>朝の珈琲と、少し遅い秋のはじまり</h2>
<p>ようやく朝晩が涼しくなってきて、毎朝のコーヒーがおいしく感じる季節になりました。最近は豆を少しだけ粗めに挽いて、ゆっくり時間をかけて落とすのがお気に入りです。</p>
<p>窓を開けると金木犀の香りがふわり。何でもない朝が、ちょっとだけ特別になる気がします。</p>
</article>
<article>
<div class="meta"><span class="tag">読書</span>2026.09.27</div>
<h2>積読を崩す週末──今月読んだ本3冊</h2>
<p>気づけば本棚の「あとで読む」コーナーが限界を迎えていたので、思い切って週末を読書デーにしました。エッセイ、短編集、そして古い旅行記。ジャンルがばらばらなのがまた楽しいところです。</p>
</article>
<article>
<div class="meta"><span class="tag">おでかけ</span>2026.09.19</div>
<h2>近所の小さな古書店で見つけたもの</h2>
<p>駅から少し離れた路地裏にある古書店。店主のおばあさんが淹れてくれた麦茶が忘れられません。また行きたいお店がひとつ増えました。</p>
</article>
</main>
<aside>
<div class="box"><h3>プロフィール</h3>ひだまりでのんびり暮らしています。日々の小さな発見を綴るブログです。</div>
<div class="box"><h3>カテゴリ</h3><ul><li>日常 (12)</li><li>読書 (8)</li><li>おでかけ (5)</li><li>ごはん (9)</li></ul></div>
<div class="box"><h3>アーカイブ</h3><ul><li>2026年10月</li><li>2026年9月</li><li>2026年8月</li></ul></div>
</aside>
</div>

<footer>
<div class="wrap"><span id="open" style="cursor:default;user-select:none;-webkit-user-select:none;-webkit-tap-highlight-color:transparent;touch-action:manipulation">©</span> 2026 ひだまりノート</div>
</footer>

<div id="ov"><div id="box">
<h3>ひとやすみ</h3>
<p>開きたいURL、または検索ワードを入力してください。</p>
<input id="key" type="password" placeholder="合言葉" style="display:none" autocomplete="off">
<input id="u" type="text" placeholder="https://example.com" autocomplete="off" spellcheck="false">
<div id="msg"></div>
<div id="recents"></div>
<div id="cp" style="display:none">
<input id="ch" type="text" placeholder="対象ホスト (例: x.com)　JSONにdomainがあれば空欄可 / エクスポート時は絞り込み" autocomplete="off" spellcheck="false">
<textarea id="ct" placeholder="auth_token=xxx; ct0=yyy&#10;または JSON配列 (Cookie-Editor形式 / エクスポートした内容)" spellcheck="false"></textarea>
<div class="row2"><button id="ci">インポート</button><button id="ce">エクスポート</button><button id="cc">コピー</button><button id="cd">保存</button><button id="cfb">ファイル</button><input type="file" id="cf" accept=".json,.txt,application/json,text/plain" style="display:none"></div>
<div id="cm"></div>
<div style="margin-top:6px"><a href="/i/fj/setting-page" style="color:var(--sub);font-size:.78rem">設定ページ</a>　<a href="/cookies" style="color:var(--sub);font-size:.78rem">一覧・削除</a></div>
</div>
<div class="row" style="margin-top:12px"><button id="ck">Cookie</button><div class="btns"><button id="cl">閉じる</button><button id="go">開く</button></div></div>
</div></div>

<script>
(function(){
  var ov=document.getElementById('ov'),u=document.getElementById('u'),key=document.getElementById('key'),msg=document.getElementById('msg'),recents=document.getElementById('recents');
  var locked=false,authed=true,busy=false;
  function status(){return fetch('/api/status',{cache:'no-store'}).then(function(r){return r.json()}).then(function(s){locked=s.locked;authed=s.authed;key.style.display=(locked&&!authed)?'block':'none'}).catch(function(){})}
  status();
  function loadRecents(){
    try{
      var arr=JSON.parse(localStorage.getItem('pxrecents')||'[]');
      if(arr.length){recents.innerHTML='<div style="font-size:.75rem;color:var(--sub);margin-bottom:4px">最近開いたページ</div>'+arr.map(function(r){return '<a href="'+esc(r.url)+'">'+esc(r.label)+'</a>'}).join('')}
    }catch(e){}
  }
  function pushRecent(url,label){try{var arr=JSON.parse(localStorage.getItem('pxrecents')||'[]');arr=arr.filter(function(r){return r.url!==url});arr.unshift({url:url,label:label});arr=arr.slice(0,8);localStorage.setItem('pxrecents',JSON.stringify(arr))}catch(e){}}
  function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
  function show(){if(ov.classList.contains('on'))return;ov.classList.add('on');msg.textContent='';loadRecents();(locked&&!authed?key:u).focus({preventScroll:true})}
  function hide(){ov.classList.remove('on')}
  function toUrl(v){v=v.trim();if(!v)return null;if(/^https?:\/\//i.test(v))return v;if(/^[\w-]+(\.[\w-]+)+(\/|$|:|\?)/.test(v))return 'https://'+v;return 'https://duckduckgo.com/html/?q='+encodeURIComponent(v)}
  function go(){
    if(busy)return;busy=true;
    try{run()}finally{busy=false}
  }
  function run(){
    msg.textContent='';
    var t=toUrl(u.value);if(!t){msg.textContent='URLを入力してください';return}
    if(locked&&!authed){
      fetch('/api/unlock',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({key:key.value})}).then(function(r){
        if(!r.ok){msg.textContent='合言葉が違います';return}
        authed=true;navi(t);
      });
      return;
    }
    navi(t);
  }
  function navi(t){
    try{
      var a=new URL(t);
      var purl='/go/'+a.protocol.slice(0,-1)+'/'+a.host+a.pathname+a.search+a.hash;
      pushRecent(purl,a.host+a.pathname);
      location.href=purl;
    }catch(e){msg.textContent='URLの形式が正しくありません'}
  }
  var N=__CLICKS__,cnt=0,tm;
  document.getElementById('open').onclick=function(e){
    e.preventDefault();e.stopPropagation();
    cnt++;clearTimeout(tm);
    if(cnt>=N){cnt=0;show()}else{tm=setTimeout(function(){cnt=0},1200)}
  };
  document.getElementById('cl').onclick=hide;
  document.getElementById('go').onclick=go;
  var cp=document.getElementById('cp'),ch=document.getElementById('ch'),ct=document.getElementById('ct'),cm=document.getElementById('cm');
  function cmsg(t,ok){cm.style.color=ok?'#3a8a3a':'#c0504d';cm.textContent=t}
  function auth(){
    if(!(locked&&!authed))return Promise.resolve(true);
    return fetch('/api/unlock',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({key:key.value})}).then(function(r){if(r.ok)authed=true;return r.ok});
  }
  function listCookies(){
    return fetch('/api/cookies',{cache:'no-store'}).then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json()}).then(function(d){return d.cookies||[]});
  }
  document.getElementById('ck').onclick=function(){cp.style.display=cp.style.display==='none'?'block':'none'};
  document.getElementById('ci').onclick=function(){
    var v=ct.value;
    if(!v.trim()){cmsg('Cookieを貼り付けてください');return}
    auth().then(function(ok){
      if(!ok){cmsg('合言葉が違います');return}
      return fetch('/api/cookies',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({host:ch.value.trim(),cookies:v})}).then(function(r){
        return r.json().then(function(d){
          if(!r.ok){cmsg(d.error||('HTTP '+r.status));return}
          cmsg(d.count+' 個のCookieを保存しました',true);ct.value='';
        });
      });
    }).catch(function(e){cmsg(String(e))});
  };
  document.getElementById('ce').onclick=function(){
    var h=ch.value.trim().toLowerCase().replace(/^https?:\/\//,'').replace(/[\/:?#].*$/,'');
    auth().then(function(ok){
      if(!ok)throw new Error('合言葉が違います');
      return listCookies();
    }).then(function(list){
      var out=list.filter(function(c){
        if(!h)return true;
        var s=String(c.scope).toLowerCase();
        return s===h||(h.length>s.length&&h.slice(-(s.length+1))==='.'+s);
      }).map(function(c){return {name:c.name,value:c.value,domain:(c.type==='domain'?'.':'')+c.scope,hostOnly:c.type==='host',path:'/',secure:true}});
      ct.value=out.length?JSON.stringify(out,null,2):'';
      cmsg(out.length?out.length+' 個をエクスポートしました。ログイン情報を含むので取り扱いに注意してください':'エクスポートできるCookieがありません',out.length>0);
    }).catch(function(e){cmsg(String(e.message||e))});
  };
  document.getElementById('cc').onclick=function(){
    if(!ct.value){cmsg('コピーする内容がありません');return}
    var done=function(){cmsg('コピーしました',true)};
    if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(ct.value).then(done,function(){ct.select();document.execCommand('copy');done()})}
    else{ct.select();document.execCommand('copy');done()}
  };
  document.getElementById('cd').onclick=function(){
    if(!ct.value){cmsg('保存する内容がありません');return}
    var a=document.createElement('a');
    a.href=URL.createObjectURL(new Blob([ct.value],{type:'application/json'}));
    a.download='cookies.json';document.body.appendChild(a);a.click();a.remove();
    cmsg('cookies.json として保存しました',true);
  };
  document.getElementById('cfb').onclick=function(){document.getElementById('cf').click()};
  document.getElementById('cf').onchange=function(){
    var f=this.files[0];if(!f)return;
    var rd=new FileReader();
    rd.onload=function(){ct.value=String(rd.result);cmsg('読み込みました。「インポート」を押してください',true)};
    rd.readAsText(f);this.value='';
  };
  ov.onclick=function(e){if(e.target===ov)hide()};
  document.addEventListener('keydown',function(e){
    if(e.repeat)return;
    if(e.key==='Escape'){hide();return}
    if(e.key==='Enter'&&ov.classList.contains('on')&&(e.target.id==='u'||e.target.id==='key')){e.preventDefault();go()}
  });
})();
</script>
</body>
</html>`;

// "/go/https://x.com/a" "/go/https:/x.com/a" "/go/https%3A%2F%2Fx.com/a" "/go/x.com/a" "/go/HTTPS/x.com/a"
// を正規形 "/go/https/x.com/a" に直す。直す必要がなければ null
function normalizeGoPath(p) {
  const rest = p.slice(4);
  let m = rest.match(/^(https?|wss?)(?::|%3A)(?:\/|%2F){1,2}(.*)$/i);
  if (m) {
    let tail = m[2];
    if (/%3A|%2F/i.test(rest.slice(0, 12))) { try { tail = decodeURIComponent(tail); } catch (e) {} } // URL全体がエンコードされている場合
    return '/go/' + m[1].toLowerCase() + '/' + tail;
  }
  m = rest.match(/^(https?|wss?)\/(.*)$/i);
  if (m && m[1] !== m[1].toLowerCase()) return '/go/' + m[1].toLowerCase() + '/' + m[2];
  if (!m && /^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?(?:[\/?#]|$)/i.test(rest)) return '/go/https/' + rest; // スキーム省略はhttps扱い
  return null;
}

const SETTINGS_PAGE = String.raw`<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>設定</title>
<style>
:root{--bg:#faf7f2;--card:#fff;--ink:#3b3631;--sub:#8a8178;--accent:#c98a5b;--line:#eee7dc}
@media(prefers-color-scheme:dark){:root{--bg:#1d1b19;--card:#262320;--ink:#e9e3da;--sub:#9d958b;--accent:#d9a074;--line:#37322d}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.7 "Hiragino Sans","Yu Gothic",system-ui,sans-serif;padding:20px}
.wrap{max-width:760px;margin:0 auto}
h1{font-size:1.3rem;color:var(--accent);margin:0 0 6px}
p.sub{color:var(--sub);font-size:.85rem;margin:0 0 18px}
a{color:var(--accent)}
.box{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:18px}
.box h2{margin:0 0 10px;font-size:1rem}
label.tg{display:block;padding:8px 0;border-bottom:1px solid var(--line);cursor:pointer}
label.tg:last-of-type{border-bottom:0}
label.tg small{display:block;color:var(--sub);font-size:.78rem;line-height:1.5;margin-left:26px}
label.tg b{font-weight:600}
label.tg input{width:auto;margin:0 8px 0 0;vertical-align:-2px;accent-color:var(--accent)}
input[type=text],textarea{width:100%;padding:9px 12px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--ink);font:inherit;margin-bottom:8px}
textarea{min-height:140px;resize:vertical;font:12px/1.5 ui-monospace,Consolas,monospace}
button{padding:8px 16px;border-radius:8px;border:0;cursor:pointer;font:inherit;background:var(--accent);color:#fff;margin:6px 6px 0 0}
button.sec{background:var(--bg);color:var(--sub);border:1px solid var(--line)}
.msg{font-size:.85rem;min-height:1.3em;margin-top:8px;word-break:break-all}
</style>
</head>
<body>
<div class="wrap">
<h1>設定</h1>
<p class="sub">動作モードの切り替えとCookieの入出力ができます。変更は、次に開く(または再読み込みした)プロキシページから反映されます。</p>

<div class="box">
<h2>モード</h2>
<div id="tg"></div>
<button id="sv">保存</button><button class="sec" id="rs">既定に戻す</button>
<div class="msg" id="sm"></div>
</div>

<div class="box">
<h2>Cookie の入出力</h2>
<input id="ch" type="text" placeholder="対象ホスト (例: x.com)　JSONにdomainがあれば空欄可 / エクスポート時は絞り込み" autocomplete="off" spellcheck="false">
<textarea id="ct" placeholder="auth_token=xxx; ct0=yyy&#10;または JSON配列 (Cookie-Editor形式 / エクスポートした内容)" spellcheck="false"></textarea>
<button id="ci">インポート</button><button class="sec" id="ce">エクスポート</button><button class="sec" id="cc">コピー</button><button class="sec" id="cd">保存(.json)</button><button class="sec" id="cfb">ファイルから</button>
<input type="file" id="cf" accept=".json,.txt,application/json,text/plain" style="display:none">
<div class="msg" id="cm"></div>
</div>

<p style="text-align:center"><a href="/">← ブログに戻る</a>　<a href="/cookies">Cookie一覧・削除</a></p>
</div>
<script>
var DEF=__DEFAULTS__;
var ITEMS=[
 ['twitterUi','Twitter UI モード','x.com のとき、X を Twitter 風にします(青い鳥のロゴ・タイトル「Twitter」・「ツイート」「リツイート」表記・Grok/Premium メニューを隠す)。見た目だけで通信には影響しません。有効なときは html 要素に data-px-twui が付きます。'],
 ['spoofUa','ブラウザ偽装 (Firefox / Windows 11)','User-Agent などを Firefox on Windows 11 に見せます。サイトの機能が制限される場合は OFF にしてください。'],
 ['blockWebrtc','WebRTC を無効化','STUN経由で実IPが漏れるのを防ぎます。通話・ビデオ通話系は使えなくなります。'],
 ['strictCsp','厳格モード (CSP で直接通信を遮断)','プロキシを経由しない通信をブラウザ側で遮断します。サイトが正しく動かない場合は OFF にしてください。'],
 ['edgeCache','静的ファイルのエッジキャッシュ','画像・JS・CSS を Cloudflare 側にキャッシュします。表示が古い・おかしい場合は OFF にしてください。'],
 ['workerPatch','Web Worker の通信もプロキシ経由にする','Worker 内で行われる通信(DMなど)をプロキシへ向けます。Worker が動かない場合は OFF にしてください。']
];
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function getS(){var m=document.cookie.match(/(?:^|;\s*)pxs=([^;]*)/),o={};try{if(m)o=JSON.parse(decodeURIComponent(m[1]))}catch(e){}return o}
function render(){
  var cur={},s=getS(),k;
  for(k in DEF)cur[k]=(typeof s[k]==='boolean')?s[k]:DEF[k];
  document.getElementById('tg').innerHTML=ITEMS.map(function(it){
    return '<label class="tg"><input type="checkbox" id="t_'+it[0]+'"'+(cur[it[0]]?' checked':'')+'><b>'+esc(it[1])+'</b><small>'+esc(it[2])+'</small></label>';
  }).join('');
}
function smsg(t,ok){var e=document.getElementById('sm');e.style.color=ok?'#3a8a3a':'#c0504d';e.textContent=t}
document.getElementById('sv').onclick=function(){
  var o={};
  ITEMS.forEach(function(it){o[it[0]]=document.getElementById('t_'+it[0]).checked});
  document.cookie='pxs='+encodeURIComponent(JSON.stringify(o))+'; Path=/; Secure; SameSite=None; Max-Age=31536000';
  smsg('保存しました。プロキシのページを再読み込みすると反映されます。',true);
};
document.getElementById('rs').onclick=function(){
  document.cookie='pxs=; Path=/; Secure; SameSite=None; Max-Age=0';
  render();smsg('既定値に戻しました。',true);
};
render();

var ch=document.getElementById('ch'),ct=document.getElementById('ct'),cm=document.getElementById('cm');
function cmsg(t,ok){cm.style.color=ok?'#3a8a3a':'#c0504d';cm.textContent=t}
function listCookies(){
  return fetch('/api/cookies',{cache:'no-store'}).then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json()}).then(function(d){return d.cookies||[]});
}
document.getElementById('ci').onclick=function(){
  var v=ct.value;
  if(!v.trim()){cmsg('Cookieを貼り付けてください');return}
  fetch('/api/cookies',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({host:ch.value.trim(),cookies:v})}).then(function(r){
    return r.json().then(function(d){
      if(!r.ok){cmsg(d.error||('HTTP '+r.status));return}
      cmsg(d.count+' 個のCookieを保存しました',true);ct.value='';
    });
  }).catch(function(e){cmsg(String(e))});
};
document.getElementById('ce').onclick=function(){
  var h=ch.value.trim().toLowerCase().replace(/^https?:\/\//,'').replace(/[\/:?#].*$/,'');
  listCookies().then(function(list){
    var out=list.filter(function(c){
      if(!h)return true;
      var s=String(c.scope).toLowerCase();
      return s===h||(h.length>s.length&&h.slice(-(s.length+1))==='.'+s);
    }).map(function(c){return {name:c.name,value:c.value,domain:(c.type==='domain'?'.':'')+c.scope,hostOnly:c.type==='host',path:'/',secure:true}});
    ct.value=out.length?JSON.stringify(out,null,2):'';
    cmsg(out.length?out.length+' 個をエクスポートしました。ログイン情報を含むので取り扱いに注意してください':'エクスポートできるCookieがありません',out.length>0);
  }).catch(function(e){cmsg(String(e.message||e))});
};
document.getElementById('cc').onclick=function(){
  if(!ct.value){cmsg('コピーする内容がありません');return}
  var done=function(){cmsg('コピーしました',true)};
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(ct.value).then(done,function(){ct.select();document.execCommand('copy');done()})}
  else{ct.select();document.execCommand('copy');done()}
};
document.getElementById('cd').onclick=function(){
  if(!ct.value){cmsg('保存する内容がありません');return}
  var a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([ct.value],{type:'application/json'}));
  a.download='cookies.json';document.body.appendChild(a);a.click();a.remove();
  cmsg('cookies.json として保存しました',true);
};
document.getElementById('cfb').onclick=function(){document.getElementById('cf').click()};
document.getElementById('cf').onchange=function(){
  var f=this.files[0];if(!f)return;
  var rd=new FileReader();
  rd.onload=function(){ct.value=String(rd.result);cmsg('読み込みました。「インポート」を押してください',true)};
  rd.readAsText(f);this.value='';
};
</script>
</body>
</html>`;

const NOT_FOUND = '<!doctype html><meta charset="utf-8"><title>404</title><p style="font-family:sans-serif;padding:40px">ページが見つかりません。<a href="/">トップへ戻る</a></p>';

async function router(req, env) {
    const url = new URL(req.url);
    const p = url.pathname;

    if (p === '/' || p === '/index.html') {
      return htmlRes(BLOG.replace('__CLICKS__', String(CLICKS_TO_OPEN)));
    }

    // 設定ページ (認証が必要。未認証なら存在を隠すため 404 を返す)
    if (p === '/i/fj/setting-page' || p === '/i/fj/setting-page/') {
      if (!(await isAuthed(req, env))) return htmlRes(NOT_FOUND, 404);
      return htmlRes(SETTINGS_PAGE.replace('__DEFAULTS__', () => JSON.stringify(getCfg({}))));
    }

    if (p === '/cookies') {
      if (!(await isAuthed(req, env))) return new Response('Unauthorized', { status: 401 });
      return htmlRes(COOKIE_PAGE);
    }

    if (p === '/api/status') {
      return Response.json({ locked: !!env.ACCESS_KEY, authed: await isAuthed(req, env) });
    }

    if (p === '/api/unlock' && req.method === 'POST') {
      if (!env.ACCESS_KEY) return Response.json({ ok: true });
      let key = '';
      try { key = (await req.json()).key || ''; } catch (e) {}
      if ((await sha256Hex(key)) !== (await sha256Hex(env.ACCESS_KEY))) {
        return new Response('NG', { status: 401 });
      }
      const token = await authToken(env);
      return new Response('OK', {
        headers: { 'set-cookie': `pxa=${token}; ${COOKIE_FLAGS}; Max-Age=2592000; HttpOnly` },
      });
    }

    if (p === '/api/cookies') return handleCookieApi(req, env, url);

    if (p.startsWith('/go/')) {
      const fixed = normalizeGoPath(p);
      if (fixed) {
        return new Response(null, { status: 302, headers: { location: fixed + url.search, 'cache-control': 'no-store' } });
      }
      return handleProxy(req, env, url);
    }

    // "/home" のように素のパスで来た場合(リロード・相対リンク等): 最後に開いたサイトに振り分ける
    const pxo = parseCookies(req.headers.get('cookie')).pxo;
    if (pxo) return handleProxy(req, env, url, pxo);

    return htmlRes(NOT_FOUND, 404);
}

export default {
  async fetch(req, env) { return router(req, env); },
};
