/* MARU 데이터 복호 게이트 v2 — 비밀번호/해시를 담지 않음. 데이터는 *.enc(AES-GCM)로만 배포. */
(function () {
  'use strict';
  var SKEY = 'maru_pages_key_v2';           // sessionStorage: {salt, key(raw base64)} — 탭 닫으면 삭제
  // 사이트 루트 = 이 스크립트(<루트>/js/secure-gate.js)의 한 단계 위. 저장소 이름·호스팅 경로와 무관
  var BASE = new URL('..', (document.currentScript && document.currentScript.src) || location.href).pathname;
  var ITER = 600000;
  var MAGIC = 'MENC1';
  function b64(u8) { var s = ''; for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); }
  function unb64(s) { var b = atob(s), u = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
  function hex(u8) { return Array.from(u8).map(function (x) { return ('0' + x.toString(16)).slice(-2); }).join(''); }
  function parse(buf) {
    var u = new Uint8Array(buf);
    if (String.fromCharCode.apply(null, u.slice(0, 5)) !== MAGIC) throw new Error('bad file');
    return { salt: u.slice(5, 21), iv: u.slice(21, 33), ct: u.slice(33) };
  }
  var getBin = function (url) { return fetch(url, { cache: 'no-store' }).then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + url); return r.arrayBuffer(); }); };
  function derive(pass, salt) {
    return crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']).then(function (k) {
      return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: ITER }, k, 256);
    }).then(function (bits) { return new Uint8Array(bits); });
  }
  function aes(raw) { return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']); }
  function dec(key, p, aad) { return crypto.subtle.decrypt({ name: 'AES-GCM', iv: p.iv, additionalData: new TextEncoder().encode(aad) }, key, p.ct); }  // aad=사이트 내 경로 → 파일 바꿔치기 거부

  var keyPromise = null;
  function cached(saltHex) {
    try { var o = JSON.parse(sessionStorage.getItem(SKEY) || 'null'); if (o && o.salt === saltHex) return unb64(o.key); } catch (e) {}
    return null;
  }
  function getKey() {
    if (keyPromise) return keyPromise;
    keyPromise = getBin(BASE + 'js/gate.enc').then(function (buf) {
      var p = parse(buf), sh = hex(p.salt), raw = cached(sh);
      var tryRaw = function (r) { return aes(r).then(function (k) { return dec(k, p, 'js/gate.enc').then(function () { return { k: k, r: r }; }); }); };
      var ask = function () {
        return prompt_().then(function (ui) {
          return derive(ui.pass, p.salt).then(tryRaw).then(function (o) {
            try { sessionStorage.setItem(SKEY, JSON.stringify({ salt: sh, key: b64(o.r) })); } catch (e) {}
            ui.close(); return o.k;
          }, function () { ui.fail(); return ask(); });
        });
      };
      if (raw) return tryRaw(raw).then(function (o) { return o.k; }, function () { try { sessionStorage.removeItem(SKEY); } catch (e) {} return ask(); });
      return ask();
    });
    return keyPromise;
  }

  var ui = null;
  function prompt_() {
    return new Promise(function (resolve) {
      function mount() {
        if (!ui) {
          var w = document.createElement('div');
          w.id = 'maru-auth-gate';
          w.setAttribute('style', 'position:fixed;inset:0;z-index:2147483647;background:#0f172a;display:flex;align-items:center;justify-content:center;font-family:sans-serif;');
          w.innerHTML =
            '<form id="maru-auth-form" style="background:#fff;box-sizing:border-box;padding:28px 24px;border-radius:12px;width:min(92vw,380px);box-shadow:0 12px 40px rgba(0,0,0,.35)">' +
            '<div style="font-size:20px;font-weight:800;color:#1c3558;margin-bottom:8px">MARU 대시보드</div>' +
            '<div style="font-size:16px;font-weight:600;color:#1e293b;margin-bottom:16px">비밀번호를 입력하세요<br><span style="font-size:15px;font-weight:600;color:#334155">한 번 입력하면 탭을 닫을 때까지 유지됩니다</span></div>' +
            '<input id="maru-auth-pass" type="password" autocomplete="current-password" style="width:100%;box-sizing:border-box;padding:12px;font-size:17px;color:#0f172a;border:2px solid #1c3558;border-radius:8px;margin-bottom:10px" />' +
            '<div id="maru-auth-err" role="alert" style="display:none;font-size:16px;font-weight:700;color:#b91c1c;margin-bottom:10px">비밀번호가 맞지 않습니다. 다시 입력하세요.</div>' +
            '<div id="maru-auth-wait" style="display:none;font-size:16px;font-weight:600;color:#1c3558;margin-bottom:10px">확인 중…</div>' +
            '<button type="submit" style="width:100%;padding:12px;font-size:17px;font-weight:800;color:#fff;background:#1c3558;border:0;border-radius:8px;cursor:pointer">열기</button></form>';
          document.body.appendChild(w);
          document.documentElement.style.overflow = 'hidden';
          ui = { w: w };
        }
        var input = document.getElementById('maru-auth-pass'), err = document.getElementById('maru-auth-err'), wait = document.getElementById('maru-auth-wait');
        var form = document.getElementById('maru-auth-form');
        form.onsubmit = function (ev) {
          ev.preventDefault(); err.style.display = 'none'; wait.style.display = 'block';
          resolve({
            pass: input.value || '',
            close: function () { ui.w.remove(); ui = null; document.documentElement.style.overflow = ''; },
            fail: function () { wait.style.display = 'none'; err.style.display = 'block'; input.value = ''; input.focus(); }
          });
        };
        setTimeout(function () { input.focus(); }, 30);
      }
      if (document.body) mount(); else document.addEventListener('DOMContentLoaded', mount, { once: true });
    });
  }

  function rel(url) { return decodeURIComponent(new URL(url, location.href).pathname).slice(BASE.length); }
  function bytes(url) { var r = rel(url); return Promise.all([getKey(), getBin(BASE + r.split('/').map(encodeURIComponent).join('/') + '.enc')]).then(function (a) { return dec(a[0], parse(a[1]), r); }); }
  var DATA_RE = /\.(json|xlsx|pdf|md|txt|csv)$/i;
  var TYPES = { md: 'text/plain;charset=utf-8', txt: 'text/plain;charset=utf-8', csv: 'text/csv;charset=utf-8', json: 'application/json', pdf: 'application/pdf', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' };
  function inSite(u) { return u.origin === location.origin && u.pathname.indexOf(BASE) === 0; }
  function ext(u) { var m = u.pathname.match(DATA_RE); return m ? m[1].toLowerCase() : ''; }
  // fetch('x.json') 등 사이트 내부 데이터 요청은 자동으로 x.json.enc 를 받아 복호
  var rawFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    try {
      var u = new URL(typeof input === 'string' ? input : input.url, location.href);
      if (inSite(u) && ext(u)) return bytes(u.pathname).then(function (b) { return new Response(b, { status: 200, headers: { 'Content-Type': TYPES[ext(u)] } }); });
    } catch (e) {}
    return rawFetch(input, init);
  };
  getBin = function (url) { return rawFetch(url, { cache: 'no-store' }).then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + url); return r.arrayBuffer(); }); };
  var blobs = {};
  function blobUrl(path) {
    if (blobs[path]) return Promise.resolve(blobs[path]);
    var e = path.match(DATA_RE)[1].toLowerCase();
    return bytes(path).then(function (b) { return (blobs[path] = URL.createObjectURL(new Blob([b], { type: TYPES[e] }))); });
  }
  // <a href="x.pdf|x.xlsx|x.json"> 클릭 → 복호 후 pdf는 새 창 열기, 나머지는 내려받기
  function hookLinks(doc) {
    doc.addEventListener('click', function (ev) {
      var a = ev.target && ev.target.closest ? ev.target.closest('a[href]') : null;
      if (!a || ev.defaultPrevented) return;
      var u; try { u = new URL(a.getAttribute('href'), location.href); } catch (e) { return; }
      if (!inSite(u) || !ext(u)) return;
      ev.preventDefault();
      var path = decodeURIComponent(u.pathname), name = path.split('/').pop();
      var w = (ext(u) === 'pdf') ? window.open('', '_blank') : null;
      if (w) { try { w.document.write('<p style="font:700 18px sans-serif;color:#1c3558;padding:24px">문서를 여는 중…</p>'); } catch (e) {} }
      blobUrl(path).then(function (href) {
        if (w) { w.location.href = href; return; }
        var d = doc.createElement('a'); d.href = href; d.download = name; doc.body.appendChild(d); d.click(); d.remove();
      }).catch(function (e) { if (w) w.close(); alert('파일을 열지 못했습니다: ' + e.message); });
    }, true);
  }
  // 암호화된 페이지 본문(*.html.enc)을 복호해 현재 문서로 교체
  function page() {
    var p = decodeURIComponent(location.pathname); if (/\/$/.test(p)) p += 'index.html';
    return bytes(p).then(function (b) {
      var html = new TextDecoder().decode(b);
      document.open(); document.write(html); document.close();
      hookLinks(document);
    }).catch(function (e) {
      document.body.insertAdjacentHTML('afterbegin', '<div style="font:700 17px sans-serif;color:#b91c1c;background:#fff;padding:16px">페이지를 열지 못했습니다: ' + e.message + '</div>');
    });
  }
  window.MaruSecure = { bytes: bytes, page: page, blobUrl: blobUrl, hookLinks: hookLinks,
    json: function (url) { return bytes(url).then(function (b) { return JSON.parse(new TextDecoder().decode(b)); }); } };
})();
