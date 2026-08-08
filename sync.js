/* ============================================================
   Cloudflare KV 同步层 — 共享代码，桌面/手机均可加载
   URL: ./sync.js  (相对部署)
   ============================================================ */

(function (root) {
  'use strict';

  /* -------- 配置（用户可改） -------- */
  // CF Worker URL —— 用户部署后填入，例如 https://rental-sync.workers.dev
  // 留空则只走本地 JSON 文件；桌面端还会自动用 Node fetch 直调（不需 worker）
  const DEFAULT_WORKER_URL = '';

  /* -------- 工具 -------- */
  function lsGet(k){ try{ return localStorage.getItem(k);}catch(e){return null;} }
  function lsSet(k,v){ try{ localStorage.setItem(k,v);}catch(e){} }
  function base64(buf){
    // 兼容老浏览器：先把 ArrayBuffer 视作 Uint8Array
    const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf)
               : Array.isArray(buf) ? new Uint8Array(buf) : buf;
    let s = '';
    for (let i=0;i<bytes.length;i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function fromBase64(str){
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  /* -------- PBKDF2 密码哈希（Web Crypto） -------- */
  async function pbkdf2(password, salt, iterations){
    iterations = iterations || 120000;
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      'raw', enc.encode(password),
      'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      {name:'PBKDF2', salt, iterations, hash:'SHA-256'},
      baseKey, 256);
    return new Uint8Array(bits);
  }
  async function hashPassword(password){
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hash = await pbkdf2(password, salt);
    return {
      salt: base64(salt),
      hash: base64(hash),
      iter: 120000,
      algo: 'pbkdf2-sha256'
    };
  }
  async function verifyPassword(password, rec){
    if (!rec || !rec.salt || !rec.hash) return false;
    const salt = fromBase64(rec.salt);
    const hash = await pbkdf2(password, salt, rec.iter || 120000);
    return base64(hash) === rec.hash;
  }

  /* -------- 用户数据库（localStorage） -------- */
  const UDB_KEY = 'rental_userdb_v1';
  function loadUserDB(){ try{ return JSON.parse(lsGet(UDB_KEY))||{users:{}}; }catch(e){ return {users:{}}; } }
  function saveUserDB(db){ lsSet(UDB_KEY, JSON.stringify(db)); }

  async function registerUser(name, password){
    if (!name || name.length < 3)  return {ok:false, err:'账号至少 3 个字符'};
    if (!/^[a-zA-Z0-9_.\-@]+$/.test(name))
      return {ok:false, err:'账号仅允许字母/数字/_/-/./@'};
    if (!password || password.length < 6)
      return {ok:false, err:'密码至少 6 位'};
    const db = loadUserDB();
    if (db.users[name]) return {ok:false, err:'该账号已存在'};
    db.users[name] = {
      hashRec: await hashPassword(password),
      createdAt: Date.now(),
      syncedAt: 0,
    };
    saveUserDB(db);
    return {ok:true, name};
  }
  async function loginUser(name, password){
    const db = loadUserDB();
    const rec = db.users[name];
    if (!rec) return {ok:false, err:'账号不存在'};
    if (!await verifyPassword(password, rec.hashRec)) return {ok:false, err:'密码错误'};
    return {ok:true, name, rec};
  }
  async function changePassword(name, oldP, newP){
    const r = await loginUser(name, oldP);
    if (!r.ok) return r;
    const db = loadUserDB();
    db.users[name].hashRec = await hashPassword(newP);
    saveUserDB(db);
    return {ok:true};
  }

  /* -------- Cloudflare KV 同步（CORS 友好的 worker URL） -------- */
  const LS_NAME_KEY = 'rental_account_v1';      // 当前账号
  const LS_DATA_KEY = name => `rental_data_${name}_v1`;   // 当前账号本地数据

  function dataKeyLocal(name){ return lsGet(LS_DATA_KEY(name)) || JSON.stringify({properties:[]}); }

  function setAccount(name){ lsSet(LS_NAME_KEY, name); }
  function getAccount(){ return lsGet(LS_NAME_KEY) || ''; }

  async function cloudGet(name, workerUrl){
    workerUrl = workerUrl || DEFAULT_WORKER_URL;
    if (!workerUrl) return {ok:false, err:'未设置云端地址'};
    try {
      const r = await fetch(`${workerUrl}/get?u=${encodeURIComponent(name)}`, {
        method:'GET', mode:'cors', credentials:'omit',
        headers:{'Accept':'application/json'}
      });
      if (!r.ok) throw new Error('HTTP '+r.status);
      const txt = await r.text();
      const data = txt ? JSON.parse(txt) : {properties:[]};
      return {ok:true, data, raw:txt};
    } catch(e){ return {ok:false, err:String(e)}; }
  }

  async function cloudPut(name, data, workerUrl){
    workerUrl = workerUrl || DEFAULT_WORKER_URL;
    if (!workerUrl) return {ok:false, err:'未设置云端地址'};
    try {
      const r = await fetch(`${workerUrl}/put?u=${encodeURIComponent(name)}`, {
        method:'POST', mode:'cors', credentials:'omit',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({data, updatedAt:Date.now()})
      });
      if (!r.ok) throw new Error('HTTP '+r.status);
      return {ok:true};
    } catch(e){ return {ok:false, err:String(e)}; }
  }

  /* -------- 自动同步队列 -------- */
  const SYNC_OPTS_KEY = 'rental_syncopts_v1';
  function getSyncOpts(){
    try{ return JSON.parse(lsGet(SYNC_OPTS_KEY))||{}; } catch(e){ return {}; }
  }
  function setSyncOpts(o){ lsSet(SYNC_OPTS_KEY, JSON.stringify(o)); }

  let _syncTimer = null;
  function scheduleAutoSync(name, getData, delay){
    if (_syncTimer) clearTimeout(_syncTimer);
    _syncTimer = setTimeout(async ()=>{
      const opts = getSyncOpts();
      if (!opts.auto || !opts.url) return;
      const data = getData();
      const r = await cloudPut(name, data, opts.url);
      if (r.ok) console.log('[sync] auto upload ok');
      else console.warn('[sync] auto upload fail:', r.err);
    }, delay || 8000);
  }

  /* -------- 浏览器 ➜ 桌面 IPC（桌面端 main.js 接管 fetch） -------- */
  async function viaIPC(action, payload){
    if (typeof window === 'undefined' || !window.rentalIPC) return null;
    return await window.rentalIPC(action, payload);
  }

  /* 桌面浏览器能用 Node 直接调 CF API，绕过 CORS */
  async function desktopCloudGet(name){
    return (await viaIPC('cloudGet', {name})) || {ok:false, err:'desktop ipc unavailable'};
  }
  async function desktopCloudPut(name, data){
    return (await viaIPC('cloudPut', {name, data})) || {ok:false, err:'desktop ipc unavailable'};
  }

  root.RentalSync = {
    DEFAULT_WORKER_URL,
    hashPassword, verifyPassword,
    registerUser, loginUser, changePassword,
    loadUserDB, saveUserDB,
    setAccount, getAccount, dataKeyLocal,
    cloudGet, cloudPut,
    desktopCloudGet, desktopCloudPut,
    scheduleAutoSync,
    getSyncOpts, setSyncOpts,
  };
})(window);
