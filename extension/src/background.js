/**
 * DarkMatter Background — Service Worker
 * Handles: queue drain, auth, API calls, badge updates.
 * Never blocks the content script or browser.
 */
'use strict';

const DM_API = 'https://darkmatterhub.ai';
const QUEUE_KEY = 'dm_queue_v2';
const MAX_QUEUE = 500;
const DRAIN_INTERVAL_MS = 3000; // drain queue every 3 seconds

// ── Message handler from content scripts ─────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'CAPTURE_TURN') {
    enqueue(msg);
    sendResponse({ ok: true });
  }
  return false; // no async response needed
});

// ── Queue a capture ───────────────────────────────────────────────────
async function enqueue(capture) {
  const { [QUEUE_KEY]: raw } = await chrome.storage.local.get(QUEUE_KEY);
  const queue = raw || [];
  if (queue.length >= MAX_QUEUE) queue.shift(); // drop oldest if full
  queue.push({ ...capture, _queued: Date.now() });
  await chrome.storage.local.set({ [QUEUE_KEY]: queue });
}

// ── Drain queue — runs every 3 seconds ───────────────────────────────
async function drainQueue() {
  const { dmAuth, dmEnabled, [QUEUE_KEY]: queue } = await chrome.storage.local.get(['dmAuth', 'dmEnabled', QUEUE_KEY]);
  if (!dmAuth?.agent_id || !dmAuth?.api_key || dmEnabled === false) return;
  if (!queue?.length) return;

  const toSend = queue.splice(0, 10); // process 10 at a time
  const remaining = queue;

  const results = await Promise.allSettled(toSend.map(capture => commitCapture(capture, dmAuth)));

  // Put failed ones back (up to 3 retries)
  const requeue = [];
  results.forEach((r, i) => {
    if (r.status === 'rejected') {
      const cap = toSend[i];
      if ((cap._retries || 0) < 3) {
        requeue.push({ ...cap, _retries: (cap._retries || 0) + 1 });
      }
    }
  });

  await chrome.storage.local.set({ [QUEUE_KEY]: [...remaining, ...requeue] });

  // Update badge
  const pending = remaining.length + requeue.length;
  updateBadge(pending);
}

// ── Commit a single capture to DarkMatter API ─────────────────────────
async function commitCapture(capture, auth) {
  // Group by conversationId using trace_id
  const payload = {
    platform:      capture.platform,
    role:          capture.role,
    text:          capture.text,
    url:           capture.url,
    pageTitle:     capture.pageTitle,
    _source:       'extension',
    _captured_at:  capture.timestamp,
  };

  const body = {
    toAgentId:   auth.agent_id,
    payload,
    traceId:     capture.conversationId,
    clientTimestamp: capture.timestamp,
    agent: { role: capture.role, platform: capture.platform },
  };

  const r = await fetch(`${DM_API}/api/commit`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${auth.api_key}` },
    body:    JSON.stringify(body),
    signal:  AbortSignal.timeout(8000),
  });

  if (!r.ok) {
    const err = await r.text();
    throw new Error(`HTTP ${r.status}: ${err.slice(0, 100)}`);
  }

  return r.json();
}

// ── Badge: shows pending queue count ─────────────────────────────────
function updateBadge(pending) {
  if (pending > 0) {
    chrome.action.setBadgeText({ text: pending > 99 ? '99+' : String(pending) });
    chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' });
  } else {
    chrome.action.setBadgeText({ text: '' });
  }
}

// ── Alarm-based drain (survives service worker restarts) ──────────────
chrome.alarms.create('drain', { periodInMinutes: 0.05 }); // every 3 seconds
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === 'drain') drainQueue();
});

// Also drain immediately on startup
drainQueue();

// ── Auth bridge: receives auth from popup ─────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'SET_AUTH') {
    chrome.storage.local.set({ dmAuth: msg.auth, dmEnabled: true }).then(() => {
      sendResponse({ ok: true });
      drainQueue();
    });
    return true;
  }
  if (msg.type === 'GET_STATUS') {
    chrome.storage.local.get(['dmAuth', 'dmEnabled', QUEUE_KEY]).then(s => {
      sendResponse({
        signedIn:  !!s.dmAuth?.agent_id,
        enabled:   s.dmEnabled !== false,
        pending:   (s[QUEUE_KEY] || []).length,
        agentId:   s.dmAuth?.agent_id,
        email:     s.dmAuth?.email,
        workspace: s.dmAuth?.workspace_name,
      });
    });
    return true;
  }
  if (msg.type === 'SIGN_OUT') {
    chrome.storage.local.remove(['dmAuth', 'dmEnabled']).then(() => sendResponse({ ok: true }));
    chrome.action.setBadgeText({ text: '' });
    return true;
  }
  if (msg.type === 'TOGGLE_ENABLED') {
    chrome.storage.local.set({ dmEnabled: msg.enabled }).then(() => sendResponse({ ok: true }));
    return true;
  }
});
