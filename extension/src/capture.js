/**
 * DarkMatter Capture — Content Script
 * DESIGN: tiny (~5KB), zero blocking, idempotent, multi-layer.
 */
'use strict';

const PLATFORM = (() => {
  const h = location.hostname;
  if (h.includes('claude.ai'))         return 'claude';
  if (h.includes('chatgpt.com') || h.includes('chat.openai.com')) return 'chatgpt';
  if (h.includes('grok.com'))          return 'grok';
  if (h.includes('gemini.google.com')) return 'gemini';
  if (h.includes('perplexity.ai'))     return 'perplexity';
  return null;
})();
if (!PLATFORM) throw new Error('DM: unsupported platform');

// Selector candidates — multiple per platform for resilience against DOM updates
const SEL = {
  claude:      { ai: ['[class*="font-claude-response"]','[data-is-streaming]'], user: ['[class*="font-user-message"]','[data-testid="user-message"]'], streaming: '[data-is-streaming="true"]' },
  chatgpt:     { ai: ['[data-message-author-role="assistant"]','.markdown.prose'], user: ['[data-message-author-role="user"]'], streaming: '.result-streaming' },
  grok:        { ai: ['[class*="message-bubble"]:not([class*="user"])','[class*="assistant-message"]'], user: ['[class*="message-bubble"][class*="user"]'], streaming: '[class*="loading"]' },
  gemini:      { ai: ['message-content','.model-response-text','[class*="response-container"]'], user: ['[class*="user-query"]','.query-text'], streaming: '[class*="loading-indicator"]' },
  perplexity:  { ai: ['[class*="prose"]','[data-testid*="answer"]'], user: ['[class*="query-text"]'], streaming: '[class*="animate-pulse"]' },
};
const cfg = SEL[PLATFORM];

const committed = new Set();
let convId = null, lastUrl = location.href, active = false;

async function init() {
  const s = await chrome.storage.local.get(['dmAuth','dmEnabled','dmWorkspace']);
  if (!s.dmAuth?.agent_id || s.dmEnabled === false) return;
  active = true;
  startObserver();
  setInterval(() => { if (!isStreaming()) sweep(); }, 20000);
}

function isStreaming() {
  if (!cfg.streaming) return false;
  try { return !!document.querySelector(cfg.streaming); } catch(e) { return false; }
}

let debounce;
function startObserver() {
  new MutationObserver(() => {
    clearTimeout(debounce);
    debounce = setTimeout(() => { if (!isStreaming()) sweep(); }, 900);
  }).observe(document.body, { childList: true, subtree: true });
}

function sweep() {
  if (!active) return;
  if (location.href !== lastUrl) { lastUrl = location.href; convId = null; committed.clear(); }

  const process = (els, role) => {
    els.forEach(el => {
      const text = (el.innerText || el.textContent || '').trim().slice(0, 40000);
      if (!text) return;
      const fp = text.length + ':' + text.slice(0,80) + text.slice(-40);
      if (committed.has(fp)) return;
      committed.add(fp);
      queue({ role, text });
    });
  };

  cfg.ai.forEach(s => { try { process(document.querySelectorAll(s), 'assistant'); } catch(e){} });
  cfg.user.forEach(s => { try { process(document.querySelectorAll(s), 'user'); } catch(e){} });
}

function queue(turn) {
  if (!convId) convId = 'cap_' + PLATFORM + '_' + Date.now() + '_' + Math.random().toString(36).slice(2,8);
  chrome.runtime.sendMessage({
    type: 'CAPTURE_TURN', platform: PLATFORM, conversationId: convId,
    role: turn.role, text: turn.text,
    url: location.href, pageTitle: document.title,
    timestamp: new Date().toISOString(),
  }).catch(() => {}); // background may have restarted — periodic sweep catches up
}

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && active && !isStreaming()) setTimeout(sweep, 1200);
});
window.addEventListener('beforeunload', () => { if (active) sweep(); });

init();
