// Osano CMP adapter for the consent audit: { detect, readState, readConfig, applyMode }
// Selectors were found live on www.newegg.com (Osano "permissive" mode, US variant)

export const name = 'osano';

const SEL = {
  window: '.osano-cm-window',
  toggle: 'input.osano-cm-toggle__input[data-category]',
  save: 'button.osano-cm-save',
  acceptAll: ['.osano-cm-accept-all', '.osano-cm-accept', '.osano-cm-button--type_accept'],
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// True when the request is Osano's main script
export const isScriptUrl = (url) => /\/\/cmp\.osano\.com\/.+\/osano\.js(\?|$)/.test(url);

// Wait for window.Osano.cm to be ready, returns true when loaded
export const detect = async (page, timeoutMs = 8000) =>
  page
    .waitForFunction(() => !!window.Osano?.cm && typeof window.Osano.cm.getConsent === 'function', {
      timeout: timeoutMs,
    })
    .then(() => true)
    .catch(() => false);

// Consent state Osano reports in the page
export const readState = (page) =>
  page
    .evaluate(() => {
      const cm = window.Osano?.cm;
      if (!cm) return { loaded: false };
      const safe = (fn) => {
        try {
          return fn();
        } catch {
          return null;
        }
      };
      return {
        loaded: true,
        jurisdiction: safe(() => cm.jurisdiction) || null,
        mode: safe(() => cm.mode) || null,
        consent: safe(() => cm.getConsent()) || null,
        optedOut: safe(() => cm.optOut) ?? null,
      };
    })
    .catch(() => ({ loaded: false }));

// Find the customer config literal: the object passed just before the {timer:...} flavor arg
export const findConfigLiteral = (source) => {
  const end = source.lastIndexOf('},{timer:') + 1;
  if (end <= 0) return null;
  let depth = 0;
  let quote = null;
  for (let i = end - 1; i >= 0; i--) {
    const c = source[i];
    if (quote) {
      if (c === quote && source[i - 1] !== '\\') quote = null;
      continue;
    }
    if (c === "'" || c === '"') quote = c;
    else if (c === '}') depth++;
    else if (c === '{' && --depth === 0) return source.slice(i, end);
  }
  return null;
};

// Rewrite the bundled default jurisdiction, to simulate a visitor from another US state
export const rewriteJurisdiction = (source, state) =>
  source.replace(/jurisdiction:"us-[a-z]{2}"/g, `jurisdiction:"us-${state}"`);

const FACT_KEYS = [
  'mode',
  'gpcSupport',
  'dntSupport',
  'enableDoNotSell',
  'enableDoNotSellDefault',
  'deleteStorageOnOptout',
  'remoteConsent',
  'allowTimeout',
  'timeoutSeconds',
  'googleConsent',
  'microsoftConsent',
  'amazonConsent',
  'ccpaRelaxed',
  'doNotSellCategories',
  'analyticsOnByDefault',
  'managePreferencesEnabled',
  'crossDomain',
  'domains',
  'revision',
];

// Evaluate the config literal inside a blank browser page (never in Node), return plain facts
export const readConfig = async (browser, source) => {
  if (!source) return { available: false, reason: 'osano.js was not loaded' };
  const literal = findConfigLiteral(source);
  if (!literal)
    return { available: false, reason: 'Could not find the settings object in osano.js' };
  const context = await browser.createBrowserContext();
  try {
    const page = await context.newPage();
    await page.setJavaScriptEnabled(true);
    await page.goto('about:blank');
    const parsed = await page.evaluate(
      (text, keys) => {
        const cfg = Function(`"use strict"; return (${text});`)();
        const facts = {};
        for (const k of keys) if (k in cfg) facts[k] = cfg[k];
        const classMap = (m) =>
          Object.fromEntries(
            Object.entries(m || {}).map(([k, v]) => [k, v?.classification || null]),
          );
        return {
          facts,
          scripts: classMap(cfg.scripts),
          iframes: classMap(cfg.iframes),
          cookies: classMap(cfg.cookies),
          localStorage: classMap(cfg.localStorage),
        };
      },
      literal,
      FACT_KEYS,
    );
    const defaultJurisdiction = source.match(/jurisdiction:"(us-[a-z]{2})"/)?.[1] || null;
    return {
      available: true,
      ...parsed.facts,
      defaultJurisdiction,
      classification: {
        scripts: parsed.scripts,
        iframes: parsed.iframes,
        cookies: parsed.cookies,
        localStorage: parsed.localStorage,
      },
    };
  } catch (err) {
    return { available: false, reason: `Could not evaluate settings: ${err.message}` };
  } finally {
    await context.close().catch(() => {});
  }
};

// Click visible elements in the page via the DOM; returns what happened
const uiStep = (page, action, arg) =>
  page.evaluate(
    (action, arg, SEL) => {
      const visible = (el) => !!el && (el.offsetParent !== null || el.getClientRects().length > 0);
      const root = document.querySelector(SEL.window) || document;
      if (action === 'acceptButton') {
        for (const sel of SEL.acceptAll) {
          const btn = [...root.querySelectorAll(sel)].find(visible);
          if (btn) {
            btn.click();
            return { clicked: sel };
          }
        }
        return { clicked: null };
      }
      if (action === 'toggles') {
        // arg: { category: wantChecked }, missing categories left alone
        const toggles = [...root.querySelectorAll(SEL.toggle)].filter(
          (el) => !el.disabled && visible(el.closest('label') || el.parentElement || el),
        );
        const seen = [];
        for (const el of toggles) {
          const cat = el.dataset.category;
          seen.push(cat);
          if (!(cat in arg) || el.checked === arg[cat]) continue;
          el.click();
        }
        return { categories: seen };
      }
      if (action === 'save') {
        const btn = [...root.querySelectorAll(SEL.save)].find(visible);
        if (!btn) return { saved: false };
        btn.click();
        return { saved: true };
      }
      return {};
    },
    action,
    arg,
    SEL,
  );

const settle = async (page) => {
  await sleep(800);
  await page.waitForNetworkIdle({ idleTime: 600, timeout: 5000 }).catch(() => {});
};

const openView = async (page, fn) => {
  await page.evaluate((fn) => window.Osano.cm[fn](), fn);
  await page.waitForSelector(`${SEL.window} ${SEL.save}`, { visible: true, timeout: 5000 });
};

// Drive the Osano UI like a user would; returns { ok, method, steps, consent, error? }
export const applyMode = async (page, mode) => {
  const steps = [];
  try {
    if (!(await detect(page))) return { ok: false, error: 'Osano not loaded', steps };
    let check = () => true;

    if (mode === 'accept-all') {
      const res = await uiStep(page, 'acceptButton');
      if (res.clicked) {
        steps.push(`click ${res.clicked}`);
      } else {
        // No accept button in the banner: enable every category in the drawer and save
        steps.push('no accept button in banner; Osano.cm.showDrawer()');
        await openView(page, 'showDrawer');
        const t = await uiStep(page, 'toggles', {
          MARKETING: true,
          ANALYTICS: true,
          PERSONALIZATION: true,
          STORAGE: true,
          OPT_OUT: false,
        });
        steps.push(`toggle on ${t.categories.filter((c) => c !== 'OPT_OUT').join(', ')}`);
        steps.push(`toggle off OPT_OUT`);
        if (!(await uiStep(page, 'save')).saved) throw new Error('Save button not found');
        steps.push(`click ${SEL.save}`);
      }
      check = (c) =>
        ['MARKETING', 'ANALYTICS', 'PERSONALIZATION'].every((k) => !c[k] || c[k] === 'ACCEPT') &&
        c.OPT_OUT !== 'ACCEPT';
    } else if (mode === 'opt-out') {
      steps.push('Osano.cm.showDoNotSell()');
      await openView(page, 'showDoNotSell');
      const t = await uiStep(page, 'toggles', { OPT_OUT: true });
      if (!t.categories.includes('OPT_OUT'))
        throw new Error('No OPT_OUT toggle in Do Not Sell view');
      steps.push(`toggle on ${SEL.toggle.replace('[data-category]', '[data-category="OPT_OUT"]')}`);
      if (!(await uiStep(page, 'save')).saved) throw new Error('Save button not found');
      steps.push(`click ${SEL.save}`);
      check = (c) => c.OPT_OUT === 'ACCEPT';
    } else if (mode.startsWith('deny-')) {
      const target = mode.slice(5).toUpperCase();
      steps.push('Osano.cm.showDrawer()');
      await openView(page, 'showDrawer');
      const want = { MARKETING: true, ANALYTICS: true, PERSONALIZATION: true, STORAGE: true };
      want.OPT_OUT = false;
      want[target] = false;
      const t = await uiStep(page, 'toggles', want);
      if (!t.categories.includes(target)) {
        throw new Error(`No toggle for ${target} (found ${t.categories.join(', ') || 'none'})`);
      }
      steps.push(
        `enable all, disable ${SEL.toggle.replace('[data-category]', `[data-category="${target}"]`)}`,
      );
      if (!(await uiStep(page, 'save')).saved) throw new Error('Save button not found');
      steps.push(`click ${SEL.save}`);
      check = (c) => c[target] === 'DENY';
    } else {
      return { ok: true, method: 'none', steps };
    }

    await settle(page);
    await detect(page);
    const state = await readState(page);
    const ok = !!state.consent && check(state.consent);
    return {
      ok,
      steps,
      consent: state.consent,
      ...(ok ? {} : { error: 'Consent not as expected' }),
    };
  } catch (err) {
    return { ok: false, steps, error: err.message };
  }
};

// Osano category for a URL or cookie name, from the classification patterns
export const classify = (map, value) => {
  for (const [pattern, category] of Object.entries(map || {})) {
    if (!pattern || pattern.length > 300) continue;
    try {
      if (new RegExp(pattern, 'i').test(value)) return category;
    } catch {
      if (value.includes(pattern)) return category;
    }
  }
  return null;
};
