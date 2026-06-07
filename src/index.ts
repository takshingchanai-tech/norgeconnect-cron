/**
 * NorwayContact Cron Worker
 * Runs on a daily schedule (08:00 UTC = 09:00 Oslo winter / 10:00 Oslo summer)
 *
 * Queue flow:
 *   scheduled  → dispatches one 'dispatch' message per active client
 *   'dispatch' → selects targets, queues one 'email' message per target (2-min stagger + jitter)
 *               + one 'report' message delayed 4 hours
 *   'email'    → sends one email to one target, logs result
 *   'report'   → sends daily/weekly report to client
 *
 * Other tasks (in scheduled, DB-only):
 *   - Trial reminders and expiry management
 *   - Login token cleanup
 *
 * Secrets (wrangler secret put):
 *   STRIPE_SECRET_KEY, RESEND_API_KEY,
 *   GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET,
 *   OUTLOOK_CLIENT_ID, OUTLOOK_CLIENT_SECRET
 *
 * Plain vars (wrangler.toml [vars]):
 *   STRIPE_PRICE_ID, PAYMENT_LINK_URL, SYSTEM_FROM_EMAIL
 */

export interface Env {
  DB: D1Database;
  STRIPE_SECRET_KEY: string;
  STRIPE_METER_EVENT: string;    // e.g. norwaycontact_active_day
  PAYMENT_LINK_MONTHLY: string;
  PAYMENT_LINK_PRO_MONTHLY: string;
  RESEND_API_KEY: string;        // For sending system emails
  SYSTEM_FROM_EMAIL: string;     // e.g. hello@norgeconnect.no
  GMAIL_CLIENT_ID: string;
  GMAIL_CLIENT_SECRET: string;
  OUTLOOK_CLIENT_ID: string;
  OUTLOOK_CLIENT_SECRET: string;
  CRON_TRIGGER_KEY: string;      // Secret key required to hit /trigger and /backfill-sender-emails
  EMAIL_QUEUE: Queue<QueueMsg>;
  TOKEN_ENCRYPTION_KEY: string;
  SITE_URL: string;              // e.g. https://www.norwaycontact.com
}

interface Client {
  id: string;
  email: string;
  company: string;
  org_number: string | null;
  sig_name: string | null;
  sig_info: string | null;
  subject_template: string;
  pitch_template: string;
  logo_base64: string | null;
  logo_key: string | null;
  stripe_customer_id: string | null;
  stripe_subscription_id: string | null;
  stripe_item_id: string | null;
  gmail_access_token: string | null;
  gmail_refresh_token: string | null;
  gmail_token_expiry: string | null;
  outlook_access_token: string | null;
  outlook_refresh_token: string | null;
  outlook_token_expiry: string | null;
  email_provider: 'gmail' | 'outlook' | null;
  gmail_sender_email: string | null;
  outlook_sender_email: string | null;
  trial_start: string;
  trial_end: string;
  status: 'trial' | 'active' | 'awaiting' | 'paused' | 'cancelled';
  pause_sending: number;
  daily_limit: number;
  payment_reminder_sent: number;
  report_frequency: 'daily' | 'weekly';
  last_report_sent: string | null;
  use_intro: number;
  language: string | null;
  created_at: string;
  next_billing_date: string | null;
  target_warning_sent: string | null;
}

interface Target {
  org_number: string;
  company_name: string;
  owner_name: string | null;
  email: string;
  industry_name: string | null;
  revenue_band: string | null;
  location: string | null;
  homepage: string | null;
  do_not_contact: number;
}

type QueueMsg =
  | { type: 'dispatch'; clientId: string; today: string }
  | { type: 'email';    clientId: string; targetOrgNumber: string; today: string }
  | { type: 'report';   clientId: string; today: string };

// EMAILS_PER_DAY replaced by client.daily_limit (Standard=20, Pro=50)
const CONTACT_COOLDOWN_DAYS = 5;

// ---------------------------------------------------------------------------
// Token encryption — AES-256-GCM using Worker secret as key material
// ---------------------------------------------------------------------------

async function getEncKey(secret: string): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), 'HKDF', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256',
      salt: new TextEncoder().encode('norwaycontact-oauth-tokens'),
      info: new TextEncoder().encode('v1') },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false, ['encrypt', 'decrypt']
  );
}

async function encryptToken(plaintext: string, key: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  const b64 = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b)));
  return `v1:${b64(iv.buffer)}:${b64(ct)}`;
}

async function decryptToken(stored: string, key: CryptoKey): Promise<string | null> {
  if (!stored.startsWith('v1:')) return null;
  const [, ivB64, ctB64] = stored.split(':');
  try {
    const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
    const ct = Uint8Array.from(atob(ctB64), c => c.charCodeAt(0));
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new TextDecoder().decode(pt);
  } catch { return null; }
}

async function getUnsubHmacKey(secret: string): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), 'HKDF', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256',
      salt: new TextEncoder().encode('norwaycontact-unsubscribe'),
      info: new TextEncoder().encode('v1') },
    keyMaterial,
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
}

async function signUnsubToken(org: string, key: CryptoKey): Promise<string> {
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(org));
  return Array.from(new Uint8Array(sig).slice(0, 16))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// Cloudflare Queue sendBatch is capped at 100 messages per call.
// This helper chunks any larger array into sequential batches of 100.
// ---------------------------------------------------------------------------

async function sendBatchChunked<T>(
  queue: Queue<T>,
  messages: Array<{ body: T; delaySeconds?: number }>,
  chunkSize = 100
): Promise<void> {
  for (let i = 0; i < messages.length; i += chunkSize) {
    await queue.sendBatch(messages.slice(i, i + chunkSize));
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export default {
  // Stage 1: fires at 08:00 UTC — dispatches one 'dispatch' message per active client
  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const today = toISODate(new Date());
    console.log(`[cron] Running for date: ${today}`);

    const { results: clients } = await env.DB.prepare(`
      SELECT id FROM clients
      WHERE status IN ('trial', 'active')
      AND email_provider IS NOT NULL
      AND pause_sending = 0
    `).all<{ id: string }>();

    if (clients.length > 0) {
      await sendBatchChunked(
        env.EMAIL_QUEUE,
        clients.map(c => ({ body: { type: 'dispatch' as const, clientId: c.id, today } }))
      );
      console.log(`[cron] Dispatched ${clients.length} client(s) to queue`);
    }

    ctx.waitUntil(Promise.all([
      runTrialManagement(env, today),
      cleanupLoginTokens(env),
      cleanupCancelledClients(env),
    ]));
  },

  // Stage 2/3/4: queue handler processes one message at a time
  async queue(batch: MessageBatch<QueueMsg>, env: Env): Promise<void> {
    for (const msg of batch.messages) {
      try {
        const job = msg.body;
        if (job.type === 'dispatch') {
          await handleDispatch(env, job.clientId, job.today);
        } else if (job.type === 'email') {
          await handleSendEmail(env, job.clientId, job.targetOrgNumber, job.today);
        } else if (job.type === 'report') {
          const client = await env.DB.prepare('SELECT * FROM clients WHERE id = ?')
            .bind(job.clientId).first<Client>();
          if (client) await sendReportForClient(env, client, job.today);
        }
        msg.ack();
      } catch (err) {
        console.error(`[queue] Job failed:`, msg.body, err);
        msg.retry();
      }
    }
  },

  // Allow manual trigger for testing: GET /trigger?key=xxx
  async fetch(request: Request, env: Env): Promise<Response> {
    const url  = new URL(request.url);
    const path = url.pathname;
    const key  = url.searchParams.get('key');

    if (path === '/trigger' || path === '/backfill-sender-emails') {
      if (!env.CRON_TRIGGER_KEY || key !== env.CRON_TRIGGER_KEY) {
        return new Response('Forbidden', { status: 403 });
      }
    }

    if (path === '/trigger') {
      const today = toISODate(new Date());
      const { results: clients } = await env.DB.prepare(`
        SELECT id FROM clients
        WHERE status IN ('trial', 'active')
        AND email_provider IS NOT NULL
        AND pause_sending = 0
      `).all<{ id: string }>();

      if (clients.length > 0) {
        await sendBatchChunked(
          env.EMAIL_QUEUE,
          clients.map(c => ({ body: { type: 'dispatch' as const, clientId: c.id, today } }))
        );
      }
      await runTrialManagement(env, today);
      await cleanupLoginTokens(env);
      await cleanupCancelledClients(env);
      return new Response(`Dispatched ${clients.length} job(s) to queue`, { status: 200 });
    }

    // One-time backfill: populate gmail_sender_email / outlook_sender_email
    // for existing clients who connected before this field was added.
    if (path === '/backfill-sender-emails') {
      const results = await backfillSenderEmails(env);
      return new Response(JSON.stringify(results), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response('NorwayContact Cron Worker', { status: 200 });
  },
};

// ---------------------------------------------------------------------------
// Stage 2: handleDispatch — selects targets, queues one email message per target
// ---------------------------------------------------------------------------

async function handleDispatch(env: Env, clientId: string, today: string): Promise<void> {
  const client = await env.DB.prepare('SELECT * FROM clients WHERE id = ?')
    .bind(clientId).first<Client>();
  if (!client) return;

  const accessToken = await getValidAccessToken(env, client);
  if (!accessToken) {
    console.warn(`[dispatch] Client ${clientId}: no valid token, skipping`);
    return;
  }

  const sentTodayRow = await env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM sent_emails WHERE client_id = ? AND sent_at >= ? AND status = 'sent'"
  ).bind(client.id, today).first<{ cnt: number }>();
  const remaining = (client.daily_limit ?? 20) - (sentTodayRow?.cnt ?? 0);
  if (remaining <= 0) {
    console.log(`[dispatch] Client ${clientId}: daily limit already reached`);
    return;
  }

  const cooloffDate = toISODate(addDays(new Date(), -CONTACT_COOLDOWN_DAYS));

  // Stage A: fresh targets — never contacted by this client.
  // Atomic claim: UPDATE sets last_contacted = today so concurrent dispatches for other
  // clients skip these targets. RETURNING gives back exactly what was claimed.
  const freshClaimQuery = `
    UPDATE targets SET last_contacted = ?
    WHERE org_number IN (
      SELECT t.org_number
      FROM targets t
      WHERE EXISTS (
        SELECT 1 FROM client_industries ci
        WHERE ci.client_id = ? AND t.industry_name = ci.industry
      )
      AND   t.email IS NOT NULL
      AND   t.do_not_contact = 0
      AND   NOT EXISTS (SELECT 1 FROM unsubscribed_emails ue WHERE ue.email = t.email)
      AND   (t.last_contacted IS NULL OR t.last_contacted < ?)
      AND   NOT EXISTS (
        SELECT 1 FROM sent_emails s
        WHERE s.client_id = ? AND s.target_org_number = t.org_number
      )
      ORDER BY RANDOM()
      LIMIT ?
    )
    RETURNING org_number`;

  const { results: freshTargets } = await env.DB.prepare(freshClaimQuery).bind(
    today, client.id, cooloffDate, client.id, remaining
  ).all<{ org_number: string }>();

  let targets = freshTargets;

  // Stage B: pool exhausted — fall back to targets last contacted >30 days ago by this client.
  // Same atomic claim pattern.
  if (targets.length === 0) {
    const recontactClaimQuery = `
      UPDATE targets SET last_contacted = ?
      WHERE org_number IN (
        SELECT t.org_number
        FROM targets t
        WHERE EXISTS (
          SELECT 1 FROM client_industries ci
          WHERE ci.client_id = ? AND t.industry_name = ci.industry
        )
        AND   t.email IS NOT NULL
        AND   t.do_not_contact = 0
        AND   NOT EXISTS (SELECT 1 FROM unsubscribed_emails ue WHERE ue.email = t.email)
        AND   (t.last_contacted IS NULL OR t.last_contacted < ?)
        AND   NOT EXISTS (
          SELECT 1 FROM sent_emails s
          WHERE s.client_id = ?
          AND   s.target_org_number = t.org_number
          AND   s.sent_at >= datetime('now', '-30 days')
        )
        ORDER BY RANDOM()
        LIMIT ?
      )
      RETURNING org_number`;

    const { results: recontactTargets } = await env.DB.prepare(recontactClaimQuery).bind(
      today, client.id, cooloffDate, client.id, remaining
    ).all<{ org_number: string }>();

    targets = recontactTargets;
    if (targets.length > 0) {
      console.log(`[dispatch] Client ${clientId}: fresh pool exhausted — re-contacting ${targets.length} target(s) (>30 days)`);
    }
  }

  if (targets.length === 0) {
    console.warn(`[dispatch] Client ${clientId}: no targets available`);
    return;
  }

  // Stagger emails 2 minutes apart with ±30s jitter — looks human, avoids rate limits
  const INTERVAL_SECONDS = 120;
  const messages: Array<{ body: QueueMsg; delaySeconds: number }> = targets.map((t, i) => ({
    body: { type: 'email' as const, clientId: client.id, targetOrgNumber: t.org_number, today },
    delaySeconds: i * INTERVAL_SECONDS + Math.floor(Math.random() * 30),
  }));

  // Report fires 4 hours after dispatch (~midday Oslo time)
  messages.push({
    body: { type: 'report' as const, clientId: client.id, today },
    delaySeconds: 4 * 3600,
  });

  await env.EMAIL_QUEUE.sendBatch(messages);
  console.log(`[dispatch] Client ${clientId}: queued ${targets.length} email(s) staggered over ~${Math.round(targets.length * INTERVAL_SECONDS / 60)} min`);

  // Record Stripe usage now — targets confirmed available, emails queued.
  // Wrapped in try/catch: a thrown network error would otherwise bubble up to the
  // queue handler which retries the entire handleDispatch, re-queuing duplicate emails.
  if (client.status === 'active' && client.stripe_customer_id) {
    try {
      await recordStripeUsage(env, client.stripe_customer_id);
    } catch (err) {
      console.error(`[dispatch] Stripe meter event failed for ${clientId} (non-fatal):`, err);
    }
  }

  // Check if low-target warning should be sent (7 days before billing renewal)
  try {
    await checkAndSendTargetWarning(env, client, today);
  } catch (err) {
    console.error(`[dispatch] Target warning check failed for ${clientId} (non-fatal):`, err);
  }
}

async function checkAndSendTargetWarning(env: Env, client: Client, today: string): Promise<void> {
  if (client.status !== 'active' || !client.next_billing_date) return;

  // Pin to noon UTC so day differences are always clean integers regardless of when cron fires
  const todayNoon   = new Date(today + 'T12:00:00Z').getTime();
  const billingNoon = new Date(client.next_billing_date + 'T12:00:00Z').getTime();

  // Only warn once per 30 days
  if (client.target_warning_sent) {
    const warnedNoon = new Date(client.target_warning_sent + 'T12:00:00Z').getTime();
    const daysSinceWarning = Math.round((todayNoon - warnedNoon) / 86400000);
    if (daysSinceWarning < 30) return;
  }

  // Only warn in the 7-day window before billing renewal
  const daysUntilBilling = Math.round((billingNoon - todayNoon) / 86400000);
  if (daysUntilBilling > 7 || daysUntilBilling <= 0) return;

  // Count fresh targets only — warning is specifically about running out of new companies to contact
  const freshRow = await env.DB.prepare(`
    SELECT COUNT(*) as cnt FROM targets t
    WHERE EXISTS (
      SELECT 1 FROM client_industries ci
      WHERE ci.client_id = ? AND t.industry_name = ci.industry
    )
    AND t.email IS NOT NULL
    AND t.do_not_contact = 0
    AND NOT EXISTS (SELECT 1 FROM unsubscribed_emails ue WHERE ue.email = t.email)
    AND NOT EXISTS (
      SELECT 1 FROM sent_emails s
      WHERE s.client_id = ? AND s.target_org_number = t.org_number
    )
  `).bind(client.id, client.id).first<{ cnt: number }>();

  const freshCount    = freshRow?.cnt ?? 0;
  const monthlyNeeded = (client.daily_limit ?? 20) * 30;

  if (freshCount >= monthlyNeeded) return; // Enough fresh targets — no warning needed

  await sendTargetWarningEmail(env, client, freshCount, monthlyNeeded);
  await env.DB.prepare("UPDATE clients SET target_warning_sent = ? WHERE id = ?")
    .bind(today, client.id).run();
  console.log(`[dispatch] Target warning sent to ${client.email}: ${freshCount}/${monthlyNeeded} fresh targets remaining`);
}

// ---------------------------------------------------------------------------
// Stage 3: handleSendEmail — sends one email for one target
// ---------------------------------------------------------------------------

async function handleSendEmail(
  env: Env,
  clientId: string,
  targetOrgNumber: string,
  today: string
): Promise<void> {
  const [client, target] = await Promise.all([
    env.DB.prepare('SELECT * FROM clients WHERE id = ?').bind(clientId).first<Client>(),
    env.DB.prepare('SELECT * FROM targets WHERE org_number = ?').bind(targetOrgNumber).first<Target>(),
  ]);

  if (!client || !target) {
    console.warn(`[email] Missing client or target: ${clientId} / ${targetOrgNumber}`);
    return;
  }

  // Re-check in case client cancelled or target unsubscribed since dispatch
  if (!['trial', 'active'].includes(client.status) || client.pause_sending) {
    console.log(`[email] Client ${clientId}: no longer active, skipping`);
    return;
  }
  if (target.do_not_contact) {
    console.log(`[email] Target ${targetOrgNumber} opted out since dispatch, skipping`);
    return;
  }

  const emailBlocked = await env.DB.prepare(
    'SELECT 1 FROM unsubscribed_emails WHERE email = ?'
  ).bind(target.email).first();
  if (emailBlocked) {
    console.log(`[email] Target email ${target.email} is globally unsubscribed, skipping`);
    return;
  }

  const accessToken = await getValidAccessToken(env, client);
  if (!accessToken) {
    console.warn(`[email] Client ${clientId}: no valid token`);
    return;
  }

  const unsubHmacKey = await getUnsubHmacKey(env.TOKEN_ENCRYPTION_KEY);
  const unsubToken = await signUnsubToken(target.org_number, unsubHmacKey);
  const body = buildEmailBody(client, target, unsubToken);
  const success = client.email_provider === 'gmail'
    ? await sendViaGmail(accessToken, target.email, client.subject_template, body)
    : await sendViaOutlook(accessToken, target.email, client.subject_template, body);

  await env.DB.prepare(`
    INSERT INTO sent_emails
      (id, client_id, target_org_number, target_company, target_owner,
       target_email, target_location, target_revenue, sent_at, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    crypto.randomUUID(), client.id, target.org_number, target.company_name,
    target.owner_name ?? null, target.email, target.location ?? null,
    target.revenue_band ?? null, new Date().toISOString(),
    success ? 'sent' : 'failed'
  ).run();

  await env.DB.prepare(
    'UPDATE targets SET last_contacted = ?, times_sent = times_sent + 1 WHERE org_number = ?'
  ).bind(today, target.org_number).run();

  console.log(`[email] ${client.company} → ${target.company_name}: ${success ? 'sent' : 'failed'}`);
}

// ---------------------------------------------------------------------------
// Task 2: Trial management — reminders and expiry
// ---------------------------------------------------------------------------

async function runTrialManagement(env: Env, today: string): Promise<void> {
  const tomorrow = toISODate(addDays(new Date(), 1));

  // Day-6 reminder: trial ends tomorrow, send payment link
  const { results: expiringTomorrow } = await env.DB.prepare(`
    SELECT * FROM clients
    WHERE status = 'trial'
    AND trial_end = ?
    AND payment_reminder_sent = 0
  `).bind(tomorrow).all<Client>();

  for (const client of expiringTomorrow) {
    await sendPaymentReminder(env, client, 'tomorrow');
    await env.DB.prepare("UPDATE clients SET payment_reminder_sent = 1 WHERE id = ?")
      .bind(client.id).run();
    console.log(`[cron] Sent payment reminder to ${client.email}`);
  }

  // Awaiting payment for >3 days — pause service.
  // Runs BEFORE the expired-today block so that a client whose trial expired 4+ days ago
  // (missed cron) doesn't get moved trial→awaiting and then immediately paused in the same run.
  const threeDaysAgo = toISODate(addDays(new Date(), -3));
  const { results: longAwaiting } = await env.DB.prepare(`
    SELECT * FROM clients
    WHERE status = 'awaiting'
    AND trial_end < ?
  `).bind(threeDaysAgo).all<Client>();

  for (const client of longAwaiting) {
    await env.DB.prepare("UPDATE clients SET status = 'paused' WHERE id = ?")
      .bind(client.id).run();
    console.log(`[cron] Paused client ${client.email} (no payment after 3 days)`);
  }

  // Trial expired today — move to 'awaiting' and send urgent reminder
  const { results: expiredToday } = await env.DB.prepare(`
    SELECT * FROM clients
    WHERE status = 'trial'
    AND trial_end <= ?
  `).bind(today).all<Client>();

  for (const client of expiredToday) {
    await sendPaymentReminder(env, client, 'expired');
    await env.DB.prepare("UPDATE clients SET status = 'awaiting' WHERE id = ?")
      .bind(client.id).run();
    console.log(`[cron] Trial expired for ${client.email}, moved to awaiting`);
  }
}

// ---------------------------------------------------------------------------
// Email composition
// ---------------------------------------------------------------------------

const API_BASE = 'https://norgeconnect-api.takshingchanai.workers.dev';

async function createDashboardToken(env: Env, clientId: string): Promise<string> {
  try {
    const token = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    await env.DB.prepare(
      'INSERT INTO login_tokens (token, client_id, expires_at, used) VALUES (?, ?, ?, 0)'
    ).bind(token, clientId, expiresAt).run();
    return `${API_BASE}/api/login/verify?token=${token}`;
  } catch {
    return `${env.SITE_URL}/dashboard?id=${clientId}`;
  }
}

function parseLogos(raw: string | null): string[] {
  if (!raw) return [];
  if (raw.startsWith('[')) {
    try { return JSON.parse(raw) as string[]; } catch { return [raw]; }
  }
  return [raw];
}

function buildEmailBody(client: Client, target: Target, unsubToken: string): string {
  const esc = (s: string) => s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\n/g, '<br>');

  const ownerFirst = target.owner_name?.split(' ')[0];
  const greeting = ownerFirst ? `Hei ${esc(ownerFirst)},` : 'Hei,';

  // sig_info may be stored with literal \n sequences — normalise before splitting
  const sigLines = (client.sig_info ?? '')
    .replace(/\\n/g, '\n')
    .split('\n')
    .filter(Boolean)
    .map(esc)
    .join('<br>');

  const sigBlock = [
    client.sig_name ? `<strong>${esc(client.sig_name)}</strong>` : '',
    client.company ? esc(client.company) : '',
    sigLines,
  ].filter(Boolean).join('<br>');

  const logoHtml = parseLogos(client.logo_base64)
    .map((_, i) => `<img src="${API_BASE}/api/logo?key=${client.logo_key}&n=${i}" alt="" style="max-height:60px;max-width:200px;display:block;margin-bottom:8px;">`)
    .join('');

  const unsubUrl = `${API_BASE}/api/unsubscribe?org=${target.org_number}&token=${unsubToken}`;

  const introHtml = (client.use_intro !== 0 && target.industry_name)
    ? `<p>Vi jobber med selskaper innen ${esc(target.industry_name)} og tok kontakt fordi vi tror vårt tilbud kan være relevant for <strong>${esc(target.company_name)}</strong>.</p>`
    : '';

  return `<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;font-size:14px;color:#333;line-height:1.7;max-width:600px;margin:0;padding:20px;">
<p>${greeting}</p>
${introHtml}<p>${esc(client.pitch_template)}</p>
<br>
<p style="margin-bottom:6px;">Med vennlig hilsen,</p>
${logoHtml}
<p style="margin:0;line-height:1.5;">${sigBlock}</p>
<br>
<hr style="border:none;border-top:1px solid #ddd;margin:16px 0;">
<p style="font-size:12px;color:#666;">Ønsker du ikke å motta slike henvendelser? <a href="${unsubUrl}" style="color:#444;text-decoration:underline;">Klikk her for å melde deg av</a> &nbsp;·&nbsp; <a href="https://www.norwaycontact.com/privacy" style="color:#444;text-decoration:underline;">Personvern</a></p>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Gmail sender
// ---------------------------------------------------------------------------

function rfc2047Encode(s: string): string {
  // Strip CR/LF to prevent email header injection
  const sanitized = s.replace(/[\r\n]/g, '');
  if (/^[\x00-\x7F]*$/.test(sanitized)) return sanitized;
  const bytes = new TextEncoder().encode(sanitized);
  const binaryStr = Array.from(bytes, b => String.fromCharCode(b)).join('');
  return `=?UTF-8?B?${btoa(binaryStr)}?=`;
}

async function sendViaGmail(
  accessToken: string,
  to: string,
  subject: string,
  body: string
): Promise<boolean> {
  // Build RFC 2822 message
  const raw = [
    `To: ${to.replace(/[\r\n]/g, '')}`,
    `Subject: ${rfc2047Encode(subject)}`,
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=UTF-8',
    '',
    body,
  ].join('\r\n');

  const encoded = btoa(unescape(encodeURIComponent(raw)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const res = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ raw: encoded }),
  });

  if (!res.ok) {
    console.error('[gmail] Send failed:', await res.text());
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Outlook / Microsoft Graph sender
// ---------------------------------------------------------------------------

async function sendViaOutlook(
  accessToken: string,
  to: string,
  subject: string,
  body: string
): Promise<boolean> {
  const res = await fetch('https://graph.microsoft.com/v1.0/me/sendMail', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      message: {
        subject,
        body: { contentType: 'HTML', content: body },
        toRecipients: [{ emailAddress: { address: to } }],
      },
      saveToSentItems: true,
    }),
  });

  if (!res.ok) {
    console.error('[outlook] Send failed:', await res.text());
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// OAuth token refresh
// ---------------------------------------------------------------------------

async function getValidAccessToken(env: Env, client: Client): Promise<string | null> {
  if (!client.email_provider) return null;

  const isGmail = client.email_provider === 'gmail';
  const expiry        = isGmail ? client.gmail_token_expiry   : client.outlook_token_expiry;
  const encAccess     = isGmail ? client.gmail_access_token   : client.outlook_access_token;
  const encRefresh    = isGmail ? client.gmail_refresh_token  : client.outlook_refresh_token;

  if (!encAccess || !encRefresh) return null;

  const encKey = await getEncKey(env.TOKEN_ENCRYPTION_KEY);
  const accessToken  = await decryptToken(encAccess,  encKey);
  const refreshToken = await decryptToken(encRefresh, encKey);
  if (!accessToken || !refreshToken) return null;

  // Refresh if expiring within 5 minutes
  const expiresAt = expiry ? new Date(expiry).getTime() : 0;
  if (Date.now() < expiresAt - 5 * 60 * 1000) {
    return accessToken; // Still valid — return plaintext
  }

  return isGmail
    ? refreshGmailToken(env, client.id, refreshToken)   // plaintext refresh token passed in
    : refreshOutlookToken(env, client.id, refreshToken);
}

async function refreshGmailToken(env: Env, clientId: string, refreshToken: string): Promise<string | null> {
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.GMAIL_CLIENT_ID,
      client_secret: env.GMAIL_CLIENT_SECRET,
      refresh_token: refreshToken,
      grant_type: 'refresh_token',
    }),
  });

  if (!res.ok) { console.error('[oauth] Gmail refresh failed:', await res.text()); return null; }

  const tokens = await res.json() as { access_token: string; expires_in: number };
  const expiry = new Date(Date.now() + tokens.expires_in * 1000).toISOString();

  const encKey = await getEncKey(env.TOKEN_ENCRYPTION_KEY);
  const encNewAccess = await encryptToken(tokens.access_token, encKey);

  await env.DB.prepare(
    "UPDATE clients SET gmail_access_token = ?, gmail_token_expiry = ? WHERE id = ?"
  ).bind(encNewAccess, expiry, clientId).run();

  return tokens.access_token; // return plaintext for immediate use
}

async function refreshOutlookToken(env: Env, clientId: string, refreshToken: string): Promise<string | null> {
  const res = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.OUTLOOK_CLIENT_ID,
      client_secret: env.OUTLOOK_CLIENT_SECRET,
      refresh_token: refreshToken,
      grant_type: 'refresh_token',
    }),
  });

  if (!res.ok) { console.error('[oauth] Outlook refresh failed:', await res.text()); return null; }

  const tokens = await res.json() as { access_token: string; expires_in: number; refresh_token?: string };
  const expiry = new Date(Date.now() + tokens.expires_in * 1000).toISOString();

  const encKey = await getEncKey(env.TOKEN_ENCRYPTION_KEY);
  const encNewAccess = await encryptToken(tokens.access_token, encKey);

  if (tokens.refresh_token) {
    // Microsoft may rotate the refresh token on each use — save the new one to prevent expiry
    const encNewRefresh = await encryptToken(tokens.refresh_token, encKey);
    await env.DB.prepare(
      "UPDATE clients SET outlook_access_token = ?, outlook_refresh_token = ?, outlook_token_expiry = ? WHERE id = ?"
    ).bind(encNewAccess, encNewRefresh, expiry, clientId).run();
  } else {
    await env.DB.prepare(
      "UPDATE clients SET outlook_access_token = ?, outlook_token_expiry = ? WHERE id = ?"
    ).bind(encNewAccess, expiry, clientId).run();
  }

  return tokens.access_token; // return plaintext for immediate use
}

// ---------------------------------------------------------------------------
// Stripe usage recording
// ---------------------------------------------------------------------------

async function recordStripeUsage(env: Env, stripeCustomerId: string): Promise<void> {
  const res = await fetch('https://api.stripe.com/v1/billing/meter_events', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      event_name: env.STRIPE_METER_EVENT,
      'payload[value]': '1',
      'payload[stripe_customer_id]': stripeCustomerId,
    }),
  });
  if (!res.ok) console.error('[stripe] Meter event failed:', await res.text());
}

// ---------------------------------------------------------------------------
// System emails via Resend
// ---------------------------------------------------------------------------

async function sendResendEmail(env: Env, to: string, subject: string, text: string, html?: string): Promise<void> {
  const body: Record<string, unknown> = {
    from: `NorwayContact <${env.SYSTEM_FROM_EMAIL}>`,
    to: [to],
    subject,
    text,
    headers: {
      'List-Unsubscribe': `<mailto:${env.SYSTEM_FROM_EMAIL}?subject=unsubscribe>`,
      'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
    },
  };
  if (html) body.html = html;
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) console.error('[resend] Email failed:', await res.text());
}

async function sendPaymentReminder(
  env: Env,
  client: Client,
  when: 'tomorrow' | 'expired'
): Promise<void> {
  const isEn = client.language === 'en';
  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const name = esc(client.sig_name ?? client.company);
  const dashboardUrl = await createDashboardToken(env, client.id);

  const subject = when === 'tomorrow'
    ? (isEn ? 'Your NorwayContact trial expires tomorrow'                            : 'Din NorwayContact prøveperiode utløper i morgen')
    : (isEn ? 'Your NorwayContact trial has ended — continue without interruption'   : 'Din NorwayContact prøveperiode er over — fortsett uten avbrudd');

  // ── Copy ─────────────────────────────────────────────────────────────────
  const greeting  = isEn ? `Hi ${name},` : `Hei ${name},`;
  const bodyLine1 = when === 'tomorrow'
    ? (isEn ? 'Your free trial expires <strong>tomorrow</strong>. Choose a plan below to continue without interruption.'         : 'Prøveperioden din utløper <strong>i morgen</strong>. Velg et abonnement nedenfor for å fortsette uten avbrudd.')
    : (isEn ? 'Your trial has ended. Email sending has been <strong>temporarily paused</strong>.'                                : 'Prøveperioden din er over. E-postutsendelsen er <strong>midlertidig satt på pause</strong>.');
  const bodyLine2 = when === 'tomorrow'
    ? (isEn ? 'It takes under 2 minutes — card payment via Stripe. Start sending the next morning.'                              : 'Det tar under 2 minutter — kortbetaling via Stripe. Utsendelsene starter neste morgen.')
    : (isEn ? 'All your settings, templates, and data are preserved. Choose a plan to resume.'                                   : 'Alle innstillinger, maler og data er beholdt. Velg et abonnement for å fortsette.');
  const stdLabel    = isEn ? 'Standard — 20 emails/day'       : 'Standard — 20 henvendelser/dag';
  const proLabel    = isEn ? 'Pro — 50 emails/day'            : 'Pro — 50 henvendelser/dag';
  const proSubline  = isEn ? '2.5× more reach per day'        : '2,5× mer rekkevidde per dag';
  const cancelNote  = isEn ? 'Auto-renews — cancel before next renewal.' : 'Fornyes automatisk — avslutt før neste fornyelse.';
  const helpLine    = isEn
    ? `Questions? Reply to this email or write to <a href="mailto:hello@norwaycontact.com" style="color:#1B3A6B;">hello@norwaycontact.com</a> · <a href="${dashboardUrl}" style="color:#1B3A6B;">Go to dashboard →</a>`
    : `Spørsmål? Svar på denne e-posten eller skriv til <a href="mailto:hello@norwaycontact.com" style="color:#1B3A6B;">hello@norwaycontact.com</a> · <a href="${dashboardUrl}" style="color:#1B3A6B;">Gå til dashboard →</a>`;
  const footerNote  = isEn
    ? 'NorwayContact · hello@norwaycontact.com<br>You are receiving this because you signed up at norwaycontact.com.'
    : 'NorwayContact · hello@norwaycontact.com<br>Du mottar denne e-posten fordi du registrerte deg på norwaycontact.com.';

  // ── HTML ──────────────────────────────────────────────────────────────────
  const html = `<!DOCTYPE html>
<html lang="${isEn ? 'en' : 'no'}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#FAFAF8;font-family:sans-serif;color:#111;">
<div style="max-width:580px;margin:40px auto;background:white;border:1px solid #E2E2DC;border-radius:12px;overflow:hidden;">

  <div style="background:#1B3A6B;padding:28px 32px;">
    <span style="color:white;font-size:1.125rem;font-weight:700;letter-spacing:-0.02em;">NorwayContact</span>
  </div>

  <div style="padding:36px 32px 28px;">
    <p style="margin:0 0 4px;font-size:1rem;color:#111;">${greeting}</p>
    <p style="margin:0 0 6px;font-size:0.9375rem;color:#374151;line-height:1.7;">${bodyLine1}</p>
    <p style="margin:0 0 28px;font-size:0.875rem;color:#6B7280;line-height:1.7;">${bodyLine2}</p>

    <!-- Standard plan -->
    <div style="border:1px solid #E2E2DC;border-radius:10px;padding:20px 24px;margin-bottom:14px;">
      <p style="margin:0 0 14px;font-weight:700;color:#111;font-size:0.9375rem;">${stdLabel}</p>
      <a href="${env.PAYMENT_LINK_MONTHLY}?prefilled_email=${encodeURIComponent(client.email)}" style="display:inline-block;padding:11px 20px;background:#1B3A6B;color:white;border-radius:8px;font-weight:600;font-size:0.875rem;text-decoration:none;white-space:nowrap;">
        ${isEn ? '1700 NOK/month →' : '1700 NOK/mnd →'}
      </a>
    </div>

    <!-- Pro plan -->
    <div style="border:1px solid #C7D9F5;border-radius:10px;padding:20px 24px;margin-bottom:24px;background:#F0F5FF;">
      <p style="margin:0 0 2px;font-weight:700;color:#111;font-size:0.9375rem;">${proLabel}</p>
      <p style="margin:0 0 14px;font-size:0.8125rem;color:#6B7280;">${proSubline}</p>
      <a href="${env.PAYMENT_LINK_PRO_MONTHLY}?prefilled_email=${encodeURIComponent(client.email)}" style="display:inline-block;padding:11px 20px;background:#1B3A6B;color:white;border-radius:8px;font-weight:600;font-size:0.875rem;text-decoration:none;white-space:nowrap;">
        ${isEn ? '3400 NOK/month →' : '3400 NOK/mnd →'}
      </a>
    </div>

    <p style="margin:0 0 20px;font-size:0.875rem;color:#6B7280;">${cancelNote}</p>

    <hr style="border:none;border-top:1px solid #E2E2DC;margin:0 0 16px;">
    <p style="margin:0;font-size:0.8125rem;color:#9CA3AF;line-height:1.7;">${helpLine}</p>
  </div>

  <div style="background:#F5F5F2;padding:14px 32px;">
    <p style="margin:0;font-size:0.8125rem;color:#9CA3AF;line-height:1.6;">${footerNote}</p>
  </div>

</div>
</body>
</html>`;

  // ── Plain text fallback ───────────────────────────────────────────────────
  const text = [
    greeting,
    '',
    when === 'tomorrow'
      ? (isEn ? 'Your free trial expires tomorrow.' : 'Prøveperioden din utløper i morgen.')
      : (isEn ? 'Your trial has ended. Email sending has been temporarily paused.' : 'Prøveperioden din er over. E-postutsendelsen er midlertidig satt på pause.'),
    '',
    isEn ? 'Standard — 20 emails/day:' : 'Standard — 20 henvendelser/dag:',
    `  1700 NOK/${isEn ? 'month' : 'mnd'}  → ${env.PAYMENT_LINK_MONTHLY}?prefilled_email=${encodeURIComponent(client.email)}`,
    '',
    isEn ? 'Pro — 50 emails/day:' : 'Pro — 50 henvendelser/dag:',
    `  3400 NOK/${isEn ? 'month' : 'mnd'}  → ${env.PAYMENT_LINK_PRO_MONTHLY}?prefilled_email=${encodeURIComponent(client.email)}`,
    '',
    cancelNote,
    '',
    '— NorwayContact',
  ].join('\n');

  await sendResendEmail(env, client.email, subject, text, html);
}

// ---------------------------------------------------------------------------
// Task 3: Send report for a single client (called from queue handler)
// ---------------------------------------------------------------------------

async function sendReportForClient(env: Env, client: Client, today: string): Promise<void> {
  const isWeekly = client.report_frequency === 'weekly';
  if (!shouldSendReport(client, today, isWeekly)) return;

  const sinceDate = isWeekly
    ? toISODate(addDays(new Date(today), -6))
    : today;

  const { results: rows } = await env.DB.prepare(`
    SELECT s.target_company, s.target_owner, s.target_location, s.target_email,
           t.homepage AS target_homepage, t.industry_name AS target_industry
    FROM sent_emails s
    LEFT JOIN targets t ON t.org_number = s.target_org_number
    WHERE s.client_id = ? AND DATE(s.sent_at) >= ? AND s.status = 'sent'
    ORDER BY s.sent_at ASC
  `).bind(client.id, sinceDate).all<{
    target_company: string;
    target_owner: string | null;
    target_location: string | null;
    target_email: string;
    target_homepage: string | null;
    target_industry: string | null;
  }>();

  if (rows.length === 0) return;

  const isEn = client.language === 'en';
  const subject = isWeekly
    ? (isEn ? `NorwayContact — Weekly report` : `NorwayContact — Ukentlig rapport`)
    : (isEn ? `NorwayContact — Daily report, ${today}` : `NorwayContact — Daglig rapport, ${today}`);

  const dashboardUrl = await createDashboardToken(env, client.id);
  const html = buildReportHtml(client, rows, isWeekly, today, dashboardUrl);
  const text = rows.map((r, i) =>
    `${i + 1}. ${r.target_company}  |  ${r.target_owner ?? '—'}  |  ${r.target_location ?? '—'}  |  ${r.target_email}${r.target_homepage ? '  |  ' + r.target_homepage : ''}`
  ).join('\n');

  const reportTo = (client.email_provider === 'gmail' ? client.gmail_sender_email : client.outlook_sender_email) ?? client.email;
  await sendResendEmail(env, reportTo, subject, text, html);
  await env.DB.prepare("UPDATE clients SET last_report_sent = ? WHERE id = ?")
    .bind(today, client.id).run();

  console.log(`[queue] Report sent to ${reportTo}: ${rows.length} rows (${isWeekly ? 'weekly' : 'daily'})`);
}

function shouldSendReport(client: Client, today: string, isWeekly: boolean): boolean {
  if (!isWeekly) return true;
  const todayMs = new Date(today).getTime();
  if (!client.last_report_sent) {
    // Skip-trial clients have trial_start = '9999-12-31' (sentinel) — use created_at instead.
    // Truncate created_at to date-only so the comparison is in whole calendar days (midnight UTC)
    // rather than hours — otherwise a client who signed up at 15:00 UTC would see their first
    // weekly report delayed by one day.
    const startDate = client.trial_start >= '9999'
      ? client.created_at.split('T')[0]
      : client.trial_start;
    const daysSinceStart = (todayMs - new Date(startDate).getTime()) / 86400000;
    return daysSinceStart >= 6;
  }
  const daysSinceLast = (todayMs - new Date(client.last_report_sent).getTime()) / 86400000;
  return daysSinceLast >= 7;
}

function buildReportHtml(
  client: Client,
  rows: Array<{ target_company: string; target_owner: string | null; target_location: string | null; target_email: string; target_homepage: string | null; target_industry: string | null }>,
  isWeekly: boolean,
  today: string,
  dashboardUrl: string
): string {
  const isEn = client.language === 'en';
  const count = rows.length;
  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const summaryLine = isWeekly
    ? (isEn ? `You reached ${count} Norwegian companies this week. Here is the overview:` : `Du nådde ${count} norske bedrifter denne uken. Her er oversikten:`)
    : (isEn ? `You reached ${count} Norwegian companies today (${today}). Here is the overview:` : `Du nådde ${count} norske bedrifter i dag (${today}). Her er oversikten:`);

  const tableRows = rows.map((r, i) => {
    const bg = i % 2 === 0 ? '#ffffff' : '#FAFAF8';
    const homepageCell = r.target_homepage
      ? `<a href="${encodeURI(r.target_homepage.startsWith('http') ? r.target_homepage : 'https://' + r.target_homepage).replace(/"/g, '%22')}" style="color:#1B3A6B;font-size:0.8125rem;text-decoration:underline;">${esc(r.target_homepage.replace(/^https?:\/\/(www\.)?/, ''))}</a>`
      : `<span style="color:#9CA3AF;">—</span>`;
    return `<tr style="border-bottom:1px solid #E2E2DC;background:${bg};">
      <td style="padding:7px 8px;color:#6B7280;font-size:0.8125rem;width:24px;">${i + 1}</td>
      <td style="padding:7px 8px;font-weight:600;color:#111;font-size:0.8125rem;white-space:nowrap;">${esc(r.target_company)}</td>
      <td style="padding:7px 8px;color:#374151;font-size:0.8125rem;white-space:nowrap;">${esc(r.target_owner ?? '—')}</td>
      <td style="padding:7px 8px;color:#374151;font-size:0.8125rem;white-space:nowrap;">${esc(r.target_location ?? '—')}</td>
      <td style="padding:7px 8px;color:#1B3A6B;font-size:0.8125rem;white-space:nowrap;">${esc(r.target_email)}</td>
      <td style="padding:7px 8px;white-space:nowrap;">${homepageCell}</td>
    </tr>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="${isEn ? 'en' : 'no'}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#FAFAF8;font-family:Arial,sans-serif;color:#111;">
<div style="max-width:800px;margin:32px auto;background:white;border:1px solid #E2E2DC;border-radius:12px;overflow:hidden;">

  <div style="background:#1B3A6B;padding:24px 32px;">
    <span style="color:white;font-size:1.125rem;font-weight:700;letter-spacing:-0.02em;">NorwayContact</span>
    <span style="color:#93BFEF;font-size:0.875rem;margin-left:12px;">${isWeekly ? (isEn ? 'Weekly report' : 'Ukentlig rapport') : (isEn ? 'Daily report' : 'Daglig rapport')}</span>
  </div>

  <div style="padding:28px 32px 20px;">
    <p style="margin:0 0 6px;font-size:1rem;font-weight:700;color:#111;">${summaryLine}</p>

    <div style="display:inline-block;background:#EEF4FF;color:#1B3A6B;font-size:1.5rem;font-weight:700;padding:10px 20px;border-radius:8px;margin:14px 0 20px;letter-spacing:-0.02em;">
      ${count} ${isEn ? 'companies' : 'selskaper'}
    </div>

    <table style="width:100%;border-collapse:collapse;border:1px solid #E2E2DC;border-radius:8px;overflow:hidden;">
      <thead>
        <tr style="background:#F5F5F2;">
          <th style="padding:9px 8px;text-align:left;font-size:0.75rem;color:#6B7280;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;width:24px;">#</th>
          <th style="padding:9px 8px;text-align:left;font-size:0.75rem;color:#6B7280;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;">${isEn ? 'Company' : 'Selskap'}</th>
          <th style="padding:9px 8px;text-align:left;font-size:0.75rem;color:#6B7280;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;">${isEn ? 'Owner' : 'Eier'}</th>
          <th style="padding:9px 8px;text-align:left;font-size:0.75rem;color:#6B7280;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;">${isEn ? 'Location' : 'Sted'}</th>
          <th style="padding:9px 8px;text-align:left;font-size:0.75rem;color:#6B7280;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;">${isEn ? 'Email' : 'E-post'}</th>
          <th style="padding:9px 8px;text-align:left;font-size:0.75rem;color:#6B7280;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;">${isEn ? 'Website' : 'Nettside'}</th>
        </tr>
      </thead>
      <tbody>
        ${tableRows}
      </tbody>
    </table>

    ${(() => {
      const sample = rows[0];
      const ownerFirst = sample.target_owner?.split(' ')[0];
      const greeting = ownerFirst ? `Hei ${esc(ownerFirst)},` : 'Hei,';
      const introHtml = (client.use_intro !== 0 && sample.target_industry)
        ? `<p style="margin:0 0 12px;">Vi jobber med selskaper innen ${esc(sample.target_industry)} og tok kontakt fordi vi tror vårt tilbud kan være relevant for <strong>${esc(sample.target_company)}</strong>.</p>`
        : '';
      const sampleHeading = isEn ? 'Example email sent today' : 'Eksempel på e-post sendt i dag';
      const sampleSubline = isEn
        ? `This is how the email looked to the recipient at <strong style="color:#111;">${esc(sample.target_company)}</strong>:`
        : `Slik så e-posten ut for mottakeren hos <strong style="color:#111;">${esc(sample.target_company)}</strong>:`;
      const pitchHtml = esc(client.pitch_template).replace(/\n/g, '<br>');
      const sigLines = (client.sig_info ?? '').replace(/\\n/g, '\n').split('\n').filter(Boolean).map(esc).join('<br>');
      const sigBlock = [
        client.sig_name ? `<strong>${esc(client.sig_name)}</strong>` : '',
        client.company  ? esc(client.company)  : '',
        sigLines,
      ].filter(Boolean).join('<br>');
      const logoHtml = parseLogos(client.logo_base64)
        .map((_, i) => `<img src="${API_BASE}/api/logo?key=${client.logo_key}&n=${i}" alt="" style="max-height:52px;max-width:180px;display:block;margin-bottom:6px;">`)
        .join('');
      return `
    <div style="margin-top:28px;">
      <p style="margin:0 0 10px;font-size:0.875rem;font-weight:700;color:#374151;">${sampleHeading}</p>
      <p style="margin:0 0 12px;font-size:0.8125rem;color:#6B7280;">${sampleSubline}</p>
      <div style="border:1px solid #E2E2DC;border-radius:8px;overflow:hidden;font-family:Arial,sans-serif;font-size:14px;color:#333;line-height:1.7;">
        <div style="background:#F5F5F2;padding:10px 16px;border-bottom:1px solid #E2E2DC;font-size:0.8125rem;color:#6B7280;">
          <div><strong style="color:#374151;">${isEn ? 'To' : 'Til'}:</strong> ${esc(sample.target_email)}</div>
          <div><strong style="color:#374151;">${isEn ? 'Subject' : 'Emne'}:</strong> ${esc(client.subject_template)}</div>
        </div>
        <div style="padding:20px 24px;">
          <p style="margin:0 0 12px;">${greeting}</p>
          ${introHtml}
          <p style="margin:0 0 12px;">${pitchHtml}</p>
          <p style="margin:0 0 6px;">Med vennlig hilsen,</p>
          ${logoHtml}
          <p style="margin:0;line-height:1.5;">${sigBlock}</p>
          <hr style="border:none;border-top:1px solid #ddd;margin:16px 0;">
          <p style="margin:0;font-size:12px;color:#666;">Ønsker du ikke å motta slike henvendelser? <span style="color:#444;text-decoration:underline;">Klikk her for å melde deg av</span></p>
        </div>
      </div>
    </div>`;
    })()}

    <div style="margin-top:20px;text-align:center;">
      <a href="${dashboardUrl}" style="display:inline-block;padding:11px 24px;background:#1B3A6B;color:white;border-radius:8px;font-weight:600;font-size:0.9rem;text-decoration:none;">
        ${isEn ? 'Go to dashboard →' : 'Se dashboardet →'}
      </a>
    </div>
  </div>

  <div style="background:#F5F5F2;padding:14px 32px;">
    <p style="margin:0;font-size:0.8125rem;color:#9CA3AF;line-height:1.6;">
      NorwayContact · <a href="mailto:hello@norwaycontact.com" style="color:#6B7280;">hello@norwaycontact.com</a><br>
      ${isEn ? 'You are receiving this report as a NorwayContact subscriber.' : 'Du mottar denne rapporten fordi du er abonnent på NorwayContact.'}
    </p>
  </div>

</div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Target warning email
// ---------------------------------------------------------------------------

async function sendTargetWarningEmail(
  env: Env,
  client: Client,
  freshCount: number,
  monthlyNeeded: number
): Promise<void> {
  const isEn = client.language === 'en';
  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const name = esc(client.sig_name ?? client.company);
  const dashboardUrl = await createDashboardToken(env, client.id);
  const billingDate = client.next_billing_date
    ? new Date(client.next_billing_date + 'T12:00:00Z')
        .toLocaleDateString(isEn ? 'en-GB' : 'nb-NO', { day: 'numeric', month: 'long', year: 'numeric' })
    : '';
  const daysLeft = Math.max(1, Math.round(freshCount / (client.daily_limit || 20)));

  const subject = isEn
    ? `Your fresh target list is running low — subscription renewal on ${billingDate}`
    : `Nye målselskaper nærmer seg slutten — abonnementsfornyelse ${billingDate}`;

  const greeting = isEn ? `Hi ${name},` : `Hei ${name},`;
  const line1    = isEn
    ? `Your subscription renews on <strong>${billingDate}</strong>.`
    : `Abonnementet ditt fornyes <strong>${billingDate}</strong>.`;
  const line2    = isEn
    ? `You have <strong>${freshCount} fresh companies</strong> left to contact in your selected industries — enough for approximately <strong>${daysLeft} day${daysLeft === 1 ? '' : 's'}</strong> of sending.`
    : `Du har <strong>${freshCount} nye selskaper</strong> igjen å kontakte i dine valgte bransjer — nok til omtrent <strong>${daysLeft} dag${daysLeft === 1 ? '' : 'er'}</strong> med utsendelse.`;
  const line3    = isEn
    ? `After that, we will automatically continue by re-contacting companies we reached out to more than 30 days ago. If you would like to keep reaching new companies, you can add more industries from your dashboard.`
    : `Etter det vil vi automatisk fortsette med å kontakte selskaper vi nådde ut til for mer enn 30 dager siden. Hvis du ønsker å nå nye selskaper, kan du legge til flere bransjer i dashbordet ditt.`;
  const ctaLabel   = isEn ? `Add more target industries →` : `Legg til flere målbransjer →`;
  const cancelNote = isEn
    ? `You can cancel your subscription at any time from your dashboard.`
    : `Du kan avslutte abonnementet når som helst fra dashbordet.`;
  const footer     = isEn
    ? `NorwayContact · hello@norwaycontact.com`
    : `NorwayContact · hello@norwaycontact.com`;

  const html = `<!DOCTYPE html>
<html lang="${isEn ? 'en' : 'no'}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#FAFAF8;font-family:sans-serif;color:#111;">
<div style="max-width:560px;margin:40px auto;background:white;border:1px solid #E2E2DC;border-radius:12px;overflow:hidden;">
  <div style="background:#1B3A6B;padding:28px 32px;">
    <span style="color:white;font-size:1.125rem;font-weight:700;letter-spacing:-0.02em;">NorwayContact</span>
  </div>
  <div style="padding:36px 32px 28px;">
    <p style="margin:0 0 6px;font-size:1rem;color:#111;">${greeting}</p>
    <p style="margin:0 0 12px;font-size:0.9375rem;color:#374151;line-height:1.7;">${line1}</p>
    <p style="margin:0 0 12px;font-size:0.9375rem;color:#374151;line-height:1.7;">${line2}</p>
    <p style="margin:0 0 24px;font-size:0.9375rem;color:#374151;line-height:1.7;">${line3}</p>
    <a href="${dashboardUrl}" style="display:inline-block;padding:11px 24px;background:#1B3A6B;color:white;border-radius:8px;font-weight:600;font-size:0.9rem;text-decoration:none;">${ctaLabel}</a>
    <hr style="border:none;border-top:1px solid #E2E2DC;margin:24px 0 16px;">
    <p style="margin:0;font-size:0.8125rem;color:#9CA3AF;line-height:1.7;">${cancelNote}</p>
  </div>
  <div style="background:#F5F5F2;padding:14px 32px;">
    <p style="margin:0;font-size:0.8125rem;color:#9CA3AF;">${footer}</p>
  </div>
</div>
</body>
</html>`;

  const text = [
    greeting, '',
    isEn ? `Your subscription renews on ${billingDate}.` : `Abonnementet ditt fornyes ${billingDate}.`,
    isEn
      ? `You have ${freshCount} fresh companies left (~${daysLeft} days of sending). After that, we'll automatically re-contact companies from 30+ days ago.`
      : `Du har ${freshCount} nye selskaper igjen (~${daysLeft} dager med utsendelse). Etter det vil vi automatisk kontakte selskaper fra 30+ dager siden.`,
    '',
    isEn ? `Add more target industries: ${dashboardUrl}` : `Legg til flere målbransjer: ${dashboardUrl}`,
    '', cancelNote,
    '', '— NorwayContact',
  ].join('\n');

  await sendResendEmail(env, client.email, subject, text, html);
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function addDays(date: Date, days: number): Date {
  const d = new Date(date);
  d.setDate(d.getDate() + days);
  return d;
}

function toISODate(date: Date): string {
  return date.toISOString().split('T')[0];
}

// ---------------------------------------------------------------------------
// Cleanup: delete expired login tokens older than 1 day
// ---------------------------------------------------------------------------

async function cleanupLoginTokens(env: Env): Promise<void> {
  const { meta } = await env.DB.prepare(
    "DELETE FROM login_tokens WHERE expires_at < datetime('now', '-1 day')"
  ).run();
  if (meta.changes > 0) {
    console.log(`[cron] Cleaned up ${meta.changes} expired login token(s)`);
  }
}

// ---------------------------------------------------------------------------
// GDPR 90-day post-cancellation data cleanup
// Privacy policy: account data deleted 90 days after cancellation.
// Invoices are kept (Norwegian bookkeeping law — 5-year minimum).
// ---------------------------------------------------------------------------

async function cleanupCancelledClients(env: Env): Promise<void> {
  const { results: stale } = await env.DB.prepare(`
    SELECT id FROM clients
    WHERE status = 'cancelled'
      AND cancelled_at IS NOT NULL
      AND cancelled_at < datetime('now', '-90 days')
      AND email NOT LIKE '[deleted-%'
  `).all<{ id: string }>();

  if (stale.length === 0) return;

  for (const { id } of stale) {
    await env.DB.prepare('DELETE FROM sent_emails      WHERE client_id = ?').bind(id).run();
    await env.DB.prepare('DELETE FROM client_industries WHERE client_id = ?').bind(id).run();
    await env.DB.prepare('DELETE FROM login_tokens      WHERE client_id = ?').bind(id).run();

    // Anonymise the client row — keep it for invoice FK integrity (invoices retained 5 years)
    await env.DB.prepare(`
      UPDATE clients SET
        email                 = '[deleted-' || id || ']',
        company               = '[deleted]',
        org_number            = NULL,
        sig_name              = NULL,
        sig_info              = NULL,
        subject_template      = '',
        pitch_template        = '',
        logo_base64           = NULL,
        logo_key              = NULL,
        gmail_access_token    = NULL,
        gmail_refresh_token   = NULL,
        gmail_token_expiry    = NULL,
        outlook_access_token  = NULL,
        outlook_refresh_token = NULL,
        outlook_token_expiry  = NULL,
        gmail_sender_email    = NULL,
        outlook_sender_email  = NULL,
        stripe_customer_id    = NULL,
        stripe_subscription_id = NULL,
        stripe_item_id        = NULL,
        stripe_price_id       = NULL,
        email_provider        = NULL
      WHERE id = ?
    `).bind(id).run();

    console.log(`[cron] GDPR cleanup: anonymised client ${id} (90 days post-cancellation)`);
  }

  console.log(`[cron] GDPR 90-day cleanup: processed ${stale.length} client(s)`);
}

// ---------------------------------------------------------------------------
// One-time backfill: fetch sender email for clients missing it
// ---------------------------------------------------------------------------

async function backfillSenderEmails(env: Env): Promise<object> {
  const { results: clients } = await env.DB.prepare(`
    SELECT id, email, company, org_number,
           sig_name, sig_info, subject_template, pitch_template, logo_base64,
           stripe_customer_id, stripe_subscription_id, stripe_item_id,
           gmail_access_token, gmail_refresh_token, gmail_token_expiry,
           outlook_access_token, outlook_refresh_token, outlook_token_expiry,
           email_provider, trial_start, trial_end, status, payment_reminder_sent
    FROM clients
    WHERE email_provider IS NOT NULL
      AND (
        (email_provider = 'gmail'   AND gmail_sender_email   IS NULL AND gmail_refresh_token   IS NOT NULL) OR
        (email_provider = 'outlook' AND outlook_sender_email IS NULL AND outlook_refresh_token IS NOT NULL)
      )
  `).all<Client>();

  const updated: string[] = [];
  const failed: string[]  = [];

  for (const client of clients) {
    try {
      const token = await getValidAccessToken(env, client);
      if (!token) { failed.push(client.id); continue; }

      if (client.email_provider === 'gmail') {
        const res = await fetch('https://www.googleapis.com/oauth2/v1/userinfo', {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) { failed.push(client.id); continue; }
        const info = await res.json() as { email: string };
        if (!info.email) { failed.push(client.id); continue; }
        await env.DB.prepare(`UPDATE clients SET gmail_sender_email = ? WHERE id = ?`)
          .bind(info.email, client.id).run();
        updated.push(`${client.id} → ${info.email}`);

      } else {
        const res = await fetch('https://graph.microsoft.com/v1.0/me', {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) { failed.push(client.id); continue; }
        const profile = await res.json() as { mail: string; userPrincipalName: string };
        const email = profile.mail ?? profile.userPrincipalName;
        if (!email) { failed.push(client.id); continue; }
        await env.DB.prepare(`UPDATE clients SET outlook_sender_email = ? WHERE id = ?`)
          .bind(email, client.id).run();
        updated.push(`${client.id} → ${email}`);
      }
    } catch {
      failed.push(client.id);
    }
  }

  return { updated, failed, total: clients.length };
}
