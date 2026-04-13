/**
 * NorgeConnect Cron Worker
 * Runs on a daily schedule (07:00 UTC = 09:00 Oslo time)
 *
 * Tasks:
 *   1. Send 20 emails per active/trial client via their Gmail or Outlook
 *   2. Record 1 Stripe usage unit per active (paid) client
 *   3. Email daily sent-report to the client
 *   4. Send Stripe Payment Link to trial clients on day 6
 *   5. Pause clients whose trial expired with no payment
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
  STRIPE_PRICE_ID: string;       // Metered price ID, e.g. price_xxx
  PAYMENT_LINK_URL: string;      // Pre-created Stripe Payment Link URL
  RESEND_API_KEY: string;        // For sending system emails
  SYSTEM_FROM_EMAIL: string;     // e.g. hello@norgeconnect.no
  GMAIL_CLIENT_ID: string;
  GMAIL_CLIENT_SECRET: string;
  OUTLOOK_CLIENT_ID: string;
  OUTLOOK_CLIENT_SECRET: string;
}

interface Client {
  id: string;
  email: string;
  company: string;
  org_number: string | null;
  industry: string;
  revenue_filter: string | null;
  sig_name: string | null;
  sig_info: string | null;
  subject_template: string;
  pitch_template: string;
  logo_base64: string | null;
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
  trial_start: string;
  trial_end: string;
  status: 'trial' | 'active' | 'awaiting' | 'paused' | 'cancelled';
  payment_reminder_sent: number;
}

interface Target {
  org_number: string;
  company_name: string;
  owner_name: string | null;
  email: string;
  industry_name: string | null;
  revenue_band: string | null;
  location: string | null;
}

const EMAILS_PER_DAY = 20;
const CONTACT_COOLDOWN_DAYS = 90;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export default {
  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const today = toISODate(new Date());
    console.log(`[cron] Running for date: ${today}`);

    ctx.waitUntil(Promise.all([
      runEmailCampaigns(env, today),
      runTrialManagement(env, today),
    ]));
  },

  // Allow manual trigger for testing: GET /trigger
  async fetch(request: Request, env: Env): Promise<Response> {
    if (new URL(request.url).pathname === '/trigger') {
      const today = toISODate(new Date());
      await runEmailCampaigns(env, today);
      await runTrialManagement(env, today);
      return new Response('Done', { status: 200 });
    }
    return new Response('NorgeConnect Cron Worker', { status: 200 });
  },
};

// ---------------------------------------------------------------------------
// Task 1: Send daily emails for all active clients
// ---------------------------------------------------------------------------

async function runEmailCampaigns(env: Env, today: string): Promise<void> {
  const { results: clients } = await env.DB.prepare(`
    SELECT * FROM clients
    WHERE status IN ('trial', 'active')
    AND email_provider IS NOT NULL
  `).all<Client>();

  console.log(`[cron] ${clients.length} client(s) to process`);

  for (const client of clients) {
    try {
      await processClient(env, client, today);
    } catch (err) {
      console.error(`[cron] Client ${client.id} failed:`, err);
    }
  }
}

async function processClient(env: Env, client: Client, today: string): Promise<void> {
  // Refresh OAuth token if expiring within 5 minutes
  const accessToken = await getValidAccessToken(env, client);
  if (!accessToken) {
    console.warn(`[cron] Client ${client.id}: no valid token, skipping`);
    return;
  }

  // Pick 20 unsent targets matching the client's filters
  const cooloffDate = toISODate(addDays(new Date(), -CONTACT_COOLDOWN_DAYS));
  const targets = await env.DB.prepare(`
    SELECT t.*
    FROM targets t
    WHERE (t.industry_name LIKE ? OR ? IS NULL)
    AND   (t.revenue_band = ? OR ? IS NULL)
    AND   t.email IS NOT NULL
    AND   (t.last_contacted IS NULL OR t.last_contacted < ?)
    AND   NOT EXISTS (
      SELECT 1 FROM sent_emails s
      WHERE s.client_id = ? AND s.target_org_number = t.org_number
    )
    ORDER BY RANDOM()
    LIMIT ?
  `).bind(
    client.industry ? `%${client.industry}%` : null,
    client.industry ? `%${client.industry}%` : null,
    client.revenue_filter ?? null,
    client.revenue_filter ?? null,
    cooloffDate,
    client.id,
    EMAILS_PER_DAY
  ).all<Target>();

  if (targets.results.length === 0) {
    console.warn(`[cron] Client ${client.id}: no targets available`);
    return;
  }

  const sentRows: Array<{ id: string; client_id: string; target_org_number: string;
    target_company: string; target_owner: string | null; target_email: string;
    target_location: string | null; target_revenue: string | null;
    sent_at: string; status: string }> = [];

  for (const target of targets.results) {
    const body = buildEmailBody(client, target);
    const success = client.email_provider === 'gmail'
      ? await sendViaGmail(accessToken, target.email, client.subject_template, body)
      : await sendViaOutlook(accessToken, target.email, client.subject_template, body);

    sentRows.push({
      id: crypto.randomUUID(),
      client_id: client.id,
      target_org_number: target.org_number,
      target_company: target.company_name,
      target_owner: target.owner_name,
      target_email: target.email,
      target_location: target.location,
      target_revenue: target.revenue_band,
      sent_at: new Date().toISOString(),
      status: success ? 'sent' : 'failed',
    });

    // Mark target as contacted so other clients don't spam same company same day
    await env.DB.prepare("UPDATE targets SET last_contacted = ? WHERE org_number = ?")
      .bind(today, target.org_number).run();
  }

  // Batch insert sent_emails
  for (const row of sentRows) {
    await env.DB.prepare(`
      INSERT INTO sent_emails
        (id, client_id, target_org_number, target_company, target_owner,
         target_email, target_location, target_revenue, sent_at, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      row.id, row.client_id, row.target_org_number, row.target_company,
      row.target_owner, row.target_email, row.target_location,
      row.target_revenue, row.sent_at, row.status
    ).run();
  }

  const sentCount = sentRows.filter(r => r.status === 'sent').length;
  console.log(`[cron] Client ${client.id}: sent ${sentCount}/${targets.results.length} emails`);

  // Record 1 Stripe usage unit (only for paid active clients)
  if (client.status === 'active' && client.stripe_item_id) {
    await recordStripeUsage(env, client.stripe_item_id);
  }

  // Send daily report email to client
  await sendDailyReport(env, client, sentRows, today);
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

  // Trial expired today — move to 'awaiting' and send urgent reminder
  const { results: expiredToday } = await env.DB.prepare(`
    SELECT * FROM clients
    WHERE status = 'trial'
    AND trial_end < ?
  `).bind(today).all<Client>();

  for (const client of expiredToday) {
    await sendPaymentReminder(env, client, 'expired');
    await env.DB.prepare("UPDATE clients SET status = 'awaiting' WHERE id = ?")
      .bind(client.id).run();
    console.log(`[cron] Trial expired for ${client.email}, moved to awaiting`);
  }

  // Awaiting payment for >3 days — pause service
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
}

// ---------------------------------------------------------------------------
// Email composition
// ---------------------------------------------------------------------------

function buildEmailBody(client: Client, target: Target): string {
  const ownerFirst = target.owner_name?.split(' ')[0] ?? 'Hei';

  const intro = `Hei ${ownerFirst},\n\nVi jobber med selskaper innen ${client.industry} og tok kontakt fordi vi tror vårt tilbud kan være relevant for ${target.company_name}.`;
  const pitch = client.pitch_template;
  const outro = 'Om dette ikke er aktuelt for dere, er det bare å se bort fra denne meldingen.';
  const signoff = [
    `\n\nMed vennlig hilsen`,
    client.sig_name ?? '',
    client.company ?? '',
    client.sig_info ?? '',
  ].filter(Boolean).join('\n');

  return `${intro}\n\n${pitch}\n\n${outro}${signoff}`;
}

// ---------------------------------------------------------------------------
// Gmail sender
// ---------------------------------------------------------------------------

async function sendViaGmail(
  accessToken: string,
  to: string,
  subject: string,
  body: string
): Promise<boolean> {
  // Build RFC 2822 message
  const raw = [
    `To: ${to}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
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
        body: { contentType: 'Text', content: body },
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
  const expiry = isGmail ? client.gmail_token_expiry : client.outlook_token_expiry;
  const accessToken = isGmail ? client.gmail_access_token : client.outlook_access_token;
  const refreshToken = isGmail ? client.gmail_refresh_token : client.outlook_refresh_token;

  if (!accessToken || !refreshToken) return null;

  // Refresh if expiring within 5 minutes
  const expiresAt = expiry ? new Date(expiry).getTime() : 0;
  if (Date.now() < expiresAt - 5 * 60 * 1000) {
    return accessToken; // Still valid
  }

  return isGmail
    ? refreshGmailToken(env, client.id, refreshToken)
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

  await env.DB.prepare(
    "UPDATE clients SET gmail_access_token = ?, gmail_token_expiry = ? WHERE id = ?"
  ).bind(tokens.access_token, expiry, clientId).run();

  return tokens.access_token;
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

  const tokens = await res.json() as { access_token: string; expires_in: number };
  const expiry = new Date(Date.now() + tokens.expires_in * 1000).toISOString();

  await env.DB.prepare(
    "UPDATE clients SET outlook_access_token = ?, outlook_token_expiry = ? WHERE id = ?"
  ).bind(tokens.access_token, expiry, clientId).run();

  return tokens.access_token;
}

// ---------------------------------------------------------------------------
// Stripe usage recording
// ---------------------------------------------------------------------------

async function recordStripeUsage(env: Env, stripeItemId: string): Promise<void> {
  const timestamp = Math.floor(Date.now() / 1000);
  const res = await fetch(
    `https://api.stripe.com/v1/subscription_items/${stripeItemId}/usage_records`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        quantity: '1',
        timestamp: String(timestamp),
        action: 'increment',
      }),
    }
  );
  if (!res.ok) console.error('[stripe] Usage record failed:', await res.text());
}

// ---------------------------------------------------------------------------
// System emails via Resend
// ---------------------------------------------------------------------------

async function sendResendEmail(env: Env, to: string, subject: string, text: string): Promise<void> {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: `NorgeConnect <${env.SYSTEM_FROM_EMAIL}>`,
      to: [to],
      subject,
      text,
    }),
  });
  if (!res.ok) console.error('[resend] Email failed:', await res.text());
}

async function sendDailyReport(
  env: Env,
  client: Client,
  rows: Array<{ target_company: string; target_owner: string | null;
    target_email: string; target_location: string | null;
    target_revenue: string | null; status: string }>,
  date: string
): Promise<void> {
  const sent = rows.filter(r => r.status === 'sent');
  if (sent.length === 0) return;

  const lines = sent.map((r, i) =>
    `${i + 1}. ${r.target_company}${r.target_owner ? ` (${r.target_owner})` : ''}\n` +
    `   Email: ${r.target_email}\n` +
    `   Sted: ${r.target_location ?? '—'}  |  Omsetning: ${r.target_revenue ?? '—'}`
  ).join('\n\n');

  const subject = `NorgeConnect daglig rapport — ${date}`;
  const text = [
    `Hei ${client.sig_name ?? client.company},`,
    '',
    `Her er din daglige rapport for ${date}.`,
    `Sendt: ${sent.length} av ${rows.length} e-poster`,
    '',
    '── Sendte henvendelser ──────────────────',
    lines,
    '─────────────────────────────────────────',
    '',
    'Logg inn på NorgeConnect for å se full historikk.',
    '',
    '— NorgeConnect',
  ].join('\n');

  await sendResendEmail(env, client.email, subject, text);
}

async function sendPaymentReminder(
  env: Env,
  client: Client,
  when: 'tomorrow' | 'expired'
): Promise<void> {
  const subject = when === 'tomorrow'
    ? 'Din NorgeConnect prøveperiode utløper i morgen'
    : 'Din NorgeConnect prøveperiode er over — fortsett uten avbrudd';

  const text = when === 'tomorrow'
    ? [
        `Hei ${client.sig_name ?? client.company},`,
        '',
        'Prøveperioden din utløper i morgen.',
        '',
        'For å fortsette uten avbrudd, klikk lenken nedenfor og fullfør betalingen.',
        'Det tar under 2 minutter — kortbetaling via Stripe.',
        '',
        `Betal her: ${env.PAYMENT_LINK_URL}`,
        '',
        'Pris: 39 NOK/dag · faktureres 1. hver måned · avslutt når som helst.',
        '',
        '— NorgeConnect',
      ].join('\n')
    : [
        `Hei ${client.sig_name ?? client.company},`,
        '',
        'Prøveperioden din er over. E-postutsendelsen er midlertidig satt på pause.',
        '',
        'Betal her for å reaktivere umiddelbart:',
        `${env.PAYMENT_LINK_URL}`,
        '',
        'Alle innstillinger og data er beholdt.',
        '',
        '— NorgeConnect',
      ].join('\n');

  await sendResendEmail(env, client.email, subject, text);
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
