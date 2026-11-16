import { createClient } from "npm:@supabase/supabase-js@2";
import { parsePhoneNumberFromString } from "npm:libphonenumber-js@1.13.15/max";
import nodemailer from "npm:nodemailer@6.10.1";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
const POLICY_VERSION = "agrolyst-siwes-applicant-policy-2026-10-27-v1";
const GOOGLE_MAPS_API_KEY = Deno.env.get("GOOGLE_MAPS_API_KEY");
const SMTP_HOST = Deno.env.get("SMTP_HOST") || "";
const SMTP_PORT = Number(Deno.env.get("SMTP_PORT") || "465");
const SMTP_USER = Deno.env.get("SMTP_USER") || "";
const SMTP_PASS = Deno.env.get("SMTP_PASS") || "";
const SMTP_FROM_EMAIL = Deno.env.get("SMTP_FROM_EMAIL") || "";
const SMTP_FROM_NAME = Deno.env.get("SMTP_FROM_NAME") || "Agrolyst Farms";
const TWILIO_ACCOUNT_SID = Deno.env.get("TWILIO_ACCOUNT_SID");
const TWILIO_AUTH_TOKEN = Deno.env.get("TWILIO_AUTH_TOKEN");
const TWILIO_FROM_NUMBER = Deno.env.get("TWILIO_FROM_NUMBER");
const TWILIO_MESSAGING_SERVICE_SID = Deno.env.get("TWILIO_MESSAGING_SERVICE_SID");

// Best-effort per-isolate throttle; configure Google Cloud quotas for a hard billing limit.
const addressAutocompleteLimits = new Map<string, { count: number; resetAt: number }>();

const corsHeaders = (req: Request) => {
  const origin = req.headers.get("origin") ?? "";
  const allowed =
    /^https:\/\/([a-z0-9-]+\.)?agrolystfarms\.com$/i.test(origin) ||
    origin === "https://agrolyst.github.io" ||
    origin === "https://apply-siwes-agrolyst.onrender.com" ||
    origin === "http://localhost:5500" ||
    origin === "http://127.0.0.1:5500";
  return {
    "Access-Control-Allow-Origin": allowed ? origin : "https://applysiwes.agrolystfarms.com",
    "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  };
};

function respond(req: Request, status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders(req) });
}

const clean = (value: unknown, max = 500) =>
  typeof value === "string" ? value.trim().slice(0, max) : "";

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const emailCheckLimits = new Map<string, { count: number; resetAt: number }>();
const phoneCheckLimits = new Map<string, { count: number; resetAt: number }>();

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}
async function recoveryHmac(value: string): Promise<string> {
  if (!SERVICE_ROLE_KEY) throw new Error("Recovery hashing is not configured.");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(SERVICE_ROLE_KEY),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return toHex(new Uint8Array(signature));
}
function maskRecoveryContact(type: string, value: string): string {
  if (type === "email") {
    const [user, domain] = value.split("@");
    return (user.length <= 2 ? user[0] ?? "*" : user.slice(0, 2)) +
      "*".repeat(Math.max(3, Math.min(8, user.length))) + "@" + domain;
  }
  return value.length >= 5 ? value.slice(0, 4) + "••••" + value.slice(-2) : "••••";
}
function isSmtpConfigured(): boolean {
  return Boolean(
    SMTP_HOST &&
    SMTP_PORT === 465 &&
    SMTP_USER &&
    SMTP_PASS &&
    SMTP_FROM_EMAIL
  );
}

async function sendSmtpEmail(to: string, subject: string, text: string, html: string): Promise<void> {
  if (!isSmtpConfigured()) {
    throw new Error("SMTP secrets are missing or invalid. Configure SMTP_HOST, SMTP_PORT=465, SMTP_USER, SMTP_PASS and SMTP_FROM_EMAIL.");
  }

  const transport = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: true,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 10000,
    tls: { servername: SMTP_HOST },
  });

  try {
    const result = await transport.sendMail({
      from: { name: SMTP_FROM_NAME, address: SMTP_FROM_EMAIL },
      to,
      subject,
      text,
      html,
    });
    if (!result.accepted?.length) throw new Error("SMTP server did not accept the recovery message.");
  } finally {
    transport.close();
  }
}


async function sendAccountLinkCode(email: string, code: string): Promise<void> {
  const textMessage = "Your Agrolyst SIWES sign-in code is " + code +
    ". It expires in 10 minutes. Enter this code on the Agrolyst SIWES portal to sign in and connect your application. Do not share it.";
  const htmlMessage = "<div style=\"font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#193c2a\">" +
    "<div style=\"background:#123d2b;padding:22px;color:#d4e76a;font-weight:800;letter-spacing:2px\">AGROLYST SIWES</div>" +
    "<div style=\"padding:26px;border:1px solid #dce5d9\"><h2 style=\"margin-top:0\">Your secure sign-in code</h2>" +
    "<p>Use this one-time code to sign in to your Agrolyst SIWES applicant account and connect your application.</p>" +
    "<div style=\"font-size:32px;letter-spacing:8px;font-weight:800;background:#f4f7f0;padding:18px;text-align:center\">" + code + "</div>" +
    "<p>This code expires in 10 minutes and can only be used once.</p>" +
    "<p style=\"color:#68756b;font-size:12px\">Never share this code with anyone, including someone claiming to be Agrolyst staff. If you did not request it, ignore this email.</p></div></div>";
  await sendSmtpEmail(email, "Your Agrolyst SIWES sign-in code", textMessage, htmlMessage);
}

async function sendRecoveryCode(type: "email" | "phone", contact: string, code: string): Promise<void> {
  const textMessage = "Your Agrolyst SIWES Application ID recovery code is " + code +
    ". It expires in 10 minutes. Do not share this code with anyone.";
  if (type === "email") {
    const htmlMessage = "<div style=\"font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#193c2a\">" +
      "<div style=\"background:#123d2b;padding:22px;color:#d4e76a;font-weight:800;letter-spacing:2px\">AGROLYST SIWES</div>" +
      "<div style=\"padding:26px;border:1px solid #dce5d9\"><h2 style=\"margin-top:0\">Recover your Application ID</h2>" +
      "<p>Use this one-time code to verify your email address and recover your SIWES Application ID.</p>" +
      "<div style=\"font-size:30px;letter-spacing:7px;font-weight:800;background:#f4f7f0;padding:18px;text-align:center\">" + code + "</div>" +
      "<p>This code expires in 10 minutes. If you did not request this, you can ignore this email.</p>" +
      "<p style=\"color:#68756b;font-size:12px\">Never share a verification code with anyone, including someone claiming to be Agrolyst staff.</p></div></div>";
    await sendSmtpEmail(contact, "Your Agrolyst SIWES Application ID recovery code", textMessage, htmlMessage);
    return;
  }
  const accountSid = Deno.env.get("TWILIO_ACCOUNT_SID");
  const authToken = Deno.env.get("TWILIO_AUTH_TOKEN");
  const fromNumber = Deno.env.get("TWILIO_FROM_NUMBER");
  const messagingServiceSid = Deno.env.get("TWILIO_MESSAGING_SERVICE_SID");
  if (!accountSid || !authToken || (!fromNumber && !messagingServiceSid)) throw new Error("SMS recovery is not configured.");
  const form = new URLSearchParams({ To: contact, Body: textMessage });
  if (messagingServiceSid) form.set("MessagingServiceSid", messagingServiceSid);
  else form.set("From", fromNumber!);
  const response = await fetch("https://api.twilio.com/2010-04-01/Accounts/" +
    encodeURIComponent(accountSid) + "/Messages.json", {
      method: "POST",
      headers: { "Authorization": "Basic " + btoa(accountSid + ":" + authToken), "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
      signal: AbortSignal.timeout(10000),
    });
  if (!response.ok) {
    const details = await response.text().catch(() => "");
    console.error("Recovery SMS delivery failed with HTTP", response.status, details.slice(0, 300));
    throw new Error("SMS delivery failed.");
  }
}

async function emailAlreadyUsed(db: ReturnType<typeof createClient>, email: string): Promise<boolean> {
  // Escape LIKE metacharacters so an email containing "_" or "%" is matched literally.
  const pattern = email.replace(/[\\%_]/g, (character) => "\\" + character);
  const { data, error } = await db.from("siwes_applications")
    .select("email")
    .ilike("email", pattern)
    .limit(25);
  if (error) throw error;
  return (data ?? []).some((row: { email?: string | null }) =>
    clean(row.email, 254).toLowerCase() === email
  );
}


Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(req) });
  if (req.method !== "POST") return respond(req, 405, { error: "Use POST for this endpoint." });
  if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
    console.error("Missing required Supabase function configuration.");
    return respond(req, 500, { error: "The application service is not configured yet. Please try again later." });
  }

  let body: Record<string, unknown>;
  try {
    const length = Number(req.headers.get("content-length") ?? "0");
    if (length > 20000) return respond(req, 413, { error: "The request is too large." });
    body = await req.json();
  } catch {
    return respond(req, 400, { error: "Please send a valid application request." });
  }

  const db = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  const action = clean(body.action, 40);

  if (action === "request-application-id-recovery") {
    try {
    const type = clean(body.contact_type, 10);
    if (type !== "email" && type !== "phone") return respond(req, 400, { ok: false, error: "Choose email or phone number for recovery." });

    const rawContact = clean(body.contact, 254);
    let normalizedContact = "";
    if (type === "email") {
      normalizedContact = rawContact.toLowerCase();
      if (!emailRegex.test(normalizedContact)) return respond(req, 400, { ok: false, error: "Enter a valid email address." });
      if (!isSmtpConfigured()) {
        console.warn("Application ID recovery requested, but the SIWES SMTP Edge Function secrets are missing or the port is unsupported.");
        return respond(req, 503, { ok: false, error: "Email recovery is not configured yet. The administrator must add the SIWES SMTP secrets to the Edge Function. You do not need to sign in." });
      }
    } else {
      const parsedPhone = parsePhoneNumberFromString(rawContact);
      if (!parsedPhone || !parsedPhone.isValid()) return respond(req, 400, { ok: false, error: "Enter a valid phone number including its country calling code." });
      normalizedContact = parsedPhone.number;
      if (!Deno.env.get("TWILIO_ACCOUNT_SID") || !Deno.env.get("TWILIO_AUTH_TOKEN") ||
          (!Deno.env.get("TWILIO_FROM_NUMBER") && !Deno.env.get("TWILIO_MESSAGING_SERVICE_SID"))) {
        return respond(req, 503, { ok: false, error: "SMS recovery has not been configured yet. Please contact Agrolyst support." });
      }
    }

    const now = Date.now();
    const forwardedFor = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
    const clientIp = forwardedFor || req.headers.get("x-real-ip") || req.headers.get("cf-connecting-ip") || "unknown-client";
    const contactDigest = await recoveryHmac("contact:" + type + ":" + normalizedContact);
    const ipDigest = await recoveryHmac("ip:" + clientIp);
    const since = new Date(now - 15 * 60_000).toISOString();
    const [contactRate, ipRate] = await Promise.all([
      db.from("siwes_application_id_recovery_challenges").select("id", { count: "exact", head: true }).eq("contact_digest", contactDigest).gte("created_at", since),
      db.from("siwes_application_id_recovery_challenges").select("id", { count: "exact", head: true }).eq("ip_digest", ipDigest).gte("created_at", since),
    ]);
    if (contactRate.error || ipRate.error) {
      console.error("Application ID recovery rate check failed:", contactRate.error?.message ?? ipRate.error?.message);
      return respond(req, 500, { ok: false, error: "Recovery is temporarily unavailable. Please try again later." });
    }
    if ((contactRate.count ?? 0) >= 3 || (ipRate.count ?? 0) >= 12) return respond(req, 429, { ok: false, error: "Too many recovery attempts. Please wait 15 minutes before trying again." });

    let matched = false;
    try {
      if (type === "email") {
        const pattern = normalizedContact.replace(/[\\\\%_]/g, (character) => "\\" + character);
        const { data, error } = await db.from("siwes_applications").select("id,email").ilike("email", pattern).limit(100);
        if (error) throw error;
        matched = (data ?? []).some((row: { email?: string | null }) => clean(row.email, 254).toLowerCase() === normalizedContact);
      } else {
        const { data, error } = await db.from("siwes_applications").select("id,phone").eq("phone", normalizedContact).limit(1);
        if (error) throw error;
        matched = Boolean(data?.length);
      }
    } catch (error) {
      console.error("Application ID recovery record lookup failed:", error instanceof Error ? error.message : "database error");
      return respond(req, 500, { ok: false, error: "Recovery is temporarily unavailable. Please try again later." });
    }

    const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000).padStart(6, "0");
    const challengeId = crypto.randomUUID();
    const otpDigest = await recoveryHmac("otp:" + challengeId + ":" + code);
    const { error: insertError } = await db.from("siwes_application_id_recovery_challenges").insert({
      id: challengeId, contact_type: type, contact_digest: contactDigest, ip_digest: ipDigest,
      otp_digest: otpDigest, attempts: 0, expires_at: new Date(now + 10 * 60_000).toISOString(),
    });
    if (insertError) {
      console.error("Application ID recovery challenge could not be created:", insertError.message);
      return respond(req, 500, { ok: false, error: "Recovery is temporarily unavailable. Please try again later." });
    }
    if (matched) {
      try {
        await sendRecoveryCode(type as "email" | "phone", normalizedContact, code);
      } catch (error) {
        console.error("Application ID recovery delivery is not available:", error instanceof Error ? error.message : "delivery error");
        await db.from("siwes_application_id_recovery_challenges").update({ consumed_at: new Date().toISOString() }).eq("id", challengeId);
        return respond(req, 503, { ok: false, error: type === "email"
          ? "We could not send the recovery email. Please contact Agrolyst support or try later."
          : "We could not send the recovery SMS. Please contact Agrolyst support or try later." });
      }
    }
    return respond(req, 200, {
      ok: true, challenge_id: challengeId, contact_type: type,
      masked_contact: maskRecoveryContact(type, normalizedContact),
      message: "If an application matches those contact details, a one-time code has been sent. Check your inbox or phone. The code expires in 10 minutes.",
    });
    } catch (error) {
      console.error("Unexpected application ID recovery request error:", error instanceof Error ? error.message : "unknown server error");
      return respond(req, 500, { ok: false, error: "The recovery request could not be completed. Please try again later. If this continues, contact Agrolyst support." });
    }
  }

  if (action === "verify-application-id-recovery") {
    const type = clean(body.contact_type, 10);
    const challengeId = clean(body.challenge_id, 64);
    const rawContact = clean(body.contact, 254);
    const code = clean(body.code, 6);
    if ((type !== "email" && type !== "phone") ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(challengeId) ||
        !/^[0-9]{6}$/.test(code)) {
      return respond(req, 400, { ok: false, error: "Enter the six-digit verification code from your message." });
    }
    let normalizedContact = "";
    if (type === "email") {
      normalizedContact = rawContact.toLowerCase();
      if (!emailRegex.test(normalizedContact)) return respond(req, 400, { ok: false, error: "Enter the same email address you used for recovery." });
    } else {
      const parsedPhone = parsePhoneNumberFromString(rawContact);
      if (!parsedPhone || !parsedPhone.isValid()) return respond(req, 400, { ok: false, error: "Enter the same valid phone number you used for recovery, including its country code." });
      normalizedContact = parsedPhone.number;
    }
    const contactDigest = await recoveryHmac("contact:" + type + ":" + normalizedContact);
    const { data: challenge, error: challengeError } = await db.from("siwes_application_id_recovery_challenges")
      .select("id,contact_type,contact_digest,otp_digest,attempts,expires_at,consumed_at")
      .eq("id", challengeId).eq("contact_type", type).eq("contact_digest", contactDigest).maybeSingle();
    if (challengeError) {
      console.error("Application ID recovery verification lookup failed:", challengeError.message);
      return respond(req, 500, { ok: false, error: "We could not verify the code right now. Please request a new code." });
    }
    if (!challenge || challenge.consumed_at || new Date(challenge.expires_at).getTime() <= Date.now()) {
      return respond(req, 400, { ok: false, error: "This recovery code is invalid or expired. Request a new code and try again." });
    }
    if (challenge.attempts >= 5) {
      await db.from("siwes_application_id_recovery_challenges").update({ consumed_at: new Date().toISOString() }).eq("id", challengeId).is("consumed_at", null);
      return respond(req, 429, { ok: false, error: "Too many incorrect codes. Request a new recovery code." });
    }
    const candidateDigest = await recoveryHmac("otp:" + challengeId + ":" + code);
    if (candidateDigest !== challenge.otp_digest) {
      const nextAttempts = challenge.attempts + 1;
      await db.from("siwes_application_id_recovery_challenges").update({
        attempts: nextAttempts, ...(nextAttempts >= 5 ? { consumed_at: new Date().toISOString() } : {}),
      }).eq("id", challengeId).eq("attempts", challenge.attempts).is("consumed_at", null);
      return respond(req, 400, { ok: false, error: nextAttempts >= 5
        ? "Too many incorrect codes. Request a new recovery code."
        : "That code does not match. Check the code and try again." });
    }

    let ids: Array<{ reference_no: string; status: string; created_at: string; submitted_at: string | null }> = [];
    try {
      if (type === "email") {
        const pattern = normalizedContact.replace(/[\\\\%_]/g, (character) => "\\" + character);
        const { data, error } = await db.from("siwes_applications")
          .select("reference_no,status,created_at,submitted_at,email")
          .ilike("email", pattern).order("created_at", { ascending: false }).limit(100);
        if (error) throw error;
        ids = (data ?? []).filter((row: { email?: string | null }) => clean(row.email, 254).toLowerCase() === normalizedContact);
      } else {
        const { data, error } = await db.from("siwes_applications")
          .select("reference_no,status,created_at,submitted_at")
          .eq("phone", normalizedContact).order("created_at", { ascending: false }).limit(100);
        if (error) throw error;
        ids = data ?? [];
      }
    } catch (error) {
      console.error("Application ID recovery final lookup failed:", error instanceof Error ? error.message : "database error");
      return respond(req, 500, { ok: false, error: "We could not retrieve your Application ID right now. Request a new code later or contact Agrolyst support." });
    }
    if (!ids.length) {
      await db.from("siwes_application_id_recovery_challenges").update({ consumed_at: new Date().toISOString() }).eq("id", challengeId).is("consumed_at", null);
      return respond(req, 404, { ok: false, error: "No application ID was found for this verified contact. Please contact Agrolyst support if you believe this is an error." });
    }
    const nowIso = new Date().toISOString();
    const { data: consumed, error: consumeError } = await db.from("siwes_application_id_recovery_challenges")
      .update({ verified_at: nowIso, consumed_at: nowIso })
      .eq("id", challengeId).eq("attempts", challenge.attempts).is("consumed_at", null)
      .gt("expires_at", nowIso).select("id").maybeSingle();
    if (consumeError || !consumed) return respond(req, 400, { ok: false, error: "This recovery code has already been used. Request a new code if you still need help." });
    return respond(req, 200, {
      ok: true,
      applications: ids.map((item) => ({ reference_no: item.reference_no, status: item.status, submitted_at: item.submitted_at })),
    });
  }



  if (action === "recover-application-id") {
    const channel = clean(body.channel, 12).toLowerCase();
    if (channel !== "email" && channel !== "phone") {
      return respond(req, 400, { ok: false, error: "Choose email or phone as the recovery method." });
    }

    if (channel === "email" && !isSmtpConfigured()) {
      return respond(req, 503, { ok: false, error: "Email recovery SMTP is not configured yet. Please contact Agrolyst for assistance." });
    }
    if (channel === "phone" && !(TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN && (TWILIO_FROM_NUMBER || TWILIO_MESSAGING_SERVICE_SID))) {
      return respond(req, 503, { ok: false, error: "SMS recovery delivery is not configured yet. Please use email recovery or contact Agrolyst for assistance." });
    }

    let normalizedTarget = "";
    if (channel === "email") {
      normalizedTarget = clean(body.email, 254).toLowerCase();
      if (!emailRegex.test(normalizedTarget)) return respond(req, 400, { ok: false, error: "Enter a valid email address." });
    } else {
      const parsedPhone = parsePhoneNumberFromString(clean(body.phone, 40));
      if (!parsedPhone || !parsedPhone.isValid()) {
        return respond(req, 400, { ok: false, error: "Enter a valid phone number with its country calling code." });
      }
      normalizedTarget = parsedPhone.number;
    }

    const ip = req.headers.get("cf-connecting-ip") ||
      req.headers.get("x-real-ip") ||
      req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown-client";
    const digest = async (value: string) => {
      const bytes = new TextEncoder().encode(value);
      const hash = await crypto.subtle.digest("SHA-256", bytes);
      return Array.from(new Uint8Array(hash)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
    };
    const targetHash = await digest(channel + ":" + normalizedTarget);
    const requesterHash = await digest(ip);
    const { data: attemptId, error: rateLimitError } = await db.rpc("begin_siwes_application_id_recovery", {
      p_target_hash: targetHash,
      p_requester_hash: requesterHash,
      p_channel: channel,
    });
    if (rateLimitError) {
      console.error("Application ID recovery rate-limit check failed:", rateLimitError.message);
      return respond(req, 503, { ok: false, error: "Application ID recovery is temporarily unavailable. Please try again later." });
    }
    if (!attemptId) return respond(req, 429, { ok: false, error: "Too many recovery requests. Please wait before trying again." });

    let refs: string[] = [];
    try {
      if (channel === "email") {
        const refsHtml = refs.map((reference) => "<li style=\"margin:7px 0;font-size:18px;font-weight:bold;color:#1e6842\">" + reference + "</li>").join("");
        const htmlMessage = "<div style=\"font-family:Arial,sans-serif;line-height:1.65;color:#193c2a;max-width:560px;margin:auto\"><div style=\"background:#123d2b;color:#fff;padding:22px;border-radius:12px 12px 0 0\"><strong style=\"letter-spacing:1px\">AGROLYST SIWES PORTAL</strong><h2 style=\"margin-bottom:0\">Application ID recovery</h2></div><div style=\"padding:24px;border:1px solid #dce5d9;border-top:0;border-radius:0 0 12px 12px\"><p>Your application reference" + (refs.length > 1 ? "s are" : " is") + ":</p><ul style=\"padding-left:22px\">" + refsHtml + "</ul><p>Keep " + (refs.length > 1 ? "these IDs" : "this ID") + " private. <a href=\"https://applysiwes.agrolystfarms.com/check/status\">Check application status</a>.</p><p style=\"font-size:12px;color:#68756b\">If you did not request this message, you can ignore it.</p></div></div>";
        await sendSmtpEmail(normalizedTarget, "Your Agrolyst SIWES Application ID", messageText, htmlMessage);
      } else {
        const params = new URLSearchParams();
        if (TWILIO_MESSAGING_SERVICE_SID) params.set("MessagingServiceSid", TWILIO_MESSAGING_SERVICE_SID);
        else params.set("From", TWILIO_FROM_NUMBER!);
        params.set("To", normalizedTarget);
        params.set("Body", messageText);
        const auth = btoa(TWILIO_ACCOUNT_SID + ":" + TWILIO_AUTH_TOKEN);
        const response = await fetch("https://api.twilio.com/2010-04-01/Accounts/" + encodeURIComponent(TWILIO_ACCOUNT_SID!) + "/Messages.json", {
          method: "POST",
          headers: { "Authorization": "Basic " + auth, "Content-Type": "application/x-www-form-urlencoded" },
          body: params,
          signal: AbortSignal.timeout(10000),
        });
        if (!response.ok) {
          console.error("Application ID recovery SMS delivery failed with HTTP", response.status);
          throw new Error("SMS delivery failed");
        }
      }
      await db.from("siwes_application_id_recovery_attempts").update({ delivery_status: "sent" }).eq("id", attemptId);
    } catch (error) {
      console.error("Application ID recovery delivery failed:", error instanceof Error ? error.message : "provider request failed");
      await db.from("siwes_application_id_recovery_attempts").update({ delivery_status: "failed" }).eq("id", attemptId);
    }

    return respond(req, 200, {
      ok: true,
      message: "If a submitted application matches those details, recovery instructions will be sent to that contact. Please check your inbox or SMS messages, including spam or filtered messages.",
    });
  }

  if (action === "check-private-contacts") {
    const authHeader = req.headers.get("authorization") ?? "";
    const accessToken = authHeader.replace(/^Bearer\s+/i, "").trim();
    if (!accessToken) {
      return respond(req, 401, { ok: false, error: "Please sign in again before validating your application details." });
    }

    let authenticatedUser: { id: string } | null = null;
    try {
      const { data, error } = await db.auth.getUser(accessToken);
      if (!error && data?.user?.id) authenticatedUser = { id: data.user.id };
    } catch {
      authenticatedUser = null;
    }
    if (!authenticatedUser) {
      return respond(req, 401, { ok: false, error: "Your session has expired. Please sign in again." });
    }

    const applicationId = clean(body.application_id, 64);
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(applicationId)) {
      return respond(req, 400, { ok: false, error: "We could not identify your application. Refresh the page and try again." });
    }

    const { data: ownedApplication, error: ownershipError } = await db
      .from("siwes_applications")
      .select("id,user_id")
      .eq("id", applicationId)
      .eq("user_id", authenticatedUser.id)
      .maybeSingle();

    if (ownershipError) {
      console.error("Private application ownership check failed:", ownershipError.message);
      return respond(req, 500, { ok: false, error: "We could not verify your application. Please try again." });
    }
    if (!ownedApplication) {
      return respond(req, 404, { ok: false, error: "We could not verify this application against your signed-in account." });
    }

    const email = clean(body.email, 254).toLowerCase();
    if (!emailRegex.test(email)) {
      return respond(req, 400, { ok: false, field: "email", error: "Enter a valid email address before continuing." });
    }

    // Phone contact collection is temporarily unavailable. Only check email uniqueness.
    const { data: flags, error: duplicateError } = await db.rpc(
      "siwes_contact_duplicate_flags_excluding",
      {
        p_email: email,
        p_phone: null,
        p_application_id: ownedApplication.id,
      },
    );
    if (duplicateError) {
      console.error("Private SIWES contact check failed:", duplicateError.message);
      return respond(req, 500, { ok: false, error: "We could not verify whether this email has already been used. Please try again." });
    }

    const duplicateFlags = (flags ?? {}) as Record<string, unknown>;
    const emailAvailable = !Boolean(duplicateFlags.email_exists);
    return respond(req, 200, {
      ok: true,
      email_available: emailAvailable,
      ...( !emailAvailable ? { email_error: "This email address already belongs to another SIWES application. Continue with your existing application or contact Agrolyst for assistance." } : {}),
    });
  }

  if (action === "address-autocomplete") {
    const now = Date.now();
    const forwardedFor = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
    const clientKey = forwardedFor || req.headers.get("x-real-ip") || req.headers.get("cf-connecting-ip") || "unknown-client";
    const rate = addressAutocompleteLimits.get(clientKey);
    if (!rate || rate.resetAt <= now) {
      addressAutocompleteLimits.set(clientKey, { count: 1, resetAt: now + 60_000 });
    } else {
      rate.count += 1;
      if (rate.count > 60) {
        return respond(req, 429, { error: "Too many address searches. Please wait a minute or enter your address manually." });
      }
    }
    if (addressAutocompleteLimits.size > 2000) {
      for (const [key, value] of addressAutocompleteLimits) {
        if (value.resetAt <= now) addressAutocompleteLimits.delete(key);
      }
    }

    if (!GOOGLE_MAPS_API_KEY) {
      return respond(req, 503, { error: "Google address suggestions are not configured yet. You can enter your address manually." });
    }

    const input = clean(body.input, 160);
    const providedSession = clean(body.session_token, 80);
    if (input.length < 3) {
      return respond(req, 200, { ok: true, suggestions: [] });
    }
    if (providedSession && !/^[a-z0-9-]{16,64}$/i.test(providedSession)) {
      return respond(req, 400, { error: "Invalid address search session." });
    }

    const sessionToken = providedSession || crypto.randomUUID();
    let googleResponse: Response;
    try {
      googleResponse = await fetch("https://places.googleapis.com/v1/places:autocomplete", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Goog-Api-Key": GOOGLE_MAPS_API_KEY,
          "X-Goog-FieldMask": "suggestions.placePrediction.placeId,suggestions.placePrediction.text.text,suggestions.placePrediction.structuredFormat.mainText.text,suggestions.placePrediction.structuredFormat.secondaryText.text",
        },
        body: JSON.stringify({
          input,
          sessionToken,
          languageCode: "en",
          regionCode: "NG",
          includedRegionCodes: ["ng"],
        }),
        signal: AbortSignal.timeout(8000),
      });
    } catch (error) {
      console.error("Google Places autocomplete request failed:", error instanceof Error ? error.message : "network error");
      return respond(req, 502, { error: "Google address suggestions are temporarily unavailable. You can enter your address manually." });
    }

    if (!googleResponse.ok) {
      console.error("Google Places autocomplete returned HTTP", googleResponse.status);
      return respond(req, 502, { error: "Google address suggestions are temporarily unavailable. You can enter your address manually." });
    }

    let googleBody: Record<string, unknown>;
    try {
      googleBody = await googleResponse.json();
    } catch {
      return respond(req, 502, { error: "Google returned an invalid address response. You can enter your address manually." });
    }

    const rawSuggestions = Array.isArray(googleBody.suggestions) ? googleBody.suggestions : [];
    const suggestions = rawSuggestions.flatMap((item: any) => {
      const prediction = item?.placePrediction;
      const description = clean(prediction?.text?.text, 500);
      if (!description) return [];
      return [{
        place_id: clean(prediction?.placeId, 180),
        description,
        main_text: clean(prediction?.structuredFormat?.mainText?.text, 180),
        secondary_text: clean(prediction?.structuredFormat?.secondaryText?.text, 300),
      }];
    }).slice(0, 5);

    return respond(req, 200, { ok: true, suggestions });
  }

  if (action === "check-email") {
    const now = Date.now();
    const forwardedFor = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
    const clientKey = forwardedFor || req.headers.get("x-real-ip") || req.headers.get("cf-connecting-ip") || "unknown-client";
    const rate = emailCheckLimits.get(clientKey);
    if (!rate || rate.resetAt <= now) {
      emailCheckLimits.set(clientKey, { count: 1, resetAt: now + 60_000 });
    } else {
      rate.count += 1;
      if (rate.count > 20) {
        return respond(req, 429, { error: "Too many email checks. Please wait a minute and try again." });
      }
    }
    if (emailCheckLimits.size > 2000) {
      for (const [key, value] of emailCheckLimits) {
        if (value.resetAt <= now) emailCheckLimits.delete(key);
      }
    }

    const email = clean(body.email, 254).toLowerCase();
    if (!emailRegex.test(email)) {
      return respond(req, 400, { ok: false, error: "Enter a valid email address before continuing." });
    }
    try {
      const used = await emailAlreadyUsed(db, email);
      return respond(req, 200, {
        ok: true,
        available: !used,
        ...(used ? { error: "This email address has already been used for a SIWES application. Please use your existing application or contact Agrolyst for assistance." } : {}),
      });
    } catch (error) {
      console.error("Could not check public application email:", error instanceof Error ? error.message : "database query failed");
      return respond(req, 500, { ok: false, error: "We could not verify this email right now. Please try again." });
    }
  }

  if (action === "check-phone") {
    const now = Date.now();
    const forwardedFor = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
    const clientKey = forwardedFor || req.headers.get("x-real-ip") || req.headers.get("cf-connecting-ip") || "unknown-client";
    const rate = phoneCheckLimits.get(clientKey);
    if (!rate || rate.resetAt <= now) {
      phoneCheckLimits.set(clientKey, { count: 1, resetAt: now + 60_000 });
    } else {
      rate.count += 1;
      if (rate.count > 20) {
        return respond(req, 429, { ok: false, error: "Too many phone checks. Please wait a minute and try again." });
      }
    }
    if (phoneCheckLimits.size > 2000) {
      for (const [key, value] of phoneCheckLimits) {
        if (value.resetAt <= now) phoneCheckLimits.delete(key);
      }
    }

    const rawPhone = clean(body.phone, 40);
    const parsedPhone = parsePhoneNumberFromString(rawPhone);
    if (!parsedPhone || !parsedPhone.isValid()) {
      return respond(req, 400, { ok: false, error: "Enter a valid phone number with the correct country code before continuing." });
    }

    const { data: flags, error } = await db.rpc("siwes_contact_duplicate_flags", {
      p_email: null,
      p_phone: parsedPhone.number,
    });
    if (error) {
      console.error("Could not verify duplicate public application phone:", error.message);
      return respond(req, 500, { ok: false, error: "We could not verify this phone number right now. Please try again." });
    }
    const phoneExists = Boolean((flags as Record<string, unknown> | null)?.phone_exists);
    return respond(req, 200, {
      ok: true,
      available: !phoneExists,
      phone: parsedPhone.number,
      ...(phoneExists ? {
        error: "This phone number has already been used for a SIWES application. Use your existing application or contact Agrolyst for assistance.",
      } : {}),
    });
  }


  if (action === "request-account-link-code") {
    const email = clean(body.email, 254).toLowerCase();
    if (!emailRegex.test(email)) return respond(req, 400, { ok: false, error: "Enter a valid email address." });
    if (!isSmtpConfigured()) return respond(req, 503, { ok: false, error: "Secure email delivery is temporarily unavailable. Please contact Agrolyst support." });

    const now = Date.now();
    const forwardedFor = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
    const clientIp = forwardedFor || req.headers.get("x-real-ip") || req.headers.get("cf-connecting-ip") || "unknown-client";
    const contactDigest = await recoveryHmac("account-link:email:" + email);
    const ipDigest = await recoveryHmac("ip:" + clientIp);
    const since = new Date(now - 15 * 60_000).toISOString();
    const [contactRate, ipRate] = await Promise.all([
      db.from("siwes_application_id_recovery_challenges").select("id", { count: "exact", head: true }).eq("contact_digest", contactDigest).gte("created_at", since),
      db.from("siwes_application_id_recovery_challenges").select("id", { count: "exact", head: true }).eq("ip_digest", ipDigest).gte("created_at", since),
    ]);
    if (contactRate.error || ipRate.error) {
      console.error("Account-link rate check failed:", contactRate.error?.message ?? ipRate.error?.message);
      return respond(req, 500, { ok: false, error: "We could not start secure sign-in right now. Please try again later." });
    }
    if ((contactRate.count ?? 0) >= 3 || (ipRate.count ?? 0) >= 12) {
      return respond(req, 429, { ok: false, error: "Too many code requests. Please wait 15 minutes before trying again." });
    }

    let eligible = false;
    try {
      const { data: matches, error: lookupError } = await db.from("siwes_applications")
        .select("id,status,user_id,email").eq("email", email).limit(2);
      if (lookupError) throw lookupError;
      const activeMatches = (matches ?? []).filter((row: { email?: string | null; status?: string | null }) => {
        const status = clean(row.status, 60).toLowerCase();
        return clean(row.email, 254).toLowerCase() === email &&
          Boolean(status) &&
          !["rejected", "withdrawn", "cancelled", "canceled", "closed", "archived", "inactive", "denied", "expired"].includes(status);
      });
      eligible = activeMatches.length === 1;
    } catch (error) {
      console.error("Account-link application lookup failed:", error instanceof Error ? error.message : "database error");
      return respond(req, 500, { ok: false, error: "We could not check your application right now. Please try again later." });
    }

    const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000).padStart(6, "0");
    const challengeId = crypto.randomUUID();
    const otpDigest = await recoveryHmac("otp:" + challengeId + ":" + code);
    const { error: insertError } = await db.from("siwes_application_id_recovery_challenges").insert({
      id: challengeId, contact_type: "email", contact_digest: contactDigest, ip_digest: ipDigest,
      otp_digest: otpDigest, attempts: 0, expires_at: new Date(now + 10 * 60_000).toISOString(),
    });
    if (insertError) {
      console.error("Account-link challenge creation failed:", insertError.message);
      return respond(req, 500, { ok: false, error: "We could not start secure sign-in right now. Please try again later." });
    }

    if (eligible) {
      try {
        await sendAccountLinkCode(email, code);
      } catch (error) {
        console.error("Account-link code delivery failed:", error instanceof Error ? error.message : "delivery error");
        await db.from("siwes_application_id_recovery_challenges").update({ consumed_at: new Date().toISOString() }).eq("id", challengeId);
        return respond(req, 503, { ok: false, error: "We could not send your sign-in code. Please try again later or contact Agrolyst support." });
      }
    }
    return respond(req, 200, {
      ok: true, challenge_id: challengeId,
      masked_contact: maskRecoveryContact("email", email),
      message: "If an active SIWES application matches this email, a six-digit sign-in code has been sent. Check your inbox and spam folder.",
    });
  }

  if (action === "verify-account-link-code") {
    const email = clean(body.email, 254).toLowerCase();
    const challengeId = clean(body.challenge_id, 64);
    const code = clean(body.code, 6);
    if (!emailRegex.test(email) ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(challengeId) ||
        !/^[0-9]{6}$/.test(code)) {
      return respond(req, 400, { ok: false, error: "Enter the six-digit code sent to your email." });
    }

    const contactDigest = await recoveryHmac("account-link:email:" + email);
    const { data: challenge, error: challengeError } = await db.from("siwes_application_id_recovery_challenges")
      .select("id,otp_digest,attempts,expires_at,consumed_at")
      .eq("id", challengeId).eq("contact_type", "email").eq("contact_digest", contactDigest).maybeSingle();
    if (challengeError) {
      console.error("Account-link challenge lookup failed:", challengeError.message);
      return respond(req, 500, { ok: false, error: "We could not verify that code. Please request a new one." });
    }
    if (!challenge || challenge.consumed_at || new Date(challenge.expires_at).getTime() <= Date.now()) {
      return respond(req, 400, { ok: false, error: "That code is invalid or expired. Request a new code and try again." });
    }
    if (challenge.attempts >= 5) {
      await db.from("siwes_application_id_recovery_challenges").update({ consumed_at: new Date().toISOString() }).eq("id", challengeId).is("consumed_at", null);
      return respond(req, 429, { ok: false, error: "Too many incorrect codes. Request a new sign-in code." });
    }
    const candidateDigest = await recoveryHmac("otp:" + challengeId + ":" + code);
    if (candidateDigest !== challenge.otp_digest) {
      const nextAttempts = challenge.attempts + 1;
      await db.from("siwes_application_id_recovery_challenges").update({
        attempts: nextAttempts, ...(nextAttempts >= 5 ? { consumed_at: new Date().toISOString() } : {}),
      }).eq("id", challengeId).eq("attempts", challenge.attempts).is("consumed_at", null);
      return respond(req, 400, { ok: false, error: nextAttempts >= 5
        ? "Too many incorrect codes. Request a new sign-in code."
        : "That code does not match. Check it and try again." });
    }

    const { data: matches, error: lookupError } = await db.from("siwes_applications")
      .select("id,status,user_id,email").eq("email", email).limit(2);
    if (lookupError) {
      console.error("Account-link verification application lookup failed:", lookupError.message);
      return respond(req, 500, { ok: false, error: "We could not verify your application. Please request a new code later." });
    }
    const activeMatches = (matches ?? []).filter((row: { email?: string | null; status?: string | null }) => {
      const status = clean(row.status, 60).toLowerCase();
      return clean(row.email, 254).toLowerCase() === email &&
        Boolean(status) &&
        !["rejected", "withdrawn", "cancelled", "canceled", "closed", "archived", "inactive", "denied", "expired"].includes(status);
    });
    if (activeMatches.length !== 1) {
      await db.from("siwes_application_id_recovery_challenges").update({ consumed_at: new Date().toISOString() }).eq("id", challengeId).is("consumed_at", null);
      return respond(req, 400, { ok: false, error: "We could not verify an active application for this email. Check the address or contact Agrolyst support." });
    }

    const nowIso = new Date().toISOString();
    const { data: consumed, error: consumeError } = await db.from("siwes_application_id_recovery_challenges")
      .update({ verified_at: nowIso, consumed_at: nowIso })
      .eq("id", challengeId).eq("attempts", challenge.attempts).is("consumed_at", null)
      .gt("expires_at", nowIso).select("id").maybeSingle();
    if (consumeError || !consumed) return respond(req, 400, { ok: false, error: "That code has already been used. Request a new sign-in code." });

    const application = activeMatches[0] as { user_id?: string | null };
    let authUserId = application.user_id ?? null;
    if (authUserId) {
      const { data: found, error: foundError } = await db.auth.admin.getUserById(authUserId);
      if (foundError || !found?.user || clean(found.user.email, 254).toLowerCase() !== email) {
        console.error("Linked applicant Auth user could not be verified:", foundError?.message ?? "email mismatch");
        return respond(req, 409, { ok: false, error: "Your application account needs a manual check. Please contact Agrolyst support." });
      }
      const { error: confirmError } = await db.auth.admin.updateUserById(authUserId, { email_confirm: true });
      if (confirmError) throw confirmError;
    } else {
      const { data: created, error: createError } = await db.auth.admin.createUser({
        email, email_confirm: true, password: crypto.randomUUID() + "Aa9!",
        user_metadata: { signup_intent: "public_application_link", account_source: "siwes_email_code" },
      });
      if (!createError && created?.user) {
        authUserId = created.user.id;
      } else {
        const { data: users, error: usersError } = await db.auth.admin.listUsers({ page: 1, perPage: 1000 });
        const existing = (users?.users ?? []).find((item: { id: string; email?: string }) =>
          clean(item.email, 254).toLowerCase() === email
        );
        if (usersError || !existing) {
          console.error("Could not create or locate applicant Auth user:", createError?.message ?? usersError?.message ?? "unknown error");
          return respond(req, 500, { ok: false, error: "We verified your code, but could not prepare your account. Please request a new code or contact support." });
        }
        authUserId = existing.id;
        const { error: confirmError } = await db.auth.admin.updateUserById(authUserId, { email_confirm: true });
        if (confirmError) throw confirmError;
      }
    }

    const { data: generated, error: linkError } = await db.auth.admin.generateLink({ type: "magiclink", email });
    const authOtp = generated?.properties?.email_otp;
    if (linkError || !authOtp) {
      console.error("Could not generate the verified applicant session:", linkError?.message ?? "missing email OTP");
      return respond(req, 500, { ok: false, error: "Your email was verified, but we could not sign you in. Please request a new code." });
    }
    const { data: authResult, error: authError } = await db.auth.verifyOtp({
      email, token: authOtp, type: "magiclink",
    });
    if (authError || !authResult?.session?.access_token || !authResult.session.refresh_token) {
      console.error("Could not establish the verified applicant session:", authError?.message ?? "missing session");
      return respond(req, 500, { ok: false, error: "Your email was verified, but we could not complete sign-in. Please request a new code." });
    }
    return respond(req, 200, {
      ok: true,
      session: {
        access_token: authResult.session.access_token,
        refresh_token: authResult.session.refresh_token,
      },
    });
  }

  if (action === "link-account") {
    const authorization = req.headers.get("authorization") ?? "";
    const tokenMatch = authorization.match(/^Bearer\s+(.+)$/i);
    if (!tokenMatch) {
      return respond(req, 401, { error: "Please sign in with the account linked to your application email." });
    }

    let authUser;
    try {
      const { data: userData, error: userError } = await db.auth.getUser(tokenMatch[1]);
      if (userError || !userData?.user) {
        return respond(req, 401, { error: "Your session could not be verified. Please sign in again." });
      }
      authUser = userData.user;
    } catch {
      return respond(req, 401, { error: "Your session could not be verified. Please sign in again." });
    }

    const verified = Boolean(authUser.email_confirmed_at || authUser.confirmed_at);
    const email = clean(authUser.email, 254).toLowerCase();
    if (!verified || !emailRegex.test(email)) {
      return respond(req, 403, { error: "Please verify the email address on your account first. Then sign in again to link your SIWES application." });
    }

    const { data: matches, error: lookupError } = await db
      .from("siwes_applications")
      .select("id,reference_no,email,user_id,status")
      .eq("email", email)
      .limit(2);

    if (lookupError) {
      console.error("Public SIWES account link lookup failed:", lookupError.message);
      return respond(req, 500, { error: "We could not check for an existing application right now. Please try again later." });
    }
    if (!matches || matches.length === 0) {
      return respond(req, 200, { ok: true, linked: false, reason: "no_matching_application" });
    }
    if (matches.length > 1) {
      // Ambiguous email ownership is never auto-linked; support must resolve duplicate legacy records.
      return respond(req, 409, { ok: false, linked: false, reason: "multiple_matching_applications", error: "More than one application uses this email address. Please contact Agrolyst support so the records can be checked safely." });
    }

    const application = matches[0];
    const applicationStatus = clean(application.status, 60).toLowerCase();
    if (!applicationStatus || ["rejected", "withdrawn", "cancelled", "canceled", "closed", "archived", "inactive", "denied", "expired"].includes(applicationStatus)) {
      return respond(req, 200, { ok: true, linked: false, reason: "inactive_application" });
    }
    if (application.user_id && application.user_id !== authUser.id) {
      return respond(req, 200, { ok: true, linked: false, reason: "already_linked" });
    }
    if (application.user_id === authUser.id) {
      return respond(req, 200, { ok: true, linked: true, already_linked: true, application: { reference_no: application.reference_no, status: application.status } });
    }

    const { data: updated, error: updateError } = await db
      .from("siwes_applications")
      .update({ user_id: authUser.id, updated_at: new Date().toISOString() })
      .eq("id", application.id)
      .is("user_id", null)
      .select("reference_no,status,user_id")
      .maybeSingle();

    if (updateError) {
      console.error("Public SIWES application link update failed:", updateError.message);
      return respond(req, 500, { error: "We found your application but could not link it right now. Please try again later." });
    }
    if (updated?.user_id === authUser.id) {
      return respond(req, 200, { ok: true, linked: true, application: { reference_no: updated.reference_no, status: updated.status } });
    }

    // Recheck an update race without exposing another applicant's record.
    const { data: finalCheck } = await db
      .from("siwes_applications")
      .select("reference_no,status,user_id")
      .eq("id", application.id)
      .maybeSingle();
    if (finalCheck?.user_id === authUser.id) {
      return respond(req, 200, { ok: true, linked: true, already_linked: true, application: { reference_no: finalCheck.reference_no, status: finalCheck.status } });
    }
    return respond(req, 409, { ok: false, linked: false, reason: "link_conflict", error: "This application could not be linked automatically. Please contact Agrolyst support for assistance." });
  }

  if (action === "submit") {
    const p = (body.application && typeof body.application === "object")
      ? body.application as Record<string, unknown>
      : {};
    // Honeypot used as a basic anti-bot check.
    if (clean(p.website, 160)) return respond(req, 400, { error: "We could not process this request. Please review the form and try again." });

    const data = {
      full_name: clean(p.full_name, 160),
      email: clean(p.email, 254).toLowerCase(),
      phone: clean(p.phone, 40),
      institution: clean(p.institution, 200),
      department: clean(p.department, 160),
      course_of_study: clean(p.course_of_study, 160),
      study_level: clean(p.study_level, 60),
      training_area: clean(p.training_area, 100),
      duration: clean(p.duration, 60),
      start_date: clean(p.start_date, 10),
      end_date: clean(p.end_date, 10),
      address: clean(p.address, 500),
      emergency_contact_name: clean(p.emergency_contact_name, 160) || null,
      emergency_contact_phone: clean(p.emergency_contact_phone, 40) || null,
      reason_for_applying: clean(p.reason_for_applying, 1500) || null,
    };

    const required: Array<keyof typeof data> = [
      "full_name", "email", "phone", "institution", "department",
      "course_of_study", "study_level", "training_area", "duration",
      "start_date", "end_date", "address",
    ];
    if (required.some((key) => !data[key])) {
      return respond(req, 400, { error: "Please complete all required fields before submitting." });
    }
    if (!emailRegex.test(data.email)) return respond(req, 400, { error: "Enter a valid email address." });

    const parsedPhone = parsePhoneNumberFromString(data.phone);
    if (!parsedPhone || !parsedPhone.isValid()) {
      return respond(req, 400, { field: "phone", error: "Enter a valid phone number with the correct country calling code." });
    }
    data.phone = parsedPhone.number;

    if (data.emergency_contact_phone) {
      const parsedEmergencyPhone = parsePhoneNumberFromString(data.emergency_contact_phone);
      if (!parsedEmergencyPhone || !parsedEmergencyPhone.isValid()) {
        return respond(req, 400, { field: "emergency_contact_phone", error: "Enter a valid emergency contact number with its country calling code, or leave it blank." });
      }
      data.emergency_contact_phone = parsedEmergencyPhone.number;
    }

    // Reapplication cleanup: only replace a rejected record when BOTH verified-form
    // contact values match exactly. Never remove an active/approved application or
    // a rejected record based on email OR phone alone.
    const { data: priorRejected, error: priorLookupError } = await db
      .from("siwes_applications")
      .select("id,status,email,phone")
      .eq("status", "rejected")
      .eq("email", data.email)
      .eq("phone", data.phone)
      .limit(5);
    if (priorLookupError) {
      console.error("Could not check rejected SIWES applications:", priorLookupError.message);
      return respond(req, 500, { error: "We could not check your previous application. Please try again later." });
    }

    for (const prior of priorRejected ?? []) {
      const { data: rejectionEvents, error: eventLookupError } = await db
        .from("siwes_application_email_events")
        .select("delivery_status")
        .eq("application_id", prior.id)
        .eq("event_type", "rejected")
        .order("created_at", { ascending: false })
        .limit(1);
      if (eventLookupError) {
        console.error("Could not verify rejection notice delivery:", eventLookupError.message);
        return respond(req, 500, { error: "We could not safely prepare your reapplication. Please try again later." });
      }
      if (!rejectionEvents?.length || rejectionEvents[0].delivery_status !== "sent") {
        return respond(req, 409, { error: "Your previous rejection notice is still being processed. Please try again shortly." });
      }

      const { data: priorDocuments, error: documentsLookupError } = await db
        .from("siwes_documents")
        .select("storage_path")
        .eq("application_id", prior.id);
      if (documentsLookupError) {
        console.error("Could not load previous SIWES document paths:", documentsLookupError.message);
        return respond(req, 500, { error: "We could not safely clear your previous application. Please contact Agrolyst support." });
      }

      const paths = (priorDocuments ?? [])
        .map((document: { storage_path?: string | null }) => clean(document.storage_path, 1000))
        .filter(Boolean);
      if (paths.length) {
        const { error: storageDeleteError } = await db.storage.from("siwes-private").remove(paths);
        if (storageDeleteError) {
          console.error("Previous SIWES document cleanup failed:", storageDeleteError.message);
          return respond(req, 500, { error: "We could not safely clear your previous uploaded documents. Please try again later." });
        }
      }

      const { error: priorDeleteError } = await db
        .from("siwes_applications")
        .delete()
        .eq("id", prior.id)
        .eq("status", "rejected")
        .eq("email", data.email)
        .eq("phone", data.phone);
      if (priorDeleteError) {
        console.error("Previous rejected SIWES application cleanup failed:", priorDeleteError.message);
        return respond(req, 500, { error: "Your previous application documents were cleared, but its application record could not be fully removed. Please contact Agrolyst support before submitting again." });
      }
    }

    const { data: duplicateFlags, error: duplicateCheckError } = await db.rpc(
      "siwes_contact_duplicate_flags",
      { p_email: data.email, p_phone: data.phone },
    );
    if (duplicateCheckError) {
      console.error("Could not verify duplicate application contacts:", duplicateCheckError.message);
      return respond(req, 500, { error: "We could not verify whether this email has been used. Please try again." });
    }
    if (Boolean((duplicateFlags as Record<string, unknown> | null)?.email_exists)) {
      return respond(req, 409, { field: "email", error: "This email address has already been used for a SIWES application. Please use your existing application or contact Agrolyst for assistance." });
    }
    if (Boolean((duplicateFlags as Record<string, unknown> | null)?.phone_exists)) {
      return respond(req, 409, { field: "phone", error: "This phone number has already been used for a SIWES application. Please use your existing application or contact Agrolyst for assistance." });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(data.start_date) ||
        !/^\d{4}-\d{2}-\d{2}$/.test(data.end_date) ||
        data.end_date < data.start_date) {
      return respond(req, 400, { error: "Enter valid training dates. The end date must be on or after the start date." });
    }
    if (body.confirm_email !== true || body.privacy_ack !== true) {
      return respond(req, 400, { error: "Please confirm your email and acknowledge the privacy notice before submitting." });
    }
    if (body.policy_accepted !== true || clean(body.policy_version, 100) !== POLICY_VERSION) {
      return respond(req, 400, { error: "Please read and accept the current Applicant Policy before submitting." });
    }

    const submittedAt = new Date().toISOString();
    const { data: inserted, error } = await db
      .from("siwes_applications")
      .insert({
        ...data,
        user_id: null,
        public_submission_claim: true,
        status: "under_review",
        submitted_at: submittedAt,
        public_policy_version: POLICY_VERSION,
        public_policy_accepted_at: submittedAt,
      })
      .select("reference_no,status,submitted_at")
      .single();

    if (error || !inserted) {
      if (error?.code === "23505") {
        const constraint = clean((error as { constraint?: string } | null)?.constraint, 120);
        if (["siwes_applications_public_phone_claim_unique", "siwes_applications_contact_phone_unique"].includes(constraint)) {
          return respond(req, 409, { field: "phone", error: "This phone number has already been used for a SIWES application. Please use your existing application or contact Agrolyst for assistance." });
        }
        return respond(req, 409, { field: "email", error: "This email address has already been used for a SIWES application. Please use your existing application or contact Agrolyst for assistance." });
      }
      console.error("Could not create public SIWES application:", error?.message ?? "No row returned");
      return respond(req, 500, { error: "We could not submit your application right now. Your form has not been confirmed as submitted. Please try again later." });
    }
    return respond(req, 201, {
      ok: true,
      application: {
        reference_no: inserted.reference_no,
        status: inserted.status,
        submitted_at: inserted.submitted_at,
      },
    });
  }

  if (action === "print-acceptance-letter") {
    const reference = clean(body.reference_no, 50).toUpperCase();
    const email = clean(body.email, 254).toLowerCase();
    if (!reference || !emailRegex.test(email)) {
      return respond(req, 400, { error: "Enter your Application ID and the email address used on the application." });
    }

    const { data: application, error: applicationError } = await db
      .from("siwes_applications")
      .select("reference_no,email,status,full_name,phone,institution,department,course_of_study,study_level,training_area,duration,start_date,end_date,address,acceptance_letter_number,acceptance_letter_issued_at")
      .eq("reference_no", reference)
      .maybeSingle();

    if (applicationError) {
      console.error("Public acceptance letter lookup failed:", applicationError.message);
      return respond(req, 500, { error: "We could not prepare the acceptance letter right now. Please try again later." });
    }
    if (!application || clean(application.email, 254).toLowerCase() !== email) {
      return respond(req, 404, { error: "We could not find an application matching those details. Check your Application ID and email and try again." });
    }
    if (application.status !== "acceptance_letter_issued" || !application.acceptance_letter_number || !application.acceptance_letter_issued_at) {
      return respond(req, 403, { error: "The acceptance letter is not available for printing yet. It will appear here after Agrolyst officially issues it." });
    }

    const { data: template, error: templateError } = await db
      .from("siwes_document_templates")
      .select("html_template,title,version")
      .eq("template_key", "siwes_acceptance_letter")
      .eq("active", true)
      .maybeSingle();

    if (templateError || !template?.html_template) {
      console.error("Acceptance letter template unavailable:", templateError?.message ?? "No active template");
      return respond(req, 500, { error: "The official acceptance letter template is unavailable. Please contact Agrolyst." });
    }

    const escapeHtml = (value: unknown) => String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
    const displayDate = (value: string | null | undefined) => {
      if (!value) return "To be confirmed";
      const parsed = new Date(value);
      return Number.isNaN(parsed.getTime())
        ? value
        : new Intl.DateTimeFormat("en-NG", { day: "numeric", month: "long", year: "numeric", timeZone: "Africa/Lagos" }).format(parsed);
    };
    const startDate = displayDate(application.start_date);
    const endDate = displayDate(application.end_date);
    const issueDate = displayDate(application.acceptance_letter_issued_at);
    const values: Record<string, string> = {
      logo_url: "https://raw.githubusercontent.com/agrolyst/siwes-agrolyst/main/agrolystfarmslogo.png",
      reference_no: application.reference_no,
      letter_number: application.acceptance_letter_number,
      letter_title: "Acceptance Letter for Industrial Training",
      issue_date: issueDate,
      student_name: application.full_name ?? "",
      student_email: application.email ?? "",
      student_phone: application.phone ?? "",
      institution: application.institution ?? "",
      department: application.department ?? "Not provided",
      contact_address: application.address ?? "",
      course_of_study: application.course_of_study ?? "",
      study_level: application.study_level ?? "",
      training_area: application.training_area ?? "",
      duration: application.duration ?? "",
      start_date: startDate,
      end_date: endDate,
    };
    const renderedHtml = String(template.html_template).replace(/{{\s*([a-z_]+)\s*}}/g, (match, key: string) =>
      Object.prototype.hasOwnProperty.call(values, key) ? escapeHtml(values[key]) : ""
    );

    return respond(req, 200, {
      ok: true,
      letter: {
        reference_no: application.reference_no,
        letter_number: application.acceptance_letter_number,
        issued_at: application.acceptance_letter_issued_at,
        title: template.title ?? "SIWES Acceptance Letter",
        template_version: template.version ?? 1,
        html: renderedHtml,
      },
    });
  }

  if (action === "check-status") {
    const reference = clean(body.reference_no, 50).toUpperCase();
    const email = clean(body.email, 254).toLowerCase();
    if (!reference || !emailRegex.test(email)) {
      return respond(req, 400, { error: "Enter your Application ID and the email address used on the application." });
    }
    const { data: application, error } = await db
      .from("siwes_applications")
      .select("id,reference_no,email,status,submitted_at,reviewed_at,acceptance_letter_issued_at,resumption_confirmed_at,completed_at,updated_at")
      .eq("reference_no", reference)
      .maybeSingle();

    if (error) {
      console.error("Public application status lookup failed:", error.message);
      return respond(req, 500, { error: "We could not check the status right now. Please try again later." });
    }
    // Use the reference AND matching email. Never expose records by reference alone.
    if (!application || clean(application.email, 254).toLowerCase() !== email) {
      return respond(req, 404, { error: "We could not find an application matching those details. Check your Application ID and email and try again." });
    }

    // Return applicant-safe document metadata only. Never return file paths, names,
    // reviewer notes, AI findings, extracted data, or staff identities.
    const [{ data: documents, error: documentsError }, { data: reviews, error: reviewsError }] = await Promise.all([
      db.from("siwes_documents")
        .select("document_type,status,uploaded_at,reviewed_at")
        .eq("application_id", application.id)
        .order("uploaded_at", { ascending: true }),
      db.from("siwes_document_ai_reviews")
        .select("document_id,review_status,reviewed_at")
        .eq("application_id", application.id),
    ]);

    if (documentsError || reviewsError) {
      console.error("Public application checklist lookup failed:", documentsError?.message ?? reviewsError?.message);
      return respond(req, 500, { error: "We could not load the application checklist right now. Please try again later." });
    }

    const safeDocuments = (documents ?? []).map((document: {
      document_type: string; status: string; uploaded_at: string; reviewed_at: string | null;
    }) => ({
      document_type: document.document_type,
      status: document.status,
      uploaded_at: document.uploaded_at,
      reviewed_at: document.reviewed_at,
    }));
    const reviewRows = reviews ?? [];
    const aiCompleted = reviewRows.filter((review: { review_status: string }) => review.review_status === "completed").length;
    const aiPending = reviewRows.filter((review: { review_status: string }) => review.review_status === "pending").length;
    const aiFailed = reviewRows.filter((review: { review_status: string }) => review.review_status === "failed").length;
    const aiStatus = safeDocuments.length === 0 || reviewRows.length === 0
      ? "not_started"
      : aiFailed > 0
        ? "needs_attention"
        : aiPending > 0 || aiCompleted < safeDocuments.length
          ? "in_progress"
          : "completed";

    return respond(req, 200, {
      ok: true,
      application: {
        reference_no: application.reference_no,
        status: application.status,
        submitted_at: application.submitted_at,
        reviewed_at: application.reviewed_at,
        acceptance_letter_issued_at: application.acceptance_letter_issued_at,
        resumption_confirmed_at: application.resumption_confirmed_at,
        completed_at: application.completed_at,
        updated_at: application.updated_at,
        documents: safeDocuments,
        ai_review: {
          status: aiStatus,
          total_documents: safeDocuments.length,
          reviewed_documents: aiCompleted,
          pending_documents: aiPending,
          failed_documents: aiFailed,
        },
      },
    });
  }

  return respond(req, 400, { error: "Unsupported application action." });
});
