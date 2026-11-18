// Supabase edge function "qsv". Stores commitments (register, validate) and encrypted key
// backups (put, get). It never sees a plaintext key: backups arrive already encrypted, and
// commitments are one-way hashes. The secret key is read from the QSV_SECRET_KEY secret.
import { createClient } from "npm:@supabase/supabase-js@2";

const HEX64 = /^[0-9a-f]{64}$/;
const CLOUD_ID = /^key-[0-9a-f]{16}$/;
const BASE64 = /^[A-Za-z0-9+/=]+$/;
const BLOB_MAX = 64 * 1024;
const PG_UNIQUE_VIOLATION = "23505";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("QSV_SECRET_KEY")!,
  { auth: { persistSession: false, autoRefreshToken: false } },
);

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function readBody(req: Request): Promise<Record<string, unknown> | null> {
  if (req.method !== "POST") return null;
  try {
    const body = await req.json();
    return typeof body === "object" && body !== null ? (body as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

// ---- commitments -------------------------------------------------------------

async function register(commitment: string): Promise<Response> {
  const { error } = await supabase.from("commitments").insert({ commitment });
  if (error && error.code !== PG_UNIQUE_VIOLATION) {
    console.error("register failed:", error.code);
    return json({ ok: false, error: "register_failed" }, 500);
  }
  return json({ ok: true });
}

async function validate(commitment: string): Promise<Response> {
  const { data, error } = await supabase
    .from("commitments")
    .select("revoked")
    .eq("commitment", commitment)
    .maybeSingle();
  if (error) {
    console.error("validate failed:", error.code);
    return json({ ok: false, error: "lookup_failed" }, 500);
  }
  if (!data || data.revoked) return json({ ok: false }, 403);
  return json({ ok: true });
}

// ---- encrypted cloud backups -------------------------------------------------

async function put(id: string, blob: string): Promise<Response> {
  const { data, error } = await supabase
    .from("cloud_blobs")
    .insert({ id, blob })
    .select("created_at")
    .single();
  if (error) {
    if (error.code === PG_UNIQUE_VIOLATION) return json({ ok: false, error: "exists" }, 409);
    console.error("put failed:", error.code);
    return json({ ok: false, error: "put_failed" }, 500);
  }
  return json({ ok: true, created_at: data.created_at });
}

async function get(id: string): Promise<Response> {
  const { data, error } = await supabase
    .from("cloud_blobs")
    .select("blob, created_at")
    .eq("id", id)
    .maybeSingle();
  if (error) {
    console.error("get failed:", error.code);
    return json({ ok: false, error: "get_failed" }, 500);
  }
  if (!data) return json({ ok: false, error: "not_found" }, 404);
  return json({ ok: true, created_at: data.created_at, blob: data.blob });
}

// ---- routing -----------------------------------------------------------------

Deno.serve(async (req) => {
  const { pathname } = new URL(req.url);
  const route = ["/register", "/validate", "/put", "/get"].find((r) => pathname.endsWith(r));
  if (!route) return json({ ok: false, error: "not_found" }, 404);

  const body = await readBody(req);
  if (!body) return json({ ok: false, error: "bad_request" }, 400);

  if (route === "/register" || route === "/validate") {
    const c = body.commitment;
    if (typeof c !== "string" || !HEX64.test(c)) return json({ ok: false, error: "bad_request" }, 400);
    return route === "/register" ? register(c) : validate(c);
  }

  const id = body.id;
  if (typeof id !== "string" || !CLOUD_ID.test(id)) return json({ ok: false, error: "bad_request" }, 400);

  if (route === "/put") {
    const blob = body.blob;
    if (typeof blob !== "string" || blob.length === 0 || blob.length > BLOB_MAX || !BASE64.test(blob)) {
      return json({ ok: false, error: "bad_request" }, 400);
    }
    return put(id, blob);
  }
  return get(id);
});
