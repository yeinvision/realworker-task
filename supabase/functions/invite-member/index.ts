import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const jsonHeaders = { "Content-Type": "application/json" };

const response = (status: number, body: Record<string, unknown>, corsHeaders = {}) =>
  new Response(JSON.stringify(body), { status, headers: { ...jsonHeaders, ...corsHeaders } });

Deno.serve(async request => {
  const origin = request.headers.get("Origin") || "";
  const allowedOrigins = (Deno.env.get("INVITE_ALLOWED_ORIGINS") || "")
    .split(",")
    .map(value => value.trim())
    .filter(Boolean);

  if (!origin || !allowedOrigins.includes(origin)) {
    return response(403, { error: "허용되지 않은 앱 주소에서 요청했어요." });
  }

  const corsHeaders = {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin"
  };

  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (request.method !== "POST") return response(405, { error: "POST 요청만 허용됩니다." }, corsHeaders);

  const authorization = request.headers.get("Authorization");
  if (!authorization?.startsWith("Bearer ")) {
    return response(401, { error: "로그인이 필요합니다." }, corsHeaders);
  }

  let email: string;
  try {
    const body = await request.json();
    email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  } catch {
    return response(400, { error: "이메일 주소를 확인해주세요." }, corsHeaders);
  }

  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return response(400, { error: "올바른 이메일 주소를 입력해주세요." }, corsHeaders);
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    console.error("Invite function is missing Supabase environment variables.");
    return response(500, { error: "초대 기능의 서버 설정이 완료되지 않았어요." }, corsHeaders);
  }

  const callerClient = createClient(supabaseUrl, anonKey, {
    global: { headers: { Authorization: authorization } },
    auth: { autoRefreshToken: false, persistSession: false }
  });
  const { data: userData, error: userError } = await callerClient.auth.getUser();
  if (userError || !userData.user) {
    return response(401, { error: "로그인 정보를 확인할 수 없어요. 다시 로그인해주세요." }, corsHeaders);
  }

  const { data: isAdmin, error: adminError } = await callerClient.rpc("is_app_admin");
  if (adminError) {
    console.error("Unable to verify invitation administrator permission.");
    return response(500, { error: "관리자 권한을 확인하지 못했어요." }, corsHeaders);
  }
  if (isAdmin !== true) return response(403, { error: "멤버 초대는 지정된 관리자만 할 수 있어요." }, corsHeaders);

  const adminClient = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  });
  const redirectTo = new URL("/", origin).toString();
  const { error: inviteError } = await adminClient.auth.admin.inviteUserByEmail(email, { redirectTo });
  if (inviteError) {
    if (/rate.?limit/i.test(inviteError.message)) {
      return response(429, { error: "초대 이메일 발송 한도에 걸렸어요. 잠시 후 다시 시도하거나 Supabase SMTP 설정을 확인해주세요." }, corsHeaders);
    }
    if (/already|registered|exists/i.test(inviteError.message)) {
      return response(409, { error: "이미 등록된 계정이거나 초대된 주소예요." }, corsHeaders);
    }
    console.error("Supabase rejected an invitation request.");
    return response(502, { error: "초대 메일 전송에 실패했어요. Supabase Auth 이메일 설정을 확인해주세요." }, corsHeaders);
  }

  return response(200, { success: true }, corsHeaders);
});
