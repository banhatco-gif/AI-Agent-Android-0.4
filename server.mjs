import http from "node:http";
import OpenAI from "openai";
import crypto from "node:crypto";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const PORT = Number(process.env.PORT || 8080);
const AUTH_TOKEN = process.env.AGENT_AUTH_TOKEN || "";
const MODEL = process.env.OPENAI_MODEL || "gpt-5-mini";
const REGISTRATION_KEY = process.env.DEVICE_REGISTRATION_KEY || "";
const DEVICE_SIGNING_SECRET = process.env.DEVICE_SIGNING_SECRET || AUTH_TOKEN || "";
const TOKEN_TTL_MS = 180 * 24 * 60 * 60 * 1000;

const itemProperties = {
  inboxId: { type: "integer" },
  summary: { type: "string" },
  category: { type: "string", enum: ["TASK","MEETING","DEADLINE","NOTICE","INFO"] },
  workArea: { type: "string", enum: ["DANG_UY","CHI_BO","THU_Y","TO_DAN_PHO","CA_NHAN","OTHER"] },
  confidence: { type: "number", minimum: 0, maximum: 1 },
  priority: { type: "string", enum: ["LOW","NORMAL","HIGH","URGENT"] },
  taskTitle: { type: ["string","null"] }, taskDetails: { type: ["string","null"] }, dueAt: { type: ["integer","null"] },
  eventTitle: { type: ["string","null"] }, eventDetails: { type: ["string","null"] }, eventStartAt: { type: ["integer","null"] },
  eventEndAt: { type: ["integer","null"] }, eventLocation: { type: ["string","null"] }
};
const itemRequired = Object.keys(itemProperties);
const singleSchema = { type: "object", properties: itemProperties, required: itemRequired, additionalProperties: false };
const batchSchema = {
  type: "object",
  properties: {
    groupSummary: { type: "string" },
    highlights: { type: "array", items: { type: "string" } },
    analyses: { type: "array", items: singleSchema }
  },
  required: ["groupSummary","highlights","analyses"], additionalProperties: false
};
const askSchema = { type: "object", properties: { answer: { type: "string" } }, required: ["answer"], additionalProperties: false };

function json(res, status, obj) {
  res.writeHead(status, {"content-type":"application/json; charset=utf-8", "cache-control":"no-store"});
  res.end(JSON.stringify(obj));
}
function b64url(input) { return Buffer.from(input).toString("base64url"); }
function signDevice(payloadB64) {
  if (!DEVICE_SIGNING_SECRET) return "";
  return crypto.createHmac("sha256", DEVICE_SIGNING_SECRET).update(payloadB64).digest("base64url");
}
function issueDeviceToken(installId) {
  const payload = b64url(JSON.stringify({sub:String(installId).slice(0,120), iat:Date.now(), exp:Date.now()+TOKEN_TTL_MS}));
  return `${payload}.${signDevice(payload)}`;
}
function verifyDeviceToken(token) {
  try {
    if (!DEVICE_SIGNING_SECRET || !token.includes(".")) return false;
    const [payload, sig] = token.split(".", 2);
    const expected = signDevice(payload);
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return Number(data.exp || 0) > Date.now() && String(data.sub || "").length > 8;
  } catch { return false; }
}
function authorized(req) {
  const raw = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (AUTH_TOKEN && raw === AUTH_TOKEN) return true;
  return verifyDeviceToken(raw);
}
async function readJson(req, max = 150_000) {
  let raw = "";
  for await (const chunk of req) { raw += chunk; if (raw.length > max) throw new Error("payload_too_large"); }
  return JSON.parse(raw || "{}");
}
function safeItem(input) {
  return {
    inboxId: Number(input.inboxId || 0), source: String(input.source || "").slice(0,100),
    title: String(input.title || "").slice(0,500), body: String(input.body || "").slice(0,6000),
    receivedAt: Number(input.receivedAt || Date.now()), timezone: "Asia/Bangkok"
  };
}
const instructions = `Bạn là AI Agent quản lý công việc tiếng Việt trên điện thoại Android.
Chỉ trích xuất điều thật sự có trong tin; không bịa người, ngày, địa điểm hay nhiệm vụ. Múi giờ Asia/Bangkok (UTC+7).
TASK: có hành động cần thực hiện. MEETING: có lịch làm việc và thời điểm đủ rõ. DEADLINE: nhấn mạnh hạn. NOTICE/INFO: chỉ thông báo/trao đổi.
Nếu không có đầu việc rõ: taskTitle=null. Nếu không có lịch rõ: eventTitle=null và event*=null.
Nếu vừa có việc vừa có lịch, có thể điền cả task và event. Phân loại workArea: DANG_UY, CHI_BO, THU_Y, TO_DAN_PHO, CA_NHAN, OTHER.
Tóm tắt ngắn, giữ tên đơn vị/người nhận/hạn quan trọng. Trả đúng inboxId đầu vào cho từng phân tích.`;

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/health") return json(res, 200, {ok:true, version:"0.5.0", deviceRegistration:true});
  if (req.method === "POST" && req.url === "/device/register") {
    if (!DEVICE_SIGNING_SECRET) return json(res, 503, {error:"device_signing_not_configured"});
    if (REGISTRATION_KEY && (req.headers["x-registration-key"] || "") !== REGISTRATION_KEY) return json(res, 403, {error:"registration_denied"});
    let body;
    try { body = await readJson(req, 20_000); } catch (e) { return json(res, 400, {error:e.message}); }
    const installId = String(body.installId || "").trim();
    if (installId.length < 16 || installId.length > 120) return json(res, 400, {error:"invalid_install_id"});
    return json(res, 200, {token:issueDeviceToken(installId), expiresInDays:180});
  }
  if (req.method !== "POST" || !["/analyze","/analyze-batch","/ask"].includes(req.url)) return json(res, 404, {error:"not_found"});
  if (!authorized(req)) return json(res, 401, {error:"unauthorized"});

  let input;
  try { input = await readJson(req); } catch (e) { return json(res, e.message === "payload_too_large" ? 413 : 400, {error:e.message}); }
  try {
    if (req.url === "/analyze") {
      const safe = safeItem(input);
      const response = await client.responses.create({
        model: MODEL, instructions, input: JSON.stringify(safe),
        text: { format: { type: "json_schema", name: "android_ai_agent_item_v03", strict: true, schema: singleSchema } }
      });
      return json(res, 200, JSON.parse(response.output_text));
    }

    if (req.url === "/analyze-batch") {
      const items = Array.isArray(input.items) ? input.items.slice(0,20).map(safeItem) : [];
      if (!items.length) return json(res, 400, {error:"empty_items"});
      const response = await client.responses.create({
        model: MODEL,
        instructions: instructions + `\nBạn đang nhận nhiều notification liên tiếp của CÙNG một nhóm Zalo. Hãy gom ý trùng nhau. groupSummary tối đa 4 câu; highlights chỉ chứa các việc/hạn/lịch đáng chú ý. analyses phải có đúng một phần tử cho mỗi input item, giữ đúng inboxId.`,
        input: JSON.stringify({groupTitle:String(input.groupTitle || "").slice(0,500), items}),
        text: { format: { type: "json_schema", name: "android_ai_agent_batch_v03", strict: true, schema: batchSchema } }
      });
      return json(res, 200, JSON.parse(response.output_text));
    }

    const tasks = Array.isArray(input.tasks) ? input.tasks.slice(0,40) : [];
    const events = Array.isArray(input.events) ? input.events.slice(0,30) : [];
    const question = String(input.question || "").slice(0,1000);
    const response = await client.responses.create({
      model: MODEL,
      instructions: `Bạn là trợ lý công việc tiếng Việt. Chỉ trả lời dựa trên danh sách task/event được cung cấp. Hiện tại là ${new Date(Number(input.now || Date.now())).toISOString()}, múi giờ Asia/Bangkok. Trả lời ngắn, ưu tiên việc gần hạn và lịch gần nhất. Nếu không có dữ liệu phù hợp, nói rõ.`,
      input: JSON.stringify({question, tasks, events}),
      text: { format: { type: "json_schema", name: "android_ai_agent_ask_v03", strict: true, schema: askSchema } }
    });
    return json(res, 200, JSON.parse(response.output_text));
  } catch (e) {
    console.error("agent_error", req.url, e?.status || e?.name || "unknown");
    return json(res, 500, {error:"ai_request_failed"});
  }
});
server.listen(PORT, () => console.log(`AI Agent backend 0.5 listening on :${PORT}`));