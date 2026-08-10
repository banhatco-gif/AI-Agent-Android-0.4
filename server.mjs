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
const ZALO_VERIFICATION_PATH = "/zalo_verifierV-Rd5e7JSJjazU4tflHRBYA4rGpEyWzNDZGp.html";
const ZALO_VERIFICATION_TOKEN = "V-Rd5e7JSJjazU4tflHRBYA4rGpEyWzNDZGp";
const ZALO_APP_ID = process.env.ZALO_APP_ID || "3017784749195688493";
const ZALO_OA_SECRET_KEY = process.env.ZALO_OA_SECRET_KEY || "";

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
async function readRaw(req, max = 150_000) {
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > max) throw new Error("payload_too_large");
  }
  return raw;
}
async function readJson(req, max = 150_000) {
  const raw = await readRaw(req, max);
  return JSON.parse(raw || "{}");
}
function timingSafeTextEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function verifyZaloWebhook(raw, payload, signatureHeader) {
  if (!ZALO_OA_SECRET_KEY) return { configured:false, valid:false };
  const appId = String(payload.app_id || "");
  const timestamp = String(payload.timestamp || "");
  if (!appId || !timestamp || (ZALO_APP_ID && appId !== ZALO_APP_ID)) {
    return { configured:true, valid:false };
  }
  const expected = crypto.createHash("sha256")
    .update(appId + raw + timestamp + ZALO_OA_SECRET_KEY)
    .digest("hex");
  const received = String(signatureHeader || "").replace(/^mac\s*=\s*/i, "").trim();
  return { configured:true, valid:timingSafeTextEqual(received, expected) };
}
function safeItem(input) {
  return {
    inboxId: Number(input.inboxId || 0), source: String(input.source || "").slice(0,100),
    title: String(input.title || "").slice(0,500), body: String(input.body || "").slice(0,6000),
    receivedAt: Number(input.receivedAt || Date.now()), timezone: "Asia/Bangkok"
  };
}
const instructions = `Bạn là AI Agent quản lý công việc tiếng Việt trên điện thoại Android.
Chỉ trích xuất điều thật sự có trong tin hoặc tài liệu; không bịa người, ngày, địa điểm hay nhiệm vụ. Múi giờ Asia/Bangkok (UTC+7).
TASK: có hành động cần thực hiện. MEETING: có lịch làm việc và thời điểm đủ rõ. DEADLINE: nhấn mạnh hạn. NOTICE/INFO: chỉ thông báo/trao đổi.
Nếu không có đầu việc rõ: taskTitle=null. Nếu không có lịch rõ: eventTitle=null và event*=null.
Nếu vừa có việc vừa có lịch, có thể điền cả task và event. Phân loại workArea: DANG_UY, CHI_BO, THU_Y, TO_DAN_PHO, CA_NHAN, OTHER.
Tóm tắt ngắn, giữ tên đơn vị/người nhận/hạn quan trọng. Trả đúng inboxId đầu vào cho từng phân tích.`;

function zaloVerification(res) {
  const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="zalo-platform-site-verification" content="${ZALO_VERIFICATION_TOKEN}"></head><body>zalo-platform-site-verification = ${ZALO_VERIFICATION_TOKEN}</body></html>`;
  res.writeHead(200, {"content-type":"text/html; charset=utf-8", "cache-control":"no-store"});
  res.end(html);
}

function privacyPolicy(res) {
  const html = `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Chính sách quyền riêng tư - AI Agent Công việc</title><style>body{font-family:system-ui,sans-serif;max-width:820px;margin:40px auto;padding:0 20px;line-height:1.65;color:#202124}h1,h2{line-height:1.25}small{color:#5f6368}</style></head><body><h1>Chính sách quyền riêng tư – AI Agent Công việc</h1><small>Cập nhật: 09/08/2026</small><p>AI Agent Công việc giúp người dùng quản lý công việc từ thông báo, nội dung và tệp người dùng chủ động chia sẻ hoặc cấp quyền thư mục trên thiết bị.</p><h2>Dữ liệu được xử lý</h2><ul><li>Nội dung thông báo Zalo mà Android cung cấp sau khi người dùng bật quyền truy cập thông báo.</li><li>Tệp người dùng tải xuống, chia sẻ sang AI Agent hoặc đặt trong thư mục đã cấp quyền đọc cho ứng dụng.</li><li>Câu hỏi giọng nói sau khi được chuyển thành văn bản.</li><li>Nhiệm vụ, thời hạn, sự kiện và thông tin lịch do ứng dụng trích xuất.</li></ul><h2>Mục đích sử dụng</h2><p>Dữ liệu được dùng để phân tích, tóm tắt, tạo nhiệm vụ/sự kiện, nhắc hạn và lập báo cáo. Ứng dụng không bán dữ liệu và không dùng dữ liệu cho quảng cáo.</p><h2>Chia sẻ và truyền dữ liệu</h2><p>Khi cần phân tích AI, nội dung hoặc tệp liên quan được truyền qua HTTPS đến backend của ứng dụng và dịch vụ AI OpenAI để xử lý.</p><h2>Lưu trữ và bảo mật</h2><p>Dữ liệu công việc chính được lưu cục bộ trên thiết bị. Backend không chủ ý lưu nội dung sau khi hoàn tất yêu cầu. Token được bảo vệ bằng Android Keystore và dữ liệu được truyền bằng HTTPS.</p><h2>Quyền lựa chọn</h2><p>Người dùng có thể thu hồi quyền đọc thông báo, quyền thư mục hoặc quyền Lịch trong Android; xóa từng mục hoặc gỡ cài đặt ứng dụng.</p><h2>Liên hệ</h2><p>Email: <a href="mailto:banhat.co@gmail.com">banhat.co@gmail.com</a></p></body></html>`;
  res.writeHead(200, {"content-type":"text/html; charset=utf-8", "cache-control":"public, max-age=3600"});
  res.end(html);
}

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === ZALO_VERIFICATION_PATH) return zaloVerification(res);
  if (req.method === "GET" && req.url === "/privacy") return privacyPolicy(res);
  if (req.method === "GET" && req.url === "/health") return json(res, 200, {ok:true, version:"0.9.0", deviceRegistration:true, fileAnalysis:true, zaloWebhook:true, zaloSignatureConfigured:Boolean(ZALO_OA_SECRET_KEY)});
  if (req.method === "GET" && req.url === "/zalo/webhook") return json(res, 200, {ok:true, endpoint:"zalo_webhook", signatureConfigured:Boolean(ZALO_OA_SECRET_KEY)});
  if (req.method === "POST" && req.url === "/zalo/webhook") {
    let raw;
    try { raw = await readRaw(req, 1_000_000); }
    catch (e) { return json(res, e.message === "payload_too_large" ? 413 : 400, {error:e.message}); }
    if (!raw.trim()) return json(res, 200, {ok:true, validation:true});
    let event;
    try { event = JSON.parse(raw); }
    catch { return json(res, 400, {error:"invalid_json"}); }
    const verification = verifyZaloWebhook(raw, event, req.headers["x-zevent-signature"]);
    if (!verification.configured) {
      console.warn("zalo_webhook_ignored", String(event.event_name || "unknown").slice(0,100), "signature_not_configured");
      return json(res, 200, {ok:true, accepted:false, reason:"signature_not_configured"});
    }
    if (!verification.valid) return json(res, 401, {error:"invalid_signature"});
    console.log("zalo_webhook_received", String(event.event_name || "unknown").slice(0,100), String(event.timestamp || "").slice(0,30));
    return json(res, 200, {ok:true, accepted:true});
  }
  if (req.method === "POST" && req.url === "/device/register") {
    if (!DEVICE_SIGNING_SECRET) return json(res, 503, {error:"device_signing_not_configured"});
    if (REGISTRATION_KEY && (req.headers["x-registration-key"] || "") !== REGISTRATION_KEY) return json(res, 403, {error:"registration_denied"});
    let body;
    try { body = await readJson(req, 20_000); } catch (e) { return json(res, 400, {error:e.message}); }
    const installId = String(body.installId || "").trim();
    if (installId.length < 16 || installId.length > 120) return json(res, 400, {error:"invalid_install_id"});
    return json(res, 200, {token:issueDeviceToken(installId), expiresInDays:180});
  }
  if (req.method !== "POST" || !["/analyze","/analyze-batch","/analyze-file","/ask"].includes(req.url)) return json(res, 404, {error:"not_found"});
  if (!authorized(req)) return json(res, 401, {error:"unauthorized"});

  let input;
  try { input = await readJson(req, req.url === "/analyze-file" ? 15_000_000 : 150_000); }
  catch (e) { return json(res, e.message === "payload_too_large" ? 413 : 400, {error:e.message}); }

  try {
    if (req.url === "/analyze") {
      const safe = safeItem(input);
      const response = await client.responses.create({
        model: MODEL, instructions, input: JSON.stringify(safe),
        text: { format: { type: "json_schema", name: "android_ai_agent_item_v09", strict: true, schema: singleSchema } }
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
        text: { format: { type: "json_schema", name: "android_ai_agent_batch_v09", strict: true, schema: batchSchema } }
      });
      return json(res, 200, JSON.parse(response.output_text));
    }

    if (req.url === "/analyze-file") {
      const inboxId = Number(input.inboxId || 0);
      const filename = String(input.filename || "document").slice(0,240);
      const mimeType = String(input.mimeType || "application/octet-stream").slice(0,120);
      const fileData = String(input.fileData || "");
      const groupTitle = String(input.groupTitle || "Tệp Zalo").slice(0,500);
      if (!inboxId || !fileData || fileData.length > 14_500_000) return json(res, 400, {error:"invalid_file_input"});
      const content = [{ type:"input_text", text:`Đọc kỹ tệp '${filename}' từ nguồn '${groupTitle}'. Tóm tắt nội dung phục vụ báo cáo; phát hiện chỉ đạo, đầu việc, người/đơn vị thực hiện, thời hạn, lịch họp và địa điểm nếu có. Chỉ lấy thông tin thật sự có trong tệp. inboxId=${inboxId}.` }];
      if (mimeType.startsWith("image/")) content.push({ type:"input_image", image_url:`data:${mimeType};base64,${fileData}` });
      else content.push({ type:"input_file", filename, file_data:fileData });
      const response = await client.responses.create({
        model: MODEL,
        instructions,
        input: [{ role:"user", content }],
        text: { format: { type: "json_schema", name: "android_ai_agent_file_v09", strict: true, schema: singleSchema } }
      });
      const result = JSON.parse(response.output_text);
      result.inboxId = inboxId;
      return json(res, 200, result);
    }

    const tasks = Array.isArray(input.tasks) ? input.tasks.slice(0,40) : [];
    const events = Array.isArray(input.events) ? input.events.slice(0,30) : [];
    const question = String(input.question || "").slice(0,1000);
    const response = await client.responses.create({
      model: MODEL,
      instructions: `Bạn là trợ lý công việc tiếng Việt. Chỉ trả lời dựa trên danh sách task/event được cung cấp. Hiện tại là ${new Date(Number(input.now || Date.now())).toISOString()}, múi giờ Asia/Bangkok. Trả lời ngắn, ưu tiên việc gần hạn và lịch gần nhất. Nếu không có dữ liệu phù hợp, nói rõ.`,
      input: JSON.stringify({question, tasks, events}),
      text: { format: { type: "json_schema", name: "android_ai_agent_ask_v09", strict: true, schema: askSchema } }
    });
    return json(res, 200, JSON.parse(response.output_text));
  } catch (e) {
    console.error("agent_error", req.url, e?.status || e?.name || "unknown");
    return json(res, 500, {error:"ai_request_failed"});
  }
});
server.listen(PORT, () => console.log(`AI Agent backend 0.9 listening on :${PORT}`));
