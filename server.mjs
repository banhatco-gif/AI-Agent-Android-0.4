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

function privacyPolicy(res) {
  const html = `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Chính sách quyền riêng tư - AI Agent Công việc</title><style>body{font-family:system-ui,sans-serif;max-width:820px;margin:40px auto;padding:0 20px;line-height:1.65;color:#202124}h1,h2{line-height:1.25}small{color:#5f6368}</style></head><body><h1>Chính sách quyền riêng tư – AI Agent Công việc</h1><small>Cập nhật: 09/08/2026</small><p>AI Agent Công việc giúp người dùng tự quản lý công việc từ thông báo Zalo, tạo nhiệm vụ, nhắc hạn và đồng bộ sự kiện vào lịch trên thiết bị.</p><h2>Dữ liệu được xử lý</h2><ul><li>Nội dung thông báo Zalo mà Android cung cấp sau khi người dùng tự bật quyền truy cập thông báo, gồm tên nguồn, tiêu đề, nội dung và thời điểm.</li><li>Câu hỏi giọng nói sau khi dịch vụ nhận dạng giọng nói trên thiết bị chuyển thành văn bản.</li><li>Nhiệm vụ, thời hạn, sự kiện và thông tin lịch do người dùng tạo hoặc ứng dụng trích xuất.</li><li>Mã cài đặt ngẫu nhiên và mã xác thực thiết bị để bảo vệ kết nối backend.</li></ul><h2>Mục đích sử dụng</h2><p>Dữ liệu chỉ được dùng để phân tích và tóm tắt thông báo, tạo nhiệm vụ/sự kiện, trả lời câu hỏi về công việc, gửi lời nhắc và đồng bộ lịch theo lựa chọn của người dùng. Ứng dụng không bán dữ liệu và không dùng dữ liệu cho quảng cáo.</p><h2>Chia sẻ và truyền dữ liệu</h2><p>Khi cần phân tích AI, nội dung liên quan được truyền qua HTTPS đến backend của ứng dụng và nhà cung cấp dịch vụ AI OpenAI để xử lý. Dữ liệu lịch chỉ được ghi vào nhà cung cấp lịch trên thiết bị khi người dùng cấp quyền hoặc bật tự đồng bộ. Dữ liệu có thể được xử lý bởi nhà cung cấp hạ tầng cần thiết để vận hành backend.</p><h2>Lưu trữ và bảo mật</h2><p>Nhiệm vụ, sự kiện và hộp thư AI được lưu cục bộ trên thiết bị. Backend không chủ ý lưu nội dung thông báo sau khi hoàn tất yêu cầu và không ghi nội dung thông báo vào nhật ký. Token được bảo vệ bằng Android Keystore; dữ liệu được truyền bằng HTTPS; sao lưu đám mây mặc định của ứng dụng bị tắt.</p><h2>Quyền lựa chọn và xóa dữ liệu</h2><p>Người dùng có thể tắt quyền đọc thông báo, quyền thông báo hoặc quyền Lịch trong Cài đặt Android; tắt tự đồng bộ lịch trong ứng dụng; xóa từng mục; hoặc gỡ cài đặt để xóa dữ liệu cục bộ. Các sự kiện đã ghi vào Lịch cần được xóa trong ứng dụng Lịch tương ứng.</p><h2>Trẻ em</h2><p>Ứng dụng không hướng đến trẻ em dưới 13 tuổi.</p><h2>Liên hệ</h2><p>Email: <a href="mailto:banhat.co@gmail.com">banhat.co@gmail.com</a></p></body></html>`;
  res.writeHead(200, {"content-type":"text/html; charset=utf-8", "cache-control":"public, max-age=3600"});
  res.end(html);
}

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/privacy") return privacyPolicy(res);
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