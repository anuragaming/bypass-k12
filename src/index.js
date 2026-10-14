export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Thay bằng tên miền đích thực tế trong code của bạn
    const TARGET_HOST = "k12online.vn"; 
    const targetUrl = new URL(url.pathname + url.search, `https://${TARGET_HOST}`);

    // 2. Tạo bộ Header sạch (KHÔNG copy nguyên request.headers của Cloudflare)
    const cleanHeaders = new Headers();

    // Chỉ giữ lại các header an toàn cần thiết từ request gốc
    const allowedHeaders = [
      "accept",
      "accept-language",
      "content-type",
      "authorization",
      "cookie"
    ];

    for (const headerName of allowedHeaders) {
      if (request.headers.has(headerName)) {
        cleanHeaders.set(headerName, request.headers.get(headerName));
      }
    }

    // 3. Giả lập Header của trình duyệt hợp lệ và khớp với tên miền đích
    cleanHeaders.set("Host", TARGET_HOST);
    cleanHeaders.set("Origin", `https://${TARGET_HOST}`);
    cleanHeaders.set("Referer", `https://${TARGET_HOST}/`);
    cleanHeaders.set(
      "User-Agent",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    );

    // 4. Gửi request tới máy chủ đích
    const modifiedRequest = new Request(targetUrl.toString(), {
      method: request.method,
      headers: cleanHeaders,
      body: ["GET", "HEAD"].includes(request.method) ? null : request.body,
      redirect: "manual"
    });

    const response = await fetch(modifiedRequest);

    // 5. Trả kết quả về và xử lý CORS nếu cần
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set("Access-Control-Allow-Origin", "*");

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  }
};
