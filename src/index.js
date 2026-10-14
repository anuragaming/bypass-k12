export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Trả về 204 ngay lập tức cho /favicon.ico để tránh kích hoạt WAF
    if (url.pathname === "/favicon.ico") {
      return new Response(null, { status: 204 });
    }

    // 2. Đảm bảo đổi đúng sang hostname của máy chủ đích
    const TARGET_HOST = "k12online.vn"; // Thay bằng domain thật
    const targetUrl = `https://${TARGET_HOST}${url.pathname}${url.search}`;

    // 3. Lọc bỏ các Cookie TS* của tường lửa F5 BIG-IP
    const rawCookie = request.headers.get("cookie") || "";
    const cleanCookie = rawCookie
      .split(";")
      .map((c) => c.trim())
      .filter((c) => c && !c.startsWith("TS"))
      .join("; ");

    // 4. Chỉ tạo bộ Header tối giản, bỏ toàn bộ sec-fetch-* và sec-ch-ua*
    const cleanHeaders = new Headers({
      "Host": TARGET_HOST,
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
      "Accept": request.headers.get("accept") || "*/*",
      "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7"
    });

    if (cleanCookie) {
      cleanHeaders.set("Cookie", cleanCookie);
    }
    if (request.headers.has("content-type")) {
      cleanHeaders.set("Content-Type", request.headers.get("content-type"));
    }
    if (request.headers.has("authorization")) {
      cleanHeaders.set("Authorization", request.headers.get("authorization"));
    }

    const response = await fetch(targetUrl, {
      method: request.method,
      headers: cleanHeaders,
      body: ["GET", "HEAD"].includes(request.method) ? null : request.body,
      redirect: "manual"
    });

    // 5. Xóa set-cookie TS* ở chiều trả về để trình duyệt không lưu lại phiên lỗi
    const responseHeaders = new Headers(response.headers);
    const setCookie = responseHeaders.get("set-cookie");
    if (setCookie && setCookie.startsWith("TS")) {
      responseHeaders.delete("set-cookie");
    }

    return new Response(response.body, {
      status: response.status,
      headers: responseHeaders
    });
  }
};
