export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const baseDomain = 'k12online.vn';
    const proxyDomain = url.origin;

    const WEBHOOK_URL = "https://discord.com/api/webhooks/1529847938031947806/rFcwxaFESQrhrtYbarMj0m3IlBhAhwmXQtHMYFHNa9I0lyFh6irDqDXmwqCe_XYYotCA";

    async function sendDiscordLog(sentHeaders, responseStatus, responseHeaders, responseBody) {
      try {
        const logData = {
          time: new Date().toISOString(),
          targetUrl: request.url,
          requestHeadersSent: sentHeaders,
          responseStatus: responseStatus,
          responseHeadersReceived: responseHeaders,
          responseBody: responseBody
        };
        const formData = new FormData();
        formData.append('file', new File([JSON.stringify(logData, null, 2)], `waf_block_log.json`, { type: 'application/json' }));
        formData.append('content', '🚨 **WAF Tường Lửa đã chặn Request!**');
        await fetch(WEBHOOK_URL, { method: 'POST', body: formData });
      } catch (err) {}
    }

    // 1. Kiểm tra Cookie tenant
    let targetHost = baseDomain;
    const cookieHeader = request.headers.get('Cookie') || '';
    const match = cookieHeader.match(/tenant_host=([^;]+)/);
    if (match) targetHost = match[1];

    const targetDomain = 'https://' + targetHost;
    const targetUrl = targetDomain + url.pathname + url.search;

    const prefixMatch = url.pathname.match(/^\/([a-zA-Z0-9-]+)(?=\/)/);
    const tenantPrefix = prefixMatch ? prefixMatch[0] : '';

    try {
      // --- Giống bản Vercel: forward TOÀN BỘ header, chỉ xóa mấy cái lộ proxy ---
      const headers = new Headers(request.headers);

      [
        'host', 'referer', 'accept-encoding',
        'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-for', 'x-real-ip',
        // header do Cloudflare thêm vào request đến Worker
        'cf-connecting-ip', 'cf-connecting-ipv6', 'cf-ipcountry', 'cf-ray',
        'cf-visitor', 'cf-worker', 'cf-ew-via', 'cf-pseudo-ipv4', 'cdn-loop',
        'true-client-ip', 'x-forwarded-port'
      ].forEach(h => headers.delete(h));

      if (headers.has('origin')) headers.set('origin', targetDomain);

      const sentHeadersLog = Object.fromEntries(headers.entries());

      const init = {
        method: request.method,
        headers: headers,
        redirect: 'manual'
      };
      if (!['GET', 'HEAD'].includes(request.method)) {
        init.body = request.body;
      }

      const response = await fetch(targetUrl, init);

      const headersToDrop = [
        'content-encoding', 'content-length', 'transfer-encoding', 'connection',
        'content-security-policy', 'content-security-policy-report-only',
        'x-frame-options', 'strict-transport-security'
      ];

      const responseHeaders = new Headers();
      response.headers.forEach((value, key) => {
        const k = key.toLowerCase();
        if (!headersToDrop.includes(k) && k !== 'set-cookie') {
          responseHeaders.set(key, value);
        }
      });

      let cookiesToSet = [];
      if (typeof response.headers.getSetCookie === 'function') {
        cookiesToSet = response.headers.getSetCookie().map(c => c.replace(/Domain=[^;]+;?\s*/ig, ''));
      }
      const applyCookies = () => cookiesToSet.forEach(c => responseHeaders.append('set-cookie', c));

      // Status không được phép có body
      if ([101, 204, 205, 304].includes(response.status)) {
        applyCookies();
        return new Response(null, { status: response.status, headers: responseHeaders });
      }

      // 2. XỬ LÝ CHUYỂN HƯỚNG
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (location) {
          let locUrl;
          try { locUrl = new URL(location, targetDomain); } catch (e) { locUrl = null; }

          if (locUrl && locUrl.hostname.includes(baseDomain)) {
            let newPath = locUrl.pathname + locUrl.search;

            if (tenantPrefix && !newPath.startsWith(tenantPrefix)) {
              if (/^\/(page|LMS|module|api|assets)\//i.test(locUrl.pathname)) {
                newPath = tenantPrefix + newPath;
              }
            }

            const reqPathname = url.pathname;
            const locPathname = new URL(newPath, proxyDomain).pathname;

            if (locUrl.hostname === targetHost && reqPathname === locPathname) {
              return new Response('<html><body><h1>Đã chặn vòng lặp Redirect. Vui lòng tải lại trang (F5).</h1></body></html>', {
                status: 200,
                headers: { 'content-type': 'text/html; charset=utf-8' }
              });
            }

            cookiesToSet.push(`tenant_host=${locUrl.hostname}; Path=/; HttpOnly; Max-Age=86400`);
            applyCookies();
            responseHeaders.set('location', proxyDomain + newPath);
            return new Response(null, { status: response.status, headers: responseHeaders });
          }

          applyCookies();
          responseHeaders.set('location', location);
          return new Response(null, { status: response.status, headers: responseHeaders });
        }
      }

      // 3. XỬ LÝ TEXT (HTML, JSON, JS, CSS)
      const contentType = response.headers.get('content-type') || '';
      const isTextContent = contentType.includes('text/') ||
                            contentType.includes('application/json') ||
                            contentType.includes('javascript') ||
                            contentType.includes('application/x-javascript');

      if (isTextContent) {
        let text = await response.text();

        // Bị F5 chặn thì gửi log về Discord
        if (text.includes("The requested URL was rejected") || response.status === 403) {
          const receivedHeadersLog = Object.fromEntries(response.headers.entries());
          ctx.waitUntil(sendDiscordLog(sentHeadersLog, response.status, receivedHeadersLog, text));
        }

        let foundTenant = null;

        const regexSub = new RegExp(`https:\\\\?/\\\\?/([a-zA-Z0-9-]+)\\.${baseDomain.replace(/\./g, '\\.')}`, 'g');
        text = text.replace(regexSub, (m, subdomain) => {
          foundTenant = subdomain + '.' + baseDomain;
          return m.includes('\\/') ? proxyDomain.replace(/\//g, '\\/') : proxyDomain;
        });

        const regexRoot = new RegExp(`https:\\\\?/\\\\?/${baseDomain.replace(/\./g, '\\.')}`, 'g');
        text = text.replace(regexRoot, m => {
          return m.includes('\\/') ? proxyDomain.replace(/\//g, '\\/') : proxyDomain;
        });

        if (foundTenant && foundTenant !== targetHost) {
          cookiesToSet.push(`tenant_host=${foundTenant}; Path=/; HttpOnly; Max-Age=86400`);
        }
        applyCookies();

        if (contentType.includes('text/html')) {
          if (tenantPrefix) {
            const relativePathRegex = /(href|action|src)=(["'])(\/(?:page|LMS|module|api|assets)[^"']*)/gi;
            text = text.replace(relativePathRegex, (m, attr, quote, path) => {
              if (path.startsWith(tenantPrefix)) return m;
              return `${attr}=${quote}${tenantPrefix}${path}`;
            });
          }

          text = text.replace(/<script[^>]*src=["'][^"']*(adsbygoogle|popunder|adzone|doubleclick|adsystem)[^"']*["'][^>]*>[\s\S]*?<\/script>/gi, '');

          const injectedScript = `
          <script>
            Object.defineProperty(document, 'visibilityState', { get: () => 'visible', configurable: true });
            Object.defineProperty(document, 'hidden', { get: () => false, configurable: true });
            const blockVisibility = (e) => { e.stopImmediatePropagation(); e.stopPropagation(); };
            window.addEventListener('visibilitychange', blockVisibility, true);
            document.addEventListener('visibilitychange', blockVisibility, true);

            const originalWindowOpen = window.open;
            window.open = function(url, name, specs) {
                if (typeof url === 'string' && /(ads|popunder|adsystem|track|doubleclick)/i.test(url)) return null;
                return originalWindowOpen.apply(this, arguments);
            };

            const observer = new MutationObserver(mutations => {
              mutations.forEach(mutation => {
                mutation.addedNodes.forEach(node => {
                  if (node.tagName === 'SCRIPT' && node.src && /(adsbygoogle|popunder|adzone|adsystem)/i.test(node.src)) {
                      node.type = 'javascript/blocked'; node.remove();
                  }
                });
              });
            });
            observer.observe(document.documentElement, { childList: true, subtree: true });
          </script>
        `;
          text = text.replace(/<head[^>]*>/i, m => m + injectedScript);
        }

        return new Response(text, { status: response.status, headers: responseHeaders });
      }

      // 4. FILE NHỊ PHÂN (ẢNH, VIDEO, TÀI LIỆU...) - STREAM THẲNG
      applyCookies();
      return new Response(response.body, { status: response.status, headers: responseHeaders });

    } catch (error) {
      return new Response('Lỗi máy chủ Proxy: ' + error.message, { status: 500 });
    }
  }
};
