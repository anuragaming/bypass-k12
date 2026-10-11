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

    let targetHost = baseDomain;
    const cookieHeader = request.headers.get('Cookie') || '';
    const match = cookieHeader.match(/tenant_host=([^;]+)/);
    if (match) targetHost = match[1];

    const targetDomain = 'https://' + targetHost;
    const targetUrl = targetDomain + url.pathname + url.search;
    const prefixMatch = url.pathname.match(/^\/([a-zA-Z0-9-]+)(?=\/)/);
    const tenantPrefix = prefixMatch ? prefixMatch[0] : '';

    try {
      // --- CHIẾN THUẬT MỚI: DANH SÁCH TRẮNG (WHITELIST HEADERS) ---
      const modifiedHeaders = new Headers();
      
      // Chỉ cho phép các Header tiêu chuẩn của trình duyệt đi qua
      const allowedKeys = [
        'accept', 'accept-language', 'user-agent', 'sec-ch-ua',
        'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'sec-fetch-dest',
        'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user', 'cookie',
        'upgrade-insecure-requests', 'cache-control'
      ];

      for (const [key, value] of request.headers.entries()) {
        if (allowedKeys.includes(key.toLowerCase())) {
          modifiedHeaders.set(key, value);
        }
      }

      // Đóng giả Host, Origin, Referer tuyệt đối chuẩn xác
      modifiedHeaders.set('Host', targetHost); 
      
      if (request.headers.has('origin')) {
        modifiedHeaders.set('origin', targetDomain);
      }
      if (request.headers.has('referer')) {
        const ref = request.headers.get('referer');
        // Sửa link referer từ dạng workers.dev thành dạng k12online.vn
        modifiedHeaders.set('referer', ref.replace(proxyDomain, targetDomain));
      } else {
         // Nếu không có referer, tự tạo referer hợp lý để WAF tin tưởng
         modifiedHeaders.set('referer', targetDomain + '/');
      }

      const sentHeadersLog = Object.fromEntries(modifiedHeaders.entries());

      const init = {
        method: request.method,
        headers: modifiedHeaders,
        redirect: 'manual'
      };

      if (!['GET', 'HEAD'].includes(request.method)) {
        init.body = request.body;
      }

      const response = await fetch(targetUrl, init);
      const responseHeaders = new Headers(response.headers);
      
      const headersToDrop = [
        'content-encoding', 'content-length', 'transfer-encoding', 'connection',
        'content-security-policy', 'content-security-policy-report-only', 
        'x-frame-options', 'strict-transport-security'
      ];
      headersToDrop.forEach(h => responseHeaders.delete(h));

      let cookiesToSet = [];
      if (response.headers.has('set-cookie')) {
        const setCookies = response.headers.getSetCookie();
        setCookies.forEach(c => cookiesToSet.push(c.replace(/Domain=[^;]+;?\s*/ig, '')));
        responseHeaders.delete('set-cookie');
      }

      const contentType = responseHeaders.get('content-type') || '';
      const isTextContent = contentType.includes('text/') || 
                            contentType.includes('application/json') || 
                            contentType.includes('javascript');

      if (isTextContent) {
        let text = await response.text();

        // Kiểm tra xem có bị F5 chặn không
        if (text.includes("The requested URL was rejected") || response.status === 403) {
           const receivedHeadersLog = Object.fromEntries(response.headers.entries());
           ctx.waitUntil(sendDiscordLog(sentHeadersLog, response.status, receivedHeadersLog, text));
        }

        let foundTenant = null;
        const regexSub = new RegExp(`https:\\\\?/\\\\?/([a-zA-Z0-9-]+)\\.${baseDomain.replace(/\./g, '\\.')}`, 'g');
        text = text.replace(regexSub, (match, subdomain) => {
          foundTenant = subdomain + '.' + baseDomain;
          return match.includes('\\/') ? proxyDomain.replace(/\//g, '\\/') : proxyDomain;
        });

        const regexRoot = new RegExp(`https:\\\\?/\\\\?/${baseDomain.replace(/\./g, '\\.')}`, 'g');
        text = text.replace(regexRoot, match => {
          return match.includes('\\/') ? proxyDomain.replace(/\//g, '\\/') : proxyDomain;
        });

        if (foundTenant && foundTenant !== targetHost) {
          cookiesToSet.push(`tenant_host=${foundTenant}; Path=/; HttpOnly; Max-Age=86400`);
        }

        cookiesToSet.forEach(c => responseHeaders.append('set-cookie', c));

        if (contentType.includes('text/html')) {
          if (tenantPrefix) {
            const relativePathRegex = /(href|action|src)=(["'])(\/(?:page|LMS|module|api|assets)[^"']*)/gi;
            text = text.replace(relativePathRegex, (match, attr, quote, path) => {
              if (path.startsWith(tenantPrefix)) return match;
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
            </script>
          `;
          text = text.replace(/<head[^>]*>/i, match => match + injectedScript);
        }

        return new Response(text, { status: response.status, headers: responseHeaders });
      } 
      
      if (response.status >= 300 && response.status < 400) {
        const location = responseHeaders.get('location');
        if (location) {
          let locUrl;
          try { locUrl = new URL(location, targetDomain); } catch (e) { locUrl = null; }
          if (locUrl && locUrl.hostname.includes(baseDomain)) {
            let newPath = locUrl.pathname + locUrl.search;
            if (tenantPrefix && !newPath.startsWith(tenantPrefix) && /^\/(page|LMS|module|api|assets)\//i.test(locUrl.pathname)) {
                newPath = tenantPrefix + newPath;
            }
            if (locUrl.hostname === targetHost && url.pathname === new URL(newPath, proxyDomain).pathname) {
              return new Response('Chặn lặp Redirect', { status: 200 });
            }
            cookiesToSet.push(`tenant_host=${locUrl.hostname}; Path=/; HttpOnly; Max-Age=86400`);
            cookiesToSet.forEach(c => responseHeaders.append('set-cookie', c));
            responseHeaders.set('location', proxyDomain + newPath);
            return new Response(null, { status: response.status, headers: responseHeaders });
          }
          responseHeaders.set('location', location);
          return new Response(null, { status: response.status, headers: responseHeaders });
        }
      }

      cookiesToSet.forEach(c => responseHeaders.append('set-cookie', c));
      return new Response(response.body, { status: response.status, headers: responseHeaders });

    } catch (error) {
      return new Response('Lỗi máy chủ Proxy: ' + error.message, { status: 500 });
    }
  }
};
