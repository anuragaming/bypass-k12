export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const baseDomain = 'k12online.vn';
    const proxyDomain = url.origin;
    
    // 1. Kiểm tra Cookie
    let targetHost = baseDomain;
    const cookieHeader = request.headers.get('Cookie') || '';
    const match = cookieHeader.match(/tenant_host=([^;]+)/);
    if (match) targetHost = match[1];

    const targetDomain = 'https://' + targetHost;
    const targetUrl = targetDomain + url.pathname + url.search;

    const prefixMatch = url.pathname.match(/^\/([a-zA-Z0-9-]+)(?=\/)/);
    const tenantPrefix = prefixMatch ? prefixMatch[0] : '';

    try {
      // --- BƯỚC VƯỢT TƯỜNG LỬA F5 BIG-IP (WAF BYPASS) ---
      const modifiedHeaders = new Headers(request.headers);
      
      // A. Xóa sạch mọi dấu vết nhận dạng Proxy & Cloudflare
      const headersToRemove = [
        'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor', 'cf-ew-via',
        'x-forwarded-proto', 'x-forwarded-for', 'x-real-ip', 'accept-encoding',
        // Xóa các thông số fetch chéo trang dễ bị WAF bắt lỗi
        'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user'
      ];
      headersToRemove.forEach(h => modifiedHeaders.delete(h));

      // B. Làm giả định danh để lừa Tường lửa
      modifiedHeaders.set('Host', targetHost); 
      
      if (modifiedHeaders.has('origin')) {
        modifiedHeaders.set('origin', targetDomain);
      }
      if (modifiedHeaders.has('referer')) {
        // Biến referer từ link proxy thành link gốc
        const ref = modifiedHeaders.get('referer');
        modifiedHeaders.set('referer', ref.replace(proxyDomain, targetDomain));
      }

      const init = {
        method: request.method,
        headers: modifiedHeaders,
        redirect: 'manual'
      };

      if (!['GET', 'HEAD'].includes(request.method)) {
        init.body = request.body;
      }

      // KẾT NỐI ĐẾN SERVER GỐC
      const response = await fetch(targetUrl, init);

      // 2. Chuyển tiếp Header trả về và tháo rào cản bảo mật
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
        setCookies.forEach(c => {
          cookiesToSet.push(c.replace(/Domain=[^;]+;?\s*/ig, ''));
        });
        responseHeaders.delete('set-cookie');
      }

      // 3. XỬ LÝ CHUYỂN HƯỚNG HTTP (REDIRECT) VÀ CẮT VÒNG LẶP
      if (response.status >= 300 && response.status < 400) {
        const location = responseHeaders.get('location');
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
                headers: { 'Content-Type': 'text/html; charset=UTF-8' }
              });
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

      // 4. XỬ LÝ TEXT (HTML, JSON, JS, CSS)
      const contentType = responseHeaders.get('content-type') || '';
      const isTextContent = contentType.includes('text/') || 
                            contentType.includes('application/json') || 
                            contentType.includes('javascript') ||
                            contentType.includes('application/x-javascript');

      if (isTextContent) {
        let text = await response.text();
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

        // 5. BƠM MÃ BẢO VỆ CHUYỂN TAB VÀ QUẢNG CÁO
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
          text = text.replace(/<head[^>]*>/i, match => match + injectedScript);
        }

        return new Response(text, { status: response.status, headers: responseHeaders });
      } else {
        // 6. TRUYỀN PHÁT (STREAMING) ẢNH, VIDEO SIÊU TỐC NATIVE CỦA CLOUDFLARE
        cookiesToSet.forEach(c => responseHeaders.append('set-cookie', c));
        return new Response(response.body, { status: response.status, headers: responseHeaders });
      }

    } catch (error) {
      console.error("Proxy Error:", error);
      return new Response('Lỗi máy chủ Proxy Cloudflare: ' + error.message, { status: 500 });
    }
  }
};
