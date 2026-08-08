Deno.serve(async (req: Request) => {
  try {
    // Fetch the hosted dashboard HTML
    const resp = await fetch("https://media.base44.com/files/public/6a6cf5052818d1c56512927d/d53971bac_admin_dashboard.html");
    let html = await resp.text();

    // Remove login overlay div and everything inside it
    html = html.replace(/<div class="login-overlay"[^>]*>[\s\S]*?<\/div>\s*<\/div>\s*<\/div>/, '');
    
    // Remove login-related CSS
    html = html.replace(/\.login-overlay[^{]*\{[^}]*\}/g, '');
    html = html.replace(/\.login-box[^{]*\{[^}]*\}/g, '');
    html = html.replace(/\.login-input[^{]*\{[^}]*\}/g, '');
    html = html.replace(/\.login-btn[^{]*\{[^}]*\}/g, '');
    html = html.replace(/\.login-error[^{]*\{[^}]*\}/g, '');
    html = html.replace(/\.login-hint[^{]*\{[^}]*\}/g, '');
    html = html.replace(/\.login-info[^{]*\{[^}]*\}/g, '');
    
    // Remove AUTH/password constants
    html = html.replace(/const\s+AUTH\s*=\s*"[^"]*"\s*;?/g, '');
    html = html.replace(/const\s+ADMIN_KEY\s*=\s*"[^"]*"\s*;?/g, '');
    html = html.replace(/const\s+PW\s*=\s*"[^"]*"\s*;?/g, '');
    
    // Remove login function
    html = html.replace(/function\s+doLogin\s*\(\)\s*\{[\s\S]*?\n\s*\}/g, '');
    html = html.replace(/function\s+login\s*\(\)\s*\{[\s\S]*?\n\s*\}/g, '');
    
    // Remove authKey from fetch calls
    html = html.replace(/,?\s*authKey\s*:\s*AUTH/g, '');
    html = html.replace(/,?\s*authKey\s*:\s*ADMIN_KEY/g, '');
    
    // Remove password change section
    html = html.replace(/<div id="changePasswordSection"[\s\S]*?<\/div>/g, '');
    
    // Make dashboard visible by default - replace any display:none on dashboard container
    html = html.replace(/id="dashboard"\s+style="display:\s*none"/, 'id="dashboard" style="display:block"');
    html = html.replace(/\.dashboard-container\s*\{\s*display:\s*none/, '.dashboard-container{display:block');
    
    // Remove any localStorage/sessionStorage auth checks
    html = html.replace(/if\s*\(\s*!?\s*localStorage[^;]*;\s*\n?/g, '');
    html = html.replace(/if\s*\(\s*!?\s*sessionStorage[^;]*;\s*\n?/g, '');
    
    // Auto-init: add init() call if there's an init function
    if (html.includes('function init') && !html.includes('init();')) {
      html = html.replace('</script>', 'init();\n</script>');
    }
    
    // Remove any remaining password inputs
    html = html.replace(/<input[^>]*type="password"[^>]*>/g, '');
    
    // Remove login buttons
    html = html.replace(/<button[^>]*onclick="doLogin\(\)"[^>]*>[\s\S]*?<\/button>/g, '');
    html = html.replace(/<button[^>]*onclick="login\(\)"[^>]*>[\s\S]*?<\/button>/g, '');

    return new Response(html, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Access-Control-Allow-Origin": "*"
      }
    });
  } catch (e) {
    return new Response(`Error loading dashboard: ${(e as Error).message}`, {
      status: 500,
      headers: { "Content-Type": "text/plain" }
    });
  }
});
