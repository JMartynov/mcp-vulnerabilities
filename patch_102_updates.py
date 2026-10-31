import re

with open('docs/updates.js', 'r') as f:
    updates_js = f.read()

# Add detectCollisions function to docs/updates.js
collision_js = """
  window.detectCollisions = function() {
    const banner = document.getElementById("collisionWarning");
    if (!banner) return;
    
    const toolMap = {};
    
    Array.from(selectedServers).forEach(pkgName => {
      let server = null;
      if (window.updatesData && window.updatesData.new_servers) {
        server = window.updatesData.new_servers.find(s => s.package_name === pkgName);
      }
      
      if (server && server.tools_sample) {
        server.tools_sample.forEach(tool => {
          if (!toolMap[tool]) {
            toolMap[tool] = [];
          }
          toolMap[tool].push(pkgName);
        });
      }
    });
    
    const collisions = Object.entries(toolMap).filter(([tool, servers]) => servers.length > 1);
    
    if (collisions.length > 0) {
      let html = `<strong>⚠️ Cross-Server Tool Collision Detected</strong><br>The following tools are exported by multiple selected servers, which may cause runtime conflicts:<ul>`;
      collisions.forEach(([tool, servers]) => {
        html += `<li><code>${escapeHtml(tool)}</code> (in ${servers.map(escapeHtml).join(', ')})</li>`;
      });
      html += `</ul>`;
      
      banner.innerHTML = html;
      banner.style.display = "block";
    } else {
      banner.style.display = "none";
    }
  };
"""

updates_js += collision_js

with open('docs/updates.js', 'w') as f:
    f.write(updates_js)
