// ==========================================
// KUI 多用户聚合版 - Serverless 后端 API
// ==========================================

async function sha256(text) {
    const buffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// 自动检测并热更新数据库结构
async function ensureDbSchema(db) {
    try { await db.prepare("SELECT username FROM nodes LIMIT 1").first(); } 
    catch (e) { try { await db.prepare("ALTER TABLE nodes ADD COLUMN username TEXT DEFAULT 'admin'").run(); } catch(e){} }
    
    try { await db.prepare("SELECT username FROM users LIMIT 1").first(); } 
    catch (e) {
        try {
            await db.prepare(`CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY, password TEXT NOT NULL, 
                traffic_limit INTEGER DEFAULT 0, traffic_used INTEGER DEFAULT 0, 
                expire_time INTEGER DEFAULT 0, enable INTEGER DEFAULT 1
            )`).run();
        } catch(e){}
    }
}

// 多角色动态签名验证
async function verifyAuth(authHeader, db, env) {
    if (!authHeader) return null;
    const adminUser = env.ADMIN_USERNAME || "admin";
    const adminPass = env.ADMIN_PASSWORD || "admin";

    // 静态 Token 兼容 (Agent/Sub)
    if (authHeader === adminPass || authHeader === await sha256(adminPass)) return adminUser;

    const parts = authHeader.split('.');
    if (parts.length !== 3) return null;
    const [b64User, timestamp, clientSig] = parts;

    if (Math.abs(Date.now() - parseInt(timestamp)) > 300000) return null;

    const username = atob(b64User);
    let baseKeyHex;
    if (username === adminUser) {
        baseKeyHex = await sha256(adminPass);
    } else {
        const u = await db.prepare("SELECT password FROM users WHERE username = ?").bind(username).first();
        if (!u) return null;
        baseKeyHex = u.password;
    }

    const keyBytes = new Uint8Array(baseKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(username + timestamp));
    const expectedSig = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');

    return clientSig === expectedSig ? username : null;
}

export async function onRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const method = request.method;
    const action = params.path ? params.path[0] : ''; 
    const db = env.DB; 

    // 1. Agent 上报接口 (同步累加用户总流量)
    if (action === "report" && method === "POST") {
        if (!(await verifyAuth(request.headers.get("Authorization"), db, env))) return new Response("Unauthorized", { status: 401 });
        const data = await request.json(); 
        const nowMs = Date.now();
        await db.prepare("UPDATE servers SET cpu = ?, mem = ?, last_report = ?, alert_sent = 0 WHERE ip = ?").bind(data.cpu, data.mem, nowMs, data.ip).run();
        
        const stmts = [];
        let totalDelta = 0;
        if (data.node_traffic && data.node_traffic.length > 0) {
            for (let nt of data.node_traffic) {
                stmts.push(db.prepare("UPDATE nodes SET traffic_used = traffic_used + ? WHERE id = ?").bind(nt.delta_bytes, nt.id));
                stmts.push(db.prepare(`UPDATE users SET traffic_used = traffic_used + ? WHERE username = (SELECT username FROM nodes WHERE id = ?)`).bind(nt.delta_bytes, nt.id));
                totalDelta += nt.delta_bytes;
            }
        }
        if (totalDelta > 0) stmts.push(db.prepare("INSERT INTO traffic_stats (ip, delta_bytes, timestamp) VALUES (?, ?, ?)").bind(data.ip, totalDelta, nowMs));
        if (stmts.length > 0) await db.batch(stmts);
        return Response.json({ success: true });
    }

    // 2. 聚合订阅接口 (核心：支持用户维度全量聚合)
    if (action === "sub" && method === "GET") {
        const ip = url.searchParams.get("ip");
        const reqUser = url.searchParams.get("user");
        const token = url.searchParams.get("token");
        const adminUser = env.ADMIN_USERNAME || "admin";

        let isValid = false;
        if (reqUser === adminUser) {
            isValid = (token === await sha256(env.ADMIN_PASSWORD));
        } else {
            const u = await db.prepare("SELECT password FROM users WHERE username = ?").bind(reqUser).first();
            if (u && token === u.password) isValid = true;
        }
        if (!isValid) return new Response("Forbidden", { status: 403 });

        const now = Date.now();
        // 过滤：节点未超限、用户未到期、用户未超限、用户未封禁
        let query = `
            SELECT n.* FROM nodes n
            LEFT JOIN users u ON n.username = u.username
            WHERE n.enable = 1 AND (n.traffic_limit = 0 OR n.traffic_used < n.traffic_limit)
            AND (n.expire_time = 0 OR n.expire_time > ?)
            AND (n.username = ? OR (
                u.enable = 1 AND (u.traffic_limit = 0 OR u.traffic_used < u.traffic_limit)
                AND (u.expire_time = 0 OR u.expire_time > ?)
            ))
        `;
        let sqlParams = [now, adminUser, now];
        if (reqUser !== adminUser) { query = query.replace("n.username = ?", "n.username = ?"); sqlParams[1] = reqUser; }
        if (ip) { query += " AND n.vps_ip = ?"; sqlParams.push(ip); }

        const { results } = await db.prepare(query).bind(...sqlParams).all();
        let subLinks = results.map(node => {
            const remark = encodeURIComponent(`${node.protocol}_${node.port}`);
            if (node.protocol === "VLESS") return `vless://${node.uuid}@${node.vps_ip}:${node.port}?encryption=none&security=none&type=tcp#${remark}`;
            if (node.protocol === "Reality") return `vless://${node.uuid}@${node.vps_ip}:${node.port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${node.sni}&fp=chrome&pbk=${node.public_key}&sid=${node.short_id}&type=tcp&headerType=none#${remark}-Reality`;
            if (node.protocol === "Hysteria2") return `hysteria2://${node.uuid}@${node.vps_ip}:${node.port}/?insecure=1&sni=${node.sni}#${remark}-Hy2`;
            return null;
        }).filter(l => l);

        return new Response(btoa(unescape(encodeURIComponent(subLinks.join('\n')))), { headers: { "Content-Type": "text/plain" }});
    }

    // 3. 登录接口
    if (action === "login" && method === "POST") {
        const username = await verifyAuth(request.headers.get("Authorization"), db, env);
        if (username) {
            if (username === (env.ADMIN_USERNAME || "admin")) await ensureDbSchema(db);
            return Response.json({ success: true, role: username === (env.ADMIN_USERNAME || "admin") ? 'admin' : 'user' });
        }
        return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    // 鉴权屏障
    const currentUser = await verifyAuth(request.headers.get("Authorization"), db, env);
    const isAdmin = currentUser === (env.ADMIN_USERNAME || "admin");
    if (!currentUser) return Response.json({ error: "Unauthorized" }, { status: 401 });

    try {
        if (action === "data") {
            const servers = (await db.prepare("SELECT * FROM servers").all()).results;
            const nodes = isAdmin ? (await db.prepare("SELECT * FROM nodes").all()).results : (await db.prepare("SELECT * FROM nodes WHERE username = ?").bind(currentUser).all()).results;
            const users = isAdmin ? (await db.prepare("SELECT * FROM users").all()).results : (await db.prepare("SELECT * FROM users WHERE username = ?").bind(currentUser).all()).results;
            return Response.json({ servers, nodes, users });
        }
        
        // 管理员专用：用户增删改查
        if (action === "users" && isAdmin) {
            if (method === "POST") {
                const { username, password, traffic_limit, expire_time } = await request.json();
                const hash = await sha256(password);
                await db.prepare("INSERT INTO users (username, password, traffic_limit, expire_time) VALUES (?, ?, ?, ?)").bind(username, hash, traffic_limit, expire_time).run();
                return Response.json({ success: true });
            }
            if (method === "PUT") {
                const { username, enable, reset_traffic } = await request.json();
                if (reset_traffic) await db.prepare("UPDATE users SET traffic_used = 0 WHERE username = ?").bind(username).run();
                else if (enable !== undefined) await db.prepare("UPDATE users SET enable = ? WHERE username = ?").bind(enable, username).run();
                return Response.json({ success: true });
            }
            if (method === "DELETE") {
                const target = url.searchParams.get("username");
                await db.prepare("DELETE FROM users WHERE username = ?").bind(target).run();
                await db.prepare("UPDATE nodes SET username = ? WHERE username = ?").bind(currentUser, target).run();
                return Response.json({ success: true });
            }
        }
        
        // 兼容原有的节点/服务器操作 (管理员)
        if (action === "vps" && isAdmin && method === "POST") {
            const { ip, name } = await request.json();
            await db.prepare("INSERT OR IGNORE INTO servers (ip, name, alert_sent) VALUES (?, ?, 0)").bind(ip, name).run();
            return Response.json({ success: true });
        }
        if (action === "nodes" && isAdmin && method === "POST") {
            const n = await request.json();
            await db.prepare(`INSERT INTO nodes (id, uuid, vps_ip, protocol, port, sni, private_key, public_key, short_id, relay_type, target_ip, target_port, target_id, enable, traffic_used, traffic_limit, expire_time, username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(n.id, n.uuid, n.vps_ip, n.protocol, n.port, n.sni||null, n.private_key||null, n.public_key||null, n.short_id||null, n.relay_type||null, n.target_ip||null, n.target_port||null, n.target_id||null, 1, 0, n.traffic_limit||0, n.expire_time||0, n.username||currentUser).run();
            return Response.json({ success: true });
        }

        return new Response("Not Found", { status: 404 });
    } catch (err) { return Response.json({ error: err.message }, { status: 500 }); }
}
