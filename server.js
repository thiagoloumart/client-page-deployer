require("dotenv").config();
const express = require("express");
const session = require("express-session");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const axios = require("axios");
const { Client } = require("ssh2");
const AdmZip = require("adm-zip");
const bcrypt = require("bcrypt");

if (!process.env.SESSION_SECRET || !process.env.ADMIN_PASS) {
  console.error("Defina SESSION_SECRET e ADMIN_PASS no .env antes de iniciar.");
  process.exit(1);
}

// Everything user-typed that ends up in a path or shell command must pass this.
const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
const FILE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const ALLOWED_DOMAINS = (process.env.ALLOWED_DOMAINS || process.env.DEFAULT_DOMAIN || "")
  .split(",").map((d) => d.trim()).filter(Boolean);

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middlewares ───────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 8 * 60 * 60 * 1000 }, // 8h
  })
);

// Upload config
const upload = multer({ dest: "/tmp/uploads/" });

// Serve frontend
app.use(express.static(path.join(__dirname, "frontend/public")));

// ─── Auth middleware ───────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  res.status(401).json({ error: "Não autenticado" });
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.authenticated && req.session.isAdmin) return next();
  res.status(403).json({ error: "Acesso negado. Apenas administradores." });
}

// ─── User Management ───────────────────────────────────────────
function getUsersFile() {
  return path.join(__dirname, "users.json");
}

function loadUsers() {
  const file = getUsersFile();
  if (!fs.existsSync(file)) {
    // Create default admin user from .env
    const defaultUsers = [{
      id: 1,
      username: process.env.ADMIN_USER || "admin",
      passwordHash: bcrypt.hashSync(process.env.ADMIN_PASS, 10),
      isAdmin: true,
      createdAt: new Date().toISOString()
    }];
    fs.writeFileSync(file, JSON.stringify(defaultUsers, null, 2));
    return defaultUsers;
  }
  return JSON.parse(fs.readFileSync(file));
}

function saveUsers(users) {
  fs.writeFileSync(getUsersFile(), JSON.stringify(users, null, 2));
}

// ─── Routes ───────────────────────────────────────────────────

app.get("/api/config", requireAuth, (req, res) => {
  res.json({ domain: process.env.DEFAULT_DOMAIN });
});

// Login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const users = loadUsers();
  const user = users.find(u => u.username === username);

  if (!user) {
    return res.status(401).json({ error: "Credenciais inválidas" });
  }

  const match = await bcrypt.compare(password, user.passwordHash);

  if (match) {
    req.session.authenticated = true;
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.isAdmin = user.isAdmin;
    res.json({ ok: true, isAdmin: user.isAdmin, username: user.username });
  } else {
    res.status(401).json({ error: "Credenciais inválidas" });
  }
});

// Logout
app.post("/api/logout", (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

// Check auth
app.get("/api/me", requireAuth, (req, res) => {
  res.json({
    ok: true,
    username: req.session.username,
    isAdmin: req.session.isAdmin || false
  });
});

// ─── User CRUD endpoints ───────────────────────────────────────

// List all users (admin only)
app.get("/api/users", requireAdmin, (req, res) => {
  const users = loadUsers();
  // Don't send password hashes to frontend
  const safeUsers = users.map(u => ({
    id: u.id,
    username: u.username,
    isAdmin: u.isAdmin,
    createdAt: u.createdAt
  }));
  res.json(safeUsers);
});

// Create new user (admin only)
app.post("/api/users", requireAdmin, async (req, res) => {
  const { username, password, isAdmin } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username e password são obrigatórios" });
  }

  const users = loadUsers();

  // Check if username already exists
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: "Username já existe" });
  }

  const newUser = {
    id: users.length > 0 ? Math.max(...users.map(u => u.id)) + 1 : 1,
    username,
    passwordHash: await bcrypt.hash(password, 10),
    isAdmin: isAdmin || false,
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  saveUsers(users);

  res.json({
    ok: true,
    user: {
      id: newUser.id,
      username: newUser.username,
      isAdmin: newUser.isAdmin,
      createdAt: newUser.createdAt
    }
  });
});

// Update user (admin only)
app.put("/api/users/:id", requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  const { username, password, isAdmin } = req.body;

  const users = loadUsers();
  const userIndex = users.findIndex(u => u.id === id);

  if (userIndex === -1) {
    return res.status(404).json({ error: "Usuário não encontrado" });
  }

  // Update fields
  if (username) {
    // Check if new username already exists (on another user)
    const existingUser = users.find(u => u.username === username && u.id !== id);
    if (existingUser) {
      return res.status(400).json({ error: "Username já existe" });
    }
    users[userIndex].username = username;
  }

  if (password) {
    users[userIndex].passwordHash = await bcrypt.hash(password, 10);
  }

  if (typeof isAdmin === 'boolean') {
    users[userIndex].isAdmin = isAdmin;
  }

  users[userIndex].updatedAt = new Date().toISOString();

  saveUsers(users);

  res.json({
    ok: true,
    user: {
      id: users[userIndex].id,
      username: users[userIndex].username,
      isAdmin: users[userIndex].isAdmin
    }
  });
});

// Delete user (admin only)
app.delete("/api/users/:id", requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);

  const users = loadUsers();

  // Prevent deleting the last admin
  const admins = users.filter(u => u.isAdmin);
  const userToDelete = users.find(u => u.id === id);

  if (userToDelete && userToDelete.isAdmin && admins.length === 1) {
    return res.status(400).json({ error: "Não é possível deletar o último administrador" });
  }

  const filteredUsers = users.filter(u => u.id !== id);

  if (filteredUsers.length === users.length) {
    return res.status(404).json({ error: "Usuário não encontrado" });
  }

  saveUsers(filteredUsers);

  res.json({ ok: true, message: "Usuário deletado com sucesso" });
});

// List deployments
app.get("/api/deployments", requireAuth, (req, res) => {
  const file = path.join(__dirname, "deployments.json");
  if (!fs.existsSync(file)) return res.json([]);
  res.json(JSON.parse(fs.readFileSync(file)));
});

// Delete deployment from history (local only, does not touch VPS files)
app.delete("/api/deployments/:index", requireAuth, (req, res) => {
  const file = path.join(__dirname, "deployments.json");
  if (!fs.existsSync(file)) return res.json({ ok: true });
  const list = JSON.parse(fs.readFileSync(file));
  const idx = parseInt(req.params.index);
  if (!isNaN(idx) && idx >= 0 && idx < list.length) {
    list.splice(idx, 1);
    fs.writeFileSync(file, JSON.stringify(list, null, 2));
  }
  res.json({ ok: true });
});

// Archive deployment
app.patch("/api/deployments/:index/archive", requireAuth, (req, res) => {
  const file = path.join(__dirname, "deployments.json");
  if (!fs.existsSync(file)) return res.status(404).json({ error: "Deploy não encontrado" });

  const list = JSON.parse(fs.readFileSync(file));
  const idx = parseInt(req.params.index);

  if (isNaN(idx) || idx < 0 || idx >= list.length) {
    return res.status(404).json({ error: "Deploy não encontrado" });
  }

  list[idx].archived = true;
  list[idx].archivedAt = new Date().toISOString();

  fs.writeFileSync(file, JSON.stringify(list, null, 2));
  res.json({ ok: true, message: "Deploy arquivado com sucesso!" });
});

// Unarchive deployment
app.patch("/api/deployments/:index/unarchive", requireAuth, (req, res) => {
  const file = path.join(__dirname, "deployments.json");
  if (!fs.existsSync(file)) return res.status(404).json({ error: "Deploy não encontrado" });

  const list = JSON.parse(fs.readFileSync(file));
  const idx = parseInt(req.params.index);

  if (isNaN(idx) || idx < 0 || idx >= list.length) {
    return res.status(404).json({ error: "Deploy não encontrado" });
  }

  list[idx].archived = false;
  delete list[idx].archivedAt;

  fs.writeFileSync(file, JSON.stringify(list, null, 2));
  res.json({ ok: true, message: "Deploy restaurado com sucesso!" });
});

// Update deployment info (edit)
app.patch("/api/deployments/:index", requireAuth, (req, res) => {
  const file = path.join(__dirname, "deployments.json");
  if (!fs.existsSync(file)) return res.status(404).json({ error: "Deploy não encontrado" });

  const list = JSON.parse(fs.readFileSync(file));
  const idx = parseInt(req.params.index);

  if (isNaN(idx) || idx < 0 || idx >= list.length) {
    return res.status(404).json({ error: "Deploy não encontrado" });
  }

  const { empresa, contexto } = req.body;

  if (empresa) {
    list[idx].empresa = empresa;
  }

  if (contexto) {
    if (!SLUG.test(contexto)) return res.status(400).json({ error: "Contexto inválido (use a-z, 0-9 e hífen)" });
    list[idx].contexto = contexto;
  }

  list[idx].updatedAt = new Date().toISOString();

  fs.writeFileSync(file, JSON.stringify(list, null, 2));
  res.json({ ok: true, message: "Deploy atualizado com sucesso!", deployment: list[idx] });
});

// Delete deployment files from VPS (DESTRUCTIVE!)
app.delete("/api/deployments/:index/files", requireAuth, async (req, res) => {
  const file = path.join(__dirname, "deployments.json");
  if (!fs.existsSync(file)) return res.status(404).json({ error: "Deploy não encontrado" });

  const list = JSON.parse(fs.readFileSync(file));
  const idx = parseInt(req.params.index);

  if (isNaN(idx) || idx < 0 || idx >= list.length) {
    return res.status(404).json({ error: "Deploy não encontrado" });
  }

  const deployment = list[idx];
  const { subdomain, contexto } = deployment;
  if (!SLUG.test(subdomain) || !SLUG.test(contexto)) {
    return res.status(400).json({ error: "Registro com caminho inválido; apague manualmente" });
  }
  const remotePath = `/var/www/${subdomain}/${contexto}`;

  try {
    // Connect via SSH and delete files
    const { Client } = require("ssh2");
    const conn = new Client();

    await new Promise((resolve, reject) => {
      conn.on("ready", () => {
        conn.exec(`rm -rf ${remotePath}`, (err, stream) => {
          if (err) {
            conn.end();
            return reject(err);
          }

          stream.on("close", () => {
            conn.end();
            resolve();
          });
        });
      });

      conn.on("error", reject);

      const connConfig = {
        host: process.env.VPS_HOST,
        port: parseInt(process.env.VPS_PORT || "22"),
        username: process.env.VPS_USER || "root",
      };

      if (process.env.VPS_KEY_PATH && fs.existsSync(process.env.VPS_KEY_PATH)) {
        connConfig.privateKey = fs.readFileSync(process.env.VPS_KEY_PATH);
      } else if (process.env.VPS_PASS) {
        connConfig.password = process.env.VPS_PASS;
      }

      conn.connect(connConfig);
    });

    // Also remove from history
    list.splice(idx, 1);
    fs.writeFileSync(file, JSON.stringify(list, null, 2));

    res.json({ ok: true, message: "Arquivos deletados com sucesso!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ─── Main deploy route ─────────────────────────────────────────
app.post(
  "/api/deploy",
  requireAuth,
  upload.array("files"),
  async (req, res) => {
    const { empresa, contexto, dominio_base, mainHtml } = req.body;
    const files = req.files;

    if (!empresa || !contexto || !files || files.length === 0) {
      return res.status(400).json({ error: "Campos obrigatórios ausentes" });
    }

    const subdomain = empresa.toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/^-+/, "");
    const domBase = dominio_base || process.env.DEFAULT_DOMAIN;
    const badFile = files.find((f) => !FILE_NAME.test(f.originalname));
    if (!SLUG.test(subdomain) || !SLUG.test(contexto) || !ALLOWED_DOMAINS.includes(domBase) || badFile) {
      files.forEach((f) => fs.existsSync(f.path) && fs.unlinkSync(f.path));
      return res.status(400).json({
        error: badFile ? `Nome de arquivo inválido: ${badFile.originalname}` : "Empresa, contexto ou domínio inválido",
      });
    }
    const fullDomain = `${subdomain}.${domBase}`;
    const remotePath = `/var/www/${subdomain}/${contexto}`;
    const nginxConf = `/etc/nginx/sites-available/${subdomain}`;

    // SSE stream for live logs
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();

    const log = (msg, type = "info") => {
      res.write(`data: ${JSON.stringify({ msg, type })}\n\n`);
    };

    const done = (success, msg, url) => {
      res.write(
        `data: ${JSON.stringify({ done: true, success, msg, url })}\n\n`
      );
      res.end();
    };

    try {
      log(`🚀 Iniciando deploy para ${fullDomain}/${contexto}...`);

      // 1. Cloudflare DNS
      log("☁️  Configurando DNS no Cloudflare...");
      const dnsWasCreated = await createCloudflareRecord(subdomain, domBase);
      log("✅ DNS criado com sucesso!", "success");

      // Wait for DNS propagation if it was just created
      if (dnsWasCreated) {
        log("⏳ Aguardando propagação do DNS (60 segundos)...", "info");
        for (let i = 60; i > 0; i -= 5) {
          log(`⏱️  ${i} segundos restantes...`, "info");
          await new Promise(resolve => setTimeout(resolve, 5000));
        }
        log("✅ Propagação concluída!", "success");
      }

      // 2. SSH: criar pasta + enviar arquivos + nginx + certbot
      log("🔌 Conectando à VPS via SSH...");
      await sshDeploy({
        remotePath,
        files,
        subdomain,
        fullDomain,
        contexto,
        nginxConf,
        mainHtml: mainHtml || null,
        log,
      });

      // 3. Save deployment record
      saveDeployment({ empresa, subdomain, contexto, fullDomain, domBase });

      log(`🎉 Deploy concluído!`, "success");

      // Wait longer to ensure all SSE messages are flushed before closing
      await new Promise(resolve => setTimeout(resolve, 500));

      done(true, "Deploy realizado com sucesso!", `https://${fullDomain}/${contexto}`);
    } catch (err) {
      console.error(err);
      log(`❌ Erro: ${err.message}`, "error");

      // Wait before closing on error too
      await new Promise(resolve => setTimeout(resolve, 300));

      done(false, err.message);
    } finally {
      // Cleanup temp files
      files.forEach((f) => fs.existsSync(f.path) && fs.unlinkSync(f.path));
    }
  }
);

// ─── Cloudflare ────────────────────────────────────────────────
async function createCloudflareRecord(subdomain, domBase) {
  const token = process.env.CF_API_TOKEN;
  const zoneId = process.env.CF_ZONE_ID;
  const vpsIp = process.env.VPS_IP;

  try {
    // Check if record exists
    const listRes = await axios.get(
      `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?type=A&name=${subdomain}.${domBase}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    const existing = listRes.data.result;

    if (existing.length > 0) {
      // Update existing
      await axios.put(
        `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${existing[0].id}`,
        { type: "A", name: subdomain, content: vpsIp, proxied: true, ttl: 1 },
        { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } }
      );
      return false; // DNS already existed, no need to wait
    } else {
      // Create new
      await axios.post(
        `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`,
        { type: "A", name: subdomain, content: vpsIp, proxied: true, ttl: 1 },
        { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } }
      );
      return true; // DNS was just created, need to wait for propagation
    }
  } catch (error) {
    // Check for CNAME conflict error (code 81054)
    if (error.response?.data?.errors) {
      const cnameError = error.response.data.errors.find(e => e.code === 81054);
      if (cnameError) {
        throw new Error(`Nome de cliente "${subdomain}" já existe no DNS (conflito CNAME). Por favor, escolha outro nome. Sugestões: ${subdomain}2, ${subdomain}-site, ${subdomain}-new`);
      }
    }
    // Re-throw other errors
    throw error;
  }
}

// ─── SSH Deploy ────────────────────────────────────────────────
function sshDeploy({ remotePath, files, subdomain, fullDomain, contexto, nginxConf, mainHtml, log }) {
  return new Promise((resolve, reject) => {
    const conn = new Client();

    // Helper to close connection and resolve/reject
    const closeAndResolve = () => {
      conn.end();
      // Give the connection time to close properly before resolving
      setTimeout(() => resolve(), 100);
    };

    const closeAndReject = (err) => {
      conn.end();
      // Give the connection time to close properly before rejecting
      setTimeout(() => reject(err), 100);
    };


    // Helper to execute SSH command with timeout
    const execWithTimeout = (cmd, timeout = 30000) => {
      return new Promise((res, rej) => {
        const timer = setTimeout(() => {
          rej(new Error(`Timeout executando: ${cmd.substring(0, 50)}...`));
        }, timeout);
        
        conn.exec(cmd, (err, stream) => {
          if (err) {
            clearTimeout(timer);
            return rej(err);
          }
          
          let output = "";
          stream.on("data", d => output += d);
          stream.stderr.on("data", d => output += d);
          
          stream.on("close", code => {
            clearTimeout(timer);
            res(output);
          });
        });
      });
    };

    conn.on("ready", () => {
      log("✅ SSH conectado!");

      const nginxConfig = `server {
    listen 80;
    server_name ${fullDomain};
    root /var/www/${subdomain};
    index index.html;
    location /${contexto} {
        try_files $uri $uri/ /${contexto}/index.html;
    }
}`;

      const steps = [
        `mkdir -p ${remotePath}`,
        `chown -R www-data:www-data /var/www/${subdomain}`,
        `chmod -R 755 /var/www/${subdomain}`,
      ];

      // Check if nginx conf already exists
      const nginxStep = `[ -f ${nginxConf} ] && echo "nginx_exists" || (echo '${nginxConfig.replace(/'/g, "'\\''")}' > ${nginxConf} && ln -sf ${nginxConf} /etc/nginx/sites-enabled/${subdomain} && nginx -t && systemctl reload nginx && echo "nginx_created")`;
      steps.push(nginxStep);

      let stepIndex = 0;

      const runNext = () => {
        if (stepIndex >= steps.length) {
          // Upload files
          uploadFiles(conn, files, remotePath, mainHtml, log)
            .then(() => {
              // Fix permissions after upload
              return execWithTimeout(
                `chown -R www-data:www-data /var/www/${subdomain} && chmod -R 755 /var/www/${subdomain}`,
                5000
              );
            })
            .then(() => {
              // Certbot + final reload
              log("🔒 Configurando certificado SSL...");
              const certCmd = `certbot --nginx -d ${fullDomain} --non-interactive --agree-tos --email ${process.env.CERTBOT_EMAIL} 2>&1 | tail -10`;
              return execWithTimeout(certCmd, 45000).then(out => {
                if (out.includes("Congratulations") || out.includes("Certificate not yet due") || out.includes("valid")) {
                  log("✅ SSL configurado!", "success");
                } else {
                  log("⚠️  SSL: " + out.trim(), "warn");
                }
              });
            })
            .then(() => {
              // Final nginx reload
              return execWithTimeout("systemctl reload nginx", 10000).then(() => {
                log("✅ Nginx recarregado!", "success");
              });
            })
            .then(() => {
              // All done, close connection and resolve
              closeAndResolve();
            })
            .catch((e) => {
              closeAndReject(e);
            });
          return;
        }

        const cmd = steps[stepIndex++];
        conn.exec(cmd, (err, stream) => {
          if (err) return closeAndReject(err);
          let out = "";
          stream.on("data", (d) => (out += d));
          stream.stderr.on("data", (d) => (out += d));
          stream.on("close", (code) => {
            if (out.includes("nginx_created")) log("✅ Nginx configurado!", "success");
            if (out.includes("nginx_exists")) log("ℹ️  Nginx já configurado, mantendo.", "info");
            runNext();
          });
        });
      };

      runNext();
    });

    conn.on("error", (err) => {
      closeAndReject(err);
    });

    const connConfig = {
      host: process.env.VPS_HOST,
      port: parseInt(process.env.VPS_PORT || "22"),
      username: process.env.VPS_USER || "root",
    };

    if (process.env.VPS_KEY_PATH && fs.existsSync(process.env.VPS_KEY_PATH)) {
      connConfig.privateKey = fs.readFileSync(process.env.VPS_KEY_PATH);
    } else if (process.env.VPS_PASS) {
      connConfig.password = process.env.VPS_PASS;
    } else {
      return reject(new Error("Nem VPS_PASS nem VPS_KEY_PATH válido configurados"));
    }

    conn.connect(connConfig);
  });
}

// ─── Upload files via SFTP ─────────────────────────────────────
function uploadFiles(conn, files, remotePath, mainHtml, log) {
  return new Promise((resolve, reject) => {
    conn.sftp((err, sftp) => {
      if (err) return reject(err);

      // Determine which file becomes index.html:
      // Use mainHtml if provided, otherwise fall back to first .html/.htm file
      const htmlFiles = files.filter((f) => {
        const ext = f.originalname.split(".").pop().toLowerCase();
        return ["html", "htm"].includes(ext);
      });
      const mainFile = mainHtml
        ? files.find((f) => f.originalname === mainHtml)
        : htmlFiles[0];

      const queue = [...files];
      let uploaded = 0;

      const next = () => {
        if (queue.length === 0) {
          log(`✅ ${uploaded} arquivo(s) enviado(s) com sucesso!`, "success");
          return resolve();
        }

        const file = queue.shift();
        const originalName = file.originalname;
        const isMain = mainFile && file.fieldname === mainFile.fieldname && file.originalname === mainFile.originalname && file.path === mainFile.path;
        const destName = isMain ? "index.html" : originalName;
        const dest = `${remotePath}/${destName}`;

        sftp.fastPut(file.path, dest, (e) => {
          if (e) return reject(new Error(`Erro ao enviar ${originalName}: ${e.message}`));
          uploaded++;
          log(`📤 Enviado: ${originalName}${isMain ? " → index.html" : ""}`);
          next();
        });
      };

      next();
    });
  });
}

// ─── Save deployment ───────────────────────────────────────────
function saveDeployment(data) {
  const file = path.join(__dirname, "deployments.json");
  const list = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file)) : [];
  list.unshift({ ...data, deployedAt: new Date().toISOString() });
  fs.writeFileSync(file, JSON.stringify(list.slice(0, 100), null, 2));
}

// ─── Start ─────────────────────────────────────────────────────
app.listen(PORT, '127.0.0.1', () => {
  console.log(`✅ Client Page Deployer rodando em 127.0.0.1:${PORT}`);
});
