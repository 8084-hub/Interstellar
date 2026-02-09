import http from "node:http";
import path from "node:path";
import dns from "node:dns/promises";
import net from "node:net";
import { createBareServer } from "@nebula-services/bare-server-node";
import chalk from "chalk";
import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import basicAuth from "express-basic-auth";
import mime from "mime";
import fetch from "node-fetch";
// import { setupMasqr } from "./Masqr.js";
import config from "./config.js";

console.log(chalk.yellow("🚀 Starting server..."));

const __dirname = process.cwd();
const server = http.createServer();
const app = express();
const bareServer = createBareServer("/ca/");
const PORT = process.env.PORT || 8080;
const cache = new Map();
const CACHE_TTL = 30 * 24 * 60 * 60 * 1000; // Cache for 30 Days

if (config.challenge !== false) {
  console.log(chalk.green("🔒 Password protection is enabled! Listing logins below"));
  // biome-ignore lint: idk
  Object.entries(config.users).forEach(([username, password]) => {
    console.log(chalk.blue(`Username: ${username}, Password: ${password}`));
  });
  app.use(basicAuth({ users: config.users, challenge: true }));
}

app.get("/e/*", async (req, res, next) => {
  try {
    if (cache.has(req.path)) {
      const { data, contentType, timestamp } = cache.get(req.path);
      if (Date.now() - timestamp > CACHE_TTL) {
        cache.delete(req.path);
      } else {
        res.writeHead(200, { "Content-Type": contentType });
        return res.end(data);
      }
    }

    const baseUrls = {
      "/e/1/": "https://raw.githubusercontent.com/qrs/x/fixy/",
      "/e/2/": "https://raw.githubusercontent.com/3v1/V5-Assets/main/",
      "/e/3/": "https://raw.githubusercontent.com/3v1/V5-Retro/master/",
    };

    let reqTarget;
    for (const [prefix, baseUrl] of Object.entries(baseUrls)) {
      if (req.path.startsWith(prefix)) {
        reqTarget = baseUrl + req.path.slice(prefix.length);
        break;
      }
    }

    if (!reqTarget) {
      return next();
    }

    const asset = await fetch(reqTarget);
    if (!asset.ok) {
      return next();
    }

    const data = Buffer.from(await asset.arrayBuffer());
    const ext = path.extname(reqTarget);
    const no = [".unityweb"];
    const contentType = no.includes(ext) ? "application/octet-stream" : mime.getType(ext);

    cache.set(req.path, { data, contentType, timestamp: Date.now() });
    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  } catch (error) {
    console.error("Error fetching asset:", error);
    res.setHeader("Content-Type", "text/html");
    res.status(500).send("Error fetching the asset");
  }
});

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PRIVATE_IPV4_RANGES = [
  { start: "10.0.0.0", end: "10.255.255.255" },
  { start: "172.16.0.0", end: "172.31.255.255" },
  { start: "192.168.0.0", end: "192.168.255.255" },
  { start: "127.0.0.0", end: "127.255.255.255" },
  { start: "169.254.0.0", end: "169.254.255.255" },
  { start: "0.0.0.0", end: "0.255.255.255" },
];
const BLOCKED_HOSTNAMES = new Set(["localhost"]);

const ipv4ToLong = ip =>
  ip
    .split(".")
    .reduce((acc, octet) => (acc << 8) + Number.parseInt(octet, 10), 0) >>> 0;

const isPrivateIPv4 = ip => {
  const value = ipv4ToLong(ip);
  return PRIVATE_IPV4_RANGES.some(range => {
    const start = ipv4ToLong(range.start);
    const end = ipv4ToLong(range.end);
    return value >= start && value <= end;
  });
};

const isPrivateIPv6 = ip => {
  const normalized = ip.toLowerCase();
  return (
    normalized === "::1" ||
    normalized.startsWith("fe80:") ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd")
  );
};

const isBlockedTarget = async targetUrl => {
  if (BLOCKED_HOSTNAMES.has(targetUrl.hostname)) {
    return true;
  }
  if (targetUrl.hostname.endsWith(".local") || targetUrl.hostname.endsWith(".internal")) {
    return true;
  }
  const ipType = net.isIP(targetUrl.hostname);
  if (ipType === 4) {
    return isPrivateIPv4(targetUrl.hostname);
  }
  if (ipType === 6) {
    return isPrivateIPv6(targetUrl.hostname);
  }

  const lookups = await dns.lookup(targetUrl.hostname, { all: true });
  return lookups.some(record => {
    if (record.family === 4) {
      return isPrivateIPv4(record.address);
    }
    if (record.family === 6) {
      return isPrivateIPv6(record.address);
    }
    return false;
  });
};

app.post("/api/proxy", async (req, res) => {
  try {
    const rawUrl = typeof req.body?.url === "string" ? req.body.url.trim() : "";
    if (!rawUrl) {
      return res.status(400).json({ error: "Please enter a URL to fetch." });
    }

    let targetUrl;
    try {
      targetUrl = new URL(rawUrl);
    } catch {
      return res.status(400).json({ error: "That doesn't look like a valid URL." });
    }

    if (targetUrl.protocol !== "https:") {
      return res.status(400).json({ error: "Only HTTPS URLs are allowed." });
    }

    if (await isBlockedTarget(targetUrl)) {
      return res
        .status(400)
        .json({ error: "That address is blocked for safety (local or internal)." });
    }

    // Educational demo: the server makes the outbound request on the user's behalf
    // and returns the HTML so the browser never connects directly to the target site.
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);

    const response = await fetch(targetUrl.toString(), {
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "Educational-Proxy-Demo/1.0",
      },
    });

    clearTimeout(timeout);

    if (!response.ok) {
      return res
        .status(502)
        .json({ error: `Upstream returned ${response.status} ${response.statusText}.` });
    }

    const contentType = response.headers.get("content-type") || "";
    if (!contentType.includes("text/html")) {
      return res
        .status(400)
        .json({ error: "Only HTML pages can be displayed in this demo." });
    }

    const html = await response.text();
    return res.json({ html });
  } catch (error) {
    if (error?.name === "AbortError") {
      return res.status(504).json({ error: "The request timed out." });
    }
    console.error("Proxy error:", error);
    return res.status(500).json({ error: "Proxy error. Please try again." });
  }
});

/* if (process.env.MASQR === "true") {
  console.log(chalk.green("Masqr is enabled"));
  setupMasqr(app);
} */

app.use(express.static(path.join(__dirname, "static")));
app.use("/ca", cors({ origin: true }));

const routes = [
  { path: "/b", file: "apps.html" },
  { path: "/a", file: "games.html" },
  { path: "/play.html", file: "games.html" },
  { path: "/c", file: "settings.html" },
  { path: "/d", file: "tabs.html" },
  { path: "/", file: "index.html" },
];

// biome-ignore lint: idk
routes.forEach(route => {
  app.get(route.path, (_req, res) => {
    res.sendFile(path.join(__dirname, "static", route.file));
  });
});

app.use((req, res, next) => {
  res.status(404).sendFile(path.join(__dirname, "static", "404.html"));
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).sendFile(path.join(__dirname, "static", "404.html"));
});

server.on("request", (req, res) => {
  if (bareServer.shouldRoute(req)) {
    bareServer.routeRequest(req, res);
  } else {
    app(req, res);
  }
});

server.on("upgrade", (req, socket, head) => {
  if (bareServer.shouldRoute(req)) {
    bareServer.routeUpgrade(req, socket, head);
  } else {
    socket.end();
  }
});

server.on("listening", () => {
  console.log(chalk.green(`🌍 Server is running on http://localhost:${PORT}`));
});

server.listen({ port: PORT });
