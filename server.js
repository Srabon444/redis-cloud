import express from "express";
import dotenv from "dotenv";
import { createClient } from "redis";
import crypto from "crypto";

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.disable("x-powered-by");

const APP_USERNAME = process.env.APP_USERNAME;
const APP_PASSWORD = process.env.APP_PASSWORD;

function safeEqual(a, b) {
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);

    if (bufA.length !== bufB.length) return false;

    return crypto.timingSafeEqual(bufA, bufB);
}

//! Fails closed: no creds configured -> block everything, not open access.
function basicAuth(req, res, next) {

    if (!APP_USERNAME || !APP_PASSWORD) {
        return res.status(500).json({
            error: "Server auth not configured. Set APP_USERNAME/APP_PASSWORD in .env."
        });
    }

    const header = req.headers.authorization || "";
    const [scheme, encoded] = header.split(" ");

    if (scheme !== "Basic" || !encoded) {
        res.set("WWW-Authenticate", 'Basic realm="redis-cloud"');
        return res.status(401).send("Authentication required.");
    }

    const decoded = Buffer.from(encoded, "base64").toString("utf8");
    const sepIndex = decoded.indexOf(":");
    const user = decoded.slice(0, sepIndex);
    const pass = decoded.slice(sepIndex + 1);

    if (safeEqual(user, APP_USERNAME) && safeEqual(pass, APP_PASSWORD)) {
        return next();
    }

    res.set("WWW-Authenticate", 'Basic realm="redis-cloud"');
    return res.status(401).send("Invalid credentials.");
}

app.use(express.json());
app.use(basicAuth);
app.use(express.static("public"));

const redisConfig = {
    socket: {
        host: process.env.REDIS_HOST,
        port: Number(process.env.REDIS_PORT || 6379),
        tls: process.env.REDIS_TLS === "true"
    },
    username: process.env.REDIS_USERNAME || undefined,
    password: process.env.REDIS_PASSWORD || undefined
};

function createRedisClient() {
    const client = createClient(redisConfig);

    client.on("error", err => {
        console.error("Redis error:", err.message);
    });

    return client;
}

function makeTestKey() {
    const random = crypto.randomBytes(8).toString("hex");
    return `redis-speed-test:${Date.now()}:${random}`;
}

function classifyError(error) {
    const message = error?.message || String(error);

    if (message.includes("NOPERM")) {
        return {
            status: "DENIED",
            reason: "ACL permission denied",
            message
        };
    }

    if (
        message.includes("WRONGPASS") ||
        message.includes("NOAUTH")
    ) {
        return {
            status: "FAILED",
            reason: "Authentication failed",
            message
        };
    }

    if (message.includes("ECONNREFUSED")) {
        return {
            status: "FAILED",
            reason: "Connection refused",
            message
        };
    }

    if (message.includes("ENOTFOUND")) {
        return {
            status: "FAILED",
            reason: "Hostname could not be resolved",
            message
        };
    }

    if (
        message.includes("ETIMEDOUT") ||
        message.toLowerCase().includes("timeout")
    ) {
        return {
            status: "FAILED",
            reason: "Connection timed out",
            message
        };
    }

    if (
        message.toLowerCase().includes("tls") ||
        message.toLowerCase().includes("certificate")
    ) {
        return {
            status: "FAILED",
            reason: "TLS connection failed",
            message
        };
    }

    return {
        status: "FAILED",
        reason: "Redis command failed",
        message
    };
}

/*
 * Permission diagnostic endpoint.
 */
app.post("/api/check", async (req, res) => {

    let client;
    let testKey = null;

    const results = [];

    try {

        client = createRedisClient();

        /*
         * CONNECT
         */
        try {

            await client.connect();

            results.push({
                test: "Connection",
                status: "ALLOWED",
                message: "Connected to Redis successfully."
            });

        } catch (error) {

            results.push({
                test: "Connection",
                ...classifyError(error)
            });

            return res.json({
                success: false,
                results
            });
        }

        /*
         * PING
         */
        try {

            const start = performance.now();

            const response =
                await client.ping();

            const latency =
                performance.now() - start;

            results.push({
                test: "PING",
                status: "ALLOWED",
                latencyMs: Number(latency.toFixed(2)),
                message: `PING returned ${response}.`
            });

        } catch (error) {

            results.push({
                test: "PING",
                ...classifyError(error)
            });
        }

        /*
         * Create a unique test key.
         *
         * We clean this key up afterward if possible.
         */
        testKey = makeTestKey();

        /*
         * SET
         */
        try {

            const start = performance.now();

            await client.set(
                testKey,
                "redis-speed-test"
            );

            const latency =
                performance.now() - start;

            results.push({
                test: "SET",
                status: "ALLOWED",
                latencyMs: Number(latency.toFixed(2)),
                key: testKey,
                message: "SET succeeded."
            });

        } catch (error) {

            results.push({
                test: "SET",
                ...classifyError(error),
                key: testKey
            });
        }

        /*
         * GET
         */
        try {

            const start = performance.now();

            const value =
                await client.get(testKey);

            const latency =
                performance.now() - start;

            results.push({
                test: "GET",
                status: "ALLOWED",
                latencyMs: Number(latency.toFixed(2)),
                valueReturned: value !== null,
                message: "GET succeeded."
            });

        } catch (error) {

            results.push({
                test: "GET",
                ...classifyError(error)
            });
        }

        /*
         * DEL
         */
        try {

            const start = performance.now();

            const deleted =
                await client.del(testKey);

            const latency =
                performance.now() - start;

            results.push({
                test: "DEL",
                status: "ALLOWED",
                latencyMs: Number(latency.toFixed(2)),
                deleted,
                message: "DEL succeeded."
            });

        } catch (error) {

            results.push({
                test: "DEL",
                ...classifyError(error)
            });
        }

        /*
         * Determine whether a meaningful benchmark is possible.
         */
        const set =
            results.find(x => x.test === "SET");

        const get =
            results.find(x => x.test === "GET");

        const del =
            results.find(x => x.test === "DEL");

        const canBenchmark =
            set?.status === "ALLOWED" &&
            get?.status === "ALLOWED";

        res.json({
            success: true,
            canBenchmark,
            results
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            success: false,
            error: error?.message || String(error),
            results
        });

    } finally {

        /*
         * If SET worked but DEL was denied, we can't
         * safely remove the key. This is why the benchmark
         * uses a unique random key.
         */
        if (client) {

            try {
                await client.quit();
            } catch {}
        }
    }
});

function isNonEmptyString(value) {
    return typeof value === "string" && value.trim().length > 0;
}

//! Keeps manual ops inside the ACL's key pattern (~redis-speed-test:*) so users don't hit
//! confusing NOPERM errors by typing an arbitrary key.
function buildTestKey(rawKey) {
    return `redis-speed-test:${rawKey.trim()}`;
}

/*
 * Manual GET.
 */
app.post("/api/get", async (req, res) => {

    const { key } = req.body || {};

    if (!isNonEmptyString(key)) {
        return res.status(400).json({ success: false, error: "key is required" });
    }

    let client;
    const fullKey = buildTestKey(key);

    try {

        client = createRedisClient();
        await client.connect();

        const start = performance.now();
        const value = await client.get(fullKey);
        const latency = performance.now() - start;

        res.json({
            success: true,
            result: {
                test: "GET",
                status: "ALLOWED",
                latencyMs: Number(latency.toFixed(2)),
                key: fullKey,
                value,
                message: value === null
                    ? "GET succeeded (key not found)."
                    : `GET succeeded. Value: "${value}"`
            }
        });

    } catch (error) {

        res.json({
            success: false,
            result: { test: "GET", key: fullKey, ...classifyError(error) }
        });

    } finally {
        if (client) {
            try { await client.quit(); } catch {}
        }
    }
});

/*
 * Manual SET.
 */
app.post("/api/set", async (req, res) => {

    const { key, value } = req.body || {};

    if (!isNonEmptyString(key) || !isNonEmptyString(value)) {
        return res.status(400).json({ success: false, error: "key and value are required" });
    }

    let client;
    const fullKey = buildTestKey(key);

    try {

        client = createRedisClient();
        await client.connect();

        const start = performance.now();
        await client.set(fullKey, value);
        const latency = performance.now() - start;

        res.json({
            success: true,
            result: {
                test: "SET",
                status: "ALLOWED",
                latencyMs: Number(latency.toFixed(2)),
                key: fullKey,
                message: "SET succeeded."
            }
        });

    } catch (error) {

        res.json({
            success: false,
            result: { test: "SET", key: fullKey, ...classifyError(error) }
        });

    } finally {
        if (client) {
            try { await client.quit(); } catch {}
        }
    }
});

/*
 * Manual DELETE.
 */
app.post("/api/delete", async (req, res) => {

    const { key } = req.body || {};

    if (!isNonEmptyString(key)) {
        return res.status(400).json({ success: false, error: "key is required" });
    }

    let client;
    const fullKey = buildTestKey(key);

    try {

        client = createRedisClient();
        await client.connect();

        const start = performance.now();
        const deleted = await client.del(fullKey);
        const latency = performance.now() - start;

        res.json({
            success: true,
            result: {
                test: "DEL",
                status: "ALLOWED",
                latencyMs: Number(latency.toFixed(2)),
                key: fullKey,
                deleted,
                message: deleted > 0
                    ? "DEL succeeded."
                    : "DEL succeeded (key did not exist)."
            }
        });

    } catch (error) {

        res.json({
            success: false,
            result: { test: "DEL", key: fullKey, ...classifyError(error) }
        });

    } finally {
        if (client) {
            try { await client.quit(); } catch {}
        }
    }
});

/*
 * Simple server health endpoint.
 */
app.get("/api/health", (req, res) => {

    res.json({
        ok: true,
        redisHost: redisConfig.socket.host,
        redisPort: redisConfig.socket.port,
        redisUsername: redisConfig.username,
        tls: redisConfig.socket.tls
    });
});

//! Vercel imports this file as a serverless function (api/index.js) — it must not
//! call listen() there, Vercel's runtime handles the socket itself.
if (!process.env.VERCEL) {

    app.listen(PORT, () => {

        console.log("");
        console.log("Redis Permission Diagnostic");
        console.log("----------------------------");
        console.log(`Web UI: http://localhost:${PORT}`);
        console.log(
            `Redis: ${redisConfig.socket.host}:${redisConfig.socket.port}`
        );
        console.log(`TLS: ${redisConfig.socket.tls}`);
        console.log("");
    });
}

export default app;