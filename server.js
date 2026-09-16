
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { MongoClient, ObjectId } = require("mongodb");

const app = express();

app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;

// ===============================
// MONGODB
// ===============================

const uri = process.env.MONGODB_URI;

if (!uri) {
    console.error("❌ MONGODB_URI is missing from environment variables.");
    process.exit(1);
}

const client = new MongoClient(uri);

let botsCollection;
let usersCollection;

// ===============================
// MIDDLEWARE
// ===============================

app.use(express.json());

app.use(
    session({
        secret:
            process.env.SESSION_SECRET ||
            "MaleeshaMD-WhatsApp-Bot-Secret-2026",

        resave: false,

        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 24 * 60 * 60 * 1000
        }
    })
);

app.use(express.static("public"));

// ===============================
// LOGIN PROTECTION
// ===============================

function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({
            error: "Please login first."
        });
    }

    next();
}

// ===============================
// REGISTER
// ===============================

app.post("/api/register", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({
                error: "All fields are required."
            });
        }

        const cleanUsername = username.trim();
        const cleanEmail = email.trim().toLowerCase();

        if (cleanUsername.length < 3) {
            return res.status(400).json({
                error: "Username must be at least 3 characters."
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                error: "Password must be at least 6 characters."
            });
        }

        const existingUser = await usersCollection.findOne({
            $or: [
                { username: cleanUsername },
                { email: cleanEmail }
            ]
        });

        if (existingUser) {
            return res.status(400).json({
                error: "Username or email already exists."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = {
            username: cleanUsername,
            email: cleanEmail,
            password: hashedPassword,
            createdAt: new Date()
        };

        const result = await usersCollection.insertOne(newUser);

        res.status(201).json({
            message: "Registration successful!",
            userId: result.insertedId
        });

    } catch (error) {
        console.error("Register error:", error);

        res.status(500).json({
            error: "Server error."
        });
    }
});

// ===============================
// LOGIN
// ===============================

app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                error: "Email and password are required."
            });
        }

        const cleanEmail = email.trim().toLowerCase();

        const user = await usersCollection.findOne({
            email: cleanEmail
        });

        if (!user || !user.password) {
            return res.status(401).json({
                error: "Invalid email or password. Please register again."
            });
        }

        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatch) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        req.session.userId = user._id.toString();
        req.session.username = user.username;
        req.session.email = user.email;

        req.session.save((error) => {
            if (error) {
                console.error("Session save error:", error);

                return res.status(500).json({
                    error: "Session could not be saved."
                });
            }

            res.json({
                message: "Login successful!",
                user: {
                    id: user._id,
                    username: user.username,
                    email: user.email
                }
            });
        });

    } catch (error) {
        console.error("Login error:", error);

        res.status(500).json({
            error: "Server error."
        });
    }
});

// ===============================
// CURRENT USER
// ===============================

app.get("/api/me", requireLogin, async (req, res) => {
    try {
        if (!ObjectId.isValid(req.session.userId)) {
            return res.status(401).json({
                error: "Invalid session."
            });
        }

        const user = await usersCollection.findOne(
            {
                _id: new ObjectId(req.session.userId)
            },
            {
                projection: {
                    password: 0
                }
            }
        );

        if (!user) {
            return res.status(401).json({
                error: "User not found."
            });
        }

        res.json({
            user
        });

    } catch (error) {
        console.error("Me error:", error);

        res.status(500).json({
            error: "Server error."
        });
    }
});

// ===============================
// LOGOUT
// ===============================

app.post("/api/logout", (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            console.error("Logout error:", error);

            return res.status(500).json({
                error: "Logout failed."
            });
        }

        res.clearCookie("connect.sid");

        res.json({
            message: "Logged out successfully."
        });
    });
});

// ===============================
// CREATE BOT
// ===============================

app.post("/api/bots", requireLogin, async (req, res) => {
    try {
        const { name } = req.body;

        if (!name || !name.trim()) {
            return res.status(400).json({
                error: "Bot name is required."
            });
        }

        const newBot = {
            name: name.trim(),
            description: "",
            autoReply: false,
            userId: req.session.userId,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        const result = await botsCollection.insertOne(newBot);

        res.status(201).json({
            message: "Bot created successfully!",
            bot: {
                _id: result.insertedId,
                ...newBot
            }
        });

    } catch (error) {
        console.error("Create bot error:", error);

        res.status(500).json({
            error: "Server error."
        });
    }
});

// ===============================
// GET USER BOTS
// ===============================

app.get("/api/bots", requireLogin, async (req, res) => {
    try {
        const bots = await botsCollection
            .find({
                userId: req.session.userId
            })
            .sort({
                createdAt: -1
            })
            .toArray();

        res.json(bots);

    } catch (error) {
        console.error("Get bots error:", error);

        res.status(500).json({
            error: "Server error."
        });
    }
});

// ===============================
// GET SINGLE BOT
// ===============================

app.get("/api/bots/:id", requireLogin, async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                error: "Invalid bot ID."
            });
        }

        const bot = await botsCollection.findOne({
            _id: new ObjectId(id),
            userId: req.session.userId
        });

        if (!bot) {
            return res.status(404).json({
                error: "Bot not found."
            });
        }

        res.json(bot);

    } catch (error) {
        console.error("Get bot error:", error);

        res.status(500).json({
            error: "Server error."
        });
    }
});

// ===============================
// UPDATE BOT NAME
// ===============================

app.put("/api/bots/:id", requireLogin, async (req, res) => {
    try {
        const { id } = req.params;
        const { name } = req.body;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                error: "Invalid bot ID."
            });
        }

        if (!name || !name.trim()) {
            return res.status(400).json({
                error: "Bot name is required."
            });
        }

        const result = await botsCollection.updateOne(
            {
                _id: new ObjectId(id),
                userId: req.session.userId
            },
            {
                $set: {
                    name: name.trim(),
                    updatedAt: new Date()
                }
            }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({
                error: "Bot not found."
            });
        }

        res.json({
            message: "Bot updated successfully."
        });

    } catch (error) {
        console.error("Update bot error:", error);

        res.status(500).json({
            error: "Server error."
        });
    }
});

// ===============================
// UPDATE BOT SETTINGS
// ===============================

app.put("/api/bots/:id/settings", requireLogin, async (req, res) => {
    try {
        const { id } = req.params;

        const {
            name,
            description,
            autoReply
        } = req.body;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                error: "Invalid bot ID."
            });
        }

        if (!name || !name.trim()) {
            return res.status(400).json({
                error: "Bot name is required."
            });
        }

        const result = await botsCollection.updateOne(
            {
                _id: new ObjectId(id),
                userId: req.session.userId
            },
            {
                $set: {
                    name: name.trim(),
                    description: description || "",
                    autoReply: autoReply === true,
                    updatedAt: new Date()
                }
            }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({
                error: "Bot not found."
            });
        }

        res.json({
            message: "Bot settings saved successfully."
        });

    } catch (error) {
        console.error("Settings error:", error);

        res.status(500).json({
            error: "Server error."
        });
    }
});

// ===============================
// DELETE BOT
// ===============================

app.delete("/api/bots/:id", requireLogin, async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                error: "Invalid bot ID."
            });
        }

        const result = await botsCollection.deleteOne({
            _id: new ObjectId(id),
            userId: req.session.userId
        });

        if (result.deletedCount === 0) {
            return res.status(404).json({
                error: "Bot not found."
            });
        }

        res.json({
            message: "Bot deleted successfully."
        });

    } catch (error) {
        console.error("Delete bot error:", error);

        res.status(500).json({
            error: "Server error."
        });
    }
});

// ===============================
// WHATSAPP WEBHOOK
// ===============================

// GET - Webhook verification

app.get("/webhook", (req, res) => {
    const VERIFY_TOKEN =
        process.env.WHATSAPP_VERIFY_TOKEN ||
        "maleesha-md-webhook";

    const mode = req.query["hub.mode"];
    const token = req.query["hub.verify_token"];
    const challenge = req.query["hub.challenge"];

    if (mode === "subscribe" && token === VERIFY_TOKEN) {
        console.log("✅ WhatsApp Webhook verified!");

        return res
            .status(200)
            .send(challenge);
    }

    console.log("❌ WhatsApp Webhook verification failed.");

    res.sendStatus(403);
});

// POST - Receive WhatsApp events

app.post("/webhook", async (req, res) => {
    try {
        console.log("📩 WhatsApp webhook received:");

        console.log(
            JSON.stringify(
                req.body,
                null,
                2
            )
        );

        res.sendStatus(200);

    } catch (error) {
        console.error("Webhook error:", error);

        res.sendStatus(500);
    }
});

// ===============================
// START SERVER
// ===============================

async function startServer() {
    try {
        await client.connect();

        console.log("✅ MongoDB connected successfully!");

        const db = client.db("WhatsAppBotDB");

        botsCollection = db.collection("bots");
        usersCollection = db.collection("users");

        await usersCollection.createIndex(
            { username: 1 },
            { unique: true }
        );

        await usersCollection.createIndex(
            { email: 1 },
            { unique: true }
        );

        console.log("✅ Database collections ready!");

        app.listen(PORT, "0.0.0.0", () => {
            console.log(
                `🚀 Website running on port ${PORT}`
            );
        });

    } catch (error) {
        console.error(
            "❌ Failed to start server:",
            error
        );

        process.exit(1);
    }
}

startServer();