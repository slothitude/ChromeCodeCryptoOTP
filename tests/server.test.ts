import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { PadManager } from "@cryptocode/otp-core";
import { DualChannel } from "@cryptocode/otp-gate";
import { ChromeCodeSession } from "../src/session.js";
import { initTool } from "../src/tools/init.js";
import { encryptTool } from "../src/tools/encrypt.js";
import { decryptTool } from "../src/tools/decrypt.js";
import { executeTool } from "../src/tools/execute.js";
import { statusTool } from "../src/tools/status.js";
import { resyncTool } from "../src/tools/resync.js";
import { createServer } from "../src/server.js";
import * as path from "node:path";
import * as os from "node:os";
import * as fs from "node:fs";

// Create a temp config dir for test isolation
const TEST_DIR = path.join(os.tmpdir(), `chromecode-test-${Date.now()}`);

function makeSession(): ChromeCodeSession {
	const session = new ChromeCodeSession();
	// Override to use temp dir
	// We need to directly set the channel since init() fetches URLs
	return session;
}

/**
 * Helper: create a paired sender+receiver DualChannel with synthetic pad material.
 */
function createPairedChannels(size = 10_000): { sender: DualChannel; receiver: DualChannel } {
	const uaBuf = Buffer.alloc(size);
	const auBuf = Buffer.alloc(size);
	for (let i = 0; i < size; i++) uaBuf[i] = (i * 37 + 17) & 0xff;
	for (let i = 0; i < size; i++) auBuf[i] = (i * 53 + 29) & 0xff;

	return {
		sender: new DualChannel(
			new PadManager("test://ua", Buffer.from(uaBuf), 0, 0),
			new PadManager("test://au", Buffer.from(auBuf), 0, 0),
		),
		receiver: new DualChannel(
			new PadManager("test://ua", Buffer.from(uaBuf), 0, 0),
			new PadManager("test://au", Buffer.from(auBuf), 0, 0),
		),
	};
}

/**
 * Helper: inject a DualChannel directly into a ChromeCodeSession (bypasses init which needs HTTP).
 */
function injectChannel(session: ChromeCodeSession, channel: DualChannel): void {
	// @ts-expect-error - accessing private for test setup
	session.channel = channel;
	// @ts-expect-error
	session.state = {
		version: 1,
		channels: {
			userToAgent: channel.userToAgent.toState(),
			agentToUser: channel.agentToUser.toState(),
		},
		createdAt: new Date().toISOString(),
	};
	// Override persist to be a no-op (no disk writes in tests)
	// @ts-expect-error
	session.persist = () => {};
}

describe("ChromeCodeSession", () => {
	describe("getStatus", () => {
		it("should return uninitialized status when no session exists", () => {
			const session = new ChromeCodeSession();
			const status = session.getStatus();
			assert.strictEqual(status.initialized, false);
		});

		it("should return initialized status with channel info", () => {
			const session = new ChromeCodeSession();
			const { receiver } = createPairedChannels();
			injectChannel(session, receiver);

			const status = session.getStatus();
			assert.strictEqual(status.initialized, true);
			assert.strictEqual(typeof status.uaPadRemaining, "number");
			assert.strictEqual(typeof status.auPadRemaining, "number");
			assert.strictEqual(status.uaSequence, 0);
			assert.strictEqual(status.auSequence, 0);
		});
	});

	describe("ensureReady", () => {
		it("should throw when no session exists", async () => {
			const session = new ChromeCodeSession();
			await assert.rejects(() => session.ensureReady(), /No session found/);
		});

		it("should return the channel when initialized", async () => {
			const session = new ChromeCodeSession();
			const { receiver } = createPairedChannels();
			injectChannel(session, receiver);

			const ch = await session.ensureReady();
			assert.strictEqual(ch, receiver);
		});
	});
});

describe("Tool: status", () => {
	it("should return uninitialized status", async () => {
		const session = new ChromeCodeSession();
		const result = await statusTool({}, session);
		const data = JSON.parse(result.content[0].text);
		assert.strictEqual(data.initialized, false);
	});

	it("should return full status when initialized", async () => {
		const session = new ChromeCodeSession();
		const { receiver } = createPairedChannels();
		injectChannel(session, receiver);

		const result = await statusTool({}, session);
		const data = JSON.parse(result.content[0].text);
		assert.strictEqual(data.initialized, true);
		assert.strictEqual(data.uaSequence, 0);
		assert.strictEqual(data.auSequence, 0);
	});
});

describe("Tool: encrypt + decrypt roundtrip", () => {
	it("should encrypt and decrypt a message successfully", async () => {
		// Create two sessions sharing the same pad material
		const senderSession = new ChromeCodeSession();
		const receiverSession = new ChromeCodeSession();
		const { sender, receiver } = createPairedChannels();
		injectChannel(senderSession, sender);
		injectChannel(receiverSession, receiver);

		// Encrypt with sender
		const encResult = await encryptTool(
			{ plaintext: "list files in /tmp" },
			senderSession,
		);
		const enc = JSON.parse(encResult.content[0].text);
		assert.ok(enc.ciphertext);
		assert.strictEqual(typeof enc.padBytesUsed, "number");
		assert.strictEqual(typeof enc.padPosition, "number");
		assert.strictEqual(typeof enc.sequence, "number");

		// Decrypt with receiver
		const decResult = await decryptTool(enc, receiverSession);
		const dec = JSON.parse(decResult.content[0].text);
		assert.strictEqual(dec.authenticated, true);
		assert.strictEqual(dec.instruction, "list files in /tmp");
	});

	it("should reject tampered ciphertext", async () => {
		const senderSession = new ChromeCodeSession();
		const receiverSession = new ChromeCodeSession();
		const { sender, receiver } = createPairedChannels();
		injectChannel(senderSession, sender);
		injectChannel(receiverSession, receiver);

		const encResult = await encryptTool(
			{ plaintext: "delete everything" },
			senderSession,
		);
		const enc = JSON.parse(encResult.content[0].text);

		// Tamper with ciphertext
		const tamperedBuf = Buffer.from(enc.ciphertext, "base64");
		tamperedBuf[0] ^= 0xff;
		enc.ciphertext = tamperedBuf.toString("base64");

		const decResult = await decryptTool(enc, receiverSession);
		const dec = JSON.parse(decResult.content[0].text);
		assert.strictEqual(dec.authenticated, false);
		assert.strictEqual(dec.instruction, "");
	});
});

describe("Tool: execute", () => {
	it("should return [AUTHENTICATED] for valid ciphertext (strict mode)", async () => {
		const senderSession = new ChromeCodeSession();
		const receiverSession = new ChromeCodeSession();
		receiverSession.securityMode = "strict";
		const { sender, receiver } = createPairedChannels();
		injectChannel(senderSession, sender);
		injectChannel(receiverSession, receiver);

		const encResult = await encryptTool(
			{ plaintext: "read file secret.txt" },
			senderSession,
		);
		const enc = JSON.parse(encResult.content[0].text);

		const execResult = await executeTool(enc, receiverSession);
		assert.ok(execResult.content[0].text.startsWith("[AUTHENTICATED]"));
		assert.ok(execResult.content[0].text.includes("read file secret.txt"));
	});

	it("should reject unauthenticated in strict mode", async () => {
		const session = new ChromeCodeSession();
		session.securityMode = "strict";
		const { receiver } = createPairedChannels();
		injectChannel(session, receiver);

		// Send garbage ciphertext
		const result = await executeTool(
			{
				ciphertext: Buffer.from("garbage data").toString("base64"),
				padBytesUsed: 12,
				padPosition: 0,
				sequence: 0,
			},
			session,
		);
		assert.strictEqual(
			result.content[0].text,
			"No authenticated instruction found. The input was rejected (strict mode).",
		);
	});

	it("should return [UNAUTHENTICATED] marker in lenient mode", async () => {
		const session = new ChromeCodeSession();
		session.securityMode = "lenient";
		const { receiver } = createPairedChannels();
		injectChannel(session, receiver);

		const result = await executeTool(
			{
				ciphertext: Buffer.from("garbage data").toString("base64"),
				padBytesUsed: 12,
				padPosition: 0,
				sequence: 0,
			},
			session,
		);
		assert.ok(result.content[0].text.startsWith("[UNAUTHENTICATED]"));
	});

	it("should return [UNAUTHENTICATED] with raw text in audit mode", async () => {
		const session = new ChromeCodeSession();
		session.securityMode = "audit";
		const { receiver } = createPairedChannels();
		injectChannel(session, receiver);

		const result = await executeTool(
			{
				ciphertext: Buffer.from("garbage data").toString("base64"),
				padBytesUsed: 12,
				padPosition: 0,
				sequence: 0,
			},
			session,
		);
		assert.ok(result.content[0].text.startsWith("[UNAUTHENTICATED]"));
	});

	it("should detect replay attacks (wrong sequence number)", async () => {
		const senderSession = new ChromeCodeSession();
		const receiverSession = new ChromeCodeSession();
		receiverSession.securityMode = "lenient";
		const { sender, receiver } = createPairedChannels();
		injectChannel(senderSession, sender);
		injectChannel(receiverSession, receiver);

		// Encrypt a message
		const encResult = await encryptTool(
			{ plaintext: "first message" },
			senderSession,
		);
		const enc = JSON.parse(encResult.content[0].text);

		// Decrypt it once (advances receiver sequence)
		await decryptTool(enc, receiverSession);

		// Send same message again — sequence mismatch → desync
		const decResult = await decryptTool(enc, receiverSession);
		const dec = JSON.parse(decResult.content[0].text);
		assert.strictEqual(dec.authenticated, false);
		assert.ok(dec.desync);
	});
});

describe("Tool: resync", () => {
	it("should detect desync and provide recovery info", async () => {
		const senderSession = new ChromeCodeSession();
		const receiverSession = new ChromeCodeSession();
		receiverSession.securityMode = "strict";
		const { sender, receiver } = createPairedChannels();
		injectChannel(senderSession, sender);
		injectChannel(receiverSession, receiver);

		// Encrypt a message
		const encResult = await encryptTool(
			{ plaintext: "hello" },
			senderSession,
		);
		const enc = JSON.parse(encResult.content[0].text);

		// Decrypt once (sequence advances to 1)
		await decryptTool(enc, receiverSession);

		// Send same message again (sequence 0 vs expected 1 → desync)
		const decResult = await decryptTool(enc, receiverSession);
		const dec = JSON.parse(decResult.content[0].text);
		assert.strictEqual(dec.authenticated, false);
		assert.ok(dec.desync);
		assert.strictEqual(dec.desync.senderSeq, 0);
		assert.strictEqual(dec.desync.receiverSeq, 1);
		assert.strictEqual(dec.desync.recoveryUrl, "test://ua");
	});
});

describe("MCP Server Integration", () => {
	it("should list all tools via MCP protocol", async () => {
		const server = createServer();
		const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();

		const client = new Client({ name: "test-client", version: "1.0.0" });
		await server.connect(serverTransport);
		await client.connect(clientTransport);

		const tools = await client.listTools();
		const names = tools.tools.map((t) => t.name);

		assert.ok(names.includes("chromecode_init"));
		assert.ok(names.includes("chromecode_encrypt"));
		assert.ok(names.includes("chromecode_decrypt"));
		assert.ok(names.includes("chromecode_execute"));
		assert.ok(names.includes("chromecode_status"));
		assert.ok(names.includes("chromecode_resync"));

		await client.close();
		await server.close();
	});

	it("should list prompts via MCP protocol", async () => {
		const server = createServer();
		const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();

		const client = new Client({ name: "test-client", version: "1.0.0" });
		await server.connect(serverTransport);
		await client.connect(clientTransport);

		const prompts = await client.listPrompts();
		const names = prompts.prompts.map((p) => p.name);
		assert.ok(names.includes("chromecode_protection"));

		await client.close();
		await server.close();
	});

	it("should list resources via MCP protocol", async () => {
		const server = createServer();
		const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();

		const client = new Client({ name: "test-client", version: "1.0.0" });
		await server.connect(serverTransport);
		await client.connect(clientTransport);

		const resources = await client.listResources();
		assert.strictEqual(resources.resources.length, 1);
		assert.strictEqual(resources.resources[0].uri, "chromecode://session");

		await client.close();
		await server.close();
	});

	it("should call status tool via MCP protocol", async () => {
		const server = createServer();
		const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();

		const client = new Client({ name: "test-client", version: "1.0.0" });
		await server.connect(serverTransport);
		await client.connect(clientTransport);

		const result = await client.callTool({ name: "chromecode_status", arguments: {} });
		assert.ok(result.content);
		const text = (result.content as Array<{ type: string; text: string }>)[0].text;
		const data = JSON.parse(text);
		assert.strictEqual(data.initialized, false);

		await client.close();
		await server.close();
	});
});

// Clean up temp dir
process.on("exit", () => {
	if (fs.existsSync(TEST_DIR)) {
		fs.rmSync(TEST_DIR, { recursive: true });
	}
});
