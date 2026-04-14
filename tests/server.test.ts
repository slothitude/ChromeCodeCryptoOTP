import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { PadManager } from "@cryptocode/otp-core";
import { DualChannel } from "@cryptocode/otp-gate";
import { ChromeCodeSession } from "../src/session.js";
import { encryptTool } from "../src/tools/encrypt.js";
import { decryptTool } from "../src/tools/decrypt.js";
import { executeTool } from "../src/tools/execute.js";
import { statusTool } from "../src/tools/status.js";
import { createServer } from "../src/server.js";
import * as path from "node:path";
import * as os from "node:os";
import * as fs from "node:fs";

// Create a temp config dir for test isolation
const TEST_DIR = path.join(os.tmpdir(), `chromecode-test-${Date.now()}`);

/**
 * Helper: create paired pad buffers with deterministic data.
 */
function createPadBuffers(size = 10_000): { uaBuf: Buffer; auBuf: Buffer } {
	const uaBuf = Buffer.alloc(size);
	const auBuf = Buffer.alloc(size);
	for (let i = 0; i < size; i++) uaBuf[i] = (i * 37 + 17) & 0xff;
	for (let i = 0; i < size; i++) auBuf[i] = (i * 53 + 29) & 0xff;
	return { uaBuf, auBuf };
}

/**
 * Helper: inject encrypt + decrypt channels into a session (bypasses init which needs HTTP).
 */
function injectChannels(session: ChromeCodeSession, uaBuf: Buffer, auBuf: Buffer): void {
	const encryptChannel = new DualChannel(
		new PadManager("test://ua", Buffer.from(uaBuf), 0, 0),
		new PadManager("test://au", Buffer.from(auBuf), 0, 0),
	);
	const decryptChannel = new DualChannel(
		new PadManager("test://ua", Buffer.from(uaBuf), 0, 0),
		new PadManager("test://au", Buffer.from(auBuf), 0, 0),
	);

	// @ts-expect-error - accessing private for test setup
	session.encryptChannel = encryptChannel;
	// @ts-expect-error
	session.decryptChannel = decryptChannel;
	// @ts-expect-error
	session.state = {
		version: 1,
		channels: {
			userToAgent: encryptChannel.userToAgent.toState(),
			agentToUser: encryptChannel.agentToUser.toState(),
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
			const { uaBuf, auBuf } = createPadBuffers();
			injectChannels(session, uaBuf, auBuf);

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
			await assert.rejects(() => session.ensureEncryptReady(), /No session found/);
		});

		it("should return the encrypt channel when initialized", async () => {
			const session = new ChromeCodeSession();
			const { uaBuf, auBuf } = createPadBuffers();
			injectChannels(session, uaBuf, auBuf);

			const ch = await session.ensureEncryptReady();
			assert.ok(ch === session.encryptChannel);
		});

		it("should return the decrypt channel when initialized", async () => {
			const session = new ChromeCodeSession();
			const { uaBuf, auBuf } = createPadBuffers();
			injectChannels(session, uaBuf, auBuf);

			const ch = await session.ensureDecryptReady();
			assert.ok(ch === session.decryptChannel);
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
		const { uaBuf, auBuf } = createPadBuffers();
		injectChannels(session, uaBuf, auBuf);

		const result = await statusTool({}, session);
		const data = JSON.parse(result.content[0].text);
		assert.strictEqual(data.initialized, true);
		assert.strictEqual(data.uaSequence, 0);
		assert.strictEqual(data.auSequence, 0);
	});
});

describe("Tool: encrypt + decrypt roundtrip", () => {
	it("should encrypt and decrypt a message successfully", async () => {
		const session = new ChromeCodeSession();
		const { uaBuf, auBuf } = createPadBuffers();
		injectChannels(session, uaBuf, auBuf);

		// Encrypt with the encrypt channel
		const encResult = await encryptTool(
			{ plaintext: "list files in /tmp" },
			session,
		);
		const enc = JSON.parse(encResult.content[0].text);
		assert.ok(enc.ciphertext);
		assert.strictEqual(typeof enc.padBytesUsed, "number");
		assert.strictEqual(typeof enc.padPosition, "number");
		assert.strictEqual(typeof enc.sequence, "number");

		// Decrypt with the decrypt channel
		const decResult = await decryptTool(enc, session);
		const dec = JSON.parse(decResult.content[0].text);
		assert.strictEqual(dec.authenticated, true);
		assert.strictEqual(dec.instruction, "list files in /tmp");
	});

	it("should reject tampered ciphertext", async () => {
		const session = new ChromeCodeSession();
		const { uaBuf, auBuf } = createPadBuffers();
		injectChannels(session, uaBuf, auBuf);

		const encResult = await encryptTool(
			{ plaintext: "delete everything" },
			session,
		);
		const enc = JSON.parse(encResult.content[0].text);

		// Tamper with ciphertext
		const tamperedBuf = Buffer.from(enc.ciphertext, "base64");
		tamperedBuf[0] ^= 0xff;
		enc.ciphertext = tamperedBuf.toString("base64");

		const decResult = await decryptTool(enc, session);
		const dec = JSON.parse(decResult.content[0].text);
		assert.strictEqual(dec.authenticated, false);
		assert.strictEqual(dec.instruction, "");
	});
});

describe("Tool: execute", () => {
	it("should return instruction directly for valid ciphertext", async () => {
		const session = new ChromeCodeSession();
		session.securityMode = "strict";
		const { uaBuf, auBuf } = createPadBuffers();
		injectChannels(session, uaBuf, auBuf);

		const encResult = await encryptTool(
			{ plaintext: "read file secret.txt" },
			session,
		);
		const enc = JSON.parse(encResult.content[0].text);

		const execResult = await executeTool(enc, session);
		assert.strictEqual(execResult.content[0].text, "read file secret.txt");
	});

	it("should reject unauthenticated with generic message", async () => {
		const session = new ChromeCodeSession();
		session.securityMode = "strict";
		const { uaBuf, auBuf } = createPadBuffers();
		injectChannels(session, uaBuf, auBuf);

		const result = await executeTool(
			{
				ciphertext: Buffer.from("garbage data").toString("base64"),
				padBytesUsed: 12,
				padPosition: 0,
				sequence: 0,
			},
			session,
		);
		assert.strictEqual(result.content[0].text, "No authenticated instruction found.");
	});

	it("should reject in lenient mode the same way", async () => {
		const session = new ChromeCodeSession();
		session.securityMode = "lenient";
		const { uaBuf, auBuf } = createPadBuffers();
		injectChannels(session, uaBuf, auBuf);

		const result = await executeTool(
			{
				ciphertext: Buffer.from("garbage data").toString("base64"),
				padBytesUsed: 12,
				padPosition: 0,
				sequence: 0,
			},
			session,
		);
		assert.strictEqual(result.content[0].text, "No authenticated instruction found.");
	});

	it("should reject in audit mode the same way", async () => {
		const session = new ChromeCodeSession();
		session.securityMode = "audit";
		const { uaBuf, auBuf } = createPadBuffers();
		injectChannels(session, uaBuf, auBuf);

		const result = await executeTool(
			{
				ciphertext: Buffer.from("garbage data").toString("base64"),
				padBytesUsed: 12,
				padPosition: 0,
				sequence: 0,
			},
			session,
		);
		assert.strictEqual(result.content[0].text, "No authenticated instruction found.");
	});

	it("should detect replay attacks (wrong sequence number)", async () => {
		const session = new ChromeCodeSession();
		session.securityMode = "lenient";
		const { uaBuf, auBuf } = createPadBuffers();
		injectChannels(session, uaBuf, auBuf);

		// Encrypt a message
		const encResult = await encryptTool(
			{ plaintext: "first message" },
			session,
		);
		const enc = JSON.parse(encResult.content[0].text);

		// Decrypt it once (advances decrypt channel sequence)
		await decryptTool(enc, session);

		// Send same message again — sequence mismatch → desync
		const decResult = await decryptTool(enc, session);
		const dec = JSON.parse(decResult.content[0].text);
		assert.strictEqual(dec.authenticated, false);
		assert.ok(dec.desync);
	});

	it("should handle multiple messages in sequence", async () => {
		const session = new ChromeCodeSession();
		session.securityMode = "strict";
		const { uaBuf, auBuf } = createPadBuffers();
		injectChannels(session, uaBuf, auBuf);

		const messages = ["msg one", "msg two", "msg three"];
		for (const msg of messages) {
			const enc = await encryptTool({ plaintext: msg }, session);
			const encData = JSON.parse(enc.content[0].text);

			const exec = await executeTool(encData, session);
			assert.strictEqual(exec.content[0].text, msg);
		}
	});
});

describe("Tool: resync (desync detection)", () => {
	it("should detect desync and provide recovery info", async () => {
		const session = new ChromeCodeSession();
		session.securityMode = "strict";
		const { uaBuf, auBuf } = createPadBuffers();
		injectChannels(session, uaBuf, auBuf);

		// Encrypt a message
		const encResult = await encryptTool(
			{ plaintext: "hello" },
			session,
		);
		const enc = JSON.parse(encResult.content[0].text);

		// Decrypt once (sequence advances to 1)
		await decryptTool(enc, session);

		// Send same message again (sequence 0 vs expected 1 → desync)
		const decResult = await decryptTool(enc, session);
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
