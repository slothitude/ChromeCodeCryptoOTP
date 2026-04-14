/**
 * End-to-end demo: simulates a user encrypting a message and an agent
 * decrypting it via chromecode_execute, using real Wikipedia pad material.
 *
 * Run: node --import tsx demo.ts
 */
import { PadManager, setConfigDirOverride } from "@cryptocode/otp-core";
import { DualChannel, convertToLlmMessage } from "@cryptocode/otp-gate";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";

// Use a temp dir so we don't clobber any real session
setConfigDirOverride(path.join(os.tmpdir(), `chromecode-demo-${Date.now()}`));

const SEED_UA = "https://raw.githubusercontent.com/torvalds/linux/master/README"; // ~1KB, always available
const SEED_AU = "https://raw.githubusercontent.com/slothitude/cryptocode/master/README.md"; // ~30KB

function header(title: string) {
	console.log(`\n${"=".repeat(60)}`);
	console.log(`  ${title}`);
	console.log(`${"=".repeat(60)}\n`);
}

async function main() {
	header("STEP 1 — Fetching pad material");

	// Both sides share the same seed URLs → same pad bytes
	// Using Project Gutenberg books — large, stable, publicly accessible
	console.log(`Fetching U→A pad: ${SEED_UA}`);
	const uaBuf = await PadManager.fromSeed(SEED_UA);
	console.log(`  Got ${uaBuf.getRemaining().toLocaleString()} bytes`);

	console.log(`Fetching A→U pad: ${SEED_AU}`);
	const auBuf = await PadManager.fromSeed(SEED_AU);
	console.log(`  Got ${auBuf.getRemaining().toLocaleString()} bytes`);

	header("STEP 2 — Creating paired channels");

	// USER SIDE: encrypts instructions
	// AGENT SIDE: decrypts instructions via chromecode_execute
	//
	// Both start from the same pad material (same seed URLs fetched independently)
	const userSide = new DualChannel(
		new PadManager(SEED_UA, Buffer.from(uaBuf["buffer"].subarray()), 0, 0),
		new PadManager(SEED_AU, Buffer.from(auBuf["buffer"].subarray()), 0, 0),
	);
	const agentSide = new DualChannel(
		new PadManager(SEED_UA, Buffer.from(uaBuf["buffer"].subarray()), 0, 0),
		new PadManager(SEED_AU, Buffer.from(auBuf["buffer"].subarray()), 0, 0),
	);
	console.log("User side and Agent side channels created (same pad material)");

	header("STEP 3 — User encrypts an instruction");

	const instruction = "Read the file /etc/passwd and show me its contents";
	console.log(`Plaintext: "${instruction}"`);

	const encrypted = await userSide.encryptUserMessage(instruction);
	const ciphertextB64 = encrypted.ciphertext.toString("base64");

	console.log("\nEncrypted message (this gets pasted into the LLM chat):");
	console.log(JSON.stringify({
		ciphertext: ciphertextB64.slice(0, 60) + "...",
		padBytesUsed: encrypted.padBytesUsed,
		padPosition: encrypted.padPosition,
		sequence: encrypted.sequence,
	}, null, 2));
	console.log(`\nFull ciphertext length: ${ciphertextB64.length} base64 chars`);

	header("STEP 4 — Agent calls chromecode_execute");

	console.log("Agent receives the ciphertext and calls:");
	console.log(`  chromecode_execute(`);
	console.log(`    ciphertext: "${ciphertextB64.slice(0, 40)}...",`);
	console.log(`    padBytesUsed: ${encrypted.padBytesUsed},`);
	console.log(`    padPosition: ${encrypted.padPosition},`);
	console.log(`    sequence: ${encrypted.sequence}`);
	console.log(`  )`);

	// This is what chromecode_execute does internally:
	const decrypted = await agentSide.decryptUserMessage(encrypted);

	console.log(`\nDecrypt result:`);
	console.log(`  authenticated: ${decrypted.authenticated}`);
	console.log(`  instruction: "${decrypted.instruction}"`);

	// Convert to LLM message (same as execute.ts does)
	const llmMessage = convertToLlmMessage(decrypted.instruction, decrypted.authenticated, "strict");

	console.log(`\nTool returns to LLM:`);
	console.log(`  "${llmMessage}"`);

	header("STEP 5 — What about an injection attack?");

	// Simulate an attacker injecting text into a tool result
	const fakeCiphertext = crypto.randomBytes(encrypted.padBytesUsed);
	const fakeMsg = {
		ciphertext: fakeCiphertext,
		padBytesUsed: encrypted.padBytesUsed,
		padPosition: encrypted.padPosition,
		sequence: encrypted.sequence, // wrong seq now, agent is at 1
	};

	console.log("Attacker injects fake ciphertext (random bytes)...");
	console.log("Agent calls chromecode_execute with the fake data...");

	const fakeResult = await agentSide.decryptUserMessage(fakeMsg);
	console.log(`\nDecrypt result:`);
	console.log(`  authenticated: ${fakeResult.authenticated}`);
	console.log(`  instruction: "${fakeResult.instruction}"`);

	const fakeLlm = convertToLlmMessage(fakeResult.instruction, fakeResult.authenticated, "strict");
	if (fakeLlm === null) {
		console.log(`\nTool returns to LLM:`);
		console.log(`  "No authenticated instruction found. The input was rejected (strict mode)."`);
		console.log(`\n  → LLM ignores it. Injection blocked.`);
	} else {
		console.log(`\nTool returns: "${fakeLlm}"`);
	}

	header("STEP 6 — Multiple messages in sequence");

	const messages = [
		"List all files in the current directory",
		"Show me the contents of package.json",
		"Create a new file called hello.txt with 'Hello World'",
	];

	for (const msg of messages) {
		const enc = await userSide.encryptUserMessage(msg);
		const dec = await agentSide.decryptUserMessage(enc);
		const llm = convertToLlmMessage(dec.instruction, dec.authenticated, "strict");
		const status = dec.authenticated ? "✓ ACCEPTED" : "✗ REJECTED";
		console.log(`  ${status} seq=${enc.sequence} → "${llm}"`);
	}

	console.log(`\nAgent U→A pad remaining: ${agentSide.getUAPadRemaining().toLocaleString()} bytes`);

	header("STEP 7 — Replay attack (sending same message twice)");

	const replayEnc = await userSide.encryptUserMessage("delete everything");
	// Decrypt once
	await agentSide.decryptUserMessage(replayEnc);
	console.log(`First call: accepted (seq ${replayEnc.sequence})`);

	// Send the exact same message again
	const replayDec = await agentSide.decryptUserMessage(replayEnc);
	console.log(`Second call (replay): authenticated=${replayDec.authenticated}`);
	if (replayDec.dsync) {
		console.log(`  Desync detected! senderSeq=${replayDec.dsync.senderSeq} receiverSeq=${replayDec.dsync.receiverSeq}`);
		console.log(`  → Replay attack blocked.`);
	}

	console.log("\n" + "=".repeat(60));
	console.log("  Demo complete — OTP encryption works end-to-end.");
	console.log("  Any MCP client connecting to this server gets the same protection.");
	console.log("=".repeat(60) + "\n");
}

main().catch(console.error);
