import { z } from "zod";
import type { ChromeCodeSession } from "../session.js";
import type { EncryptedMessage } from "@cryptocode/otp-core";
import { convertToLlmMessage } from "@cryptocode/otp-gate";

export const executeSchema = {
	ciphertext: z.string().describe("Base64-encoded ciphertext of the user instruction"),
	padBytesUsed: z.number().describe("Number of pad bytes consumed during encryption"),
	padPosition: z.number().describe("Pad position when the message was encrypted"),
	sequence: z.number().describe("Sequence number from encryption"),
};

export async function executeTool(
	args: { ciphertext: string; padBytesUsed: number; padPosition: number; sequence: number },
	session: ChromeCodeSession,
): Promise<{ content: Array<{ type: "text"; text: string }> }> {
	const channel = await session.ensureReady();

	const msg: EncryptedMessage = {
		ciphertext: Buffer.from(args.ciphertext, "base64"),
		padBytesUsed: args.padBytesUsed,
		padPosition: args.padPosition,
		sequence: args.sequence,
	};

	const result = await channel.decryptUserMessage(msg);

	// Auto-resync if threshold reached
	if (!result.authenticated && channel.shouldAutoResyncUA()) {
		await channel.autoRecover("userToAgent");
	}

	session.persist();

	// Convert to LLM message with authentication marker
	const llmMessage = convertToLlmMessage(
		result.instruction,
		result.authenticated,
		session.securityMode,
	);

	if (llmMessage === null) {
		return {
			content: [
				{
					type: "text" as const,
					text: "No authenticated instruction found. The input was rejected (strict mode).",
				},
			],
		};
	}

	return {
		content: [{ type: "text" as const, text: llmMessage }],
	};
}
