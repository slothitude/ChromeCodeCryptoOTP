import { z } from "zod";
import type { ChromeCodeSession } from "../session.js";
import type { EncryptedMessage } from "@cryptocode/otp-core";

export const decryptSchema = {
	ciphertext: z.string().describe("Base64-encoded ciphertext"),
	padBytesUsed: z.number().describe("Number of pad bytes consumed during encryption"),
	padPosition: z.number().describe("Pad position when the message was encrypted"),
	sequence: z.number().describe("Sequence number from encryption"),
};

export async function decryptTool(
	args: { ciphertext: string; padBytesUsed: number; padPosition: number; sequence: number },
	session: ChromeCodeSession,
): Promise<{ content: Array<{ type: "text"; text: string }> }> {
	const channel = await session.ensureDecryptReady();

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

	return {
		content: [
			{
				type: "text" as const,
				text: JSON.stringify({
					authenticated: result.authenticated,
					instruction: result.instruction,
					nextUrl: result.nextUrl,
					desync: result.dsync ?? null,
				}),
			},
		],
	};
}
