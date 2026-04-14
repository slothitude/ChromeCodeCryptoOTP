import { z } from "zod";
import type { ChromeCodeSession } from "../session.js";

export const encryptSchema = {
	plaintext: z.string().describe("The plaintext message to encrypt"),
	nextUrl: z.string().optional().describe("Next pad refill URL to embed in the envelope"),
};

export async function encryptTool(
	args: { plaintext: string; nextUrl?: string },
	session: ChromeCodeSession,
): Promise<{ content: Array<{ type: "text"; text: string }> }> {
	const channel = await session.ensureEncryptReady();
	const encrypted = await channel.encryptUserMessage(args.plaintext, args.nextUrl);
	session.persist();

	return {
		content: [
			{
				type: "text" as const,
				text: JSON.stringify({
					ciphertext: encrypted.ciphertext.toString("base64"),
					padBytesUsed: encrypted.padBytesUsed,
					padPosition: encrypted.padPosition,
					sequence: encrypted.sequence,
				}),
			},
		],
	};
}
