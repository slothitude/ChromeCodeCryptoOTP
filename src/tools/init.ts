import { z } from "zod";
import type { ChromeCodeSession } from "../session.js";

export const initSchema = {
	userSeedUrl: z.string().describe("Seed URL for the User→Agent pad channel"),
	agentSeedUrl: z.string().describe("Seed URL for the Agent→User pad channel"),
	securityMode: z
		.enum(["strict", "lenient", "audit"])
		.optional()
		.describe("Security mode: strict (drop unauthenticated), lenient (mark), audit (pass through)"),
	privateKey: z.string().optional().describe("ECDH private key (hex) for session encryption"),
	remotePublicKey: z.string().optional().describe("ECDH remote public key (hex) for session encryption"),
};

export async function initTool(
	args: {
		userSeedUrl: string;
		agentSeedUrl: string;
		securityMode?: "strict" | "lenient" | "audit";
		privateKey?: string;
		remotePublicKey?: string;
	},
	session: ChromeCodeSession,
): Promise<{ content: Array<{ type: "text"; text: string }> }> {
	const result = await session.init(
		args.userSeedUrl,
		args.agentSeedUrl,
		args.securityMode,
		args.privateKey,
		args.remotePublicKey,
	);

	return {
		content: [
			{
				type: "text" as const,
				text: JSON.stringify({
					initialized: true,
					uaPadRemaining: result.uaPadRemaining,
					auPadRemaining: result.auPadRemaining,
					createdAt: result.createdAt,
				}),
			},
		],
	};
}
