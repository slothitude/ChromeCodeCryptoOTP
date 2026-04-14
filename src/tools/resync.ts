import { z } from "zod";
import type { ChromeCodeSession } from "../session.js";

export const resyncSchema = {
	channel: z
		.enum(["userToAgent", "agentToUser"])
		.describe("Which channel to resync"),
};

export async function resyncTool(
	args: { channel: "userToAgent" | "agentToUser" },
	session: ChromeCodeSession,
): Promise<{ content: Array<{ type: "text"; text: string }> }> {
	const ch = await session.ensureDecryptReady();
	const recoveryUrl = await ch.recoverFromDesync(args.channel);
	session.persist();

	const remaining =
		args.channel === "userToAgent"
			? ch.getUAPadRemaining()
			: ch.getAUPadRemaining();

	return {
		content: [
			{
				type: "text" as const,
				text: JSON.stringify({
					recovered: true,
					recoveryUrl,
					padRemaining: remaining,
				}),
			},
		],
	};
}
