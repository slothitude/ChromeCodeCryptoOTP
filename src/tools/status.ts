import type { ChromeCodeSession } from "../session.js";

export async function statusTool(
	_args: Record<string, never>,
	session: ChromeCodeSession,
): Promise<{ content: Array<{ type: "text"; text: string }> }> {
	return {
		content: [{ type: "text" as const, text: JSON.stringify(session.getStatus(), null, 2) }],
	};
}
