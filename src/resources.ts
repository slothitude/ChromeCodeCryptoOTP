import type { ChromeCodeSession } from "./session.js";

export function sessionResource(
	_uri: URL,
	session: ChromeCodeSession,
): { contents: Array<{ uri: string; mimeType: string; text: string }> } {
	return {
		contents: [
			{
				uri: "chromecode://session",
				mimeType: "application/json",
				text: JSON.stringify(session.getStatus(), null, 2),
			},
		],
	};
}
