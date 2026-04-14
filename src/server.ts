import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ChromeCodeSession } from "./session.js";
import { initTool, initSchema } from "./tools/init.js";
import { encryptTool, encryptSchema } from "./tools/encrypt.js";
import { decryptTool, decryptSchema } from "./tools/decrypt.js";
import { executeTool, executeSchema } from "./tools/execute.js";
import { statusTool } from "./tools/status.js";
import { resyncTool, resyncSchema } from "./tools/resync.js";
import { protectionPrompt, OTP_SYSTEM_PROMPT_ADDON } from "./prompts.js";
import { sessionResource } from "./resources.js";

/** Shared session instance for all tool handlers. */
export const session = new ChromeCodeSession();

/** Create and configure the MCP server with all tools, prompts, and resources. */
export function createServer(): McpServer {
	const server = new McpServer(
		{ name: "chromecode-crypto-otp", version: "1.0.0" },
		{ instructions: OTP_SYSTEM_PROMPT_ADDON },
	);

	// Tools
	server.tool(
		"chromecode_init",
		"Initialize a new OTP session with seed URLs for both pad channels",
		initSchema,
		async (args) => initTool(args, session),
	);

	server.tool(
		"chromecode_encrypt",
		"Encrypt a plaintext message using the OTP. Returns base64 ciphertext with pad metadata.",
		encryptSchema,
		async (args) => encryptTool(args, session),
	);

	server.tool(
		"chromecode_decrypt",
		"Decrypt ciphertext and verify authenticity via OTP envelope validation",
		decryptSchema,
		async (args) => decryptTool(args, session),
	);

	server.tool(
		"chromecode_execute",
		"Proxy tool: decrypt ciphertext, verify authenticity, and return [AUTHENTICATED] or [UNAUTHENTICATED] message",
		executeSchema,
		async (args) => executeTool(args, session),
	);

	server.tool(
		"chromecode_status",
		"Get current session status: pad remaining, sequences, security mode",
		{},
		async () => statusTool({}, session),
	);

	server.tool(
		"chromecode_resync",
		"Recover from pad desync on a specific channel by re-fetching the last successful URL",
		resyncSchema,
		async (args) => resyncTool(args, session),
	);

	// Prompt
	server.prompt(
		"chromecode_protection",
		"Returns the OTP system prompt addon with authentication rules for the LLM",
		{},
		async () => protectionPrompt(),
	);

	// Resource
	server.registerResource(
		"session",
		"chromecode://session",
		{ description: "Current OTP session state", mimeType: "application/json" },
		async (uri: URL) => sessionResource(uri, session),
	);

	return server;
}
