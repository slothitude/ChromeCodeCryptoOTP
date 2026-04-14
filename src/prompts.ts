import { OTP_SYSTEM_PROMPT_ADDON } from "@cryptocode/otp-gate";

export function protectionPrompt(): { messages: Array<{ role: "user"; content: { type: "text"; text: string } }> } {
	return {
		messages: [
			{
				role: "user",
				content: { type: "text", text: OTP_SYSTEM_PROMPT_ADDON },
			},
		],
	};
}

export { OTP_SYSTEM_PROMPT_ADDON };
