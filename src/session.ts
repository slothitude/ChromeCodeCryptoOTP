import {
	PadManager,
	saveSession,
	loadSession,
	sessionExists,
	setConfigDirOverride,
	deriveSharedKey,
	encryptSessionState,
	decryptSessionState,
} from "@cryptocode/otp-core";
import { DualChannel } from "@cryptocode/otp-gate";
import type { SessionState, SecurityMode } from "@cryptocode/otp-core";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

const CONFIG_DIR = path.join(os.homedir(), ".chromecode");
const META_FILE = path.join(CONFIG_DIR, "meta.json");

interface Meta {
	securityMode: SecurityMode;
}

// Override config dir at module load so otp-core writes to ~/.chromecode
setConfigDirOverride(CONFIG_DIR);

/** ChromeCode session manager wrapping DualChannel with persistence. */
export class ChromeCodeSession {
	channel: DualChannel | null = null;
	state: SessionState | null = null;
	securityMode: SecurityMode = "strict";
	private encryptionKey: Buffer | undefined;

	/** Initialize a new OTP session with seed URLs. */
	async init(
		userSeedUrl: string,
		agentSeedUrl: string,
		securityMode: SecurityMode = "strict",
		privateKey?: string,
		remotePublicKey?: string,
	): Promise<{ uaPadRemaining: number; auPadRemaining: number; createdAt: string }> {
		// ECDH handshake if keys provided
		if (privateKey && remotePublicKey) {
			this.encryptionKey = deriveSharedKey(privateKey, remotePublicKey);
		}

		const uaPad = await PadManager.fromSeed(userSeedUrl);
		const auPad = await PadManager.fromSeed(agentSeedUrl);
		this.channel = new DualChannel(uaPad, auPad);
		this.securityMode = securityMode;

		this.state = {
			version: 1,
			channels: {
				userToAgent: uaPad.toState(),
				agentToUser: auPad.toState(),
			},
			createdAt: new Date().toISOString(),
		};

		this.persist();
		this.saveMeta();

		return {
			uaPadRemaining: uaPad.getRemaining(),
			auPadRemaining: auPad.getRemaining(),
			createdAt: this.state.createdAt,
		};
	}

	/** Restore a previously persisted session. */
	async restore(): Promise<void> {
		if (!sessionExists() && !this.hasEncryptedSession()) {
			throw new Error("No session found. Call chromecode_init first.");
		}

		if (this.encryptionKey && this.hasEncryptedSession()) {
			const encPath = path.join(CONFIG_DIR, "session.enc");
			const encrypted = fs.readFileSync(encPath);
			this.state = decryptSessionState(encrypted, this.encryptionKey);
		} else {
			this.state = loadSession();
		}

		const ua = this.state.channels.userToAgent;
		const uaPad = new PadManager(ua.currentUrl, undefined, 0, ua.lowWaterMark);
		await uaPad.appendFromUrl(ua.currentUrl);
		if (ua.position > 0) await uaPad.advance(ua.position);

		const au = this.state.channels.agentToUser;
		const auPad = new PadManager(au.currentUrl, undefined, 0, au.lowWaterMark);
		await auPad.appendFromUrl(au.currentUrl);
		if (au.position > 0) await auPad.advance(au.position);

		this.channel = new DualChannel(uaPad, auPad);
		this.loadMeta();
	}

	/** Persist current state to disk. */
	persist(): void {
		if (!this.channel || !this.state) return;

		// Update state from channel managers
		this.state.channels.userToAgent = this.channel.userToAgent.toState();
		this.state.channels.agentToUser = this.channel.agentToUser.toState();

		if (this.encryptionKey) {
			const encrypted = encryptSessionState(this.state, this.encryptionKey);
			fs.mkdirSync(CONFIG_DIR, { recursive: true });
			fs.writeFileSync(path.join(CONFIG_DIR, "session.enc"), encrypted);
		} else {
			saveSession(this.state);
		}
	}

	/** Check if the session is initialized. */
	isInitialized(): boolean {
		return this.channel !== null && this.state !== null;
	}

	/** Ensure session is initialized, restoring if needed. */
	async ensureReady(): Promise<DualChannel> {
		if (!this.channel) await this.restore();
		if (!this.channel) throw new Error("Session not initialized. Call chromecode_init first.");
		return this.channel;
	}

	/** Get current status info. */
	getStatus(): {
		initialized: boolean;
		uaPadRemaining?: number;
		auPadRemaining?: number;
		uaSequence?: number;
		auSequence?: number;
		securityMode?: SecurityMode;
		createdAt?: string;
	} {
		if (!this.channel || !this.state) {
			return { initialized: false };
		}
		return {
			initialized: true,
			uaPadRemaining: this.channel.getUAPadRemaining(),
			auPadRemaining: this.channel.getAUPadRemaining(),
			uaSequence: this.channel.userToAgent.getSequence(),
			auSequence: this.channel.agentToUser.getSequence(),
			securityMode: this.securityMode,
			createdAt: this.state.createdAt,
		};
	}

	private hasEncryptedSession(): boolean {
		return fs.existsSync(path.join(CONFIG_DIR, "session.enc"));
	}

	private saveMeta(): void {
		fs.mkdirSync(CONFIG_DIR, { recursive: true });
		const meta: Meta = { securityMode: this.securityMode };
		fs.writeFileSync(META_FILE, JSON.stringify(meta, null, 2), "utf-8");
	}

	private loadMeta(): void {
		if (fs.existsSync(META_FILE)) {
			const meta: Meta = JSON.parse(fs.readFileSync(META_FILE, "utf-8"));
			this.securityMode = meta.securityMode;
		}
	}
}
