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

/**
 * ChromeCode session manager.
 *
 * Maintains TWO DualChannel instances from the same pad material:
 *   - encryptChannel: user side (encrypts outgoing instructions)
 *   - decryptChannel: agent side (decrypts and validates incoming instructions)
 *
 * Both start from identical pad bytes but track positions independently,
 * matching the real two-party OTP architecture.
 */
export class ChromeCodeSession {
	/** User side — used by chromecode_encrypt */
	encryptChannel: DualChannel | null = null;
	/** Agent side — used by chromecode_execute/decrypt */
	decryptChannel: DualChannel | null = null;
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
		if (privateKey && remotePublicKey) {
			this.encryptionKey = deriveSharedKey(privateKey, remotePublicKey);
		}

		// Fetch pad material once, then create two independent copies
		const uaBuf = await this.fetchPadBytes(userSeedUrl);
		const auBuf = await this.fetchPadBytes(agentSeedUrl);

		this.encryptChannel = new DualChannel(
			new PadManager(userSeedUrl, Buffer.from(uaBuf), 0, 0),
			new PadManager(agentSeedUrl, Buffer.from(auBuf), 0, 0),
		);
		this.decryptChannel = new DualChannel(
			new PadManager(userSeedUrl, Buffer.from(uaBuf), 0, 0),
			new PadManager(agentSeedUrl, Buffer.from(auBuf), 0, 0),
		);
		this.securityMode = securityMode;

		this.state = {
			version: 1,
			channels: {
				userToAgent: this.encryptChannel.userToAgent.toState(),
				agentToUser: this.encryptChannel.agentToUser.toState(),
			},
			createdAt: new Date().toISOString(),
		};

		this.persist();
		this.saveMeta();

		return {
			uaPadRemaining: this.encryptChannel.getUAPadRemaining(),
			auPadRemaining: this.encryptChannel.getAUPadRemaining(),
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

		// Restore encrypt channel (user side)
		const encUa = await this.restorePadManager(this.state.channels.userToAgent);
		const encAu = await this.restorePadManager(this.state.channels.agentToUser);
		this.encryptChannel = new DualChannel(encUa, encAu);

		// Restore decrypt channel (agent side) from same state
		const decUa = await this.restorePadManager(this.state.channels.userToAgent);
		const decAu = await this.restorePadManager(this.state.channels.agentToUser);
		this.decryptChannel = new DualChannel(decUa, decAu);

		this.loadMeta();
	}

	/** Persist current state to disk (from encrypt channel). */
	persist(): void {
		if (!this.encryptChannel || !this.state) return;

		this.state.channels.userToAgent = this.encryptChannel.userToAgent.toState();
		this.state.channels.agentToUser = this.encryptChannel.agentToUser.toState();

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
		return this.encryptChannel !== null && this.decryptChannel !== null && this.state !== null;
	}

	/** Ensure session is initialized, restoring if needed. Returns the encrypt channel. */
	async ensureEncryptReady(): Promise<DualChannel> {
		if (!this.encryptChannel) await this.restore();
		if (!this.encryptChannel) throw new Error("Session not initialized. Call chromecode_init first.");
		return this.encryptChannel;
	}

	/** Ensure session is initialized, restoring if needed. Returns the decrypt channel. */
	async ensureDecryptReady(): Promise<DualChannel> {
		if (!this.decryptChannel) await this.restore();
		if (!this.decryptChannel) throw new Error("Session not initialized. Call chromecode_init first.");
		return this.decryptChannel;
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
		if (!this.encryptChannel || !this.decryptChannel || !this.state) {
			return { initialized: false };
		}
		return {
			initialized: true,
			uaPadRemaining: this.decryptChannel.getUAPadRemaining(),
			auPadRemaining: this.encryptChannel.getAUPadRemaining(),
			uaSequence: this.decryptChannel.userToAgent.getSequence(),
			auSequence: this.encryptChannel.agentToUser.getSequence(),
			securityMode: this.securityMode,
			createdAt: this.state.createdAt,
		};
	}

	/** Fetch raw pad bytes from a URL. */
	private async fetchPadBytes(url: string): Promise<Buffer> {
		const pm = await PadManager.fromSeed(url);
		// Extract the full buffer contents for cloning into two channels
		const buf = pm["buffer"] as Buffer;
		return Buffer.from(buf);
	}

	/** Restore a PadManager from persisted channel state. */
	private async restorePadManager(ch: { currentUrl: string; position: number; lowWaterMark: number }): Promise<PadManager> {
		const pm = new PadManager(ch.currentUrl, undefined, 0, ch.lowWaterMark);
		await pm.appendFromUrl(ch.currentUrl);
		if (ch.position > 0) await pm.advance(ch.position);
		return pm;
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
