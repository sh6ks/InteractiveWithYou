import {setGlobalOptions} from "firebase-functions";
import {onRequest} from "firebase-functions/https";
import {initializeApp} from "firebase-admin/app";
import {getFirestore, FieldValue} from "firebase-admin/firestore";
import * as tls from "node:tls";

initializeApp();
const adminDb = getFirestore();
const channelSendHistory = new Map<string, number[]>();
const channelLastSendAt = new Map<string, number>();
const commandAuditHistory = new Map<string, number[]>();

setGlobalOptions({maxInstances: 10});

/**
 * Returns a short-lived Twitch App Access Token from server-side secrets.
 *
 * Required runtime config:
 * - twitch.client_id
 * - twitch.client_secret
 *
 * Example:
 * firebase functions:config:set twitch.client_id="..." twitch.client_secret="..."
 */
export const getTwitchAppToken = onRequest(async (req, res) => {
	res.set("Access-Control-Allow-Origin", "*");
	res.set("Access-Control-Allow-Methods", "GET,OPTIONS");
	res.set("Access-Control-Allow-Headers", "Content-Type");

	if (req.method === "OPTIONS") {
		res.status(204).send("");
		return;
	}

	if (req.method !== "GET") {
		res.status(405).json({error: "Method not allowed"});
		return;
	}

	try {
		// Using config() keeps secrets server-side and out of the frontend bundle.
		// eslint-disable-next-line @typescript-eslint/no-var-requires
		const functions = require("firebase-functions");
		const clientId = functions.config()?.twitch?.client_id as string | undefined;
		const clientSecret = functions.config()?.twitch?.client_secret as string | undefined;

		if (!clientId || !clientSecret) {
			res.status(500).json({error: "Missing twitch.client_id or twitch.client_secret in functions config"});
			return;
		}

		const twitchResponse = await fetch("https://id.twitch.tv/oauth2/token", {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({
				client_id: clientId,
				client_secret: clientSecret,
				grant_type: "client_credentials",
			}),
		});

		const twitchJson = await twitchResponse.json();
		if (!twitchResponse.ok || !twitchJson?.access_token) {
			res.status(502).json({
				error: "Failed to fetch Twitch app token",
				details: twitchJson,
			});
			return;
		}

		res.status(200).json({
			access_token: twitchJson.access_token,
			expires_in: twitchJson.expires_in,
			token_type: twitchJson.token_type,
			client_id: clientId,
		});
	} catch (error) {
		res.status(500).json({
			error: "Unexpected error creating Twitch token",
			details: String(error),
		});
	}
});

function applyCors(req: any, res: any) {
	const origin = req.get("Origin") || "*";
	res.set("Access-Control-Allow-Origin", origin);
	res.set("Vary", "Origin");
	res.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
	res.set("Access-Control-Allow-Headers", "Content-Type");
}

function getTwitchClientId() {
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	const functions = require("firebase-functions");
	return (functions.config()?.twitch?.client_id as string | undefined) ||
		"9cac6zpfterkbzigfr28hpil7se9y3";
}

function normalizeChannel(value: unknown) {
	return String(value || "").trim().toLowerCase();
}

function normalizeRewardName(value: unknown) {
	return String(value || "")
		.trim()
		.toLowerCase()
		.replace(/\s+/g, " ");
}

function interpolateRedeemText(template: string, payload: {
	userDisplayName?: string;
	userLogin?: string;
	rewardName?: string;
	userInput?: string;
}) {
	const safeTemplate = String(template || "").trim();
	const userDisplayName = String(payload.userDisplayName || payload.userLogin || "viewer");
	const rewardName = String(payload.rewardName || "Canje");
	const userInput = String(payload.userInput || "");

	return safeTemplate
		.replaceAll("{user}", userDisplayName)
		.replaceAll("{reward}", rewardName)
		.replaceAll("{input}", userInput)
		.trim();
}

function normalizeToken(rawToken: string) {
	if (rawToken.startsWith("oauth:")) return rawToken.slice(6);
	return rawToken;
}

async function verifyTwitchToken(accessToken: string) {
	const clientId = getTwitchClientId();
	const response = await fetch("https://api.twitch.tv/helix/users", {
		headers: {
			"Client-ID": clientId,
			"Authorization": `Bearer ${accessToken}`,
		},
	});

	const payload = await response.json();
	if (!response.ok || !payload?.data?.[0]) {
		throw new Error(`No se pudo verificar token Twitch (${response.status})`);
	}

	const user = payload.data[0];
	return {
		id: String(user.id || ""),
		login: normalizeChannel(user.login),
		displayName: String(user.display_name || user.login || ""),
	};
}

function sendIrcPrivmsg(login: string, accessToken: string, channel: string, message: string): Promise<void> {
	return new Promise((resolve, reject) => {
		const socket = tls.connect(6697, "irc.chat.twitch.tv", () => {
			socket.write(`PASS oauth:${normalizeToken(accessToken)}\r\n`);
			socket.write(`NICK ${login}\r\n`);
			socket.write(`JOIN #${channel}\r\n`);
			setTimeout(() => {
				socket.write(`PRIVMSG #${channel} :${message}\r\n`);
				socket.write("QUIT\r\n");
				resolve();
				socket.end();
			}, 650);
		});

		socket.setTimeout(6000, () => {
			reject(new Error("Timeout enviando mensaje IRC"));
			socket.destroy();
		});

		socket.once("error", (error) => {
			reject(error);
			socket.destroy();
		});
	});
}

/**
 * Store/update Twitch bot credentials server-side for a channel.
 * POST body: { channel: string, accessToken: string, login?: string }
 */
export const storeTwitchBotToken = onRequest(async (req, res) => {
	applyCors(req, res);

	if (req.method === "OPTIONS") {
		res.status(204).send("");
		return;
	}

	if (req.method !== "POST") {
		res.status(405).json({error: "Method not allowed"});
		return;
	}

	try {
		const body = req.body || {};
		const channel = normalizeChannel(body.channel);
		const rawToken = String(body.accessToken || "").trim();
		if (!channel || !rawToken) {
			res.status(400).json({error: "channel y accessToken son requeridos"});
			return;
		}

		const token = normalizeToken(rawToken);
		const verified = await verifyTwitchToken(token);

		if (body.login && normalizeChannel(body.login) !== verified.login) {
			res.status(403).json({error: "El token no coincide con el login indicado"});
			return;
		}

		if (channel !== verified.login) {
			res.status(403).json({error: "Solo podés vincular el bot a tu propio canal"});
			return;
		}

		await adminDb.collection("twitchBots").doc(channel).set({
			channel,
			login: verified.login,
			displayName: verified.displayName,
			accessToken: token,
			source: "dashboard",
			updatedAt: FieldValue.serverTimestamp(),
		}, {merge: true});

		await adminDb.collection("usuarios").doc(channel).set({
			twitchBotLinked: true,
			twitchBotLogin: verified.login,
			updatedAt: FieldValue.serverTimestamp(),
		}, {merge: true});

		res.status(200).json({ok: true, channel, login: verified.login});
	} catch (error) {
		res.status(500).json({error: "No se pudo guardar token Twitch", details: String(error)});
	}
});

/**
 * Relay a message to Twitch chat server-side using stored bot credentials.
 * POST body: { channel: string, message: string }
 */
export const relayTwitchChatMessage = onRequest(async (req, res) => {
	applyCors(req, res);

	if (req.method === "OPTIONS") {
		res.status(204).send("");
		return;
	}

	if (req.method !== "POST") {
		res.status(405).json({error: "Method not allowed"});
		return;
	}

	try {
		const body = req.body || {};
		const channel = normalizeChannel(body.channel);
		const message = String(body.message || "").replace(/\r|\n/g, " ").trim();

		if (!channel || !message) {
			res.status(400).json({error: "channel y message son requeridos"});
			return;
		}

		if (message.startsWith("/")) {
			res.status(400).json({error: "No se permiten comandos slash en relay"});
			return;
		}

		if (message.length > 450) {
			res.status(400).json({error: "message demasiado largo"});
			return;
		}

		const now = Date.now();
		const minGapMs = 1200;
		const lastAt = channelLastSendAt.get(channel) || 0;
		if (now - lastAt < minGapMs) {
			res.status(429).json({error: "Rate limit: esperá un momento antes de enviar otro mensaje"});
			return;
		}

		const history = channelSendHistory.get(channel) || [];
		const recent = history.filter((ts) => now - ts < 60_000);
		if (recent.length >= 20) {
			channelSendHistory.set(channel, recent);
			res.status(429).json({error: "Rate limit: demasiados mensajes por minuto"});
			return;
		}

		const cfgSnap = await adminDb.collection("usuarios").doc(channel).get();
		const cfg = cfgSnap.exists ? cfgSnap.data() : null;
		if (!cfg?.sendToTwitchChat) {
			res.status(403).json({error: "sendToTwitchChat está deshabilitado para este canal"});
			return;
		}

		const botSnap = await adminDb.collection("twitchBots").doc(channel).get();
		if (!botSnap.exists) {
			res.status(404).json({error: "No hay token de bot vinculado para este canal"});
			return;
		}

		const bot = botSnap.data();
		const login = normalizeChannel(bot?.login);
		const accessToken = String(bot?.accessToken || "").trim();
		if (!login || !accessToken) {
			res.status(500).json({error: "Credenciales del bot incompletas"});
			return;
		}

		await sendIrcPrivmsg(login, accessToken, channel, message);
		recent.push(now);
		channelSendHistory.set(channel, recent);
		channelLastSendAt.set(channel, now);
		res.status(200).json({ok: true});
	} catch (error) {
		res.status(500).json({error: "No se pudo enviar mensaje a Twitch", details: String(error)});
	}
});

/**
 * Persist command execution audit logs from widget runtime.
 * POST body: {
 *   channel: string,
 *   trigger: string,
 *   userLogin: string,
 *   userDisplayName?: string,
 *   permission?: string,
 *   outcome: "executed" | "denied_permission" | "cooldown",
 *   source?: string
 * }
 */
export const logTwitchCommandExecution = onRequest(async (req, res) => {
	applyCors(req, res);

	if (req.method === "OPTIONS") {
		res.status(204).send("");
		return;
	}

	if (req.method !== "POST") {
		res.status(405).json({error: "Method not allowed"});
		return;
	}

	try {
		const body = req.body || {};
		const channel = normalizeChannel(body.channel);
		const trigger = String(body.trigger || "").trim().toLowerCase();
		const userLogin = normalizeChannel(body.userLogin);
		const userDisplayName = String(body.userDisplayName || "").trim().slice(0, 80);
		const permissionRaw = String(body.permission || "everyone").trim().toLowerCase();
		const permission = permissionRaw === "broadcaster" ? "owner" : permissionRaw;
		const outcome = String(body.outcome || "").trim().toLowerCase();
		const source = String(body.source || "widget").trim().toLowerCase().slice(0, 24);

		if (!channel || !trigger || !userLogin || !outcome) {
			res.status(400).json({error: "channel, trigger, userLogin y outcome son requeridos"});
			return;
		}

		if (!trigger.startsWith("!") || trigger.length > 32) {
			res.status(400).json({error: "trigger invalido"});
			return;
		}

		if (!["executed", "denied_permission", "cooldown"].includes(outcome)) {
			res.status(400).json({error: "outcome invalido"});
			return;
		}

		if (!["everyone", "subscriber", "mod", "owner"].includes(permission)) {
			res.status(400).json({error: "permission invalido"});
			return;
		}

		const now = Date.now();
		const history = commandAuditHistory.get(channel) || [];
		const recent = history.filter((ts) => now - ts < 60_000);
		if (recent.length >= 120) {
			commandAuditHistory.set(channel, recent);
			res.status(429).json({error: "Rate limit de auditoria excedido"});
			return;
		}

		await adminDb.collection("twitchCommandLogs").add({
			channel,
			trigger,
			userLogin,
			userDisplayName,
			permission,
			outcome,
			source,
			createdAt: FieldValue.serverTimestamp(),
		});

		recent.push(now);
		commandAuditHistory.set(channel, recent);
		res.status(200).json({ok: true});
	} catch (error) {
		res.status(500).json({error: "No se pudo guardar auditoria", details: String(error)});
	}
});

/**
 * Process a Channel Points redeem and dispatch configured overlay actions.
 *
 * POST body:
 * {
 *   channel: string,
 *   rewardName: string,
 *   userLogin?: string,
 *   userDisplayName?: string,
 *   userInput?: string,
 *   source?: string
 * }
 */
export const processChannelPointRedeem = onRequest(async (req, res) => {
	applyCors(req, res);

	if (req.method === "OPTIONS") {
		res.status(204).send("");
		return;
	}

	if (req.method !== "POST") {
		res.status(405).json({error: "Method not allowed"});
		return;
	}

	try {
		const body = req.body || {};
		const channel = normalizeChannel(body.channel);
		const rewardNameRaw = String(body.rewardName || "").trim();
		const rewardKey = normalizeRewardName(rewardNameRaw);
		const userLogin = normalizeChannel(body.userLogin);
		const userDisplayName = String(body.userDisplayName || "").trim().slice(0, 80);
		const userInput = String(body.userInput || "").trim().slice(0, 250);
		const source = String(body.source || "external").trim().toLowerCase().slice(0, 24);

		if (!channel || !rewardKey) {
			res.status(400).json({error: "channel y rewardName son requeridos"});
			return;
		}

		// Canal-only query to avoid composite indexes, then filter in memory.
		const redeemSnap = await adminDb.collection("channelPointRedeems")
			.where("canal", "==", channel)
			.get();

		if (redeemSnap.empty) {
			res.status(404).json({error: "No hay canjes configurados para este canal"});
			return;
		}

		const matchingDoc = redeemSnap.docs.find((docSnap) => {
			const data = docSnap.data();
			const enabled = data?.enabled !== false;
			const rewardName = normalizeRewardName(data?.rewardName);
			return enabled && rewardName && rewardName === rewardKey;
		});

		if (!matchingDoc) {
			res.status(404).json({
				error: "No hay coincidencia para ese rewardName",
				channel,
				rewardName: rewardNameRaw,
			});
			return;
		}

		const redeem = matchingDoc.data();
		const redeemType = String(redeem?.redeemType || "media").toLowerCase();
		const cfg = redeem?.config || {};

		const commonPayload = {
			canal: channel,
			rewardName: rewardNameRaw,
			triggeredBy: {
				userLogin,
				userDisplayName,
				userInput,
				source,
			},
			triggeredAt: FieldValue.serverTimestamp(),
		};

		if (redeemType === "emote_rain") {
			const emoteUrls = Array.isArray(cfg.emoteUrls) ? cfg.emoteUrls.filter(Boolean) : [];
			if (!emoteUrls.length) {
				res.status(400).json({error: "El canje emote_rain no tiene emoteUrls"});
				return;
			}

			await adminDb.collection("liveEffects").add({
				...commonPayload,
				effectType: "emote_rain",
				duration: Math.max(3, Number(cfg.duration) || 8),
				count: Math.max(10, Number(cfg.count) || 30),
				emoteUrls,
				status: "pending",
				createdAt: FieldValue.serverTimestamp(),
				updatedAt: FieldValue.serverTimestamp(),
			});

			res.status(200).json({
				ok: true,
				type: "emote_rain",
				matchedReward: redeem.rewardName,
			});
			return;
		}

		const mediaType = String(cfg.type || "image").toLowerCase();
		const assetUrl = String(cfg.assetUrl || "").trim();
		if (!assetUrl) {
			res.status(400).json({error: "El canje media no tiene assetUrl"});
			return;
		}

		const resolvedText = interpolateRedeemText(String(cfg.text || "Canje de puntos"), {
			userDisplayName,
			userLogin,
			rewardName: rewardNameRaw,
			userInput,
		});

		await adminDb.collection("liveAlerts").add({
			...commonPayload,
			type: ["image", "video", "sound"].includes(mediaType) ? mediaType : "image",
			eventType: "channel_points",
			nombre: String(redeem?.nombre || "Canje de puntos").trim() || "Canje de puntos",
			assetUrl,
			soundUrl: String(cfg.soundUrl || "").trim(),
			text: resolvedText,
			fontSize: Number(cfg.fontSize) || 34,
			textColor: String(cfg.textColor || "#f3efff"),
			mediaPosition: String(cfg.mediaPosition || "center"),
			animation: String(cfg.animation || "pulse"),
			status: "pending",
			createdAt: FieldValue.serverTimestamp(),
			updatedAt: FieldValue.serverTimestamp(),
		});

		res.status(200).json({
			ok: true,
			type: "media",
			matchedReward: redeem.rewardName,
		});
	} catch (error) {
		res.status(500).json({
			error: "No se pudo procesar el canje de puntos",
			details: String(error),
		});
	}
});
