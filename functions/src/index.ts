import {setGlobalOptions} from "firebase-functions";
import {onRequest} from "firebase-functions/https";

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
