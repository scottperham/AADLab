
async function callAPI(uri, body, bearerToken, returnType) {

	const request = {
		method: !!body ? "POST" : "GET",
		headers: {
			"Content-Type": "application/json"
		}
	}

	if (body) {
		request["body"] = JSON.stringify(body);
	}

	if (bearerToken) {
		request.headers["Authorization"] = "Bearer " + bearerToken;
	}

	let error = null;

	try {

		const response = await fetch(uri, request);

		if (!response.ok) {
			return { success: false, error: await response.text(), result: null };
		}

		let result = null;

		switch (returnType) {
			case "text":
				result = await response.text();
				break;
			case "blob":
				result = await response.blob();
				break;
			default:
				result = await response.json();
				break;
		}

		return { success: true, error: null, result: result };
	}
	catch (ex) {
		error = ex;
	}


	return { success: false, error: error, result: null };
}

let msalInstance = null;
const storage = window.localStorage;
const scopes = ["api://ec9418a2-c3a2-477e-ab46-2796cfc9208d/access_as_user", "User.Read", "profile"];

function setUserChanged(user, aadToken, apiToken, graphToken, link) {
	window.loggedInUser = { user, aadToken, apiToken, graphToken, link };
}

function getUser() {
	return window.loggedInUser;
}

function cacheServerToken(refreshToken, tokenExpiry) {
	storage.setItem("server_token", JSON.stringify({ refreshToken: refreshToken, tokenExpiry: tokenExpiry }));
}

function getServerToken() {
	const json = storage.getItem("server_token");
	return json ? JSON.parse(json) : null;
}

function msalInit() {
	if (!msal) {
		throw "Need to include msal.js";
	}

	if (!msalInstance) {
		msalInstance = new msal.PublicClientApplication({
			auth: {
				clientId: "ec9418a2-c3a2-477e-ab46-2796cfc9208d",
				redirectUri: "https://localhost:44371/"
			},
			cache: {
				cacheLocation: "localStorage"
			}
		});
	}
}

function requireMsal() {
	if (!msalInstance) {
		msalInit();
	}
}

async function signInLocal(email, password) {
	const { success, error, result } = await callAPI("/api/loginLocal", {
		email: email,
		password: password
	});

	if (success) {
		setUserChanged(result.displayName, null, result.accessToken, null, false);
		cacheServerToken(result.refreshToken, result.tokenExpiry);
	}

	return [success, error];
}

async function signInFromAuthCodeRedirect() {
	requireMsal();

	try {

		const authResult = await msalInstance.handleRedirectPromise();

		if (authResult) {
			return await handleMsalToken(authResult.accessToken);
		}
	}
	catch (err) {
		console.log("Login failed or interrupted: " + err);
	}

	return false;
}

async function signInLocalSilent() {
	const serverToken = getServerToken();

	if (!serverToken) {
		return false;
	}

	//Check expiry date of refresh token
	//if (serverToken.expiry) ...

	const { success, error, result } = await callAPI("/api/refreshToken", {
		token: serverToken.refreshToken
	});

	if (success) {
		setUserChanged(result.displayName, null, result.accessToken, null, false);
		cacheServerToken(result.refreshToken, result.tokenExpiry);
	}

	return [success, error];
}

async function signOut() {
	requireMsal();

	storage.removeItem("server_token");

	const accounts = msalInstance.getAllAccounts();

	if (accounts.length === 0) {
		return;
	}

	msalInstance.logout({
		postLogoutRedirectUri: "/login"
	});
}

async function handleMsalToken(accessToken) {
	const { success, result } = await callAPI("/api/loginWithToken", { accessToken: accessToken });

	if (success) {

		if (result.requireLink) {
			setUserChanged(result.displayName, accessToken, null, null, true);
		}
		else {
			setUserChanged(result.displayName, accessToken, result.accessToken, result.graphAccessToken, false);
			cacheServerToken(result.refreshToken, result.tokenExpiry);
		}
	}

	return success;
}

async function linkIdentity(accessToken, link) {
	const { success, result } = await callAPI("/api/linkWithIdentity", { accessToken: accessToken, link: link });

	if (success) {
		setUserChanged(result.displayName, accessToken, result.accessToken, result.graphAccessToken);
		cacheServerToken(result.refreshToken, result.tokenExpiry);
	}

	return success;
}

async function signInAADSilent() {
	requireMsal();

	const accounts = msalInstance.getAllAccounts();

	if (accounts.length === 0) {
		return false;
	}

	msalInstance.setActiveAccount(accounts[0]);

	const authResult = await msalInstance.acquireTokenSilent({
		scopes: scopes,

	});

	return await handleMsalToken(authResult.accessToken);
}

function signInAADRedirect() {
	requireMsal();

	msalInstance.loginRedirect({
		scopes: scopes,
		redirectStartPage: "/profile"
	});
}

async function signInAADPopup() {
	requireMsal();

	try {
		const authResult = await msalInstance.loginPopup({
			scopes: scopes
		});

		await handleMsalToken(authResult.accessToken);

		window.location.href = "/profile";
	}
	catch (err) {
		console.log("Login failed or interrupted: " + err);
	}
}

async function tryLoginUserSilent() {
	if (await signInFromAuthCodeRedirect()) {
		return true;
	}

	if (await signInAADSilent()) {
		return true;
	}

	return await signInLocalSilent();
}

$(async () => {

	const isLoggedIn = await tryLoginUserSilent();

	if (isLoggedIn && getUser().link && !location.href.endsWith("/link")) {
		location.href = "/link";
	}

	$.event.trigger({
		type: "ssoComplete"
	});
});