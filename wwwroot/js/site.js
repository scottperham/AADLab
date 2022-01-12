
// Helper function to call backend API methods
async function callAPI(uri, body, bearerToken, returnType) {

	//Build the request based on whether there is a body
	//This method could be tweaked if there are more required verbs or there are POSTS that don't require a body
	const request = {
		method: !!body ? "POST" : "GET",
		headers: {
			"Content-Type": "application/json"
		}
	}

	//Add the body to the request
	if (body) {
		request["body"] = JSON.stringify(body);
	}

	//If there was a bearer token passed, add that to the request
	if (bearerToken) {
		request.headers["Authorization"] = "Bearer " + bearerToken;
	}

	let error = null;

	try {

		//Try to send the request
		const response = await fetch(uri, request);

		//Was it successful...?
		if (!response.ok) {
			return { success: false, error: await response.text(), result: null };
		}

		let result = null;

		//Set the result value to the appropriate data type depending on the expected response type
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
const scopes = ["api://" + window.global.clientId + "/access_as_user", "User.Read", "profile"];

//When the user changes, cache the data globally for easy access
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

//Initialises the msal library
function msalInit() {
	if (!msal) {
		throw "Need to include msal.js";
	}

	//Noddy singleton implementation
	if (!msalInstance) {
		msalInstance = new msal.PublicClientApplication({
			auth: {
				clientId: window.global.clientId,
				redirectUri: location.protocol + '//' + location.host
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

//Try to sign in the user with a locally defined email and password
async function signInLocal(email, password) {
	const { success, error, result } = await callAPI("/api/loginLocal", {
		email: email,
		password: password
	});

	if (success) {
		//Save the user info
		setUserChanged(result.displayName, null, result.accessToken, null, false);
		//Save the refresh token info
		cacheServerToken(result.refreshToken, result.tokenExpiry);
	}

	return [success, error];
}

//Attempt to sign in the user after an auth code redirect
//This will happen after successful AAD sign in using AuthCode
async function signInFromAuthCodeRedirect() {
	requireMsal();

	try {

		const authResult = await msalInstance.handleRedirectPromise();

		if (authResult) {
			//Swap the AAD token for a server token
			return await handleMsalToken(authResult.accessToken);
		}
	}
	catch (err) {
		console.log("Login failed or interrupted: " + err);
	}

	return false;
}

//Attempt to sign in the user using locally cached credentials
//This will work if there is a locally cached refresh token
async function signInLocalSilent() {
	const serverToken = getServerToken();

	if (!serverToken) {
		return false;
	}

	//TODO: Check expiry date of refresh token
	//if (serverToken.expiry) ...

	//If there is a refresh token saved, ask the server for a new server access token
	const { success, error, result } = await callAPI("/api/refreshToken", {
		token: serverToken.refreshToken
	});

	if (success) {
		//Save the user info
		setUserChanged(result.displayName, null, result.accessToken, null, false);
		//Save the refresh token info
		cacheServerToken(result.refreshToken, result.tokenExpiry);
	}

	return [success, error];
}

//Sign out the current user
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

//Handles the backend mapping of users when logged in using AAD
async function handleMsalToken(accessToken) {
	const { success, result } = await callAPI("/api/loginWithToken", { accessToken: accessToken });

	if (success) {

		//If the user has a local account but this is the first time they've logged in with AAD
		//save this info so we can ask the user if they want the accounts linked
		if (result.requireLink) {
			setUserChanged(result.displayName, accessToken, null, null, true);
		}
		else {
			//Save the users info locally
			setUserChanged(result.displayName, accessToken, result.accessToken, result.graphAccessToken, false);
			//Save the refresh token info
			cacheServerToken(result.refreshToken, result.tokenExpiry);
		}
	}

	return success;
}

//Link the current AAD identity with their locally created identity
async function linkIdentity(accessToken, link) {
	const { success, result } = await callAPI("/api/linkWithIdentity", { accessToken: accessToken, link: link });

	if (success) {
		setUserChanged(result.displayName, accessToken, result.accessToken, result.graphAccessToken);
		cacheServerToken(result.refreshToken, result.tokenExpiry);
	}

	return success;
}

//Attempts to sign in a user without prompting for username and password
async function signInAADSilent() {
	requireMsal();

	const accounts = msalInstance.getAllAccounts();

	if (accounts.length === 0) {
		return false;
	}

	msalInstance.setActiveAccount(accounts[0]);

	//Attempt the sign in...
	const authResult = await msalInstance.acquireTokenSilent({
		scopes: scopes,

	});

	return await handleMsalToken(authResult.accessToken);
}

//Sign in using AAD by redirecting the page to the Microsoft login page
//If this is successful if will redirect to `redirectStartPage` with an AuthCode
function signInAADRedirect() {
	requireMsal();

	msalInstance.loginRedirect({
		scopes: scopes,
		redirectStartPage: "/profile"
	});
}

//Sign in using AAD by opening a popup window
//This method is useful if the application is running inside an IFrame
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

//Try to silently sign in the user from either and AuthCode in the url, cached AAD tokens (via the msal library) or cached refresh token
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

	//If the user needs to be asked whether they should link their account
	//redirect...
	if (isLoggedIn && getUser().link && !location.href.endsWith("/link")) {
		location.href = "/link";
	}

	//Tell everyone that sso is complete! (At least, it was attempted)
	$.event.trigger({
		type: "ssoComplete"
	});
});