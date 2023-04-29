# Facebook OpenID Connect example

this project is an example on how to authenticate on facebook's using OIDC.

## Setup

### Step 1 - Create an Facebook's App
Guide: [https://developers.facebook.com/docs/development/create-an-app/](https://developers.facebook.com/docs/development/create-an-app/)

In the APP dashboard, go to `Add a product` section and set up `Facebook Login`, then set `https://oidcdebugger.com/debug` in the `Valid OAuth Redirect URIs`.

### Step 2 - Configure the project
Copy the `.env.example` file
```bash
cp .env.example .env
```
Then replace the `FACEBOOK_CLIENT_ID` in `.env` with the App ID created in the Step 1.

### Step 3 - Start the Server
Install NPM dependencies
```bash
npm install
```
And start the server
```bash
npm start
```

### Step 3 - Login with Facebook
With the server running, open your browser and access [GET http://localhost:8080/facebook/login](http://localhost:8080/facebook/login)

You will be redirected to Facebook's Login page, allow and continue.

Currently facebook's OIDC only allows `response_mode=fragment`, which means only the web browser can collect the response payload. Even with a frontend, facebook's only accepts HTTPS Url's in `Valid OAuth Redirect URIs`. So to keep this example simple, you have to manually copy both `id_token` and `state`, then submit it to `POST http://localhost:8080/facebook/login`:
```json
POST /facebook/login HTTP/1.1
Host: localhost:8080
Content-type: application/json

{
    "id_token": "...",
    "state": "..."
}
```
If everything works fine, the server will return an `access_token` and yours `user_id`:
```json
{
	"access_token": "9QTBqIpx_lRw__n5hNlPHSesg7Cj4rDClFPUJGNLbVM",
	"user_id": "facebook-10210838168466201",
	"expires_at": 1682895312675,
	"token_type": "bearer"
}
```
Now you can use that `access_token` to access protected routes, like `GET /user-info`.

> Note: In the real world, the front-end app will collect the `id_token` and `state` and automatically call the `POST http://localhost:8080/facebook/login`, but without `https` we can't redirect facebook's response to our route, we could use a tool like [ngrok](https://ngrok.com/) to solve this issue, but implementing a front-end and configuring ngrok is out of the scope of this example project.


## Facebook's OIDC
Currently, facebook only support **OIDC Implicit Flow**, notice that in facebook's [openid-configuration](https://www.facebook.com/.well-known/openid-configuration/) the `response_types_supported` doesn't list `code`, also the `token_endpoint` is missing:
```json
{
   "issuer": "https://www.facebook.com",
   "authorization_endpoint": "https://facebook.com/dialog/oauth/",
   "jwks_uri": "https://www.facebook.com/.well-known/oauth/openid/jwks/",
   "response_types_supported": [
      "id_token",
      "token id_token"
   ],
   "subject_types_supported": [
      "pairwise"
   ],
   "id_token_signing_alg_values_supported": [
      "RS256"
   ],
   "claims_supported": [
      "iss",
      "aud",
      "sub",
      "iat",
      "exp",
      "jti",
      "nonce",
      "at_hash",
      "name",
      "given_name",
      "middle_name",
      "family_name",
      "email",
      "picture",
      "user_friends",
      "user_birthday",
      "user_age_range",
      "user_link",
      "user_hometown",
      "user_location",
      "user_gender"
   ]
}
```
For more information about `.well-known/openid-configuration`, check the [RFC section 4.2](https://openid.net/specs/openid-connect-discovery-1_0.html#rfc.section.4.2).
