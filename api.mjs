import express from "express";
import * as dotenv from 'dotenv';
import bodyParser from "body-parser";
import { Issuer, generators } from 'openid-client';
import { Authenticator } from 'passport';
import { Strategy } from 'passport-http-bearer';

// APP Settings
dotenv.config();
const {
    FACEBOOK_CLIENT_ID,
    FACEBOOK_REDIRECT_URL, // MUST BE CONFIGURED IN THE FACEBOOK's APP -> Settings -> Facebook Login -> Valid OAuth Redirect URIs
    APP_PORT,
} = process.env;

// Facebook OIDC Client
const facebookIssuer = await Issuer.discover('https://www.facebook.com/.well-known/openid-configuration'); 
const facebookClient = new facebookIssuer.Client({
    client_id: FACEBOOK_CLIENT_ID,
    redirect_uris: [FACEBOOK_REDIRECT_URL],
    response_types: ['id_token'], // Facebook only supports Implicit Flow
});

// Express Settings
const app = express();
app.use(bodyParser.json());     // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({ // to support URL-encoded bodies
  extended: true
}));

// Database Mock
const DATABASE = {
    // LOGIN_STATES Table
    states: {},

    // USERS Table
    users: {},

    // SESSIONS Table
    sessions: {},
};

// Passport Authenticator Settings
const authenticator = new Authenticator();
authenticator.use(new Strategy(
    function(token, done) {
        // checks if the access_token exists in the database
        const session = DATABASE.sessions[token];
        if (!session) {
            return done('unauthorized', false);
        }

        // checks if the access_token has expired
        if (Date.now() >= session.expires_at) {
            // deletes the session from the database
            delete DATABASE.sessions[token];
            return done('session expired', false);
        }

        // returns the session
        return done(null, session, { scope: 'all' });
    }
));

/**
 * Initiate the facebook login process
 * first it creates and store the session's state and nonce, then the user
 * is redirect to facebook's authorization endpoint
 */
app.get('/facebook/login', async (req, res) => {
    // Creates a random state and nonce
    const state = generators.state();
    const nonce = generators.nonce();

    // Stores the state and nonce in the database
    DATABASE.states[state] = {
        nonce,
        expires_at: Date.now() + (15 * 60 * 1000), // expires in 15 minutes
    };

    // Creates the authorization URL
    const authorizationUrl = facebookClient.authorizationUrl({
        scope: 'openid',
        response_mode: 'fragment',
        state,
        nonce,
    });

    // Redirects the user to facebook's authorization url
    res.redirect(authorizationUrl);
});

/**
 * This endpoint authenticates the user with facebook
 * first the user must provide the state and id_token, then the state is validated
 * and the id_token is verified
 */
app.post('/facebook/login', async (req, res) => {
    const { state, id_token } = req.body;

    // Check if the id_token was provided
    if (!id_token) {
        res.status(412).json({ error: 'id_token is required' });
        return;
    }

    // Check if the state provided exists in the database
    if (!state || !DATABASE.states[state]) {
        res.status(400).json({ error: 'Invalid state' });
        return;
    }

    // Check if the state has expired
    const { nonce, expires_at } = DATABASE.states[state];
    if (Date.now() >= expires_at) {
        // Delete the state from the database
        delete DATABASE.states[state];
       
        // Return an error
        res.status(400).json({ error: 'this state has expired' });
        return;
    }

    let tokenSet;
    try {
        // Ref: https://github.com/panva/node-openid-client/blob/v5.4.2/lib/client.js#L875-L1059
        //
        // 1 - Check if the id_token is a valid JWT
        // 2 - Check if the id_token has expired
        // 3 - Check if the id_token's payload.aud is equal to FACEBOOK_CLIENT_ID
        // 4 - Check if the id_token's payload.iss is equal to the facebook's issuer
        // 5 - Check if the id_token's payload.nonce is equal to the state's nonce
        // 6 - Check if the id_token's header.alg is listed in the facebook's jwks_uri
        // 7 - Check if the id_token's signature was signed by one of facebook's jwks_uri public keys
        tokenSet = await facebookClient.callback(
            FACEBOOK_REDIRECT_URL,
            { id_token, response_type: 'id_token' },
            { nonce }
        );
    } catch(error) {
        // If the id_token is invalid, return an error
        res.status(400).json({ error: error.message });
        return;
    }

    // the id_token is valid, so we can delete the state from the database
    delete DATABASE.states[state];

    // read the user information from the id_token
    const { sub, name } = tokenSet.claims();
    
    // verifies if the user is already registered in the database
    const user_id = `facebook-${sub}`;
    if (!DATABASE.users[user_id]) {
        // if not, register the user in the database
        DATABASE.users[user_id] = {
            id: user_id,
            name,
            created_at: Date.now(),
        };
    }

    // creates a new session for the user
    const session = {
        access_token: generators.random(),
        user_id: user_id,
        expires_at: Date.now() + (24 * 60 * 60 * 1000), // expires in 24 hours
        token_type: 'bearer',
    };

    // stores the session in the database
    DATABASE.sessions[session.access_token] = session;

    // returns the access_token and the expires_at timestamp
    res.status(200).json(session);
});

/**
 * protected endpoint to retrieve the user information
 **/ 
app.get('/user-info', authenticator.authenticate('bearer', { session: false }), (req, res) => {
    const session = req.user;

    // read the user_id from the session
    const { user_id } = session;

    // retrieves the user from the database
    const user = DATABASE.users[user_id];

    // returns the user information
    res.status(200).json(user)
});

// starts the server
app.listen(APP_PORT, () => {
    console.log(`App listening at http://localhost:${APP_PORT}`)
})
