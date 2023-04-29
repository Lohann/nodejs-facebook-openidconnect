import express from "express";
import * as dotenv from 'dotenv';
import bodyParser from "body-parser";
import { Issuer, generators } from 'openid-client';

// Configurações
dotenv.config();
const {
    FACEBOOK_CLIENT_ID,
    FACEBOOK_REDIRECT_URL, // Precisa ser HTTPS, lembre de cadastrar em 
    APP_PORT,
} = process.env;

// Facebook OIDC Client
const facebookIssuer = await Issuer.discover('https://www.facebook.com');
const facebookClient = new facebookIssuer.Client({
    client_id: FACEBOOK_CLIENT_ID,
    redirect_uris: [FACEBOOK_REDIRECT_URL],
    response_types: ['id_token'], // Facebook only supports Implicit Flow
});

// Configurações do EXPRESS
const app = express();

app.use(bodyParser.json());     // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({ // to support URL-encoded bodies
  extended: true
}));

// Mock de um banco de dados
const DATABASE = {
    // Tabela LOGIN_STATES
    states: {},

    // Tabela USERS
    users: {},

    // Tabela SESSIONS
    sessions: {},
};

/**
 * Endpoint que inicia o processo de login com o facebook
 * São persistidos um state e nonce aleatórios e então o usuário é redirecionado para a URL de autorização do facebook
 */
app.get('/facebook/login', async (req, res) => {
    // Cria um state e um nonce aleatórios
    const state = generators.state();
    const nonce = generators.nonce();

    // Armazena o state e o nonce no banco de dados
    DATABASE.states[state] = {
        nonce,
        expires_at: Date.now() + (15 * 60 * 1000), // expira em 15 minutos
    };

    // Cria uma URL de autorização para o facebook
    const authorizationUrl = facebookClient.authorizationUrl({
        scope: 'openid',
        response_mode: 'fragment',
        state,
        nonce,
    });

    // Redireciona o usuário para a URL de autorização criada acima
    res.redirect(authorizationUrl);
});

/**
 * Endpoint que autentica o usuário com o facebook
 * O usuário deve fornecer um state e um id_token, se forem válidos,
 * é emitido um access_token para o usuário
 */
app.post('/facebook/login', async (req, res) => {
    const { state, id_token } = req.body;

    // Valida se o id_token foi fornecido
    if (!id_token) {
        res.status(412).json({ error: 'id_token is required' });
        return;
    }

    // Valida se o state fornecido existe no banco de dados
    if (!state || !DATABASE.states[state]) {
        res.status(400).json({ error: 'Invalid state' });
        return;
    }

    // Verifica se o state expirou
    const { nonce, expires_at } = DATABASE.states[state];
    if (Date.now() >= expires_at) {
        // Apaga o state do banco de dados
        delete DATABASE.states[state];
       
        // Retorna um erro
        res.status(400).json({ error: 'this state has expired' });
        return;
    }

    let tokenSet;
    try {
        // Valida se o ID_TOKEN e o NONCE são válidos
        tokenSet = await facebookClient.callback(
            FACEBOOK_REDIRECT_URL,
            { id_token },
            { nonce }
        );
    } catch(error) {
        // Se o ID_TOKEN for inválido, retorne um erro
        res.status(400).json({ error: JSON.stringify(error) });
        return;
    }

    // ID_TOKEN é válido, então apague o state do banco de dados, ele não é mais necessário
    delete DATABASE.states[state];

    // Le as informações do ID_TOKEN
    const { sub, email } = tokenSet.claims();
    
    // Verifica se o usuário já esta cadastrado no banco de dados
    const user_id = `facebook-${sub}`;
    if (!DATABASE.users[user_id]) {
        // Se não estiver, cadastra dele no banco de dados
        DATABASE.users[user_id] = {
            id: user_id,
            email,
            created_at: Date.now(),
        };
    }

    // Cria um access_token opaco para o usuário logado
    const access_token = generators.random();
    const access_token_expires_at = Date.now() + (24 * 60 * 60 * 1000); // expira em 24 horas

    // Armazena o access_token no banco de dados
    DATABASE.sessions[access_token] = {
        user_id: user_id,
        expires_at: access_token_expires_at,
    };

    // Retorna o access_token para o usuário logado
    res.status(200).json({
        access_token,
        expires_at: access_token_expires_at,
        token_type: 'bearer'
    });
});

/**
 * Middleware que verifica se o usuário esta autenticado
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 * @returns 
 */
const authenticationMiddleware = (req, res, next) => {
    const { authorization } = req.headers; // Recupera o header Authorization

    if (!authorization) {
        res.status(401).json({ error: 'unauthorized' });
        return;
    }

    // remove o prefixo 'Bearer '
    let access_token = authorization;
    if (authorization.startsWith('Bearer ')) {
        access_token = authorization.substr(7);
    }

    // Verifica se a sessão existe no banco de dados
    const session = DATABASE.sessions[access_token];
    if (!session) {
        res.status(401).json({ error: 'unauthorized' });
        return;
    }

    // Verifica se a sessão expirou
    if (Date.now() >= session.expires_at) {
        // Deleta a sessão do banco de dados
        delete DATABASE.sessions[access_token];
        res.status(401).json({ error: 'session expired' });
        return;
    }

    // Armazena as informações da sessão na requisição
    req.session = session;
    next();
};

/**
 * Exemplo de endpoint protegido, o usuário precisa estar autenticado para acessar
 **/ 
app.get('/user-info', authenticationMiddleware, async (req, res) => {
    const { session } = req;

    // Le o id do usuário logado
    const { user_id } = session;

    // Le as informações do usuário do banco de dados
    const user = DATABASE.users[user_id];

    // Retorna as informações do usuário
    res.status(200).json(user)
});

// Inicia o servidor
app.listen(APP_PORT, () => {
    console.log(`App listening at http://localhost:${APP_PORT}`)
})
