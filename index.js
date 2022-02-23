const fs   = require('fs');
const jwt  = require('jsonwebtoken');
const jose = require('jose');
const uuid = require('uuid');
const { createHash } = require('crypto');
const { program } = require('commander');

program
    .command('keys')
    .action( () => {
        console.log(`
# Use these commands to create a private and public key
openssl genrsa -out private.key 2048
openssl rsa -in private.key -pubout > public.key
`.trim());
    });

program
    .command('session')
    .requiredOption('--private <privateKey>')
    .requiredOption('--public <publicKey>')
    .requiredOption('--webid <webid>')
    .requiredOption('--issuer <issuer>')
    .requiredOption('--expire <expiryTime>')
    .action( async(options) => {
        const token = await createAccessToken(options);
        console.log(JSON.stringify(token));
    });

program
    .command('jwks')
    .requiredOption('--public <publicKey>') 
    .action( async(options) => {
        const jwk = await exportJWK(options);
        console.log(JSON.stringify(jwk));
    });

program 
    .command('webid')
    .requiredOption('--issuer <url>')
    .requiredOption('--name <name>')
    .action( (options) => {
        console.log(`
@prefix : <#>.
@prefix schema: <http://schema.org/> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
@prefix ldp: <http://www.w3.org/ns/ldp#>.

:me 
    a           schema:Person, foaf:Person;
    foaf:name   "${options.name}" ;
    <http://www.w3.org/ns/solid/terms#oidcIssuer> <${options.issuer}> .
`);
    });

program
    .command('openid-configuration')
    .requiredOption('--jwks <uri>')
    .action( (options) => {
        const conf = exportOpenidConfiguration(options);
        console.log(JSON.stringify(conf));
    });

program
    .command('headers <method> <url>')
    .requiredOption('--session <file>')
    .requiredOption('--public <publicKey>')
    .requiredOption('--private <privateKey>')
    .action( async (method,url,options) => {
        const headers = await makeHeadersFor(method,url,options);
        console.log(`-H "Authorization:${headers.Authorization}" ` +
                    `-H "DPoP:${headers.DPoP}"` );
    });

program.parse();

async function makeHeadersFor(method,url,opts) {
    const sessionJson = JSON.parse(fs.readFileSync(opts.session));
    const accessToken = sessionJson['access_token'];
    const publicKey   = fs.readFileSync(opts.public);
    const privateKey  = fs.readFileSync(opts.private);

    const jwk = await jose.exportJWK(publicKey);
    const iat = Math.trunc( new Date().valueOf() / 1000 );
    const randomStr = uuid.v4();
    const payload = {
        jti: randomStr,
        htm: method,
        htu: url,
        iat: iat
    };

    const dpop = jwt.sign(payload, privateKey , { 
                    algorithm: 'RS256', 
                    header: { 
                        typ: "dpop+jwt" ,
                        jwk: jwk 
                    }
                });

    return {
        Authorization: `DPoP ${accessToken}` ,
        DPoP: dpop
    }
}

function exportOpenidConfiguration(opts) {
    return {
       jwks_uri: opts.jwks
    };
}

async function exportJWK(opts) {
    const publicKey  = fs.readFileSync(opts.public);
    const publicJwk  = await jose.exportJWK(publicKey);
    const kid = createHash('sha256').update(publicKey).digest('hex');

    publicJwk['use'] = 'sig';
    publicJwk['alg'] = 'RS256';
    publicJwk['kid'] = kid;

    return {
        keys: [
            publicJwk
        ]
    };
}

async function createAccessToken(opts) {
    const privateKey = fs.readFileSync(opts.private);
    const publicKey  = fs.readFileSync(opts.public);

    const publicJwk  = await jose.exportJWK(publicKey);
    const thumbprint = await jose.calculateJwkThumbprint(publicJwk);

    const kid = createHash('sha256').update(publicKey).digest('hex');
    const randomStr = uuid.v4();
    const client_id = uuid.v4();
    const iat = Math.trunc( new Date().valueOf() / 1000 );
    const expiry = iat + (opts.expire * 24 * 3600);

    const payload = {
        webid: opts.webid,
        client_id: client_id,
        iss: opts.issuer,
        sub: opts.webid,
        aud: "solid",
        cnf: {
          jkt: thumbprint
        },
        iat: iat,
        exp: expiry,
        jti: randomStr
    };

    const token = jwt.sign(payload, privateKey, { algorithm: 'RS256', header: { kid: kid }});

    return { access_token: token };
}