const express = require('express');
const {auth, resolver, loaders} = require('@iden3/js-iden3-auth')
const getRawBody = require('raw-body')
const cors = require('cors');
const app = express();
const port = 10011;
app.use(cors({
    origin: '*', // 모든 출처 허용 옵션. true 를 써도 된다.
}));

app.use(express.static('static'));
app.get("/api/sign-in", (req, res) => {
    console.log('get Auth Request');
    GetAuthRequest(req,res);
});

app.post("/api/callback", (req, res) => {
    console.log('callback');
    Callback(req,res);
});

app.listen(port, () => {
    console.log('server running on port 10011');
});

// Create a map to store the auth requests and their session IDs
const requestMap = new Map();


async function GetAuthRequest(req,res) {
    // Audience is verifier id
    const hostUrl = "http://3.26.13.71:10011";
    const sessionId = 1;
    const callbackURL = "/api/callback"
    // const audience = "did:polygonid:polygon:mumbai:2qM3XETXF7y49ZA6gDSpzuw38ZSQdfrY9tJtwcjucH" // junho
    const audience = "did:polygonid:polygon:mumbai:2qLhNLVmoQS7pQtpMeKHDqkTcENBZUj1nkZiRNPGgV" // provider

    const uri = `${hostUrl}${callbackURL}?sessionId=${sessionId}`;
    console.log('GetAuthRequest uri', uri);

    // Generate request for basic authentication
    const request = auth.createAuthorizationRequest(
        'test flow',
        audience,
        uri,
    );

    request.id = '93603def-f338-4f1a-bdf4-2bdbc388e236';
    request.thid = '93603def-f338-4f1a-bdf4-2bdbc388e236';
    request.typ = "application/iden3comm-plan-json";
    request.type = "https://iden3-communication.io/authorization/1.0/request";

    // Add request for a specific proof
    const proofRequest = {
        id: 1,
        circuitId: 'credentialAtomicQuerySigV2',
        query: {
            allowedIssuers: ['*'],
            type: 'ProofOfDaoRole',
            context: 'https://raw.githubusercontent.com/0xPolygonID/tutorial-examples/main/credential-schema/schemas-examples/proof-of-dao-role/proof-of-dao-role.json',
            credentialSubject: {
                role: {
                    $eq: 1,
                },
            },
        },
    };
    const scope = request.body.scope ?? [];
    request.body.scope = [...scope, proofRequest];
    console.log(request);
    console.log(request.body.scope);

    // Store auth request in map associated with session ID
    requestMap.set(`${sessionId}`, request);

    return res.status(200).set('Content-Type', 'application/json').send({"id":"aef4c809-f9b6-4db3-a334-e167daa2aa9b","typ":"application/iden3comm-plain-json","type":"https://iden3-communication.io/authorization/1.0/request","thid":"aef4c809-f9b6-4db3-a334-e167daa2aa9b","body":{"callbackUrl":"https://self-hosted-demo-backend-platform.polygonid.me/api/callback?sessionId=191178","reason":"test flow","scope":[{"id":1,"circuitId":"credentialAtomicQuerySigV2","query":{"allowedIssuers":["*"],"context":"https://raw.githubusercontent.com/0xPolygonID/tutorial-examples/main/credential-schema/schemas-examples/proof-of-dao-role/proof-of-dao-role.jsonld","credentialSubject":{"role":{"$eq":1}},"type":"ProofOfDaoRole"}}]},"from":"did:polygonid:polygon:mumbai:2qLhNLVmoQS7pQtpMeKHDqkTcENBZUj1nkZiRNPGgV"});
}

async function Callback(req,res) {
    console.log('Callback req.query', req.query);
    // Get session ID from request
    const sessionId = req.query.sessionId;

    // get JWZ token params from the post request
    const raw = await getRawBody(req);
    const tokenStr = raw.toString().trim();

    const ethURL = 'https://polygon-mumbai.g.alchemy.com/v2/W-XkZND8K-Mm3uW09In9Atd66Dj2j2X6';
    const contractAddress = "0x134B1BE34911E39A8397ec6289782989729807a4"
    const keyDIR = "../keys"

    const ethStateResolver = new resolver.EthStateResolver(
        ethURL,
        contractAddress,
    );

    const resolvers = {
        ['polygon:mumbai']: ethStateResolver,
    };


    // fetch authRequest from sessionID
    const authRequest = requestMap.get(`${sessionId}`);

    // Locate the directory that contains circuit's verification keys
    const verificationKeyloader = new loaders.FSKeyLoader(keyDIR);
    const sLoader = new loaders.UniversalSchemaLoader('ipfs.io');

    // EXECUTE VERIFICATION
    const verifier = new auth.Verifier(
        verificationKeyloader,
        sLoader,
        resolvers,
    );


    try {
        const opts = {
            AcceptedStateTransitionDelay: 5 * 60 * 1000, // 5 minute
        };
        authResponse = await verifier.fullVerify(tokenStr, authRequest, opts);
    } catch (error) {
        return res.status(500).send(error);
    }
    return res.status(200).set('Content-Type', 'application/json').send("user with ID: " + authResponse.from + " Succesfully authenticated");
}
