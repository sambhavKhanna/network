import express, { Request, Response, NextFunction } from "express";
import { Client } from "pg";
import { createHash } from "crypto";
import { sign, verify, Secret } from "jsonwebtoken";
import "dotenv/config"
const app = express();
const PORT = 3000;
const POSTGRES_URL = process.env.POSTGRES_URL;
const SECRET: Secret = process.env.SECRET || "";
const client = new Client(POSTGRES_URL);

(async () => { client.connect(); })();

const authenticateJwt = (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        verify(token, SECRET, (err, user) => {
            if (err) {
              return res.sendStatus(403);
            }
            next();
        });
    }
    else {
        res.status(401).json({ error: 'Invalid Token' });
    }    
}

const hashStringToNumber = (str: string) => {
    let hash = 5381;
    for (let i = 0; i < str.length; i++) {
        hash = (hash * 33) ^ str.charCodeAt(i);
    }
    return hash >>> 0; // Make sure the result is an unsigned 32-bit integer
}

app.use(express.json());
app.get('/api/v1/user', async (req: Request, res: Response) => {
    const email = req.body.email;
    const findQuery = `SELECT id FROM users WHERE email = $1`;
    const queryResult = await client.query(findQuery, [email]);
    if (queryResult.rowCount == 1) {
        res.status(404).json({ error: 'User already exists' });
    }
    else {
        res.json({});
    }
});

app.post('/api/v1/user', async (req: Request, res: Response) => {
    const { email, password } = req.body;
    const findQuery = `SELECT id FROM users WHERE email = $1`;
    const queryResult = await client.query(findQuery, [email]);
    if (queryResult.rowCount == 1) {
        res.status(404).json({ error: 'User already exists' });
    }
    else {
        const token = sign({ email }, SECRET, { expiresIn: '1h' });
        const id = hashStringToNumber(email);
        const hashPassword = createHash('sha256').update(password).digest('hex');
        const insetQuery = `INSERT INTO users VALUES($1, $2, $3)`
        await client.query(insetQuery, [id, email, hashPassword]);
        res.json({ token });
    }
});

app.post('/api/v1/follow', authenticateJwt, async (req: Request, res: Response) => {
    const { email, to } = req.body;
    const id = createHash('sha256').update(to + email).digest('hex');
    const insetQuery = `INSERT INTO network VALUES($1, $2, $3)`
    await client.query(insetQuery, [id, to, email]);
    res.json({}); 
});

app.get('/api/v1/followers', authenticateJwt, async (req: Request, res: Response) => {
    const email = req.query.email;
    const findQuery = `SELECT follower FROM network WHERE email = $1`;
    const queryResult = await client.query(findQuery, [email]);
    res.json(queryResult.rows);
});

app.get('/api/v1/all', authenticateJwt, async (req: Request, res: Response) => {
    const email = req.query.email;
    const findQuery = `SELECT email FROM users WHERE email NOT IN (SELECT follower FROM network WHERE email = $1) AND email != $1`;
    const queryResult = await client.query(findQuery, [email]);
    res.json(queryResult.rows);
});

app.listen(PORT, () => { console.log(`Server listening at port ${PORT}`) })

