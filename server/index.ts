import express from "express";
import { Client } from "pg";
import { createHash } from "crypto";
import "dotenv/config"
const app = express();
const PORT = 3000;
const POSTGRES_URL = process.env.POSTGRES_URL;
const client = new Client(POSTGRES_URL);

(async () => { client.connect(); })();

function hashStringToNumber(str: string) {
    let hash = 5381;
    for (let i = 0; i < str.length; i++) {
        hash = (hash * 33) ^ str.charCodeAt(i);
    }
    return hash >>> 0; // Make sure the result is an unsigned 32-bit integer
}

app.use(express.json());
app.get('/api/v1/user', async (req, res) => {
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

app.post('/api/v1/user', async (req, res) => {
    const { email, password } = req.body;
    const findQuery = `SELECT id FROM users WHERE email = $1`;
    const queryResult = await client.query(findQuery, [email]);
    if (queryResult.rowCount == 1) {
        res.status(404).json({ error: 'User already exists' });
    }
    else {
        const id = hashStringToNumber(email);
        const hashPassword = createHash('sha256').update(password).digest('hex');
        const insetQuery = `INSERT INTO users VALUES($1, $2, $3)`
        await client.query(insetQuery, [id, email, hashPassword]);
        res.json({});
    }
});

app.listen(PORT, () => { console.log(`Server listening at port ${PORT}`) })

