import express, { Request, Response, NextFunction } from "express";
const SECRET: Secret = process.env.SECRET || "";
import { sign, verify, Secret } from "jsonwebtoken";

export const authenticateJwt = (req: Request, res: Response, next: NextFunction) => {
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

export const hashStringToNumber = (str: string) => {
    let hash = 5381;
    for (let i = 0; i < str.length; i++) {
        hash = (hash * 33) ^ str.charCodeAt(i);
    }
    return hash >>> 0; // Make sure the result is an unsigned 32-bit integer
}
