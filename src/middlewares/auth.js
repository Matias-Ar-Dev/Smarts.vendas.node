import jwt from "jsonwebtoken"
const JWT_SECRET = 'sua-chave-secreta';

export const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ error: "Token não fornecido" });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: "Token inválido ou expirado" });
        }
        
        // Anexa o usuário ao objeto `req`
        req.user = user;
        next();
    });
};
