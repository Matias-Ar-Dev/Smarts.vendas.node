import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { findUserByEmail } from '../repos/loginRepos.js';


dotenv.config();

export async function loginUser(req, res) {
    const { email_user, password_user } = req.body;

    if (!email_user || !password_user) {
        return res.status(400).json({ error: "Email e senha são obrigatórios" });
    }

    try {
        const user = await findUserByEmail(email_user);

        if (!user) {
            return res.status(404).json({ error: "Usuário não encontrado" });
        }

        const isPasswordValid = await bcrypt.compare(password_user, user.password_user);

        if (!isPasswordValid) {
            return res.status(401).json({ error: "Senha incorreta" });
        }

        const token = jwt.sign(
            {
                id_user: user.id_user,
                email_user: user.email_user,
                role_user: user.role_user
            },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({ message: "Login bem-sucedido", token });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}
