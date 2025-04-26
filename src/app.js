import express from 'express';
import bcrypt  from 'bcrypt'
import cors from 'cors';
import jwt from "jsonwebtoken"
import { authenticateJWT } from './middlewares/auth.js';
import conexao from './app/data/conexao.js';

const app = express()
app.use(cors())
app.use(express.json())


app.get('/list_users', async (req, res) => {

    const sql = "SELECT * FROM users";
    try {
        const data = await new Promise((resolve, reject) => {
            conexao.query(sql, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
        res.status(200).json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/create_users', async (req, res) => {
    const { name_user, email_user, password_user, role_user = 'user' } = req.body;
    try {
        // Gerar o hash da senha
        const hashedPassword = await bcrypt.hash(password_user, 10);
        const sql = `
            INSERT INTO users (name_user, email_user, password_user, role_user)
            VALUES (?, ?, ?, ?)
        `;
        const result = await new Promise((resolve, reject) => {
            conexao.query(sql, [name_user, email_user, hashedPassword, role_user], (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
        res.status(201).json({ message: "Usuário criado com sucesso", id_user: result.insertId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/delete_user/:id_user', async (req, res) => {
    try {
        const id_user = Number(req.params.id_user);
        const sql = `DELETE FROM users WHERE id_user = ?`;

        const result = await new Promise((resolve, reject) => {
            conexao.query(sql, [id_user], (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });

        res.status(200).json({
            message: "Usuário deletado com sucesso"
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: "Erro ao deletar usuário"
        });
    }
});
app.put('/edit_user/:id_user', async (req, res) => {
    const id_user = Number(req.params.id_user);
    const { name_user, email_user, password_user, role_user } = req.body;

    try {
        // Gerar hash se a senha for fornecida
        let hashedPassword = null;
        if (password_user) {
            hashedPassword = await bcrypt.hash(password_user, 10);
        }

        const sql = `
            UPDATE users
            SET name_user = ?, email_user = ?, ${hashedPassword ? 'password_user = ?,' : ''} role_user = ?
            WHERE id_user = ?
        `;

        const params = [
            name_user,
            email_user,
            ...(hashedPassword ? [hashedPassword] : []),
            role_user,
            id_user
        ];

        const result = await new Promise((resolve, reject) => {
            conexao.query(sql, params, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });

        res.status(200).json({ message: "Usuário atualizado com sucesso" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.get('/filter_users_by_name', async (req, res) => {
    try {
        const { name_user } = req.query;

        const sql = `SELECT * FROM users WHERE name_user LIKE ?`;
        const params = [`%${name_user}%`];

        const result = await new Promise((resolve, reject) => {
            conexao.query(sql, params, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });

        res.status(200).json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});



//=======================


// Chave secreta para assinatura do JWT
const JWT_SECRET = 'sua-chave-secreta';

app.post('/login_users', async (req, res) => {
    const { email_user, password_user } = req.body;

    try {
        const sql = "SELECT * FROM users WHERE email_user = ?";

        const user = await new Promise((resolve, reject) => {
            conexao.query(sql, [email_user], (err, results) => {
                if (err) reject(err);
                else resolve(results[0]);
            });
        });

        if (!user) {
            return res.status(404).json({ error: "Usuário não encontrado" });
        }

        const isPasswordValid = await bcrypt.compare(password_user, user.password_user);

        if (!isPasswordValid) {
            return res.status(401).json({ error: "Senha incorreta" });
        }

        // Gerar o token JWT
        const token = jwt.sign(
            { id_user: user.id_user, email_user: user.email_user, role_user: user.role_user },
            JWT_SECRET,
            { expiresIn: '1h' } // Expiração do token em 1 hora
        );

        res.status(200).json({ message: "Login bem-sucedido", token });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
//=====================

app.get('/protected_users', authenticateJWT, (req, res) => {
    if(req.user.role_user !== "user"){
        
    res.status(403).json(
        { message: "Acesso negado"});
}
res.status(200).json({
    message: "bem vindo user",
    user: req.user

});

    })




app.get('/protected_admin', authenticateJWT, (req, res) => {
    if(req.user.role_user !== "admin"){
        return res.status(403).json({
            message: "acesso negado"
        })

    }

    res.status(200).json({
        message: "bem vindo admin",
        user: req.user
    });
})






export default app    
   
 

