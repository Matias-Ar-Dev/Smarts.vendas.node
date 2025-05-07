// controllers/userController.js

import bcrypt from 'bcrypt';
import { updateUser } from '../repos/edituserRepos.js';

export async function editUser(req, res) {
    const { id_user } = req.params;
    const { name_user, email_user, password_user, role_user } = req.body;

    try {
        // Se a senha for fornecida, criptografa
        let hashedPassword = null;
        if (password_user) {
            hashedPassword = await bcrypt.hash(password_user, 10);
        }

        // Chama o método do repository para atualizar o usuário
        const result = await updateUser(id_user, {
            name_user,
            email_user,
            password_user: hashedPassword,
            role_user
        });

        // Verifica se o update foi bem-sucedido
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Usuário não encontrado' });
        }

        res.status(200).json({ message: "Usuário atualizado com sucesso" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao atualizar o usuário', details: err.message });
    }
}
