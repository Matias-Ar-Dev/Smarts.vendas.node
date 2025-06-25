// src/controllers/userController.js

import bcrypt from 'bcryptjs';
import { createUser } from '../repos/userRepos.js';


export async function handleCreateUser(req, res) {
  const { name_user, email_user, password_user, role_user = 'user' } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password_user, 10);
    const id_user = await createUser({ name_user, email_user, hashedPassword, role_user });
    res.status(201).json({ message: "Usuário criado com sucesso", id_user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}
