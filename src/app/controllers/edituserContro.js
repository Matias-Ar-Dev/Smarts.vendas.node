import bcrypt from 'bcrypt';
import { updateUser } from '../repos/edituserRepos.js';

export async function editUser(req, res) {
  const { id_user } = req.params;
  const { name_user, email_user, password_user, role_user } = req.body;

  // Garante que só edita seu próprio usuário
  if (parseInt(id_user) !== req.user.id_user) {
    return res.status(403).json({ error: "Você só pode editar sua própria conta." });
  }

  try {
    const dataToUpdate = {
      name_user,
      email_user,
      role_user,
    };

    if (password_user && password_user.trim() !== "") {
      const hashedPassword = await bcrypt.hash(password_user, 10);
      dataToUpdate.password_user = hashedPassword;
    }

    const result = await updateUser(id_user, dataToUpdate);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    res.status(200).json({ message: "Usuário atualizado com sucesso" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao atualizar usuário", details: err.message });
  }
}
