// app/controllers/userController.js

import { deleteUserById } from "../repos/deleteuserRepos.js";


export async function handleDeleteUser(req, res) {
    try {
        const id_user = Number(req.params.id_user);
        await deleteUserById(id_user);
        res.status(200).json({ message: "Usuário deletado com sucesso" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Erro ao deletar usuário" });
    }
}
