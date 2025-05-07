import conexao from "../data/conexao.js";


export async function deleteUserById(id_user) {
    const sql = `DELETE FROM users WHERE id_user = ?`;
    const [result] = await conexao.execute(sql, [id_user]);
    return result;
}
