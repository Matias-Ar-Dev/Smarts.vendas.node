import conexao from "../data/conexao.js";

export async function updateUser(id_user, data) {
  const { name_user, email_user, password_user, role_user } = data;
  let sql, params;

  if (password_user) {
    sql = `
      UPDATE users
      SET name_user = ?, email_user = ?, password_user = ?, role_user = ?
      WHERE id_user = ?
    `;
    params = [name_user, email_user, password_user, role_user, id_user];
  } else {
    sql = `
      UPDATE users
      SET name_user = ?, email_user = ?, role_user = ?
      WHERE id_user = ?
    `;
    params = [name_user, email_user, role_user, id_user];
  }

  const [result] = await conexao.execute(sql, params);
  return result;
}
