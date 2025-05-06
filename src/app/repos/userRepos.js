// src/repositories/userRepository.js
import conexao from "../data/conexao.js";


export async function createUser({ name_user, email_user, hashedPassword, role_user }) {
  const sql = `
    INSERT INTO users (name_user, email_user, password_user, role_user)
    VALUES (?, ?, ?, ?)
  `;
  const [result] = await conexao.execute(sql, [name_user, email_user, hashedPassword, role_user]);
  return result.insertId;
}
