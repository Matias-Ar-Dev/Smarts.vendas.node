import conexao from "../data/conexao.js";


export async function findUserByEmail(email) {
    const [results] = await conexao.execute(
        "SELECT * FROM users WHERE email_user = ?",
        [email]
    );
    return results[0];
}
