// src/conexao.js
import mysql from 'mysql';
import dotenv from 'dotenv';

dotenv.config(); // Isso precisa estar ANTES da criação da conexão

console.log("DB_USER:", process.env.DB_USER); // Debug temporário

const conexao = mysql.createConnection({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

conexao.connect((err) => {
  if (err) {
    console.error('❌ Erro ao conectar ao banco de dados:', err.message);
  } else {
    console.log('✅ Conectado ao banco de dados com sucesso!');
  }
});

export default conexao;
