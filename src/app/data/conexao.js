// src/conexao.js
import mysql from 'mysql2';
import dotenv from 'dotenv';

dotenv.config(); // Carrega variáveis de ambiente

// Cria conexão com suporte a Promises
const conexao = mysql.createConnection({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
}).promise(); // <- Habilita Promises aqui

// Teste de conexão
conexao.connect()
  .then(() => {
    console.log('✅ Conectado ao banco de dados com sucesso!');
  })
  .catch((err) => {
    console.error('❌ Erro ao conectar ao banco de dados:', err.message);
  });

export default conexao;
