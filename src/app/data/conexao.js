import mysql from 'mysql';
import dotenv from 'dotenv';

// Carrega as variáveis de ambiente do arquivo .env
dotenv.config();

// Cria a conexão usando as variáveis de ambiente
const conexao = mysql.createConnection({
  host:  'localhost',
  port:  '3306',
  user:  'matias',
  password: 'matias2002',
  database: 'celke'
});

// Função para conectar ao banco e exibir mensagem de sucesso ou erro
conexao.connect((err) => {
  if (err) {
    console.error('❌ Erro ao conectar ao banco de dados:', err.message);
  } else {
    console.log('✅ Conectado ao banco de dados com sucesso!');
  }
});

export default conexao;
