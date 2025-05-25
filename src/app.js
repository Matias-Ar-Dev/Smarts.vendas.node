import express from 'express';
import bcrypt from 'bcrypt';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { authenticateJWT } from './middlewares/auth.js';
import conexao from './app/data/conexao.js';
import { fileURLToPath } from 'url';
import path from 'path';
import multer from 'multer';
import fs from 'fs'
import { handleCreateUser } from './app/controllers/userContro.js';
import { loginUser } from './app/controllers/logincontro.js';
import { handleDeleteUser } from './app/controllers/deleteuserContro.js';
import { editUser } from './app/controllers/edituserContro.js';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());




//uploads rotas
const storage = multer.diskStorage({
    destination:(req, file, cb) => {
        const baseDir = 'uploads';
        let subFolder = '';
        const ext = path.extname(file.originalname).toLowerCase()
        if (ext === '.png') {
            subFolder = 'pngFiles';
          } else if (ext === '.pdf') {
            subFolder = 'pdfFiles';
          } else if (ext === '.jpg' || ext === '.jpeg') {
            subFolder = 'jpgFiles';
          } else {
            subFolder = 'otherFiles';
          }
          const uploadDir = path.join(__dirname, baseDir, subFolder);
          fs.mkdirSync(uploadDir, {recursive: true});
          cb(null, uploadDir);
    },
    filename:(req, file, cb) => {
        const filename = Date.now()+ '_'+file.originalname;
        cb(null, filename);
    }
});
const upload = multer({storage});

app.post('/upload', upload.array('arquivo', 10), async (req, res) => {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ message: 'Nenhum arquivo enviado' });
    }
  
    try {
      const insertPromises = req.files.map(file => {
        // Verificar se todas as propriedades estão definidas
        const { originalname, filename, mimetype, path: filePath } = file;
  
        // Adicionar verificações para evitar undefined
        if (!originalname || !filename || !mimetype || !filePath) {
          console.error('Propriedade faltando no arquivo:', file);
          return res.status(400).json({ message: 'Alguns dados do arquivo estão faltando' });
        }
  
        // Inserir no banco
        return conexao.execute(
          `INSERT INTO uploads (original_name, stored_name, file_path, mime_type) VALUES (?, ?, ?, ?)`,
          [originalname, filename, filePath, mimetype]
        );
      });
  
      await Promise.all(insertPromises);
      return res.json({ message: 'Arquivos salvos com sucesso' });
    } catch (err) {
      console.error('Erro ao salvar no banco:', err);
      return res.status(500).json({ message: 'Erro ao salvar no banco', erro: err.message });
    }
  });

  app.put('/upload/:id_uploads', async (req, res) => {
    const { id_uploads } = req.params;  // Obtém o ID do arquivo a ser editado
    const { originalname, mimetype } = req.body;  // Obtém os novos dados para atualização
  
    // Verificar se o ID foi fornecido e se os dados necessários estão presentes
    if (!originalname || !mimetype) {
      return res.status(400).json({ message: 'Nome do arquivo e tipo MIME são obrigatórios' });
    }
  
    try {
      // Executar o comando de atualização no banco de dados
      const [result] = await conexao.execute(
        `UPDATE uploads SET original_name = ?, mime_type = ? WHERE id_uploads = ?`,
        [originalname, mimetype, id_uploads]  // Passar os parâmetros de forma segura
      );
  
      // Verificar se o arquivo foi encontrado e atualizado
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'Arquivo não encontrado para atualização' });
      }
  
      return res.json({ message: 'Arquivo atualizado com sucesso' });
    } catch (err) {
      console.error('Erro ao atualizar no banco:', err);
      return res.status(500).json({ message: 'Erro ao atualizar no banco', erro: err.message });
    }
  });
  
  
app.delete('/upload/:id_uploads', async (req, res) => {
    const { id_uploads } = req.params;
  
    try {
      // Primeiro, busca o caminho do arquivo pelo ID
      const [rows] = await conexao.execute('SELECT file_path FROM uploads WHERE id_uploads = ?', [id_uploads]);
  
      if (rows.length === 0) {
        return res.status(404).json({ message: 'Arquivo não encontrado.' });
      }
  
      const filePath = rows[0].file_path;  // Certifique-se de que é 'file_path' e não 'filepath'
  
      // Verifica se o caminho do arquivo realmente existe
      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ message: 'Arquivo não encontrado no sistema de arquivos.' });
      }
  
      // Exclui o registro do banco de dados
      await conexao.execute('DELETE FROM uploads WHERE id_uploads = ?', [id_uploads]);
  
      // Tenta excluir o arquivo fisicamente
      fs.unlink(filePath, (err) => {
        if (err) {
          console.error('Erro ao tentar excluir o arquivo no sistema:', err);
          return res.status(500).json({ message: 'Erro ao excluir o arquivo do sistema.' });
        }
        
        console.log(`Arquivo ${filePath} excluído com sucesso do sistema.`);
      });
      
  
      return res.json({ message: 'Arquivo excluído com sucesso.' });
  
    } catch (error) {
      console.error('Erro ao excluir arquivo:', error);
      return res.status(500).json({ message: 'Erro ao excluir o arquivo.' });
    }
  });

  

  app.get('/upload/:id_uploads', async (req, res) => {
    const { id_uploads } = req.params;
  
    try {
      const [rows] = await conexao.execute('SELECT * FROM uploads WHERE id_uploads = ?', [id_uploads]);
  
      if (rows.length === 0) {
        return res.status(404).json({ message: 'Arquivo não encontrado.' });
      }
  
      return res.json(rows[0]);
    } catch (error) {
      console.error('Erro ao buscar arquivo:', error);
      return res.status(500).json({ message: 'Erro ao buscar o arquivo.' });
    }
  });

  app.get('/uploads', async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 6;
    const offset = (page - 1) * limit;
  
    try {
      // Conta total de uploads
      const [countRows] = await conexao.execute("SELECT COUNT(*) AS total FROM uploads");
      const total = countRows[0].total;
  
      // Busca paginada e ordenada
      const [dataRows] = await conexao.execute(
        "SELECT * FROM uploads ORDER BY upload_date DESC LIMIT ? OFFSET ?",
        [limit, offset]
      );
  
      const lastPage = Math.ceil(total / limit);
  
      res.status(200).json({
        page,
        perPage: limit,
        total,
        lastPage,
        data: dataRows
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Erro ao buscar arquivos' });
    }
  });
  
  
app.get('/download/:id_uploads', async (req, res) => {
    const { id_uploads } = req.params;
  
    try {
      // Busca o caminho e nome original do arquivo
      const [rows] = await conexao.execute(
        'SELECT file_path, original_name FROM uploads WHERE id_uploads = ?',
        [id_uploads]
      );
  
      if (rows.length === 0) {
        return res.status(404).json({ message: 'Arquivo não encontrado no banco.' });
      }
  
      const { file_path, original_name } = rows[0];
  
      // Verifica se o arquivo existe fisicamente
      if (!fs.existsSync(file_path)) {
        return res.status(404).json({ message: 'Arquivo não encontrado no disco.' });
      }
  
      // Envia o arquivo com o nome original
      return res.download(file_path, original_name);
    } catch (error) {
      console.error('Erro ao baixar arquivo:', error);
      return res.status(500).json({ message: 'Erro ao processar o download.' });
    }
  });
  
  app.get('/count_users', async (req, res) => {
    const countQuery = "SELECT COUNT(*) AS total FROM users";

    try {
        // Consulta a quantidade total de usuários
        const [results] = await conexao.execute(countQuery);
        const totalUsers = results[0].total; // Total de usuários

        // Retorna a resposta com a contagem
        res.status(200).json({ totalUsers });
    } catch (err) {
        res.status(500).json({ error: 'Erro ao contar usuários', details: err.message });
    }
});
  app.get('/list_users', async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 6;
  const offset = (page - 1) * limit;

  try {
    const [countRows] = await conexao.query("SELECT COUNT(*) AS total FROM users");
    const total = countRows[0].total;

    const [dataRows] = await conexao.query(
      "SELECT * FROM users ORDER BY name_user ASC LIMIT ? OFFSET ?",
      [limit, offset]
    );

    const lastPage = Math.ceil(total / limit);

    res.status(200).json({
      page,
      perPage: limit,
      total,
      lastPage,
      data: dataRows
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

  
app.post('/create_users', handleCreateUser)

app.delete('/delete_user/:id_user',handleDeleteUser)
app.put('/edit_user/:id_user',authenticateJWT,editUser)

app.get('/filter_users_by_name', async (req, res) => {
  try {
      const { name_user } = req.query;
      const sql = `SELECT * FROM users WHERE name_user LIKE ?`;
      const params = [`%${name_user}%`];

      const [rows] = await conexao.execute(sql, params); // 'rows' já contém os resultados

      res.status(200).json(rows);
  } catch (err) {
      res.status(500).json({ error: err.message });
  }
});


app.get('/protected_users', authenticateJWT, (req, res) => {
    if (req.user.role_user !== "user") {
        return res.status(403).json({ message: "Acesso negado" });
    }

    res.status(200).json({
        message: "Bem-vindo, usuário",
        user: req.user
    });
});

app.post('/login_users', loginUser)

app.get('/protected_admin', authenticateJWT, (req, res) => {
    if (req.user.role_user !== "admin") {
        return res.status(403).json({ message: "Acesso negado" });
    }

    // Aqui você pode incluir o nome do usuário na resposta
    res.status(200).json({
        message: `Bem-vindo, admin ${req.user.name_user}`,  // Exibindo o nome do admin
        user: req.user
    });
});


app.put('/edit_profile', authenticateJWT, async (req, res) => {
  const { name_user, email_user, password_user } = req.body;
  const id_user = req.user.id_user; // Pegado do token JWT

  if (!name_user || !email_user) {
    return res.status(400).json({ message: 'Nome e email são obrigatórios' });
  }

  try {
    const campos = ['name_user = ?', 'email_user = ?'];
    const params = [name_user, email_user];

    if (password_user && password_user.trim() !== '') {
      const hashedPassword = await bcrypt.hash(password_user, 10);
      campos.push('password_user = ?');
      params.push(hashedPassword);
    }

    params.push(id_user); // Para o WHERE

    const sql = `
      UPDATE users
      SET ${campos.join(', ')}
      WHERE id_user = ?
    `;

    const [result] = await conexao.execute(sql, params);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.status(200).json({ message: 'Perfil atualizado com sucesso' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Erro ao atualizar perfil', error: err.message });
  }
});

export default app;
