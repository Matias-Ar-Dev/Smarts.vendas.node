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
    try {
      const [rows] = await conexao.execute('SELECT * FROM uploads ORDER BY upload_date DESC');
      res.json(rows);
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
  

// No seu backend (controller ou rota de listagem de usuários)
app.get('/count_users', async (req, res) => {
    const countQuery = "SELECT COUNT(*) AS total FROM users";
  
    try {
      const result = await new Promise((resolve, reject) => {
        conexao.query(countQuery, (err, results) => {
          if (err) reject(err);
          else resolve(results[0].total); // A quantidade total de usuários
        });
      });
  
      res.status(200).json({ totalUsers: result }); // Retorna a quantidade total de usuários
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
  

app.get('/list_users', async (req, res) => {
    const page = parseInt(req.query.page) || 1;    // página atual (default = 1)
    const limit = parseInt(req.query.limit) || 6; // quantos por página (default = 10)
    const offset = (page - 1) * limit;             // quantos pular

    // Contar total de registros primeiro
    const countQuery = "SELECT COUNT(*) AS total FROM users";
    const dataQuery = "SELECT * FROM users LIMIT ? OFFSET ?";

    try {
        const totalResult = await new Promise((resolve, reject) => {
            conexao.query(countQuery, (err, result) => {
                if (err) reject(err);
                else resolve(result[0].total);
            });
        });

        const data = await new Promise((resolve, reject) => {
            conexao.query(dataQuery, [limit, offset], (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });

        const lastPage = Math.ceil(totalResult / limit);

        res.status(200).json({
            page,
            perPage: limit,
            total: totalResult,
            lastPage,
            data
        });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.post('/create_user', handleCreateUser)


app.post('/create_users', async (req, res) => {
    const { name_user, email_user, password_user, role_user = 'user' } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password_user, 10);
        const sql = `
            INSERT INTO users (name_user, email_user, password_user, role_user)
            VALUES (?, ?, ?, ?)
        `;
        const result = await new Promise((resolve, reject) => {
            conexao.query(sql, [name_user, email_user, hashedPassword, role_user], (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
        res.status(201).json({ message: "Usuário criado com sucesso", id_user: result.insertId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/delete_user/:id_user', async (req, res) => {
    try {
        const id_user = Number(req.params.id_user);
        const sql = `DELETE FROM users WHERE id_user = ?`;

        await new Promise((resolve, reject) => {
            conexao.query(sql, [id_user], (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });

        res.status(200).json({ message: "Usuário deletado com sucesso" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Erro ao deletar usuário" });
    }
});

app.put('/edit_user/:id_user', async (req, res) => {
    const id_user = Number(req.params.id_user);
    const { name_user, email_user, password_user, role_user } = req.body;

    try {
        let hashedPassword = null;
        if (password_user) {
            hashedPassword = await bcrypt.hash(password_user, 10);
        }

        const sql = `
            UPDATE users
            SET name_user = ?, email_user = ?, ${hashedPassword ? 'password_user = ?,' : ''} role_user = ?
            WHERE id_user = ?
        `;

        const params = [
            name_user,
            email_user,
            ...(hashedPassword ? [hashedPassword] : []),
            role_user,
            id_user
        ];

        await new Promise((resolve, reject) => {
            conexao.query(sql, params, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });

        res.status(200).json({ message: "Usuário atualizado com sucesso" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/filter_users_by_name', async (req, res) => {
    try {
        const { name_user } = req.query;
        const sql = `SELECT * FROM users WHERE name_user LIKE ?`;
        const params = [`%${name_user}%`];

        const result = await new Promise((resolve, reject) => {
            conexao.query(sql, params, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });

        res.status(200).json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/login_users', async (req, res) => {
    const { email_user, password_user } = req.body;

    try {
        const sql = "SELECT * FROM users WHERE email_user = ?";

        const user = await new Promise((resolve, reject) => {
            conexao.query(sql, [email_user], (err, results) => {
                if (err) reject(err);
                else resolve(results[0]);
            });
        });

        if (!user) {
            return res.status(404).json({ error: "Usuário não encontrado" });
        }

        const isPasswordValid = await bcrypt.compare(password_user, user.password_user);

        if (!isPasswordValid) {
            return res.status(401).json({ error: "Senha incorreta" });
        }

        const token = jwt.sign(
            {
                id_user: user.id_user,
                email_user: user.email_user,
                role_user: user.role_user
            },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({ message: "Login bem-sucedido", token });

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

export default app;
