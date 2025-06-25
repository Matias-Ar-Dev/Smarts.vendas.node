import express from 'express';
import bcrypt from 'bcrypt';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { authenticateJWT } from './middlewares/auth.js';
import conexao from './app/data/conexao.js';
import fsSync from 'fs';
import path from 'path';
import multer from 'multer';
import fs from 'fs/promises';
import { handleCreateUser } from './app/controllers/userContro.js';
import { loginUser } from './app/controllers/logincontro.js';
import { handleDeleteUser } from './app/controllers/deleteuserContro.js';
import { editUser } from './app/controllers/edituserContro.js';


dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());




const uploadDir = './uploads'
if(!fsSync.existsSync(uploadDir))fsSync.mkdirSync(uploadDir, {recursive: true});


// Configuração do Multer com validação de tipo
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});

const upload = multer({ 
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'application/pdf',
      'image/jpeg',
      'image/png',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Tipo de arquivo não suportado.'), false);
    }
  }
});



app.post('/documentos', upload.single('arquivo'), async (req, res) => {
  const { name_document, role_document } = req.body;
  const file = req.file;

  if (!file) return res.status(400).json({ error: 'Arquivo é obrigatório.' });
  if (!name_document) return res.status(400).json({ error: 'Nome do documento é obrigatório.' });
  if (!role_document) return res.status(400).json({ error: 'Tipo (cliente/empresa) é obrigatório.' });

  const path_document = file.path;
  const document_size = file.size;

  try {
    const [result] = await conexao.execute(`
      INSERT INTO documents (name_document, path_document, role_document, document_size)
      VALUES (?, ?, ?, ?)
    `, [name_document, path_document, role_document, document_size]);

    // Buscar o documento recém inserido (assumindo que id_document é autoincrement)
    const [rows] = await conexao.execute(`SELECT * FROM documents WHERE id_document = ?`, [result.insertId]);

    res.status(201).json({ message: 'Documento salvo com sucesso!', document: rows[0] });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'Já existe um documento com esse nome.' });
    }
    console.error(error);
    res.status(500).json({ error: error.message || 'Erro ao salvar no banco de dados.' });
  }
});app.get('/documentos', async (req, res) => {
  const limit = Math.max(1, parseInt(req.query.limit) || 6);
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const offset = (page - 1) * limit;

  try {
    const [countRows] = await conexao.execute("SELECT COUNT(*) AS total FROM documents");
    const total = countRows[0].total;
    const lastPage = Math.ceil(total / limit);

    const sql = `
      SELECT 
        id_document, 
        name_document, 
        path_document, 
        role_document, 
        document_size, 
        data_create 
      FROM documents 
      ORDER BY data_create DESC 
      LIMIT ${Number(limit)} OFFSET ${Number(offset)}
    `;

    const [dataRows] = await conexao.query(sql);

    res.status(200).json({
      page,
      perPage: limit,
      total,
      lastPage,
      data: dataRows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Erro ao buscar documentos' });
  }
});


  


// ❌ Excluir documento
app.delete('/documentos/:id_document', async (req, res) => {
  const { id_document } = req.params;

  try {
    // 1. Buscar o documento
    const [rows] = await conexao.execute(
      'SELECT path_document FROM documents WHERE id_document = ?',
      [id_document]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Documento não encontrado.' });
    }

    const { path_document } = rows[0];

    // 2. Excluir arquivo físico (se existir)
    await fs.unlink(path_document).catch(() => {
      console.warn('Arquivo não encontrado no disco. Prosseguindo com exclusão do banco.');
    });

    // 3. Excluir do banco
    await conexao.execute(
      'DELETE FROM documents WHERE id_document = ?',
      [id_document]
    );

    res.json({ message: 'Documento excluído com sucesso.' });
  } catch (error) {
    console.error('Erro ao excluir documento:', error);
    res.status(500).json({ error: 'Erro ao excluir o documento.' });
  }
});


app.get('/documentos/download/:id_document', async (req, res) => {
  const { id_document } = req.params;

  try {
    // Busca o documento no banco para pegar o caminho e nome
    const [rows] = await conexao.execute(
      'SELECT path_document, name_document FROM documents WHERE id_document = ?',
      [id_document]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Documento não encontrado.' });
    }

    const { path_document, name_document } = rows[0];

    // Envia o arquivo para download
    res.download(path_document, name_document, (err) => {
      if (err) {
        console.error('Erro ao enviar arquivo:', err);
        if (!res.headersSent) {
          res.status(500).json({ error: 'Erro ao enviar arquivo.' });
        }
      }
    });

  } catch (error) {
    console.error('Erro na rota de download:', error);
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});


app.put('/documentos/:id_document', upload.single('arquivo'), async (req, res) => {
  const { id_document } = req.params;
  const { name_document, role_document } = req.body;
  const file = req.file;

  try {
    // 1. Busca o documento atual no banco
    const [rows] = await conexao.execute(
      'SELECT path_document FROM documents WHERE id_document = ?',
      [id_document]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Documento não encontrado.' });
    }

    const currentPath = rows[0].path_document;

    // 2. Definir novos valores
    // Se não enviar novo nome ou role, mantém os antigos
    // Se quiser forçar, pode validar aqui antes de atualizar

    // 3. Se enviou novo arquivo, apagar o antigo arquivo físico e atualizar path e size
    let path_document = currentPath;
    let document_size = null;

    if (file) {
      // Apaga arquivo antigo
      await fs.unlink(currentPath).catch(() => {
        console.warn('Arquivo antigo não encontrado no disco, prosseguindo.');
      });

      path_document = file.path;
      document_size = file.size;
    }

    // 4. Montar query e params dinamicamente
    const fields = [];
    const params = [];

    if (name_document) {
      fields.push('name_document = ?');
      params.push(name_document);
    }

    if (role_document) {
      fields.push('role_document = ?');
      params.push(role_document);
    }

    if (file) {
      fields.push('path_document = ?');
      params.push(path_document);

      fields.push('document_size = ?');
      params.push(document_size);
    }

    if (fields.length === 0) {
      return res.status(400).json({ error: 'Nenhum dado para atualizar.' });
    }

    params.push(id_document);

    const sql = `UPDATE documents SET ${fields.join(', ')} WHERE id_document = ?`;

    await conexao.execute(sql, params);

    res.json({ message: 'Documento atualizado com sucesso.' });

  } catch (error) {
    console.error('Erro ao atualizar documento:', error);
    res.status(500).json({ error: 'Erro ao atualizar documento.' });
  }
});


app.get('/filter_documentos', async (req, res) => {
  const name_document = req.query.name_document?.trim(); // já remove espaços

  console.log('Filtro name_document:', name_document); // para debug

  try {
    let sql = `
      SELECT 
        id_document, 
        name_document, 
        path_document, 
        role_document, 
        document_size, 
        data_create 
      FROM documents
    `;

    const params = [];

    // SOMENTE adiciona o filtro se o valor existir e for string
    if (name_document && name_document.length > 0) {
      sql += ' WHERE LOWER(name_document) LIKE ?';
      params.push(`%${name_document.toLowerCase()}%`);
    }

    sql += ' ORDER BY data_create DESC';

    console.log('SQL Final:', sql);
    console.log('Parâmetros:', params);

    const [rows] = await conexao.execute(sql, params);

    res.status(200).json(rows);
  } catch (error) {
    console.error('Erro ao buscar documentos:', error);
    res.status(500).json({ error: 'Erro ao buscar documentos.' });
  }
});

app.get('/total_por_categoria', async (req, res) => {
  try {
    const sql = `
      SELECT 
        role_document AS categoria,
        COUNT(*) AS total
      FROM documents
      GROUP BY role_document
    `;

    const [rows] = await conexao.execute(sql);

    res.status(200).json(rows); // Ex: [{ categoria: "cliente", total: 8 }, { categoria: "empresa", total: 12 }]
  } catch (error) {
    console.error('Erro ao contar documentos por categoria:', error);
    res.status(500).json({ error: 'Erro ao contar documentos por categoria.' });
  }
});


app.get('/total_documentos', async (req, res) => {
  try {
    const [rows] = await conexao.execute('SELECT COUNT(*) AS total FROM documents');
    const total = rows[0]?.total || 0;

    res.status(200).json({ total });
  } catch (error) {
    console.error('Erro ao obter total de documentos:', error);
    res.status(500).json({ error: 'Erro ao obter total de documentos.' });
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
+
app.get('/filter_users', async (req, res) => {
  try {
    const { search } = req.query;

    const sql = `
      SELECT * FROM users
      WHERE name_user LIKE ? OR email_user LIKE ?
    `;
    const params = [`%${search}%`, `%${search}%`];

    const [rows] = await conexao.execute(sql, params);

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
