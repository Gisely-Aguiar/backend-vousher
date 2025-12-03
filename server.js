const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Configuração do MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'voucher_system_auth',
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const JWT_SECRET = process.env.JWT_SECRET || 'sua_chave_secreta_super_segura_2024';

app.use(cors());
app.use(express.json());

// Middleware de autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ 
      success: false,
      error: 'Token de acesso não fornecido' 
    });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ 
        success: false,
        error: 'Token inválido' 
      });
    }
    req.user = user;
    next();
  });
};

// ============================================
// ROTAS PÚBLICAS
// ============================================

// Rota de teste
app.get('/', (req, res) => {
  res.json({
    message: 'API do Sistema de Vouchers - MODE DEV (sem criptografia)',
    timestamp: new Date().toISOString(),
    warning: '⚠️ MODO DESENVOLVIMENTO - SENHAS EM TEXTO PURO'
  });
});

// Rota de login SIMPLIFICADA (senha em texto puro)
app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('🔍 Login attempt:', req.body.username);
    
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Usuário e senha são obrigatórios' 
      });
    }
    
    // Buscar usuário
    const [users] = await pool.query(
      'SELECT * FROM system_users WHERE username = ? AND is_active = true',
      [username]
    );
    
    if (users.length === 0) {
      console.log('❌ Usuário não encontrado:', username);
      return res.status(401).json({ 
        success: false,
        error: 'Usuário não encontrado' 
      });
    }
    
    const user = users[0];
    console.log('✅ Usuário encontrado:', user.username);
    console.log('🔐 Senha no banco:', user.password);
    console.log('🔐 Senha digitada:', password);
    
    // Comparação DIRETA (sem bcrypt)
    if (password !== user.password) {
      console.log('❌ Senha incorreta');
      return res.status(401).json({ 
        success: false,
        error: 'Senha incorreta' 
      });
    }
    
    // Gerar token JWT
    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        name: user.name,
        user_type: user.user_type,
        email: user.email
      },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    
    console.log('🎉 Login bem-sucedido para:', user.username);
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        name: user.name,
        email: user.email,
        user_type: user.user_type,
        phone: user.phone
      }
    });
    
  } catch (error) {
    console.error('🔥 Erro no login:', error);
    res.status(500).json({ 
      success: false,
      error: 'Erro interno no servidor',
      details: error.message 
    });
  }
});

// Rota para resetar banco de dados (apenas dev)
app.post('/api/dev/reset-db', async (req, res) => {
  try {
    console.log('🔄 Resetando banco de dados...');
    
    // Deletar todos os dados
    await pool.query('DELETE FROM connection_logs');
    await pool.query('DELETE FROM voucher_users');
    await pool.query('DELETE FROM system_users');
    
    // Inserir usuários padrão
    await pool.query(
      `INSERT INTO system_users 
       (username, password, name, email, user_type, is_active)
       VALUES 
       ('master', 'Master@123', 'Administrador Master', 'master@empresa.com', 'master', TRUE),
       ('admin', 'admin123', 'Administrador', 'admin@empresa.com', 'administrador', TRUE),
       ('funcionario', 'func123', 'Funcionário', 'funcionario@empresa.com', 'funcionario', TRUE)`
    );
    
    res.json({
      success: true,
      message: 'Banco de dados resetado',
      usuarios_criados: [
        { username: 'master', password: 'Master@123', tipo: 'master' },
        { username: 'admin', password: 'admin123', tipo: 'administrador' },
        { username: 'funcionario', password: 'func123', tipo: 'funcionario' }
      ]
    });
    
  } catch (error) {
    console.error('❌ Erro ao resetar banco:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// ROTAS PROTEGIDAS - USUÁRIOS DO SISTEMA
// ============================================

// Criar usuário do sistema (apenas master)
// Criar usuário do sistema (apenas master)
app.post('/api/system-users', authenticateToken, async (req, res) => {
  try {
    console.log('📝 Criando novo usuário do sistema...');
    
    // Verificar se é master
    if (req.user.user_type !== 'master') {
      return res.status(403).json({ 
        success: false,
        error: 'Apenas o usuário master pode criar novos usuários' 
      });
    }

    const { username, password, name, email, phone, user_type } = req.body;
    
    console.log('Dados recebidos:', { username, name, email, user_type });
    
    // Validações
    if (!username || !password || !name || !email || !user_type) {
      return res.status(400).json({
        success: false,
        error: 'Todos os campos são obrigatórios'
      });
    }
    
    // Verificar tipos permitidos
    if (!['administrador', 'funcionario'].includes(user_type)) {
      return res.status(400).json({ 
        success: false,
        error: 'user_type deve ser "administrador" ou "funcionario"' 
      });
    }
    
    // Verificar se username já existe
    const [existingUser] = await pool.query(
      'SELECT id FROM system_users WHERE username = ?',
      [username]
    );
    
    if (existingUser.length > 0) {
      return res.status(400).json({
        success: false,
        error: 'Username já está em uso'
      });
    }
    
    // Inserir no banco (agora com created_by)
    const [result] = await pool.query(
      `INSERT INTO system_users 
       (username, password, name, email, phone, user_type, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [username, password, name, email, phone, user_type, req.user.id]
    );
    
    console.log('✅ Usuário criado com ID:', result.insertId);
    
    res.status(201).json({
      success: true,
      message: 'Usuário criado com sucesso',
      user: {
        id: result.insertId,
        username,
        name,
        email,
        phone,
        user_type
      }
    });
    
  } catch (error) {
    console.error('❌ Erro ao criar usuário:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor',
      details: error.message,
      sqlError: error.sqlMessage // Para debug
    });
  }
});

// ============================================
// ROTAS PROTEGIDAS - CLIENTES/VOUCHERS
// ============================================

// Criar cliente com voucher
app.post('/api/voucher-users', authenticateToken, async (req, res) => {
  try {
    const { name, email, phone, voucher_id, voucher_password, notes } = req.body;
    
    // Validações
    if (!name || !phone || !voucher_id || !voucher_password) {
      return res.status(400).json({
        success: false,
        error: 'Nome, telefone, voucher_id e voucher_password são obrigatórios'
      });
    }
    
    // Inserir cliente
    const [result] = await pool.query(
      `INSERT INTO voucher_users 
       (name, email, phone, voucher_id, voucher_password, registered_by, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [name, email, phone, voucher_id, voucher_password, req.user.id, notes]
    );
    
    res.status(201).json({
      success: true,
      message: 'Cliente cadastrado com sucesso',
      data: {
        id: result.insertId,
        name,
        email,
        phone,
        voucher_id,
        voucher_password
      }
    });
    
  } catch (error) {
    console.error('❌ Erro ao criar cliente:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor'
    });
  }
});

// Buscar cliente por voucher
app.get('/api/voucher-users/search/:voucher_id', authenticateToken, async (req, res) => {
  try {
    const { voucher_id } = req.params;
    
    // Buscar cliente
    const [clients] = await pool.query(
      `SELECT vu.*, su.name as registered_by_name
       FROM voucher_users vu
       LEFT JOIN system_users su ON vu.registered_by = su.id
       WHERE vu.voucher_id = ?`,
      [voucher_id]
    );
    
    if (clients.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Voucher não encontrado'
      });
    }
    
    const client = clients[0];
    
    res.json({
      success: true,
      user: client
    });
    
  } catch (error) {
    console.error('❌ Erro na busca:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor'
    });
  }
});

// Listar todos os clientes
app.get('/api/voucher-users', authenticateToken, async (req, res) => {
  try {
    const { search = '' } = req.query;
    
    let query = `
      SELECT vu.*, su.name as registered_by_name
      FROM voucher_users vu
      LEFT JOIN system_users su ON vu.registered_by = su.id
    `;
    
    const values = [];
    
    if (search) {
      query += ` WHERE vu.name LIKE ? OR vu.voucher_id LIKE ? OR vu.email LIKE ? OR vu.phone LIKE ?`;
      const searchTerm = `%${search}%`;
      values.push(searchTerm, searchTerm, searchTerm, searchTerm);
    }
    
    query += ` ORDER BY vu.registered_at DESC`;
    
    const [clients] = await pool.query(query, values);
    
    res.json({
      success: true,
      data: clients,
      count: clients.length
    });
    
  } catch (error) {
    console.error('❌ Erro ao listar clientes:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor'
    });
  }
});

// ============================================
// ROTAS ÚTEIS PARA DEBUG
// ============================================

// Ver todos os usuários do sistema
app.get('/api/dev/users', async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT id, username, password, name, user_type FROM system_users'
    );
    
    res.json({
      success: true,
      users: users
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verificar estado do banco
app.get('/api/dev/status', async (req, res) => {
  try {
    const [systemUsers] = await pool.query('SELECT COUNT(*) as count FROM system_users');
    const [voucherUsers] = await pool.query('SELECT COUNT(*) as count FROM voucher_users');
    
    res.json({
      success: true,
      system_users: systemUsers[0].count,
      voucher_users: voucherUsers[0].count,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// INICIAR SERVIDOR
// ============================================

app.listen(PORT, '0.0.0.0', () => {
  console.log('='.repeat(50));
  console.log('🚀 SERVIDOR INICIADO (MODO DEV - SEM CRIPTOGRAFIA)');
  console.log('='.repeat(50));
  console.log(`📍 Porta: ${PORT}`);
  console.log(`🌐 URL: https://voucher-backend.cleverapps.io`);
  console.log(`🕒 ${new Date().toLocaleString()}`);
  console.log('='.repeat(50));
});



