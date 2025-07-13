// server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');         // Para proteger a senha
const jwt = require('jsonwebtoken');        // Para criar token de acesso

const app = express();
app.use(cors());
app.use(express.json());

// Chave secreta para criar o token (em produção, guarde em variável de ambiente)
const JWT_SECRET = 'sua_chave_secreta_123!';

// Conectar ao MongoDB Atlas (seu banco online)
mongoose.connect('mongodb+srv://brenofort:v1WmBe3bKA2RC0TL@cluster0.jkax06q.mongodb.net/conforms?retryWrites=true&w=majority&appName=Cluster0')
  .then(() => console.log('🟢 Conectado ao MongoDB'))
  .catch((err) => console.error('🔴 Erro ao conectar ao MongoDB:', err));

// Esquema para os usuários do sistema (dados que você cadastra, nome e email)
const UsuarioSchema = new mongoose.Schema({
  nome: String,
  email: String,
});
const Usuario = mongoose.model('Usuario', UsuarioSchema);


// Esquema para os usuários que podem fazer login (autenticação)
const AuthUserSchema = new mongoose.Schema({
  username: { type: String, unique: true },  // nome de login
  passwordHash: String,                       // senha protegida (hash)
});
const AuthUser = mongoose.model('AuthUser', AuthUserSchema);

/////////////////////
// ROTAS DE AUTENTICAÇÃO (login e cadastro de usuários para entrar no sistema)

// Rota para registrar um novo usuário para login
app.post('/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Verifica se recebeu username e senha
    if (!username || !password) {
      return res.status(400).json({ erro: 'Usuário e senha são obrigatórios' });
    }

    // Verifica se já existe esse usuário no banco
    const existingUser = await AuthUser.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ erro: 'Usuário já existe' });
    }

    // Cria o hash da senha para guardar seguro no banco
    const passwordHash = await bcrypt.hash(password, 10);

    // Salva o usuário no banco
    const novoUser = new AuthUser({ username, passwordHash });
    await novoUser.save();

    res.json({ mensagem: 'Usuário registrado com sucesso' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro no registro' });
  }
});

// Rota para fazer login
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Procura o usuário no banco
    const user = await AuthUser.findOne({ username });
    if (!user) {
      return res.status(400).json({ erro: 'Usuário não encontrado' });
    }

    // Compara a senha enviada com a senha protegida do banco
    const senhaValida = await bcrypt.compare(password, user.passwordHash);
    if (!senhaValida) {
      return res.status(400).json({ erro: 'Senha inválida' });
    }

    // Cria o token JWT com os dados do usuário
    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '2h' });

    // Envia o token para o frontend
    res.json({ mensagem: 'Login realizado com sucesso', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro no login' });
  }
});

/////////////////////
// Middleware para proteger rotas: verifica se o usuário está logado

function autenticarToken(req, res, next) {
  // Pega o token do cabeçalho Authorization: Bearer TOKEN
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ erro: 'Token não fornecido' });
  }

  // Verifica se o token é válido
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ erro: 'Token inválido' });
    }
    // Salva os dados do usuário no req para usar depois, se precisar
    req.user = user;
    next();
  });
}

/////////////////////
// ROTAS DE USUÁRIOS PROTEGIDAS - só podem ser usadas se estiver logado

// Criar usuário
app.post('/usuarios', autenticarToken, async (req, res) => {
  try {
    const novoUsuario = new Usuario(req.body);
    await novoUsuario.save();
    res.json({ mensagem: 'Usuário salvo com sucesso!' });
  } catch (err) {
    console.error('Erro ao salvar usuário:', err);
    res.status(500).json({ erro: 'Erro ao salvar usuário' });
  }
});

// Listar usuários
app.get('/usuarios', autenticarToken, async (req, res) => {
  try {
    const usuarios = await Usuario.find();
    res.json(usuarios);
  } catch (err) {
    console.error('Erro ao buscar usuários:', err);
    res.status(500).json({ erro: 'Erro ao buscar usuários' });
  }
});

// Excluir usuário
app.delete('/usuarios/:id', autenticarToken, async (req, res) => {
  try {
    const resultado = await Usuario.findByIdAndDelete(req.params.id);
    if (!resultado) {
      return res.status(404).json({ erro: 'Usuário não encontrado' });
    }
    res.json({ mensagem: 'Usuário excluído com sucesso!' });
  } catch (err) {
    console.error('Erro ao excluir usuário:', err);
    res.status(500).json({ erro: 'Erro ao excluir usuário' });
  }
});

// Atualizar usuário
app.put('/usuarios/:id', autenticarToken, async (req, res) => {
  try {
    const { nome, email } = req.body;
    const atualizado = await Usuario.findByIdAndUpdate(req.params.id, { nome, email }, { new: true });
    if (!atualizado) {
      return res.status(404).json({ erro: 'Usuário não encontrado' });
    }
    res.json({ mensagem: 'Usuário atualizado com sucesso', usuario: atualizado });
  } catch (err) {
    console.error('Erro ao atualizar usuário:', err);
    res.status(500).json({ erro: 'Erro ao atualizar usuário' });
  }
});

// Iniciar servidor na porta 3000
app.listen(3000, () => {
  console.log('Servidor rodando em http://localhost:3000');
});
