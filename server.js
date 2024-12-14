require('dotenv').config(); // Carrega variáveis de ambiente de um arquivo .env
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');

// Variáveis de ambiente
const SECRET_KEY = process.env.SECRET_KEY || 'defaultsecretkey'; // Chave secreta
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin'; // Nome de usuário
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'password123'; // Senha

const corsOptions = {
  origin: 'http://localhost:4200', // Ajuste conforme necessário
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
};

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Hash da senha para o administrador
const usuarios = [
  { username: ADMIN_USERNAME, password: bcrypt.hashSync(ADMIN_PASSWORD, 10) },
];

// Função para verificar token JWT
function verificarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(403).send('Token não fornecido.');

  // Extrai o token após o prefixo 'Bearer '
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(403).send('Token malformado.');

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).send('Token inválido.');
    req.user = decoded;
    next();
  });
}

// Rota de login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = usuarios.find((u) => u.username === username);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).send('Credenciais inválidas.');
  }

  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
  res.send({ token });
});

// Rota para obter confrontos
app.get('/confrontos', (req, res) => {
  try {
    const data = fs.readFileSync('confrontos.json');
    res.json(JSON.parse(data));
  } catch (error) {
    console.error('Erro ao ler confrontos:', error);
    res.status(500).json({ message: 'Erro ao ler confrontos.' });
  }
});

// Rota para atualizar confrontos (somente a professora)
app.post('/confrontos', verificarToken, (req, res) => {
  try {
    const novosConfrontos = req.body;

    // Validar a estrutura dos dados
    if (!novosConfrontos.data || !Array.isArray(novosConfrontos.partidas)) {
      return res.status(400).json({ message: 'Formato de dados inválido.' });
    }

    // Salvar confrontos no arquivo
    fs.writeFileSync('confrontos.json', JSON.stringify({ confrontos: [novosConfrontos] }, null, 2));

    // Retornar um JSON de sucesso
    res.json({ message: 'Confrontos atualizados com sucesso!' });
  } catch (error) {
    console.error('Erro ao atualizar confrontos:', error);
    res.status(500).json({ message: 'Erro interno no servidor.' });
  }
});

// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
