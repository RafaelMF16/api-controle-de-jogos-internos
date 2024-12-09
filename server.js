const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Configurações de autenticação
const SECRET_KEY = 'sua_chave_secreta';
const usuarios = [
  { username: 'admin', password: bcrypt.hashSync('FPM1234', 10) },
];

// Função para verificar token JWT
function verificarToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send('Token não fornecido.');
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
  const data = fs.readFileSync('confrontos.json');
  res.send(JSON.parse(data));
});

// Rota para atualizar confrontos (somente a professora)
app.post('/confrontos', verificarToken, (req, res) => {
  const novosConfrontos = req.body;

  fs.writeFileSync('confrontos.json', JSON.stringify(novosConfrontos, null, 2));
  res.send('Confrontos atualizados com sucesso!');
});

// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});