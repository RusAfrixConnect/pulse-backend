const express    = require('express');
const cors       = require('cors');
const http       = require('http');
const { Server } = require('socket.io');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

app.use(cors());
app.use(express.json());

// ── BASE DE DONNÉES EN MÉMOIRE (temporaire) ──
let users    = [];
let events   = [];
let messages = [];

// ── ROUTES ──────────────────────────────────

// Test
app.get('/', (req, res) => {
  res.json({ status: 'Pulse Backend OK 🚀', version: '1.0.0' });
});

// Inscription
app.post('/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Champs manquants' });
  if (users.find(u => u.email === email))
    return res.status(400).json({ error: 'Email déjà utilisé' });
  const user = {
    id: Date.now().toString(),
    name, email, password,
    znd: 50,
    createdAt: new Date(),
  };
  users.push(user);
  res.json({ success: true, user: { id: user.id, name, email, znd: 50 } });
});

// Connexion
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  res.json({ success: true, user: { id: user.id, name: user.name, email, znd: user.znd } });
});

// Récupérer tous les events
app.get('/events', (req, res) => {
  res.json(events);
});

// Créer un event
app.post('/events', (req, res) => {
  const event = { id: Date.now().toString(), ...req.body, createdAt: new Date() };
  events.push(event);
  io.emit('new_event', event);
  res.json({ success: true, event });
});

// Récupérer les messages
app.get('/messages/:userId', (req, res) => {
  const userMessages = messages.filter(m =>
    m.from === req.params.userId || m.to === req.params.userId);
  res.json(userMessages);
});

// Envoyer un message
app.post('/messages', (req, res) => {
  const message = { id: Date.now().toString(), ...req.body, createdAt: new Date() };
  messages.push(message);
  io.emit('new_message', message);
  res.json({ success: true, message });
});

// Récupérer tous les users
app.get('/users', (req, res) => {
  res.json(users.map(u => ({
    id: u.id, name: u.name, email: u.email, znd: u.znd
  })));
});

// ── WEBSOCKET ────────────────────────────────
io.on('connection', (socket) => {
  console.log('User connecté :', socket.id);

  socket.on('join', (userId) => {
    socket.join(userId);
    console.log('User rejoint :', userId);
  });

  socket.on('send_message', (data) => {
    const message = { id: Date.now().toString(), ...data, createdAt: new Date() };
    messages.push(message);
    io.to(data.to).emit('new_message', message);
  });

  socket.on('disconnect', () => {
    console.log('User déconnecté :', socket.id);
  });
});

// ── DÉMARRAGE ────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`✅ Pulse Backend démarré sur le port ${PORT}`);
});