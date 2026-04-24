const express    = require('express');
const cors       = require('cors');
const http       = require('http');
const { Server } = require('socket.io');
const { Pool }   = require('pg');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

app.use(cors());
app.use(express.json());

// ── BASE DE DONNÉES ──────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Créer les tables si elles n'existent pas
const initDB = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100),
      email VARCHAR(100) UNIQUE,
      password VARCHAR(100),
      znd INTEGER DEFAULT 50,
      wallet_address VARCHAR(100),
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY,
      type VARCHAR(50),
      title VARCHAR(200),
      description TEXT,
      city VARCHAR(100),
      lat FLOAT,
      lng FLOAT,
      participants INTEGER DEFAULT 1,
      max_p INTEGER DEFAULT 10,
      znd_reward INTEGER DEFAULT 50,
      user_id INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      from_user INTEGER,
      to_user INTEGER,
      text TEXT,
      read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('✅ Base de données initialisée');
};

initDB();

// ── ROUTES ──────────────────────────────────

app.get('/', (req, res) => {
  res.json({ status: 'Pulse Backend OK 🚀', version: '2.0.0' });
});

// Inscription
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Champs manquants' });
  try {
    const result = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email, znd',
      [name, email, password]
    );
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505')
      return res.status(400).json({ error: 'Email déjà utilisé' });
    res.status(500).json({ error: err.message });
  }
});

// Connexion
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query(
      'SELECT id, name, email, znd FROM users WHERE email = $1 AND password = $2',
      [email, password]
    );
    if (result.rows.length === 0)
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Récupérer tous les users
app.get('/users', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, znd FROM users'
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Récupérer tous les events
app.get('/events', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM events ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Créer un event
app.post('/events', async (req, res) => {
  const { type, title, description, city, lat, lng, maxP, zndReward, userId } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO events (type, title, description, city, lat, lng, max_p, znd_reward, user_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
      [type, title, description, city, lat, lng, maxP, zndReward, userId]
    );
    const event = result.rows[0];
    io.emit('new_event', event);
    res.json({ success: true, event });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Récupérer les messages
app.get('/messages/:userId', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM messages WHERE from_user = $1 OR to_user = $1 ORDER BY created_at DESC',
      [req.params.userId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Envoyer un message
app.post('/messages', async (req, res) => {
  const { from, to, text } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO messages (from_user, to_user, text) VALUES ($1, $2, $3) RETURNING *',
      [from, to, text]
    );
    const message = result.rows[0];
    io.emit('new_message', message);
    res.json({ success: true, message });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── MARKETPLACE ──────────────────────────────

// Créer les tables marketplace
const initMarketplace = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shops (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      name VARCHAR(200),
      description TEXT,
      type VARCHAR(50),
      emoji VARCHAR(10),
      lat FLOAT,
      lng FLOAT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      shop_id INTEGER,
      name VARCHAR(200),
      description TEXT,
      price FLOAT,
      currency VARCHAR(10) DEFAULT 'ZND',
      emoji VARCHAR(10),
      available BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      buyer_id INTEGER,
      product_id INTEGER,
      shop_id INTEGER,
      price FLOAT,
      currency VARCHAR(10),
      status VARCHAR(50) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('✅ Marketplace initialisée');
};

initMarketplace();

// Créer une boutique
app.post('/shops', async (req, res) => {
  const { userId, name, description, type, emoji, lat, lng } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO shops (user_id, name, description, type, emoji, lat, lng) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [userId, name, description, type, emoji, lat, lng]
    );
    res.json({ success: true, shop: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Récupérer toutes les boutiques
app.get('/shops', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM shops ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Ajouter un produit
app.post('/products', async (req, res) => {
  const { shopId, name, description, price, currency, emoji } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO products (shop_id, name, description, price, currency, emoji) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [shopId, name, description, price, currency, emoji]
    );
    res.json({ success: true, product: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Récupérer les produits d'une boutique
app.get('/products/:shopId', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM products WHERE shop_id = $1 AND available = TRUE',
      [req.params.shopId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Créer une commande
app.post('/orders', async (req, res) => {
  const { buyerId, productId, shopId, price, currency } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO orders (buyer_id, product_id, shop_id, price, currency) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [buyerId, productId, shopId, price, currency]
    );
    res.json({ success: true, order: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Récupérer les commandes d'une boutique
app.get('/orders/:shopId', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM orders WHERE shop_id = $1 ORDER BY created_at DESC',
      [req.params.shopId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── WEBSOCKET ────────────────────────────────
io.on('connection', (socket) => {
  console.log('User connecté :', socket.id);
  socket.on('join', (userId) => socket.join(userId));
  socket.on('send_message', async (data) => {
    const result = await pool.query(
      'INSERT INTO messages (from_user, to_user, text) VALUES ($1, $2, $3) RETURNING *',
      [data.from, data.to, data.text]
    );
    io.to(data.to).emit('new_message', result.rows[0]);
  });
  socket.on('disconnect', () => {
    console.log('User déconnecté :', socket.id);
  });
});

// ── DÉMARRAGE ────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`✅ Pulse Backend v2.0 démarré sur le port ${PORT}`);
});
