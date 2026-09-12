require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const http       = require('http');
const { Server } = require('socket.io');
const { Pool }   = require('pg');
const QRCode     = require('qrcode');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const crypto     = require('crypto');
const rateLimit  = require('express-rate-limit');

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Limite le brute-force / spam de comptes sur /register et /login.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Trop de tentatives, réessaie dans quelques minutes.' },
});

// En production, définis JWT_SECRET dans les variables d'env Render pour que les tokens
// survivent aux redémarrages. Sans ça, un secret aléatoire est généré à chaque démarrage
// (sûr par défaut, mais invalide tous les tokens émis avant le redémarrage).
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.JWT_SECRET) {
  console.warn('⚠️  JWT_SECRET non défini : secret généré aléatoirement pour ce process (tokens invalidés au redémarrage). Configure JWT_SECRET sur Render.');
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ success: false, error: 'Non authentifié' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ success: false, error: 'Token invalide ou expiré' });
  }
}

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

// Render fait proxy des requêtes : nécessaire pour que express-rate-limit (et req.ip en
// général) voie la vraie IP du client via X-Forwarded-For, pas celle du proxy interne.
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());

// ── BASE DE DONNÉES ──────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function getUserWalletAddress(userId) {
  const result = await pool.query('SELECT wallet_address FROM users WHERE id = $1', [userId]);
  return result.rows[0]?.wallet_address || null;
}

// Vérifie que `address` correspond bien au wallet_address lié au compte authentifié
// (req.user.id). Renvoie une réponse d'erreur et retourne false si ce n'est pas le cas.
async function requireOwnWallet(req, res, address) {
  const ownAddress = await getUserWalletAddress(req.user.id);
  if (!ownAddress) {
    res.status(403).json({ success: false, error: 'Aucun wallet lié à ce compte, reconnecte-toi pour le synchroniser.' });
    return false;
  }
  if (ownAddress.toLowerCase() !== String(address || '').toLowerCase()) {
    res.status(403).json({ success: false, error: 'Cette adresse ne correspond pas à ton compte.' });
    return false;
  }
  return true;
}

// Créer les tables si elles n'existent pas
const initDB = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100),
      email VARCHAR(100) UNIQUE,
      password VARCHAR(100),
      birthdate VARCHAR(20),
      country VARCHAR(100),
      city VARCHAR(100),
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
  await pool.query(`
  ALTER TABLE users
  ADD COLUMN IF NOT EXISTS birthdate VARCHAR(20),
  ADD COLUMN IF NOT EXISTS country VARCHAR(100),
  ADD COLUMN IF NOT EXISTS city VARCHAR(100);
`).catch(() => {});
  // Profil de matching (IA Matching) : âge, bio, centres d'intérêt, type de relation recherchée.
  await pool.query(`
  ALTER TABLE users
  ADD COLUMN IF NOT EXISTS age INTEGER,
  ADD COLUMN IF NOT EXISTS bio VARCHAR(150),
  ADD COLUMN IF NOT EXISTS interests JSONB DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS looking_for JSONB DEFAULT '[]'::jsonb;
`).catch(() => {});
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shops (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      name VARCHAR(200) NOT NULL,
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
      shop_id INTEGER NOT NULL REFERENCES shops(id),
      name VARCHAR(200) NOT NULL,
      description TEXT,
      price NUMERIC DEFAULT 0,
      currency VARCHAR(10) DEFAULT 'ZND',
      emoji VARCHAR(10),
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  // Empêche de collecter le même trésor plusieurs fois (le state client "found" est local
  // et se réinitialise à chaque rechargement de l'app - sans ça, ZND infini).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS treasure_claims (
      user_id INTEGER NOT NULL,
      treasure_id INTEGER NOT NULL,
      claimed_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (user_id, treasure_id)
    );
  `);
  // Session de live server-authoritative (bug #C) : started_at est horodaté par le serveur,
  // pas par le client, donc elapsedSeconds ne peut plus être falsifié. ended_at IS NULL
  // empêche de terminer/créditer la même session deux fois (même garde que pledges.repaid_at).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS live_sessions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      started_at TIMESTAMP DEFAULT NOW(),
      ended_at TIMESTAMP,
      earned NUMERIC
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pledges (
      id SERIAL PRIMARY KEY,
      pledge_id VARCHAR(64) UNIQUE NOT NULL,
      borrower_address VARCHAR(100) NOT NULL,
      collateral_type VARCHAR(20) NOT NULL,
      collateral_value NUMERIC NOT NULL,
      collateral_hash VARCHAR(200),
      collateral_ref VARCHAR(200),
      credit_amount NUMERIC NOT NULL,
      duration_days INTEGER NOT NULL DEFAULT 30,
      tx_hash VARCHAR(100),
      due_date TIMESTAMP NOT NULL,
      repaid_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pledges_borrower ON pledges (borrower_address);`);
  // Solde ZND interne (hors-chaîne) : ce backend n'a pas de wallet chaud pour signer de vrais
  // transferts BEP-20, donc /api/qr/pay et /api/transfer/znd déplacent de la valeur ici,
  // séparément du solde on-chain réel et du crédit de gage (pledges.credit_amount).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wallet_ledger (
      address VARCHAR(100) PRIMARY KEY,
      balance NUMERIC NOT NULL DEFAULT 0,
      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('✅ Base de données initialisée');
};

// ── VALT — GAGES / RÉPUTATION ────────────────
// LTV (loan-to-value) : part de la valeur du bien accordée en crédit ZND.
const LTV_RATIO = 0.7;

function pledgeStatus(row) {
  if (row.repaid_at) return 'REPAID';
  if (new Date(row.due_date) < new Date()) return 'DEFAULTED';
  return 'ACTIVE';
}

function pledgeToDetails(row) {
  return {
    pledgeId: row.pledge_id,
    type: row.collateral_type,
    model: row.collateral_ref,
    collateralRef: row.collateral_ref,
    collateralValue: parseFloat(row.collateral_value),
    creditAmount: parseFloat(row.credit_amount),
    durationDays: row.duration_days,
    txHash: row.tx_hash,
    dueDate: row.due_date,
    status: pledgeStatus(row),
    createdAt: row.created_at,
  };
}

function computeReputation(rows) {
  const totalPledges = rows.length;
  const repaidPledges = rows.filter(r => pledgeStatus(r) === 'REPAID').length;
  const defaultedPledges = rows.filter(r => pledgeStatus(r) === 'DEFAULTED').length;
  const score = Math.max(0, Math.min(1000, 500 + repaidPledges * 50 - defaultedPledges * 100));
  return {
    score: String(score),
    totalPledges: String(totalPledges),
    repaidPledges: String(repaidPledges),
    defaultedPledges: String(defaultedPledges),
    maxCreditLimit: (score * 2).toFixed(1),
  };
}

initDB();

// ── ROUTES ──────────────────────────────────

app.get('/', (req, res) => {
  res.json({ status: 'Pulse Backend OK 🚀', version: '2.0.0' });
});

// Inscription
app.post('/register', authLimiter, async (req, res) => {
  const { name, email, password, birthdate, country, city } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Champs manquants' });
  const normalizedEmail = String(email).trim().toLowerCase();
  if (!EMAIL_REGEX.test(normalizedEmail))
    return res.status(400).json({ error: 'Email invalide' });
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (name, email, password, birthdate, country, city)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, name, email, znd, city, age, bio, interests, looking_for AS "lookingFor",
                 wallet_address AS "walletAddress"`,
      [name, normalizedEmail, passwordHash, birthdate, country, city]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, user, token });
  } catch (err) {
    if (err.code === '23505')
      return res.status(400).json({ error: 'Email déjà utilisé' });
    res.status(500).json({ error: err.message });
  }
});

// Connexion
app.post('/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const normalizedEmail = String(email || '').trim().toLowerCase();
  try {
    const result = await pool.query(
      `SELECT id, name, email, znd, password, city, age, bio, interests, looking_for AS "lookingFor",
              wallet_address AS "walletAddress"
       FROM users WHERE email = $1`,
      [normalizedEmail]
    );
    const user = result.rows[0];
    const match = user && await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    delete user.password;
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, user, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Lier/mettre à jour l'adresse wallet VALT de l'utilisateur connecté
app.post('/users/wallet', requireAuth, async (req, res) => {
  const { walletAddress } = req.body;
  if (!walletAddress) return res.status(400).json({ success: false, error: 'walletAddress manquant' });
  try {
    const result = await pool.query(
      'UPDATE users SET wallet_address = $1 WHERE id = $2 RETURNING id, name, email, znd, wallet_address AS "walletAddress"',
      [walletAddress, req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'Utilisateur introuvable' });
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Taxonomie de matching - le serveur ne fait confiance qu'à ces valeurs, jamais à du texte
// arbitraire envoyé par le client (évite de polluer la base avec des clés incohérentes).
const INTEREST_KEYS = [
  'sport', 'music', 'travel', 'reading', 'cooking', 'gaming', 'art', 'nature',
  'fitness', 'photography', 'dancing', 'tech', 'animals', 'fashion', 'movies', 'party',
];
const LOOKING_FOR_KEYS = ['friendship', 'serious', 'casual'];

// Profil de matching (IA Matching) : âge, ville, centres d'intérêt, type de relation recherchée.
app.post('/users/profile', requireAuth, async (req, res) => {
  const { age, bio, city, interests, lookingFor } = req.body;

  if (age !== undefined && age !== null) {
    const ageNum = parseInt(age);
    if (!Number.isInteger(ageNum) || ageNum < 13 || ageNum > 120) {
      return res.status(400).json({ success: false, error: 'Âge invalide' });
    }
  }
  if (bio !== undefined && bio !== null && String(bio).length > 150) {
    return res.status(400).json({ success: false, error: 'Bio trop longue (150 caractères max)' });
  }
  const cleanInterests = Array.isArray(interests)
    ? interests.filter(i => INTEREST_KEYS.includes(i)).slice(0, 10)
    : [];
  const cleanLookingFor = Array.isArray(lookingFor)
    ? lookingFor.filter(l => LOOKING_FOR_KEYS.includes(l)).slice(0, LOOKING_FOR_KEYS.length)
    : [];

  try {
    const result = await pool.query(
      `UPDATE users SET age = $1, bio = $2, city = $3, interests = $4, looking_for = $5
       WHERE id = $6
       RETURNING id, name, email, znd, city, age, bio, interests, looking_for AS "lookingFor",
                 wallet_address AS "walletAddress"`,
      [age ? parseInt(age) : null, bio != null ? String(bio).trim() : null, city || null,
       JSON.stringify(cleanInterests), JSON.stringify(cleanLookingFor), req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'Utilisateur introuvable' });
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Récupérer tous les users
app.get('/users', requireAuth, async (req, res) => {
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
app.post('/events', requireAuth, async (req, res) => {
  const { type, title, description, city, lat, lng, maxP, zndReward } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO events (type, title, description, city, lat, lng, max_p, znd_reward, user_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
      [type, title, description, city, lat, lng, maxP, zndReward, req.user.id]
    );
    const event = result.rows[0];
    io.emit('new_event', event);
    res.json({ success: true, event });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Récupérer les messages
app.get('/messages/:userId', requireAuth, async (req, res) => {
  if (String(req.user.id) !== String(req.params.userId)) {
    return res.status(403).json({ error: 'Accès refusé' });
  }
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
app.post('/messages', requireAuth, async (req, res) => {
  const { to, text } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO messages (from_user, to_user, text) VALUES ($1, $2, $3) RETURNING *',
      [req.user.id, to, text]
    );
    const message = result.rows[0];
    io.emit('new_message', message);
    res.json({ success: true, message });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Créer une boutique
app.post('/shops', requireAuth, async (req, res) => {
  const { name, description, type, emoji, lat, lng } = req.body;
  if (!name) return res.status(400).json({ success: false, error: 'Nom manquant' });
  try {
    const result = await pool.query(
      'INSERT INTO shops (user_id, name, description, type, emoji, lat, lng) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [req.user.id, name, description, type, emoji, lat, lng]
    );
    res.json({ success: true, shop: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Ajouter un produit à une boutique
app.post('/products', requireAuth, async (req, res) => {
  const { shopId, name, description, price, currency, emoji } = req.body;
  if (!shopId || !name) return res.status(400).json({ success: false, error: 'Champs manquants' });
  try {
    const shopResult = await pool.query('SELECT * FROM shops WHERE id = $1', [shopId]);
    if (shopResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Boutique introuvable' });
    }
    if (shopResult.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ success: false, error: 'Cette boutique ne t\'appartient pas' });
    }
    const result = await pool.query(
      'INSERT INTO products (shop_id, name, description, price, currency, emoji) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [shopId, name, description, price || 0, currency || 'ZND', emoji]
    );
    res.json({ success: true, product: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── ÉCONOMIE ZND (server-authoritative) ────────
// Remplace les écritures optimistes côté client (bug #13) : le serveur calcule et valide les
// montants, fait foi sur users.znd. Le client n'envoie plus jamais un montant à créditer/débiter
// directement, seulement des paramètres vérifiables (durée, id de trésor, raison).

// Catalogue des trésors - doit rester synchronisé avec le tableau `treasures` de App.js.
const TREASURE_CATALOG = { 1: 200, 2: 500, 3: 150, 4: 300 };
// Coûts fixes : le montant vient toujours d'ici, jamais du corps de la requête.
const SPEND_CATALOG = { territory_capture: 100 };
// Montants où l'utilisateur choisit parmi une liste fermée (ex: pourboire live) - le serveur
// n'accepte que ces valeurs précises, jamais un montant arbitraire envoyé par le client.
const SPEND_ALLOWED_AMOUNTS = { live_tip: [10, 50, 100] };

// Marche (App.js: +5 à 15 pas toutes les 2s pendant le tracking, znd = floor(steps/100))
app.post('/economy/earn/walk', requireAuth, async (req, res) => {
  const elapsedSeconds = Math.max(0, Math.min(parseInt(req.body.elapsedSeconds) || 0, 3600));
  const maxSteps = Math.floor(elapsedSeconds / 2) * 15; // pire cas possible côté client
  const earned = Math.floor(maxSteps / 100);
  try {
    const result = await pool.query('UPDATE users SET znd = znd + $1 WHERE id = $2 RETURNING znd', [earned, req.user.id]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'Utilisateur introuvable' });
    res.json({ success: true, earned, znd: result.rows[0].znd });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Trésors (montant fixe par trésor, une seule collecte par utilisateur - PRIMARY KEY (user_id, treasure_id))
app.post('/economy/earn/treasure', requireAuth, async (req, res) => {
  const treasureId = parseInt(req.body.treasureId);
  const earned = TREASURE_CATALOG[treasureId];
  if (!earned) return res.status(400).json({ success: false, error: 'Trésor inconnu' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('INSERT INTO treasure_claims (user_id, treasure_id) VALUES ($1, $2)', [req.user.id, treasureId]);
    const result = await client.query('UPDATE users SET znd = znd + $1 WHERE id = $2 RETURNING znd', [earned, req.user.id]);
    await client.query('COMMIT');
    res.json({ success: true, earned, znd: result.rows[0].znd });
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') return res.status(409).json({ success: false, error: 'Trésor déjà collecté' });
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// Live streaming (App.js: +0 à 9 ZND toutes les 3s pendant le live).
// Server-authoritative sur le temps écoulé (bug #C) : l'ancienne route acceptait un
// `elapsedSeconds` envoyé par le client et pouvait être rejouée à l'infini pour farmer du ZND
// sans limite. Ici, le serveur horodate lui-même le début/fin de la session, et une session ne
// peut être créditée qu'une seule fois (ended_at IS NULL fait office de verrou, comme
// pledges.repaid_at).
app.post('/economy/live/start', requireAuth, async (req, res) => {
  try {
    const existing = await pool.query(
      'SELECT id, started_at FROM live_sessions WHERE user_id = $1 AND ended_at IS NULL',
      [req.user.id]
    );
    if (existing.rows.length > 0) {
      // Session déjà active (ex: reprise après une reconnexion) - la réutiliser plutôt que
      // d'en ouvrir une autre en parallèle, qui permettrait de cumuler plusieurs gains simultanés.
      return res.json({ success: true, sessionId: existing.rows[0].id, startedAt: existing.rows[0].started_at });
    }
    const result = await pool.query(
      'INSERT INTO live_sessions (user_id) VALUES ($1) RETURNING id, started_at',
      [req.user.id]
    );
    res.json({ success: true, sessionId: result.rows[0].id, startedAt: result.rows[0].started_at });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/economy/live/end', requireAuth, async (req, res) => {
  const sessionId = parseInt(req.body.sessionId);
  if (!sessionId) return res.status(400).json({ success: false, error: 'sessionId manquant' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const session = await client.query(
      'SELECT * FROM live_sessions WHERE id = $1 AND user_id = $2 AND ended_at IS NULL FOR UPDATE',
      [sessionId, req.user.id]
    );
    if (session.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, error: 'Session introuvable ou déjà terminée' });
    }
    const elapsedSeconds = Math.max(0, Math.min(
      Math.floor((Date.now() - new Date(session.rows[0].started_at).getTime()) / 1000),
      3600
    ));
    const earned = Math.floor(elapsedSeconds / 3) * 9; // pire cas possible côté client

    await client.query('UPDATE live_sessions SET ended_at = NOW(), earned = $1 WHERE id = $2', [earned, sessionId]);
    const result = await client.query('UPDATE users SET znd = znd + $1 WHERE id = $2 RETURNING znd', [earned, req.user.id]);
    await client.query('COMMIT');
    res.json({ success: true, earned, znd: result.rows[0].znd });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// Dépenses (territoires, pourboires live, etc.) - le montant vient toujours d'un catalogue
// serveur (fixe ou liste fermée), jamais directement du corps de la requête.
app.post('/economy/spend', requireAuth, async (req, res) => {
  const { reason, amount: requestedAmount } = req.body;
  let amount = SPEND_CATALOG[reason];
  if (!amount && SPEND_ALLOWED_AMOUNTS[reason]?.includes(parseFloat(requestedAmount))) {
    amount = parseFloat(requestedAmount);
  }
  if (!amount) return res.status(400).json({ success: false, error: 'Raison ou montant invalide' });
  try {
    const result = await pool.query(
      'UPDATE users SET znd = znd - $1 WHERE id = $2 AND znd >= $1 RETURNING znd',
      [amount, req.user.id]
    );
    if (result.rows.length === 0) return res.status(400).json({ success: false, error: 'Solde ZND insuffisant' });
    res.json({ success: true, spent: amount, znd: result.rows[0].znd });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── VALT — VALORISATION (formules provisoires, à remplacer par un vrai moteur de pricing) ──
const CONDITION_MULTIPLIER = { new: 1, good: 0.8, fair: 0.6, poor: 0.4 };

// Source unique de la répartition crédit/frais/assurance (LTV_RATIO) - le client ne doit plus
// dupliquer cette formule (cf. audit bug #18).
function creditBreakdown(baseValue) {
  const ltvValue = baseValue * LTV_RATIO;
  return {
    fee: Math.round(ltvValue * 0.025),
    insurance: Math.round(ltvValue * 0.01),
    netCredit: Math.round(ltvValue * 0.965),
    confidence: 'medium',
  };
}

app.post('/api/valuate/physical', requireAuth, async (req, res) => {
  const { model, condition } = req.body;
  if (!model) return res.status(400).json({ success: false, error: 'Modèle manquant' });
  const baseValue = 200; // placeholder : pas de catalogue de prix réel branché
  const marketValue = Math.round(baseValue * (CONDITION_MULTIPLIER[condition] || 0.6));
  res.json({ success: true, valuation: { marketValue, ...creditBreakdown(marketValue) } });
});

app.post('/api/valuate/skill', requireAuth, async (req, res) => {
  const { hourlyRate, hours } = req.body;
  if (!hourlyRate || !hours) return res.status(400).json({ success: false, error: 'Champs manquants' });
  const totalValue = Math.round(parseFloat(hourlyRate) * parseFloat(hours));
  res.json({ success: true, valuation: { marketValue: totalValue, totalValue, ...creditBreakdown(totalValue) } });
});

app.post('/api/valuate/subscription', requireAuth, async (req, res) => {
  const { provider } = req.body;
  if (!provider) return res.status(400).json({ success: false, error: 'Fournisseur manquant' });
  const monthlyValue = 50; // placeholder : pas de barème par fournisseur branché
  res.json({ success: true, valuation: { marketValue: monthlyValue, monthlyValue, ...creditBreakdown(monthlyValue) } });
});

// ── VALT — GAGES ──────────────────────────────
app.post('/api/pledge/create', requireAuth, async (req, res) => {
  const { borrowerAddress, collateralType, collateralValue, collateralHash, collateralRef, durationDays } = req.body;
  if (!borrowerAddress || !collateralType || !collateralValue) {
    return res.status(400).json({ success: false, error: 'Champs manquants' });
  }
  if (!(await requireOwnWallet(req, res, borrowerAddress))) return;
  try {
    const pledgeId = `pledge_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const days = parseInt(durationDays) || 30;
    const creditAmount = parseFloat(collateralValue) * LTV_RATIO;
    const dueDate = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
    // Pas de mint/transfer on-chain ici : le crédit est uniquement enregistré côté backend.
    const txHash = `internal_${pledgeId}`;

    await pool.query(
      `INSERT INTO pledges
        (pledge_id, borrower_address, collateral_type, collateral_value, collateral_hash, collateral_ref, credit_amount, duration_days, tx_hash, due_date)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [pledgeId, borrowerAddress, collateralType, collateralValue, collateralHash || null, collateralRef || null, creditAmount, days, txHash, dueDate]
    );

    res.json({ success: true, pledgeId, txHash, creditAmount, dueDate });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/pledge/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM pledges WHERE pledge_id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'Gage introuvable' });
    res.json({ success: true, pledge: pledgeToDetails(result.rows[0]) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/pledge/repay', requireAuth, async (req, res) => {
  const { pledgeId } = req.body;
  if (!pledgeId) return res.status(400).json({ success: false, error: 'pledgeId manquant' });
  try {
    const existing = await pool.query('SELECT borrower_address FROM pledges WHERE pledge_id = $1', [pledgeId]);
    if (existing.rows.length === 0) return res.status(404).json({ success: false, error: 'Gage introuvable' });
    if (!(await requireOwnWallet(req, res, existing.rows[0].borrower_address))) return;

    const result = await pool.query(
      `UPDATE pledges SET repaid_at = NOW() WHERE pledge_id = $1 AND repaid_at IS NULL RETURNING *`,
      [pledgeId]
    );
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'Gage déjà remboursé' });
    res.json({ success: true, pledge: pledgeToDetails(result.rows[0]) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/user/:address/pledges', requireAuth, async (req, res) => {
  if (!(await requireOwnWallet(req, res, req.params.address))) return;
  try {
    const result = await pool.query(
      'SELECT * FROM pledges WHERE borrower_address = $1 ORDER BY created_at DESC',
      [req.params.address]
    );
    const pledgeDetails = {};
    result.rows.forEach(row => { pledgeDetails[row.pledge_id] = pledgeToDetails(row); });

    res.json({
      success: true,
      pledgeIds: result.rows.map(r => r.pledge_id),
      pledgeDetails,
      reputation: computeReputation(result.rows),
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── VALT — QR DE PAIEMENT ─────────────────────
app.post('/api/qr/generate', requireAuth, async (req, res) => {
  const { pledgeId, borrowerAddress, amount, expiryMinutes } = req.body;
  if (!pledgeId || !borrowerAddress || !amount) {
    return res.status(400).json({ success: false, error: 'Champs manquants' });
  }
  if (!(await requireOwnWallet(req, res, borrowerAddress))) return;
  try {
    const pledgeResult = await pool.query('SELECT * FROM pledges WHERE pledge_id = $1', [pledgeId]);
    if (pledgeResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Gage introuvable' });
    }
    const pledge = pledgeResult.rows[0];
    if (pledge.borrower_address.toLowerCase() !== String(borrowerAddress).toLowerCase()) {
      return res.status(403).json({ success: false, error: 'Ce gage n\'appartient pas à cette adresse' });
    }
    if (pledgeStatus(pledge) !== 'ACTIVE') {
      return res.status(400).json({ success: false, error: 'Ce gage n\'est plus actif' });
    }
    const requestedAmount = parseFloat(amount);
    if (requestedAmount > parseFloat(pledge.credit_amount)) {
      return res.status(400).json({ success: false, error: `Montant supérieur au crédit disponible (${pledge.credit_amount} ZND)` });
    }

    const expMinutes = parseInt(expiryMinutes) || 15;
    const expiresAt = new Date(Date.now() + expMinutes * 60 * 1000);
    const payload = {
      v: 1,
      pid: pledgeId,
      amt: requestedAmount,
      exp: Math.floor(expiresAt.getTime() / 1000),
      from: borrowerAddress,
    };

    const dataURL = await QRCode.toDataURL(JSON.stringify(payload));

    res.json({ success: true, qr: { dataURL, expiresAt: expiresAt.toISOString(), payload } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/qr/pay', requireAuth, async (req, res) => {
  const { qrPayload, recipientAddress } = req.body;
  if (!qrPayload || !recipientAddress) {
    return res.status(400).json({ success: false, error: 'Champs manquants' });
  }
  const { pid, amt, exp, from } = qrPayload;
  if (!pid || !amt || !exp || !from) {
    return res.status(400).json({ success: false, error: 'QR invalide' });
  }
  if (Math.floor(Date.now() / 1000) > exp) {
    return res.status(400).json({ success: false, error: 'QR expiré' });
  }
  if (String(from).toLowerCase() === String(recipientAddress).toLowerCase()) {
    return res.status(400).json({ success: false, error: 'Impossible de te payer toi-même' });
  }
  if (!(await requireOwnWallet(req, res, recipientAddress))) return;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const pledgeResult = await client.query('SELECT * FROM pledges WHERE pledge_id = $1 FOR UPDATE', [pid]);
    if (pledgeResult.rows.length === 0) throw Object.assign(new Error('Gage introuvable'), { status: 404 });
    const pledge = pledgeResult.rows[0];
    if (pledge.borrower_address.toLowerCase() !== String(from).toLowerCase()) {
      throw Object.assign(new Error('QR invalide (gage/adresse incohérents)'), { status: 403 });
    }
    if (pledgeStatus(pledge) !== 'ACTIVE') {
      throw Object.assign(new Error('Ce gage n\'est plus actif'), { status: 400 });
    }
    const amount = parseFloat(amt);
    if (amount > parseFloat(pledge.credit_amount)) {
      throw Object.assign(new Error('Crédit du gage insuffisant'), { status: 400 });
    }

    // Débit du crédit du gage, crédit du solde interne VALT du destinataire
    await client.query('UPDATE pledges SET credit_amount = credit_amount - $1 WHERE pledge_id = $2', [amount, pid]);
    await client.query(
      `INSERT INTO wallet_ledger (address, balance) VALUES ($1, $2)
       ON CONFLICT (address) DO UPDATE SET balance = wallet_ledger.balance + $2, updated_at = NOW()`,
      [recipientAddress, amount]
    );

    const txHash = `internal_qrpay_${pid}_${Date.now()}`;
    await client.query('COMMIT');

    res.json({ success: true, txHash, amount, pledgeId: pid });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(err.status || 500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

app.post('/api/transfer/znd', requireAuth, async (req, res) => {
  const { from, to, amount } = req.body;
  const amt = parseFloat(amount);
  if (!from || !to || !amt || amt <= 0) {
    return res.status(400).json({ success: false, error: 'Champs manquants ou montant invalide' });
  }
  if (String(from).toLowerCase() === String(to).toLowerCase()) {
    return res.status(400).json({ success: false, error: 'Impossible de te transférer à toi-même' });
  }
  if (!(await requireOwnWallet(req, res, from))) return;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const senderResult = await client.query(
      `INSERT INTO wallet_ledger (address, balance) VALUES ($1, 0)
       ON CONFLICT (address) DO UPDATE SET address = wallet_ledger.address
       RETURNING *`,
      [from]
    );
    const sender = senderResult.rows[0];
    if (parseFloat(sender.balance) < amt) {
      throw Object.assign(new Error('Solde ZND (interne VALT) insuffisant'), { status: 400 });
    }

    await client.query('UPDATE wallet_ledger SET balance = balance - $1, updated_at = NOW() WHERE address = $2', [amt, from]);
    await client.query(
      `INSERT INTO wallet_ledger (address, balance) VALUES ($1, $2)
       ON CONFLICT (address) DO UPDATE SET balance = wallet_ledger.balance + $2, updated_at = NOW()`,
      [to, amt]
    );

    const txHash = `internal_transfer_${Date.now()}`;
    await client.query('COMMIT');

    res.json({ success: true, txHash, amount: amt });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(err.status || 500).json({ success: false, error: err.message });
  } finally {
    client.release();
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