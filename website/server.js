import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import helmet from 'helmet';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import { MongoClient } from 'mongodb';
import logger from './logger.js';

// ENV
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3002;

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://ajax.googleapis.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://ajax.googleapis.com"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
}));

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session (use a strong secret in .env)
app.use(
  session({
    name: 'sid',
    secret: process.env.SESSION_SECRET || 'change_me_in_env',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: false, // set true when behind HTTPS
      maxAge: 1000 * 60 * 60 * 2, // 2 hours
    },
  })
);

// MongoDB connection management
let mongoClient = null;
let mongoDb = null;

async function connectToMongo(connectionString) {
  try {
    logger.info('Attempting MongoDB connection');
    if (mongoClient) {
      logger.info('Closing existing MongoDB connection');
      await mongoClient.close();
    }
    mongoClient = new MongoClient(connectionString);
    await mongoClient.connect();
    mongoDb = mongoClient.db();
    logger.info('Successfully connected to MongoDB');
    return { success: true, message: 'Connected to MongoDB successfully' };
  } catch (error) {
    logger.mongoError('connection', error, { connectionString: connectionString.replace(/\/\/[^@]+@/, '//***:***@') });
    return { success: false, message: error.message };
  }
}

async function disconnectFromMongo() {
  try {
    if (mongoClient) {
      logger.info('Disconnecting from MongoDB');
      await mongoClient.close();
      mongoClient = null;
      mongoDb = null;
      logger.info('Successfully disconnected from MongoDB');
    }
    return { success: true, message: 'Disconnected from MongoDB' };
  } catch (error) {
    logger.mongoError('disconnection', error);
    return { success: false, message: error.message };
  }
}

// Simple in-memory user storage for demo purposes
const users = new Map();

// Seed a default admin user on first run (in-memory only)
(async () => {
  try {
    const defaultEmail = (process.env.DEFAULT_ADMIN_EMAIL || 'admin@example.com').toLowerCase();
    const defaultUsername = (process.env.DEFAULT_ADMIN_USERNAME || 'admin').trim();
    const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'admin12345';
    if (users.size === 0) {
      logger.info('Seeding default admin user');
      const salt = await bcrypt.genSalt(12);
      const hash = await bcrypt.hash(defaultPassword, salt);
      const userId = Date.now().toString();
      users.set(userId, {
        id: userId,
        email: defaultEmail,
        username: defaultUsername,
        password_hash: hash,
      });
      logger.info('Default admin user seeded successfully', { username: defaultUsername, email: defaultEmail });
    }
  } catch (e) {
    logger.error('Failed to seed default admin user', { error: e.message });
  }
})();

// Auth helpers
function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    logger.debug('Authentication successful', { userId: req.session.user.id, endpoint: req.path });
    return next();
  }
  logger.warn('Unauthorized access attempt', { ip: req.ip, endpoint: req.path, userAgent: req.get('User-Agent') });
  return res.status(401).json({ error: 'Unauthorized' });
}

// Test endpoint
app.get('/api/test', (req, res) => {
  logger.info('Health check endpoint accessed', { ip: req.ip });
  res.json({ message: 'Server is working', timestamp: new Date().toISOString() });
});

// Routes - Auth (Simple in-memory authentication)
app.post('/api/auth/signup', async (req, res) => {
  try {
    logger.info('User signup attempt', { ip: req.ip });
    let { email, username, password } = req.body;
    email = (email || '').toString().trim().toLowerCase();
    username = (username || '').toString().trim();
    if (!email || !username || !password) {
      logger.warn('Signup failed - missing fields', { email: !!email, username: !!username, password: !!password, ip: req.ip });
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Basic validation
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      logger.warn('Signup failed - invalid email format', { email, ip: req.ip });
      return res.status(400).json({ error: 'Invalid email' });
    }
    if (username.length < 3 || username.length > 30) {
      logger.warn('Signup failed - invalid username length', { username, length: username.length, ip: req.ip });
      return res.status(400).json({ error: 'Username must be 3-30 chars' });
    }
    if (password.length < 8) {
      logger.warn('Signup failed - password too short', { ip: req.ip });
      return res.status(400).json({ error: 'Password must be >= 8 chars' });
    }

    // Check if user already exists
    for (let [id, user] of users) {
      if (user.email === email || user.username.toLowerCase() === username.toLowerCase()) {
        logger.warn('Signup failed - user already exists', { email, username, ip: req.ip });
        return res.status(409).json({ error: 'Email or username already exists' });
      }
    }

    const salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(password, salt);
    const userId = Date.now().toString();

    users.set(userId, {
      id: userId,
      email: email,
      username: username,
      password_hash: hash
    });

    logger.info('User signup successful', { userId, email, username, ip: req.ip });
    return res.json({ ok: true });
  } catch (err) {
    logger.error('Signup error', { error: err.message, ip: req.ip });
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    logger.info('User login attempt', { ip: req.ip });
    let { emailOrUsername, password } = req.body;
    emailOrUsername = (emailOrUsername || '').toString().trim();
    if (!emailOrUsername || !password) {
      logger.warn('Login failed - missing fields', { emailOrUsername: !!emailOrUsername, password: !!password, ip: req.ip });
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Look up by email or username
    let user = null;
    for (let [id, u] of users) {
      if (u.email === emailOrUsername.toLowerCase() || u.username.toLowerCase() === emailOrUsername.toLowerCase()) {
        user = u;
        break;
      }
    }

    if (!user) {
      logger.warn('Login failed - user not found', { emailOrUsername, ip: req.ip });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      logger.warn('Login failed - invalid password', { userId: user.id, username: user.username, ip: req.ip });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    req.session.user = { id: user.id, email: user.email, username: user.username };
    logger.info('User login successful', { userId: user.id, username: user.username, email: user.email, ip: req.ip });
    return res.json({ ok: true, user: req.session.user });
  } catch (err) {
    logger.error('Login error', { error: err.message, ip: req.ip });
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  const userId = req.session?.user?.id;
  const username = req.session?.user?.username;
  req.session.destroy(() => {
    logger.info('User logout successful', { userId, username, ip: req.ip });
    res.clearCookie('sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

// MongoDB User Management API
app.post('/api/mongo/connect', requireAuth, async (req, res) => {
  try {
    const { connectionString } = req.body;
    if (!connectionString) {
      logger.warn('MongoDB connect failed - missing connection string', { userId: req.session.user.id, ip: req.ip });
      return res.status(400).json({ error: 'Connection string is required' });
    }
    
    logger.info('MongoDB connection requested', { userId: req.session.user.id, ip: req.ip });
    const result = await connectToMongo(connectionString);
    res.json(result);
  } catch (error) {
    logger.error('MongoDB connect endpoint error', { error: error.message, userId: req.session.user.id, ip: req.ip });
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/mongo/disconnect', requireAuth, async (req, res) => {
  try {
    logger.info('MongoDB disconnection requested', { userId: req.session.user.id, ip: req.ip });
    const result = await disconnectFromMongo();
    res.json(result);
  } catch (error) {
    logger.error('MongoDB disconnect endpoint error', { error: error.message, userId: req.session.user.id, ip: req.ip });
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/mongo/status', requireAuth, (req, res) => {
  logger.debug('MongoDB status check', { userId: req.session.user.id, connected: mongoClient !== null });
  res.json({ 
    connected: mongoClient !== null,
    message: mongoClient ? 'Connected to MongoDB' : 'Not connected'
  });
});

app.get('/api/mongo/users', requireAuth, async (req, res) => {
  try {
    if (!mongoClient) {
      logger.warn('List MongoDB users failed - not connected', { userId: req.session.user.id, ip: req.ip });
      return res.status(400).json({ error: 'Not connected to MongoDB' });
    }

    logger.info('Listing MongoDB users', { userId: req.session.user.id, ip: req.ip });
    // Query admin DB to list all users across databases
    const adminDb = mongoClient.db('admin');
    const result = await adminDb.command({ usersInfo: 1 });
    const users = result && result.users ? result.users : [];
    logger.info('MongoDB users listed successfully', { userId: req.session.user.id, userCount: users.length });
    res.json({ users });
  } catch (error) {
    logger.mongoError('list users', error, { userId: req.session.user.id, ip: req.ip });
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/mongo/users', requireAuth, async (req, res) => {
  try {
    if (!mongoClient) {
      logger.warn('Create MongoDB user failed - not connected', { userId: req.session.user.id, ip: req.ip });
      return res.status(400).json({ error: 'Not connected to MongoDB' });
    }

    const { username, password, roles } = req.body;
    if (!username || !password || !roles) {
      logger.warn('Create MongoDB user failed - missing fields', { 
        userId: req.session.user.id, 
        username: !!username, 
        password: !!password, 
        roles: !!roles,
        ip: req.ip 
      });
      return res.status(400).json({ error: 'Username, password, and roles are required' });
    }

    logger.info('Creating MongoDB user', { userId: req.session.user.id, targetUsername: username, roles, ip: req.ip });
    // Use admin database for user management
    const adminDb = mongoClient.db('admin');
    await adminDb.command({
      createUser: username,
      pwd: password,
      roles: roles,
    });
    logger.info('MongoDB user created successfully', { userId: req.session.user.id, targetUsername: username, roles });
    res.json({ success: true, message: 'User created successfully' });
  } catch (error) {
    logger.mongoError('create user', error, { userId: req.session.user.id, targetUsername: req.body.username, ip: req.ip });
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/mongo/users/:username', requireAuth, async (req, res) => {
  try {
    if (!mongoClient) {
      logger.warn('Update MongoDB user failed - not connected', { userId: req.session.user.id, ip: req.ip });
      return res.status(400).json({ error: 'Not connected to MongoDB' });
    }

    const { username } = req.params;
    const { password, roles } = req.body;

    logger.info('Updating MongoDB user', { 
      userId: req.session.user.id, 
      targetUsername: username, 
      hasPassword: !!password, 
      roles, 
      ip: req.ip 
    });

    const adminDb = mongoClient.db('admin');
    const cmd = { updateUser: username };
    if (password) cmd.pwd = password;
    if (roles) cmd.roles = roles;

    await adminDb.command(cmd);
    logger.info('MongoDB user updated successfully', { userId: req.session.user.id, targetUsername: username });
    res.json({ success: true, message: 'User updated successfully' });
  } catch (error) {
    logger.mongoError('update user', error, { userId: req.session.user.id, targetUsername: req.params.username, ip: req.ip });
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/mongo/users/:username', requireAuth, async (req, res) => {
  try {
    if (!mongoClient) {
      logger.warn('Delete MongoDB user failed - not connected', { userId: req.session.user.id, ip: req.ip });
      return res.status(400).json({ error: 'Not connected to MongoDB' });
    }

    const { username } = req.params;
    logger.info('Deleting MongoDB user', { userId: req.session.user.id, targetUsername: username, ip: req.ip });
    const adminDb = mongoClient.db('admin');
    await adminDb.command({ dropUser: username });
    logger.info('MongoDB user deleted successfully', { userId: req.session.user.id, targetUsername: username });
    res.json({ success: true, message: 'User deleted successfully' });
  } catch (error) {
    logger.mongoError('delete user', error, { userId: req.session.user.id, targetUsername: req.params.username, ip: req.ip });
    res.status(500).json({ error: error.message });
  }
});

// Grant roles to existing user
app.patch('/api/mongo/users/:username/roles', requireAuth, async (req, res) => {
  try {
    if (!mongoClient) {
      logger.warn('Grant MongoDB user roles failed - not connected', { userId: req.session.user.id, ip: req.ip });
      return res.status(400).json({ error: 'Not connected to MongoDB' });
    }

    const { username } = req.params;
    const { roles } = req.body;
    
    if (!roles || !Array.isArray(roles)) {
      logger.warn('Grant MongoDB user roles failed - invalid roles', { userId: req.session.user.id, targetUsername: username, ip: req.ip });
      return res.status(400).json({ error: 'Roles array is required' });
    }

    logger.info('Granting roles to MongoDB user', { userId: req.session.user.id, targetUsername: username, roles, ip: req.ip });
    
    const adminDb = mongoClient.db('admin');
    await adminDb.command({
      grantRolesToUser: username,
      roles: roles
    });
    
    logger.info('MongoDB user roles granted successfully', { userId: req.session.user.id, targetUsername: username, roles });
    res.json({ success: true, message: 'Roles granted successfully' });
  } catch (error) {
    logger.mongoError('grant roles', error, { userId: req.session.user.id, targetUsername: req.params.username, ip: req.ip });
    res.status(500).json({ error: error.message });
  }
});

// Update username
app.patch('/api/mongo/users/:username/rename', requireAuth, async (req, res) => {
  try {
    if (!mongoClient) {
      logger.warn('Rename MongoDB user failed - not connected', { userId: req.session.user.id, ip: req.ip });
      return res.status(400).json({ error: 'Not connected to MongoDB' });
    }

    const { username } = req.params;
    const { newUsername } = req.body;
    
    if (!newUsername) {
      logger.warn('Rename MongoDB user failed - missing new username', { userId: req.session.user.id, targetUsername: username, ip: req.ip });
      return res.status(400).json({ error: 'New username is required' });
    }

    logger.info('Renaming MongoDB user', { userId: req.session.user.id, targetUsername: username, newUsername, ip: req.ip });
    
    const adminDb = mongoClient.db('admin');
    
    // Get current user info
    const userInfo = await adminDb.command({ usersInfo: username });
    if (!userInfo.users || userInfo.users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const currentUser = userInfo.users[0];
    
    // Create new user with same roles
    await adminDb.command({
      createUser: newUsername,
      pwd: 'temp_password_will_be_updated',
      roles: currentUser.roles
    });
    
    // Copy password hash (requires admin privileges)
    const usersCollection = adminDb.collection('system.users');
    const oldUserDoc = await usersCollection.findOne({ user: username });
    if (oldUserDoc) {
      await usersCollection.updateOne(
        { user: newUsername },
        { $set: { credentials: oldUserDoc.credentials } }
      );
    }
    
    // Drop old user
    await adminDb.command({ dropUser: username });
    
    logger.info('MongoDB user renamed successfully', { userId: req.session.user.id, oldUsername: username, newUsername });
    res.json({ success: true, message: 'User renamed successfully' });
  } catch (error) {
    logger.mongoError('rename user', error, { userId: req.session.user.id, targetUsername: req.params.username, ip: req.ip });
    res.status(500).json({ error: error.message });
  }
});

// Revoke roles from existing user
app.delete('/api/mongo/users/:username/roles', requireAuth, async (req, res) => {
  try {
    if (!mongoClient) {
      logger.warn('Revoke MongoDB user roles failed - not connected', { userId: req.session.user.id, ip: req.ip });
      return res.status(400).json({ error: 'Not connected to MongoDB' });
    }

    const { username } = req.params;
    const { roles } = req.body;
    
    if (!roles || !Array.isArray(roles)) {
      logger.warn('Revoke MongoDB user roles failed - invalid roles', { userId: req.session.user.id, targetUsername: username, ip: req.ip });
      return res.status(400).json({ error: 'Roles array is required' });
    }

    logger.info('Revoking roles from MongoDB user', { userId: req.session.user.id, targetUsername: username, roles, ip: req.ip });
    
    const adminDb = mongoClient.db('admin');
    await adminDb.command({
      revokeRolesFromUser: username,
      roles: roles
    });
    
    logger.info('MongoDB user roles revoked successfully', { userId: req.session.user.id, targetUsername: username, roles });
    res.json({ success: true, message: 'Roles revoked successfully' });
  } catch (error) {
    logger.mongoError('revoke roles', error, { userId: req.session.user.id, targetUsername: req.params.username, ip: req.ip });
    res.status(500).json({ error: error.message });
  }
});

// Custom role management
app.get('/api/mongo/roles', requireAuth, async (req, res) => {
  try {
    if (!mongoClient) {
      logger.warn('List MongoDB roles failed - not connected', { userId: req.session.user.id, ip: req.ip });
      return res.status(400).json({ error: 'Not connected to MongoDB' });
    }

    const { database } = req.query;
    const targetDb = database || 'admin';
    
    logger.info('Listing MongoDB roles', { userId: req.session.user.id, database: targetDb, ip: req.ip });
    const db = mongoClient.db(targetDb);
    const result = await db.command({ rolesInfo: 1, showPrivileges: true });
    const roles = result && result.roles ? result.roles : [];
    logger.info('MongoDB roles listed successfully', { userId: req.session.user.id, database: targetDb, roleCount: roles.length });
    res.json({ roles, database: targetDb });
  } catch (error) {
    logger.mongoError('list roles', error, { userId: req.session.user.id, database: req.query.database, ip: req.ip });
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/mongo/roles', requireAuth, async (req, res) => {
  try {
    if (!mongoClient) {
      logger.warn('Create MongoDB role failed - not connected', { userId: req.session.user.id, ip: req.ip });
      return res.status(400).json({ error: 'Not connected to MongoDB' });
    }

    const { roleName, privileges, inheritedRoles, database } = req.body;
    
    if (!roleName || !privileges) {
      logger.warn('Create MongoDB role failed - missing fields', { 
        userId: req.session.user.id, 
        roleName: !!roleName, 
        privileges: !!privileges,
        ip: req.ip 
      });
      return res.status(400).json({ error: 'Role name and privileges are required' });
    }

    const targetDb = database || 'admin';
    logger.info('Creating MongoDB role', { userId: req.session.user.id, roleName, database: targetDb, privileges, inheritedRoles, ip: req.ip });
    
    const db = mongoClient.db(targetDb);
    const roleDoc = {
      createRole: roleName,
      privileges: privileges,
      roles: inheritedRoles || []
    };
    
    await db.command(roleDoc);
    logger.info('MongoDB role created successfully', { userId: req.session.user.id, roleName, database: targetDb });
    res.json({ success: true, message: 'Role created successfully' });
  } catch (error) {
    logger.mongoError('create role', error, { userId: req.session.user.id, roleName: req.body.roleName, database: req.body.database, ip: req.ip });
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/mongo/roles/:roleName', requireAuth, async (req, res) => {
  try {
    if (!mongoClient) {
      logger.warn('Delete MongoDB role failed - not connected', { userId: req.session.user.id, ip: req.ip });
      return res.status(400).json({ error: 'Not connected to MongoDB' });
    }

    const { roleName } = req.params;
    const { database } = req.query;
    const targetDb = database || 'admin';
    
    logger.info('Deleting MongoDB role', { userId: req.session.user.id, roleName, database: targetDb, ip: req.ip });
    
    const db = mongoClient.db(targetDb);
    await db.command({ dropRole: roleName });
    
    logger.info('MongoDB role deleted successfully', { userId: req.session.user.id, roleName, database: targetDb });
    res.json({ success: true, message: 'Role deleted successfully' });
  } catch (error) {
    logger.mongoError('delete role', error, { userId: req.session.user.id, roleName: req.params.roleName, database: req.query.database, ip: req.ip });
    res.status(500).json({ error: error.message });
  }
});

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Fallback to index.html for SPA-style routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  logger.info('Server started successfully', { port: PORT, url: `http://localhost:${PORT}` });
});