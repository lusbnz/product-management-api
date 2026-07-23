require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const SECRET_KEY = process.env.SECRET_KEY || 'supersecretkey123';
const REFRESH_SECRET_KEY = process.env.REFRESH_SECRET_KEY || 'superrefreshsecretkey123';

const app = express();
const PORT = process.env.PORT || 3002;

const pool = new Pool({
  connectionString: process.env.POSTGRES_URL || process.env.DATABASE_URL || 'postgres://localhost:5432/productdb',
  ssl: (process.env.POSTGRES_URL || process.env.DATABASE_URL) ? { rejectUnauthorized: false } : false
});

app.use(cors());
app.use(express.json());

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Access token required' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(401).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

/**
 * @swagger
 * /api/setup:
 *   get:
 *     summary: Initialize database tables and seed data
 *     tags: [Test]
 *     security: []
 *     responses:
 *       200:
 *         description: Setup successful
 */
app.get('/api/setup', async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      );
      CREATE TABLE IF NOT EXISTS products (
        id UUID PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        "desc" TEXT,
        price NUMERIC NOT NULL,
        tags TEXT[],
        status VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        deleted_at TIMESTAMP,
        is_active BOOLEAN,
        rating NUMERIC,
        metadata JSONB
      );
      CREATE TABLE IF NOT EXISTS reviews (
        id UUID PRIMARY KEY,
        product_id UUID REFERENCES products(id),
        "user" VARCHAR(255) NOT NULL,
        rating NUMERIC NOT NULL,
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        token TEXT PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Seed users
    const usersCount = await pool.query('SELECT COUNT(*) FROM users');
    if (parseInt(usersCount.rows[0].count) === 0) {
      const usersFilePath = path.join(__dirname, 'users.json');
      if (fs.existsSync(usersFilePath)) {
        const users = JSON.parse(fs.readFileSync(usersFilePath, 'utf8'));
        for (const user of users) {
          await pool.query('INSERT INTO users (username, password) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING', [user.username, user.password]);
        }
      }
    }

    // Seed products
    const productsCount = await pool.query('SELECT COUNT(*) FROM products');
    if (parseInt(productsCount.rows[0].count) === 0) {
      const dataFilePath = path.join(__dirname, 'data.json');
      if (fs.existsSync(dataFilePath)) {
        const products = JSON.parse(fs.readFileSync(dataFilePath, 'utf8'));
        for (const p of products) {
          await pool.query(`
            INSERT INTO products (id, name, "desc", price, tags, status, created_at, deleted_at, is_active, rating, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (id) DO NOTHING
          `, [p.id, p.name, p.desc, p.price, p.tags || [], p.status, p.createdAt || new Date(), p.deletedAt || null, p.isActive, p.rating, p.metadata || {}]);
          
          if (p.reviews && p.reviews.length > 0) {
            for (const r of p.reviews) {
              await pool.query(`
                INSERT INTO reviews (id, product_id, "user", rating, comment, created_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (id) DO NOTHING
              `, [r.id || randomUUID(), p.id, r.user, r.rating, r.comment, r.createdAt || new Date()]);
            }
          }
        }
      }
    }

    res.json({ message: 'Database setup and seeded successfully' });
  } catch (error) {
    console.error('Setup error:', error);
    res.status(500).json({ message: 'Database setup failed', error: error.message });
  }
});

// Swagger definition
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Product API',
      version: '1.1.0',
      description: 'A robust Express CRUD API for products with filtering, stats, reviews, related products, and soft delete.',
    },
    servers: [
      {
        url: `http://localhost:${PORT}`,
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
  },
  apis: [path.join(__dirname, 'index.js')],
};

const specs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

// Helper function to read users
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1 AND password = $2', [username, password]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const accessToken = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1d' });
      const refreshToken = jwt.sign({ username: user.username }, REFRESH_SECRET_KEY, { expiresIn: '7d' });
      
      await pool.query('INSERT INTO refresh_tokens (token, username) VALUES ($1, $2)', [refreshToken, user.username]);
      
      res.json({ accessToken, refreshToken });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

/**
 * @swagger
 * /api/auth/refresh:
 *   post:
 *     summary: Get a new access token using a refresh token
 *     tags: [Auth]
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [token]
 *             properties:
 *               token:
 *                 type: string
 *     responses:
 *       200:
 *         description: New access token generated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken:
 *                   type: string
 *                 refreshToken:
 *                   type: string
 *       401:
 *         description: Refresh token required
 *       403:
 *         description: Invalid or expired refresh token
 */
app.post('/api/auth/refresh', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ message: 'Refresh token required' });
  
  try {
    const result = await pool.query('SELECT * FROM refresh_tokens WHERE token = $1', [token]);
    if (result.rows.length === 0) return res.status(403).json({ message: 'Invalid refresh token' });

    jwt.verify(token, REFRESH_SECRET_KEY, async (err, user) => {
      if (err) return res.status(403).json({ message: 'Invalid or expired refresh token' });

      await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [token]);
      
      const newAccessToken = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1d' });
      const newRefreshToken = jwt.sign({ username: user.username }, REFRESH_SECRET_KEY, { expiresIn: '7d' });
      
      await pool.query('INSERT INTO refresh_tokens (token, username) VALUES ($1, $2)', [newRefreshToken, user.username]);

      res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
    });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: Logout user and invalidate refresh token
 *     tags: [Auth]
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [token]
 *             properties:
 *               token:
 *                 type: string
 *     responses:
 *       200:
 *         description: Logged out successfully
 */
app.post('/api/auth/logout', async (req, res) => {
  const { token } = req.body;
  try {
    await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [token]);
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

/**
 * @swagger
 * /api/auth/change-password:
 *   post:
 *     summary: Change user password
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [oldPassword, newPassword]
 *             properties:
 *               oldPassword:
 *                 type: string
 *               newPassword:
 *                 type: string
 *     responses:
 *       200:
 *         description: Password changed successfully
 *       400:
 *         description: Incorrect old password
 */
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const username = req.user.username;
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length > 0 && result.rows[0].password === oldPassword) {
      await pool.query('UPDATE users SET password = $1 WHERE username = $2', [newPassword, username]);
      res.json({ message: 'Password changed successfully' });
    } else {
      res.status(400).json({ message: 'Incorrect old password' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

// Protect all /api/products routes
app.use('/api/products', authenticateToken);

app.get('/api/products/stats', async (req, res) => {
  try {
    const totalRes = await pool.query('SELECT COUNT(*) FROM products WHERE deleted_at IS NULL');
    const outOfStockRes = await pool.query("SELECT COUNT(*) FROM products WHERE deleted_at IS NULL AND status = 'Out of Stock'");
    const avgRatingRes = await pool.query('SELECT AVG(rating) as avg_rating FROM products WHERE deleted_at IS NULL');
    
    const total = parseInt(totalRes.rows[0].count);
    const outOfStock = parseInt(outOfStockRes.rows[0].count);
    const averageRating = avgRatingRes.rows[0].avg_rating ? parseFloat(avgRatingRes.rows[0].avg_rating).toFixed(1) : 0;
    
    const brandCountsRes = await pool.query(`
      SELECT metadata->>'brand' as brand, COUNT(*) 
      FROM products 
      WHERE deleted_at IS NULL 
      GROUP BY metadata->>'brand'
    `);
    
    const brandCounts = {};
    brandCountsRes.rows.forEach(row => {
      const brand = row.brand || 'Unknown';
      brandCounts[brand] = parseInt(row.count);
    });

    res.json({
      totalProducts: total,
      outOfStock,
      averageRating: parseFloat(averageRating),
      brandCounts
    });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

/**
 * @swagger
 * /api/products/options:
 *   get:
 *     summary: Get unique tags, brands, and statuses (excludes deleted)
 *     tags: [Dashboard]
 *     responses:
 *       200:
 *         description: Filter options
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 tags:
 *                   type: array
 *                   items:
 *                     type: string
 *                 brands:
 *                   type: array
 *                   items:
 *                     type: string
 *                 statuses:
 *                   type: array
 *                   items:
 *                     type: string
 */
app.get('/api/products/options', async (req, res) => {
  try {
    const tagsRes = await pool.query('SELECT DISTINCT unnest(tags) as tag FROM products WHERE deleted_at IS NULL');
    const brandsRes = await pool.query("SELECT DISTINCT metadata->>'brand' as brand FROM products WHERE deleted_at IS NULL");
    const statusesRes = await pool.query('SELECT DISTINCT status FROM products WHERE deleted_at IS NULL');
    
    const tags = tagsRes.rows.map(r => r.tag).filter(Boolean);
    const brands = brandsRes.rows.map(r => r.brand).filter(Boolean);
    const statuses = statusesRes.rows.map(r => r.status).filter(Boolean);

    res.json({ tags, brands, statuses });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

/**
 * @swagger
 * /api/products/batch:
 *   delete:
 *     summary: Soft delete multiple products
 *     tags: [Products]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               ids:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       200:
 *         description: Products deleted
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 */
app.delete('/api/products/batch', async (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids)) {
    return res.status(400).json({ message: 'ids array is required' });
  }
  
  try {
    const result = await pool.query('UPDATE products SET deleted_at = CURRENT_TIMESTAMP WHERE id = ANY($1) AND deleted_at IS NULL', [ids]);
    res.json({ message: `${result.rowCount} products soft-deleted successfully` });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

/**
 * @swagger
 * /api/products:
 *   get:
 *     summary: Returns the list of all products (with pagination, filter, sort)
 *     tags: [Products]
 *     parameters:
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *       - in: query
 *         name: tag
 *         schema:
 *           type: array
 *           items:
 *             type: string
 *         style: form
 *         explode: true
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *       - in: query
 *         name: brand
 *         schema:
 *           type: string
 *       - in: query
 *         name: minPrice
 *         schema:
 *           type: number
 *       - in: query
 *         name: maxPrice
 *         schema:
 *           type: number
 *       - in: query
 *         name: includeDeleted
 *         schema:
 *           type: boolean
 *           default: false
 *         description: Set to true to include soft-deleted products
 *       - in: query
 *         name: sortBy
 *         schema:
 *           type: string
 *           enum: [price, rating, createdAt, name]
 *       - in: query
 *         name: order
 *         schema:
 *           type: string
 *           enum: [asc, desc]
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 10
 *     responses:
 *       200:
 *         description: The list of products
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/Product'
 *                 total:
 *                   type: integer
 *                 page:
 *                   type: integer
 *                 limit:
 *                   type: integer
 *                 totalPages:
 *                   type: integer
 */
app.get('/api/products', async (req, res) => {
  const { search, tag, status, brand, minPrice, maxPrice, includeDeleted, sortBy, order, page = 1, limit = 10 } = req.query;

  let queryParams = [];
  let whereClauses = [];
  
  if (includeDeleted !== 'true') {
    whereClauses.push('deleted_at IS NULL');
  }

  if (search) {
    queryParams.push(`%${search.toLowerCase()}%`);
    whereClauses.push(`(LOWER(name) LIKE $${queryParams.length} OR LOWER("desc") LIKE $${queryParams.length})`);
  }
  if (tag) {
    const tagsArray = Array.isArray(tag) ? tag : [tag];
    queryParams.push(tagsArray);
    whereClauses.push(`tags && $${queryParams.length}`);
  }
  if (status) {
    queryParams.push(status);
    whereClauses.push(`status = $${queryParams.length}`);
  }
  if (brand) {
    queryParams.push(brand);
    whereClauses.push(`metadata->>'brand' = $${queryParams.length}`);
  }
  if (minPrice) {
    queryParams.push(Number(minPrice));
    whereClauses.push(`price >= $${queryParams.length}`);
  }
  if (maxPrice) {
    queryParams.push(Number(maxPrice));
    whereClauses.push(`price <= $${queryParams.length}`);
  }

  const whereStr = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';
  
  let orderCol = 'created_at';
  if (sortBy === 'price') orderCol = 'price';
  else if (sortBy === 'rating') orderCol = 'rating';
  else if (sortBy === 'name') orderCol = 'name';
  
  const sortDirection = order === 'asc' ? 'ASC' : 'DESC';
  
  try {
    const countRes = await pool.query(`SELECT COUNT(*) FROM products ${whereStr}`, queryParams);
    const total = parseInt(countRes.rows[0].count);
    
    const parsedPage = parseInt(page);
    const parsedLimit = parseInt(limit);
    const offset = (parsedPage - 1) * parsedLimit;
    
    const paginatedRes = await pool.query(`
      SELECT * FROM products 
      ${whereStr} 
      ORDER BY ${orderCol} ${sortDirection} 
      LIMIT ${parsedLimit} OFFSET ${offset}
    `, queryParams);
    
    res.json({
      data: paginatedRes.rows.map(r => ({
        ...r,
        desc: r.desc,
        createdAt: r.created_at,
        deletedAt: r.deleted_at,
        isActive: r.is_active
      })),
      total,
      page: parsedPage,
      limit: parsedLimit,
      totalPages: Math.ceil(total / parsedLimit)
    });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products WHERE id = $1 AND deleted_at IS NULL', [req.params.id]);
    if (result.rows.length > 0) {
      const p = result.rows[0];
      res.json({ ...p, desc: p.desc, createdAt: p.created_at, deletedAt: p.deleted_at, isActive: p.is_active });
    } else {
      res.status(404).json({ message: 'Product not found or deleted' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

/**
 * @swagger
 * /api/products/{id}/related:
 *   get:
 *     summary: Get related products (by tags or brand)
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of related products
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Product'
 */
app.get('/api/products/:id/related', async (req, res) => {
  try {
    const prodRes = await pool.query('SELECT tags, metadata FROM products WHERE id = $1 AND deleted_at IS NULL', [req.params.id]);
    if (prodRes.rows.length === 0) return res.status(404).json({ message: 'Product not found' });
    
    const product = prodRes.rows[0];
    const brand = product.metadata?.brand;
    const tags = product.tags || [];

    let queryStr = `
      SELECT * FROM products 
      WHERE id != $1 AND deleted_at IS NULL AND (
        metadata->>'brand' = $2 
        OR tags && $3
      )
      LIMIT 5
    `;
    const result = await pool.query(queryStr, [req.params.id, brand, tags]);
    
    res.json(result.rows.map(p => ({ ...p, desc: p.desc, createdAt: p.created_at, deletedAt: p.deleted_at, isActive: p.is_active })));
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

/**
 * @swagger
 * /api/products/{id}/reviews:
 *   get:
 *     summary: Get reviews for a product
 *     tags: [Reviews]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Array of reviews
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Review'
 */
app.get('/api/products/:id/reviews', async (req, res) => {
  try {
    const prodRes = await pool.query('SELECT id FROM products WHERE id = $1 AND deleted_at IS NULL', [req.params.id]);
    if (prodRes.rows.length === 0) return res.status(404).json({ message: 'Product not found' });
    
    const reviewsRes = await pool.query('SELECT * FROM reviews WHERE product_id = $1 ORDER BY created_at DESC', [req.params.id]);
    res.json(reviewsRes.rows.map(r => ({ ...r, createdAt: r.created_at })));
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

/**
 * @swagger
 * /api/products/{id}/reviews:
 *   post:
 *     summary: Add a review and update product rating
 *     tags: [Reviews]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [user, rating, comment]
 *             properties:
 *               user:
 *                 type: string
 *               rating:
 *                 type: number
 *                 minimum: 1
 *                 maximum: 5
 *               comment:
 *                 type: string
 *     responses:
 *       201:
 *         description: Review added
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 product_id:
 *                   type: string
 */
app.post('/api/products/:id/reviews', async (req, res) => {
  const { user, rating, comment } = req.body;
  if (!user || rating == null || !comment || rating < 1 || rating > 5) {
    return res.status(400).json({ message: 'Invalid review payload. Rating must be 1-5.' });
  }

  try {
    const prodRes = await pool.query('SELECT id, rating FROM products WHERE id = $1 AND deleted_at IS NULL', [req.params.id]);
    if (prodRes.rows.length === 0) return res.status(404).json({ message: 'Product not found' });
    
    const reviewId = randomUUID();
    await pool.query(
      'INSERT INTO reviews (id, product_id, "user", rating, comment) VALUES ($1, $2, $3, $4, $5)',
      [reviewId, req.params.id, user, rating, comment]
    );

    const avgRes = await pool.query('SELECT AVG(rating) as avg_rating FROM reviews WHERE product_id = $1', [req.params.id]);
    const newRating = parseFloat(avgRes.rows[0].avg_rating).toFixed(1);
    await pool.query('UPDATE products SET rating = $1 WHERE id = $2', [newRating, req.params.id]);

    res.status(201).json({ message: 'Review added', product_id: req.params.id });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

/**
 * @swagger
 * /api/products/{id}/restore:
 *   post:
 *     summary: Restore a soft-deleted product
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Product restored
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 */
app.post('/api/products/:id/restore', async (req, res) => {
  try {
    const prodRes = await pool.query('SELECT deleted_at FROM products WHERE id = $1', [req.params.id]);
    if (prodRes.rows.length === 0) return res.status(404).json({ message: 'Product not found' });
    
    if (prodRes.rows[0].deleted_at) {
      await pool.query('UPDATE products SET deleted_at = NULL WHERE id = $1', [req.params.id]);
      res.json({ message: 'Product restored successfully' });
    } else {
      res.json({ message: 'Product is not deleted' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

/**
 * @swagger
 * /api/products:
 *   post:
 *     summary: Create a new product
 *     tags: [Products]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Product'
 *     responses:
 *       201:
 *         description: Product created
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Product'
 */
app.post('/api/products', async (req, res) => {
  try {
    const newId = randomUUID();
    const { name, desc, price, tags, status, isActive, metadata } = req.body;
    await pool.query(
      `INSERT INTO products (id, name, "desc", price, tags, status, is_active, metadata) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [newId, name, desc, price, tags || [], status, isActive, metadata || {}]
    );
    const result = await pool.query('SELECT * FROM products WHERE id = $1', [newId]);
    const p = result.rows[0];
    res.status(201).json({ ...p, desc: p.desc, createdAt: p.created_at, isActive: p.is_active });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

/**
 * @swagger
 * /api/products/{id}:
 *   put:
 *     summary: Replace a product entirely
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Product'
 *     responses:
 *       200:
 *         description: Product updated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Product'
 */
app.put('/api/products/:id', async (req, res) => {
  try {
    const { name, desc, price, tags, status, isActive, metadata } = req.body;
    const result = await pool.query(
      `UPDATE products 
       SET name = $1, "desc" = $2, price = $3, tags = $4, status = $5, is_active = $6, metadata = $7
       WHERE id = $8 AND deleted_at IS NULL RETURNING *`,
      [name, desc, price, tags || [], status, isActive, metadata || {}, req.params.id]
    );
    if (result.rows.length > 0) {
      const p = result.rows[0];
      res.json({ ...p, desc: p.desc, createdAt: p.created_at, isActive: p.is_active });
    } else {
      res.status(404).json({ message: 'Product not found' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

/**
 * @swagger
 * /api/products/{id}:
 *   patch:
 *     summary: Partially update a product
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Product partially updated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Product'
 */
app.patch('/api/products/:id', async (req, res) => {
  try {
    const prodRes = await pool.query('SELECT * FROM products WHERE id = $1 AND deleted_at IS NULL', [req.params.id]);
    if (prodRes.rows.length === 0) return res.status(404).json({ message: 'Product not found' });
    
    const existing = prodRes.rows[0];
    const update = {
      name: req.body.name !== undefined ? req.body.name : existing.name,
      desc: req.body.desc !== undefined ? req.body.desc : existing.desc,
      price: req.body.price !== undefined ? req.body.price : existing.price,
      tags: req.body.tags !== undefined ? req.body.tags : existing.tags,
      status: req.body.status !== undefined ? req.body.status : existing.status,
      isActive: req.body.isActive !== undefined ? req.body.isActive : existing.is_active,
      metadata: req.body.metadata !== undefined ? req.body.metadata : existing.metadata,
    };
    
    const result = await pool.query(
      `UPDATE products 
       SET name = $1, "desc" = $2, price = $3, tags = $4, status = $5, is_active = $6, metadata = $7
       WHERE id = $8 RETURNING *`,
      [update.name, update.desc, update.price, update.tags || [], update.status, update.isActive, update.metadata || {}, req.params.id]
    );
    const p = result.rows[0];
    res.json({ ...p, desc: p.desc, createdAt: p.created_at, isActive: p.is_active });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

/**
 * @swagger
 * /api/products/{id}:
 *   delete:
 *     summary: Soft delete a product by id
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Product soft-deleted
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 */
app.delete('/api/products/:id', async (req, res) => {
  try {
    const result = await pool.query('UPDATE products SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1 AND deleted_at IS NULL', [req.params.id]);
    if (result.rowCount > 0) {
      res.json({ message: 'Product soft-deleted successfully' });
    } else {
      res.status(404).json({ message: 'Product not found or already deleted' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

// Start server
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
    console.log(`Swagger Docs are available on http://localhost:${PORT}/api-docs`);
  });
}

module.exports = app;
