const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const jwt = require('jsonwebtoken');

const SECRET_KEY = process.env.SECRET_KEY || 'supersecretkey123';
const REFRESH_SECRET_KEY = process.env.REFRESH_SECRET_KEY || 'superrefreshsecretkey123';

const app = express();
const PORT = process.env.PORT || 3002;
const dataFilePath = path.join(__dirname, 'data.json');
const usersFilePath = path.join(__dirname, 'users.json');

let refreshTokens = [];

app.use(cors());
app.use(express.json());

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
const readUsers = () => {
  try {
    if (!fs.existsSync(usersFilePath)) {
      const defaultUsers = [{ id: 1, username: 'admin', password: 'password123' }];
      fs.writeFileSync(usersFilePath, JSON.stringify(defaultUsers, null, 2));
      return defaultUsers;
    }
    const data = fs.readFileSync(usersFilePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading users:', error);
    return [];
  }
};

// Helper function to write users
const writeUsers = (users) => {
  try {
    fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
  } catch (error) {
    console.error('Error writing users:', error);
  }
};

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Access token required' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

/**
 * @swagger
 * tags:
 *   name: Auth
 *   description: Authentication APIs
 */

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login to get access token
 *     tags: [Auth]
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [username, password]
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Successful login
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
 *         description: Invalid credentials
 */
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const users = readUsers();
  const user = users.find(u => u.username === username && u.password === password);

  if (user) {
    const accessToken = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ username: user.username }, REFRESH_SECRET_KEY, { expiresIn: '7d' });
    refreshTokens.push(refreshToken);
    res.json({ accessToken, refreshToken });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
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
app.post('/api/auth/refresh', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ message: 'Refresh token required' });
  if (!refreshTokens.includes(token)) return res.status(403).json({ message: 'Invalid refresh token' });

  jwt.verify(token, REFRESH_SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired refresh token' });

    refreshTokens = refreshTokens.filter(t => t !== token);
    const newAccessToken = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '15m' });
    const newRefreshToken = jwt.sign({ username: user.username }, REFRESH_SECRET_KEY, { expiresIn: '7d' });
    refreshTokens.push(newRefreshToken);

    res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  });
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
app.post('/api/auth/logout', (req, res) => {
  const { token } = req.body;
  refreshTokens = refreshTokens.filter(t => t !== token);
  res.json({ message: 'Logged out successfully' });
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
app.post('/api/auth/change-password', authenticateToken, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const username = req.user.username;
  const users = readUsers();
  const userIndex = users.findIndex(u => u.username === username);

  if (userIndex !== -1 && users[userIndex].password === oldPassword) {
    users[userIndex].password = newPassword;
    writeUsers(users);
    res.json({ message: 'Password changed successfully' });
  } else {
    res.status(400).json({ message: 'Incorrect old password' });
  }
});

// Protect all /api/products routes
app.use('/api/products', authenticateToken);

// Helper function to read data
const readData = () => {
  try {
    const data = fs.readFileSync(dataFilePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading data:', error);
    return [];
  }
};

// Helper function to write data
const writeData = (data) => {
  try {
    fs.writeFileSync(dataFilePath, JSON.stringify(data, null, 2));
  } catch (error) {
    console.error('Error writing data:', error);
  }
};

/**
 * @swagger
 * components:
 *   schemas:
 *     Review:
 *       type: object
 *       properties:
 *         id:
 *           type: string
 *         user:
 *           type: string
 *         rating:
 *           type: number
 *         comment:
 *           type: string
 *         createdAt:
 *           type: string
 *           format: date-time
 *     Product:
 *       type: object
 *       properties:
 *         id:
 *           type: string
 *         name:
 *           type: string
 *         desc:
 *           type: string
 *         price:
 *           type: number
 *         tags:
 *           type: array
 *           items:
 *             type: string
 *         status:
 *           type: string
 *         createdAt:
 *           type: string
 *           format: date-time
 *         deletedAt:
 *           type: string
 *           format: date-time
 *         isActive:
 *           type: boolean
 *         rating:
 *           type: number
 *         metadata:
 *           type: object
 *         reviews:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/Review'
 */

/**
 * @swagger
 * /api/products/stats:
 *   get:
 *     summary: Get dashboard statistics (excludes deleted)
 *     tags: [Dashboard]
 *     responses:
 *       200:
 *         description: Stats object
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 totalProducts:
 *                   type: integer
 *                 outOfStock:
 *                   type: integer
 *                 averageRating:
 *                   type: number
 *                 brandCounts:
 *                   type: object
 *                   additionalProperties:
 *                     type: integer
 */
app.get('/api/products/stats', (req, res) => {
  const allProducts = readData();
  const products = allProducts.filter(p => !p.deletedAt);

  const total = products.length;
  const outOfStock = products.filter(p => p.status === 'Out of Stock').length;
  const averageRating = total > 0 ? (products.reduce((acc, p) => acc + (p.rating || 0), 0) / total).toFixed(1) : 0;
  
  const brandCounts = products.reduce((acc, p) => {
    const brand = p.metadata?.brand || 'Unknown';
    acc[brand] = (acc[brand] || 0) + 1;
    return acc;
  }, {});

  res.json({
    totalProducts: total,
    outOfStock,
    averageRating: parseFloat(averageRating),
    brandCounts
  });
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
app.get('/api/products/options', (req, res) => {
  const allProducts = readData();
  const products = allProducts.filter(p => !p.deletedAt);
  
  const tags = new Set();
  const brands = new Set();
  const statuses = new Set();

  products.forEach(p => {
    if (p.tags) p.tags.forEach(t => tags.add(t));
    if (p.metadata?.brand) brands.add(p.metadata.brand);
    if (p.status) statuses.add(p.status);
  });

  res.json({
    tags: Array.from(tags),
    brands: Array.from(brands),
    statuses: Array.from(statuses)
  });
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
app.delete('/api/products/batch', (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids)) {
    return res.status(400).json({ message: 'ids array is required' });
  }

  const products = readData();
  let deletedCount = 0;
  
  products.forEach(p => {
    if (ids.includes(p.id) && !p.deletedAt) {
      p.deletedAt = new Date().toISOString();
      deletedCount++;
    }
  });
  
  writeData(products);
  res.json({ message: `${deletedCount} products soft-deleted successfully` });
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
 *           type: string
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
app.get('/api/products', (req, res) => {
  let products = readData();
  
  const { search, tag, status, brand, minPrice, maxPrice, includeDeleted, sortBy, order, page = 1, limit = 10 } = req.query;

  // Filter soft-deleted
  if (includeDeleted !== 'true') {
    products = products.filter(p => !p.deletedAt);
  }

  // Filter
  if (search) {
    const s = search.toLowerCase();
    products = products.filter(p => p.name.toLowerCase().includes(s) || (p.desc && p.desc.toLowerCase().includes(s)));
  }
  if (tag) {
    products = products.filter(p => p.tags && p.tags.includes(tag));
  }
  if (status) {
    products = products.filter(p => p.status === status);
  }
  if (brand) {
    products = products.filter(p => p.metadata?.brand === brand);
  }
  if (minPrice) {
    products = products.filter(p => p.price >= Number(minPrice));
  }
  if (maxPrice) {
    products = products.filter(p => p.price <= Number(maxPrice));
  }

  // Sort
  if (sortBy) {
    const sortOrder = order === 'desc' ? -1 : 1;
    products.sort((a, b) => {
      let valA = a[sortBy];
      let valB = b[sortBy];
      if (typeof valA === 'string') valA = valA.toLowerCase();
      if (typeof valB === 'string') valB = valB.toLowerCase();
      
      if (valA < valB) return -1 * sortOrder;
      if (valA > valB) return 1 * sortOrder;
      return 0;
    });
  } else {
    // Default sort by createdAt desc
    products.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  }

  // Pagination
  const total = products.length;
  const startIndex = (Number(page) - 1) * Number(limit);
  const endIndex = startIndex + Number(limit);
  const paginatedProducts = products.slice(startIndex, endIndex);

  res.json({
    data: paginatedProducts,
    total,
    page: Number(page),
    limit: Number(limit),
    totalPages: Math.ceil(total / Number(limit))
  });
});

/**
 * @swagger
 * /api/products/{id}:
 *   get:
 *     summary: Get a product by id
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: The product object
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Product'
 */
app.get('/api/products/:id', (req, res) => {
  const products = readData();
  const product = products.find(p => p.id === req.params.id && !p.deletedAt);
  if (product) {
    res.json(product);
  } else {
    res.status(404).json({ message: 'Product not found or deleted' });
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
app.get('/api/products/:id/related', (req, res) => {
  const products = readData();
  const product = products.find(p => p.id === req.params.id && !p.deletedAt);
  
  if (!product) {
    return res.status(404).json({ message: 'Product not found' });
  }

  const related = products.filter(p => {
    if (p.id === product.id || p.deletedAt) return false; 
    
    const hasCommonTag = product.tags && p.tags && product.tags.some(tag => p.tags.includes(tag));
    const hasSameBrand = product.metadata?.brand && p.metadata?.brand === product.metadata.brand;
    
    return hasCommonTag || hasSameBrand;
  });

  res.json(related.slice(0, 5));
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
app.get('/api/products/:id/reviews', (req, res) => {
  const products = readData();
  const product = products.find(p => p.id === req.params.id && !p.deletedAt);
  if (product) {
    res.json(product.reviews || []);
  } else {
    res.status(404).json({ message: 'Product not found' });
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
 *                 product:
 *                   $ref: '#/components/schemas/Product'
 */
app.post('/api/products/:id/reviews', (req, res) => {
  const { user, rating, comment } = req.body;
  if (!user || rating == null || !comment || rating < 1 || rating > 5) {
    return res.status(400).json({ message: 'Invalid review payload. Rating must be 1-5.' });
  }

  const products = readData();
  const index = products.findIndex(p => p.id === req.params.id && !p.deletedAt);
  
  if (index !== -1) {
    const product = products[index];
    if (!product.reviews) product.reviews = [];
    
    const newReview = {
      id: uuidv4(),
      user,
      rating: Number(rating),
      comment,
      createdAt: new Date().toISOString()
    };
    
    product.reviews.push(newReview);
    
    const totalRating = product.reviews.reduce((acc, curr) => acc + curr.rating, 0);
    product.rating = parseFloat((totalRating / product.reviews.length).toFixed(1));
    
    writeData(products);
    res.status(201).json({ message: 'Review added', product });
  } else {
    res.status(404).json({ message: 'Product not found' });
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
 *                 product:
 *                   $ref: '#/components/schemas/Product'
 */
app.post('/api/products/:id/restore', (req, res) => {
  const products = readData();
  const product = products.find(p => p.id === req.params.id);
  
  if (product) {
    if (product.deletedAt) {
      delete product.deletedAt;
      writeData(products);
      res.json({ message: 'Product restored successfully', product });
    } else {
      res.json({ message: 'Product is not deleted', product });
    }
  } else {
    res.status(404).json({ message: 'Product not found' });
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
app.post('/api/products', (req, res) => {
  const products = readData();
  const newProduct = {
    id: uuidv4(),
    ...req.body,
    createdAt: new Date().toISOString(),
    reviews: []
  };
  products.push(newProduct);
  writeData(products);
  res.status(201).json(newProduct);
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
app.put('/api/products/:id', (req, res) => {
  const products = readData();
  const index = products.findIndex(p => p.id === req.params.id && !p.deletedAt);
  
  if (index !== -1) {
    const updatedProduct = { ...req.body, id: req.params.id, reviews: products[index].reviews }; 
    products[index] = updatedProduct;
    writeData(products);
    res.json(updatedProduct);
  } else {
    res.status(404).json({ message: 'Product not found' });
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
app.patch('/api/products/:id', (req, res) => {
  const products = readData();
  const index = products.findIndex(p => p.id === req.params.id && !p.deletedAt);
  
  if (index !== -1) {
    const updatedProduct = { ...products[index], ...req.body, id: req.params.id };
    products[index] = updatedProduct;
    writeData(products);
    res.json(updatedProduct);
  } else {
    res.status(404).json({ message: 'Product not found' });
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
app.delete('/api/products/:id', (req, res) => {
  const products = readData();
  const product = products.find(p => p.id === req.params.id);
  
  if (product && !product.deletedAt) {
    product.deletedAt = new Date().toISOString();
    writeData(products);
    res.json({ message: 'Product soft-deleted successfully' });
  } else {
    res.status(404).json({ message: 'Product not found or already deleted' });
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
