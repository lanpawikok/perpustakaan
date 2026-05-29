// index.js - Main Server File (MySQL Version for Vercel)
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'harvard-library-secret-key-2026';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ==================== DATABASE SETUP ====================
// Gunakan createPool agar cocok dengan Vercel serverless
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
});

const db = pool.promise();

// Test connection & initialize tables on startup
(async () => {
    try {
        await db.query('SELECT 1');
        console.log('Connected to MySQL database');
        await initializeDatabase();
    } catch (err) {
        console.error('Database connection failed:', err.message);
    }
})();

// ==================== INITIALIZE TABLES ====================
async function initializeDatabase() {
    await db.query(`CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'librarian',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await db.query(`CREATE TABLE IF NOT EXISTS members (
        id INT AUTO_INCREMENT PRIMARY KEY,
        npm VARCHAR(50) UNIQUE NOT NULL,
        ktm_number VARCHAR(50) UNIQUE NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(20),
        address TEXT,
        status VARCHAR(50) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await db.query(`CREATE TABLE IF NOT EXISTS books (
        id INT AUTO_INCREMENT PRIMARY KEY,
        isbn VARCHAR(50) UNIQUE,
        title VARCHAR(255) NOT NULL,
        author VARCHAR(255) NOT NULL,
        publisher VARCHAR(255),
        year INT,
        category VARCHAR(100),
        location VARCHAR(100),
        status VARCHAR(50) DEFAULT 'available',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await db.query(`CREATE TABLE IF NOT EXISTS borrowings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        book_id INT NOT NULL,
        member_id INT NOT NULL,
        borrow_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        due_date TIMESTAMP NOT NULL,
        return_date TIMESTAMP NULL,
        status VARCHAR(50) DEFAULT 'active',
        ktm_verified BOOLEAN DEFAULT 0,
        librarian_id INT,
        notes TEXT,
        FOREIGN KEY (book_id) REFERENCES books(id),
        FOREIGN KEY (member_id) REFERENCES members(id),
        FOREIGN KEY (librarian_id) REFERENCES users(id)
    )`);

    await db.query(`CREATE TABLE IF NOT EXISTS procurements (
        id INT AUTO_INCREMENT PRIMARY KEY,
        book_title VARCHAR(255) NOT NULL,
        author VARCHAR(255),
        reason TEXT,
        requester_id INT,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (requester_id) REFERENCES members(id)
    )`);

    // Insert default users
    const hashedAdmin = bcrypt.hashSync('admin123', 10);
    const hashedLib = bcrypt.hashSync('lib123', 10);

    await db.query(
        `INSERT IGNORE INTO users (username, password, full_name, role) VALUES (?, ?, ?, ?)`,
        ['admin', hashedAdmin, 'Administrator', 'admin']
    );
    await db.query(
        `INSERT IGNORE INTO users (username, password, full_name, role) VALUES (?, ?, ?, ?)`,
        ['pustakawan', hashedLib, 'Pustakawan Utama', 'librarian']
    );

    console.log('Database initialized');
}

// ==================== AUTH MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Access token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
};

// ==================== ROOT ROUTE ====================
app.get('/', (req, res) => {
    res.json({
        message: 'Welcome to Harvard Library API System',
        status: 'Server is running successfully on Vercel'
    });
});

// ==================== AUTH ROUTES ====================
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const [results] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
        if (results.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

        const user = results[0];
        if (!bcrypt.compareSync(password, user.password))
            return res.status(401).json({ message: 'Invalid credentials' });

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        res.json({ token, user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role } });
    } catch (err) {
        res.status(500).json({ message: 'Database error' });
    }
});

app.post('/api/auth/register', async (req, res) => {
    const { npm, ktm_number, full_name, email, phone, address } = req.body;
    if (!npm || !ktm_number || !full_name || !email)
        return res.status(400).json({ message: 'Required fields missing' });

    try {
        const [result] = await db.query(
            `INSERT INTO members (npm, ktm_number, full_name, email, phone, address) VALUES (?, ?, ?, ?, ?, ?)`,
            [npm, ktm_number, full_name, email, phone, address]
        );
        res.status(201).json({ message: 'Member registered successfully', member_id: result.insertId });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY')
            return res.status(409).json({ message: 'NPM, KTM, or Email already exists' });
        res.status(500).json({ message: 'Registration failed' });
    }
});

// ==================== MEMBER ROUTES ====================
app.get('/api/members', authenticateToken, async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM members ORDER BY created_at DESC');
        res.json(results);
    } catch { res.status(500).json({ message: 'Database error' }); }
});

app.get('/api/members/verify/:identifier', authenticateToken, async (req, res) => {
    try {
        const [results] = await db.query(
            'SELECT * FROM members WHERE ktm_number = ? OR npm = ?',
            [req.params.identifier, req.params.identifier]
        );
        if (results.length === 0) return res.status(404).json({ message: 'Member not found' });
        res.json(results[0]);
    } catch { res.status(500).json({ message: 'Database error' }); }
});

app.patch('/api/members/:id/status', authenticateToken, async (req, res) => {
    try {
        await db.query('UPDATE members SET status = ? WHERE id = ?', [req.body.status, req.params.id]);
        res.json({ message: 'Member status updated' });
    } catch { res.status(500).json({ message: 'Update failed' }); }
});

// ==================== BOOK ROUTES ====================
app.get('/api/books', authenticateToken, async (req, res) => {
    const { status, search } = req.query;
    let query = 'SELECT * FROM books WHERE 1=1';
    const params = [];

    if (status) { query += ' AND status = ?'; params.push(status); }
    if (search) {
        query += ' AND (title LIKE ? OR author LIKE ? OR isbn LIKE ?)';
        params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }
    query += ' ORDER BY created_at DESC';

    try {
        const [results] = await db.query(query, params);
        res.json(results);
    } catch { res.status(500).json({ message: 'Database error' }); }
});

app.get('/api/books/:id', authenticateToken, async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM books WHERE id = ?', [req.params.id]);
        if (results.length === 0) return res.status(404).json({ message: 'Book not found' });
        res.json(results[0]);
    } catch { res.status(500).json({ message: 'Database error' }); }
});

app.post('/api/books', authenticateToken, async (req, res) => {
    const { isbn, title, author, publisher, year, category, location } = req.body;
    try {
        const [result] = await db.query(
            `INSERT INTO books (isbn, title, author, publisher, year, category, location) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [isbn, title, author, publisher, year, category, location]
        );
        res.status(201).json({ message: 'Book added successfully', book_id: result.insertId });
    } catch { res.status(500).json({ message: 'Failed to add book' }); }
});

app.patch('/api/books/:id/status', authenticateToken, async (req, res) => {
    try {
        await db.query('UPDATE books SET status = ? WHERE id = ?', [req.body.status, req.params.id]);
        res.json({ message: 'Book status updated' });
    } catch { res.status(500).json({ message: 'Update failed' }); }
});

// ==================== BORROWING ROUTES ====================
app.post('/api/borrowings', authenticateToken, async (req, res) => {
    const { book_id, member_id, ktm_verified, notes } = req.body;
    if (!book_id || !member_id) return res.status(400).json({ message: 'Book ID and Member ID required' });
    if (!ktm_verified) return res.status(400).json({ message: 'KTM must be verified before borrowing' });

    try {
        const [memberRows] = await db.query('SELECT status FROM members WHERE id = ?', [member_id]);
        if (memberRows.length === 0) return res.status(404).json({ message: 'Member not found' });
        if (memberRows[0].status !== 'active') return res.status(400).json({ message: 'Member account is not active' });

        const [bookRows] = await db.query('SELECT status FROM books WHERE id = ?', [book_id]);
        if (bookRows.length === 0) return res.status(404).json({ message: 'Book not found' });
        if (bookRows[0].status !== 'available')
            return res.status(400).json({ message: 'Book is not available', status: bookRows[0].status });

        const dueDate = new Date();
        dueDate.setDate(dueDate.getDate() + 14);
        const formattedDueDate = dueDate.toISOString().slice(0, 19).replace('T', ' ');

        const [result] = await db.query(
            `INSERT INTO borrowings (book_id, member_id, due_date, ktm_verified, librarian_id, notes) VALUES (?, ?, ?, ?, ?, ?)`,
            [book_id, member_id, formattedDueDate, ktm_verified, req.user.id, notes]
        );
        await db.query('UPDATE books SET status = ? WHERE id = ?', ['borrowed', book_id]);

        res.status(201).json({ message: 'Borrowing processed successfully', borrowing_id: result.insertId, due_date: dueDate });
    } catch { res.status(500).json({ message: 'Borrowing process failed' }); }
});

app.get('/api/borrowings', authenticateToken, async (req, res) => {
    const { status } = req.query;
    let query = `
        SELECT b.*, bk.title as book_title, bk.author as book_author,
               m.full_name as member_name, m.npm as member_npm
        FROM borrowings b
        JOIN books bk ON b.book_id = bk.id
        JOIN members m ON b.member_id = m.id
        WHERE 1=1
    `;
    const params = [];
    if (status) { query += ' AND b.status = ?'; params.push(status); }
    query += ' ORDER BY b.borrow_date DESC';

    try {
        const [results] = await db.query(query, params);
        res.json(results);
    } catch { res.status(500).json({ message: 'Database error' }); }
});

app.patch('/api/borrowings/:id/return', authenticateToken, async (req, res) => {
    try {
        await db.query(
            `UPDATE borrowings SET status = 'returned', return_date = CURRENT_TIMESTAMP WHERE id = ?`,
            [req.params.id]
        );
        const [rows] = await db.query('SELECT book_id FROM borrowings WHERE id = ?', [req.params.id]);
        if (rows.length > 0) await db.query('UPDATE books SET status = ? WHERE id = ?', ['available', rows[0].book_id]);

        res.json({ message: 'Book returned successfully' });
    } catch { res.status(500).json({ message: 'Return process failed' }); }
});

// ==================== PROCUREMENT ROUTES ====================
app.post('/api/procurements', authenticateToken, async (req, res) => {
    const { book_title, author, reason, requester_id } = req.body;
    try {
        const [result] = await db.query(
            `INSERT INTO procurements (book_title, author, reason, requester_id) VALUES (?, ?, ?, ?)`,
            [book_title, author, reason, requester_id]
        );
        res.status(201).json({ message: 'Procurement SOP initiated', procurement_id: result.insertId });
    } catch { res.status(500).json({ message: 'Procurement request failed' }); }
});

app.get('/api/procurements', authenticateToken, async (req, res) => {
    try {
        const [results] = await db.query(`
            SELECT p.*, m.full_name as requester_name
            FROM procurements p
            LEFT JOIN members m ON p.requester_id = m.id
            ORDER BY p.created_at DESC
        `);
        res.json(results);
    } catch { res.status(500).json({ message: 'Database error' }); }
});

// ==================== DASHBOARD STATS ====================
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        const [[r1]] = await db.query('SELECT COUNT(*) as count FROM books');
        const [[r2]] = await db.query("SELECT COUNT(*) as count FROM books WHERE status = 'available'");
        const [[r3]] = await db.query("SELECT COUNT(*) as count FROM borrowings WHERE status = 'active'");
        const [[r4]] = await db.query('SELECT COUNT(*) as count FROM members');
        const [[r5]] = await db.query("SELECT COUNT(*) as count FROM borrowings WHERE status = 'pending'");

        res.json({
            totalBooks: r1.count,
            availableBooks: r2.count,
            activeBorrowings: r3.count,
            totalMembers: r4.count,
            pendingRequests: r5.count
        });
    } catch { res.status(500).json({ message: 'Database error' }); }
});

// ==================== ERROR HANDLING ====================
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Harvard Library Server running on port ${PORT}`);
});

module.exports = app;