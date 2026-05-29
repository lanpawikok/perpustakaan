// index.js - Main Server File (MySQL Version for Vercel)
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'harvard-library-secret-key-2026';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database Setup (Menggunakan Environment Variables Cloud MySQL)
db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err.message);
        // Jangan panggil initializeDatabase() jika error agar tidak crash
    } else {
        console.log('Connected to MySQL database');
        initializeDatabase();
    }
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
    } else {
        console.log('Connected to MySQL database');
        initializeDatabase();
    }
});

// Initialize Tables (Sintaks SQL disesuaikan untuk MySQL)
function initializeDatabase() {
    // Users table (Pustakawan & Admin)
    db.query(`CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'librarian',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    // Members table (Anggota)
    db.query(`CREATE TABLE IF NOT EXISTS members (
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

    // Books table (Koleksi)
    db.query(`CREATE TABLE IF NOT EXISTS books (
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

    // Borrowings table (Peminjaman)
    db.query(`CREATE TABLE IF NOT EXISTS borrowings (
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

    // Procurement SOP table (SOP Pengadaan)
    db.query(`CREATE TABLE IF NOT EXISTS procurements (
        id INT AUTO_INCREMENT PRIMARY KEY,
        book_title VARCHAR(255) NOT NULL,
        author VARCHAR(255),
        reason TEXT,
        requester_id INT,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (requester_id) REFERENCES members(id)
    )`);

    // Insert default admin & librarian (Menggunakan INSERT IGNORE khas MySQL)
    const hashedPassword = bcrypt.hashSync('admin123', 10);
    db.query(`INSERT IGNORE INTO users (username, password, full_name, role) 
            VALUES ('admin', ?, 'Administrator', 'admin')`, [hashedPassword]);
    
    const libPassword = bcrypt.hashSync('lib123', 10);
    db.query(`INSERT IGNORE INTO users (username, password, full_name, role) 
            VALUES ('pustakawan', ?, 'Pustakawan Utama', 'librarian')`, [libPassword]);
}

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// ==================== ROOT ROUTE ====================
app.get('/', (req, res) => {
    res.json({
        message: "Welcome to Harvard Library API System",
        status: "Server is running successfully on Vercel"
    });
});

// ==================== AUTH ROUTES ====================

// Login
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (results.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

        const user = results[0];
        const validPassword = bcrypt.compareSync(password, user.password);
        if (!validPassword) return res.status(401).json({ message: 'Invalid credentials' });

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                full_name: user.full_name,
                role: user.role
            }
        });
    });
});

// Register Member (Public)
app.post('/api/auth/register', (req, res) => {
    const { npm, ktm_number, full_name, email, phone, address } = req.body;

    if (!npm || !ktm_number || !full_name || !email) {
        return res.status(400).json({ message: 'Required fields missing' });
    }

    db.query(
        `INSERT INTO members (npm, ktm_number, full_name, email, phone, address) 
         VALUES (?, ?, ?, ?, ?, ?)`,
        [npm, ktm_number, full_name, email, phone, address],
        (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY' || err.message.includes('UUID')) {
                    return res.status(409).json({ message: 'NPM, KTM, or Email already exists' });
                }
                return res.status(500).json({ message: 'Registration failed' });
            }
            res.status(201).json({
                message: 'Member registered successfully',
                member_id: result.insertId
            });
        }
    );
});

// ==================== MEMBER ROUTES ====================

// Get all members
app.get('/api/members', authenticateToken, (req, res) => {
    db.query('SELECT * FROM members ORDER BY created_at DESC', (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        res.json(results);
    });
});

// Get member by KTM/NPM
app.get('/api/members/verify/:identifier', authenticateToken, (req, res) => {
    const { identifier } = req.params;
    
    db.query(
        'SELECT * FROM members WHERE ktm_number = ? OR npm = ?',
        [identifier, identifier],
        (err, results) => {
            if (err) return res.status(500).json({ message: 'Database error' });
            if (results.length === 0) return res.status(404).json({ message: 'Member not found' });
            res.json(results[0]);
        }
    );
});

// Update member status
app.patch('/api/members/:id/status', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    db.query(
        'UPDATE members SET status = ? WHERE id = ?',
        [status, id],
        (err, result) => {
            if (err) return res.status(500).json({ message: 'Update failed' });
            res.json({ message: 'Member status updated' });
        }
    );
});

// ==================== BOOK ROUTES ====================

// Get all books
app.get('/api/books', authenticateToken, (req, res) => {
    const { status, search } = req.query;
    let query = 'SELECT * FROM books WHERE 1=1';
    const params = [];

    if (status) {
        query += ' AND status = ?';
        params.push(status);
    }
    if (search) {
        query += ' AND (title LIKE ? OR author LIKE ? OR isbn LIKE ?)';
        params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    query += ' ORDER BY created_at DESC';

    db.query(query, params, (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        res.json(results);
    });
});

// Get single book
app.get('/api/books/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    
    db.query('SELECT * FROM books WHERE id = ?', [id], (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (results.length === 0) return res.status(404).json({ message: 'Book not found' });
        res.json(results[0]);
    });
});

// Add new book
app.post('/api/books', authenticateToken, (req, res) => {
    const { isbn, title, author, publisher, year, category, location } = req.body;

    db.query(
        `INSERT INTO books (isbn, title, author, publisher, year, category, location) 
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [isbn, title, author, publisher, year, category, location],
        (err, result) => {
            if (err) return res.status(500).json({ message: 'Failed to add book' });
            res.status(201).json({
                message: 'Book added successfully',
                book_id: result.insertId
            });
        }
    );
});

// Update book status
app.patch('/api/books/:id/status', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    db.query(
        'UPDATE books SET status = ? WHERE id = ?',
        [status, id],
        (err, result) => {
            if (err) return res.status(500).json({ message: 'Update failed' });
            res.json({ message: 'Book status updated' });
        }
    );
});

// ==================== BORROWING ROUTES ====================

// Process borrowing
app.post('/api/borrowings', authenticateToken, (req, res) => {
    const { book_id, member_id, ktm_verified, notes } = req.body;

    if (!book_id || !member_id) {
        return res.status(400).json({ message: 'Book ID and Member ID required' });
    }
    if (!ktm_verified) {
        return res.status(400).json({ message: 'KTM must be verified before borrowing' });
    }

    // Check member status
    db.query('SELECT status FROM members WHERE id = ?', [member_id], (err, memberResults) => {
        if (err || memberResults.length === 0) return res.status(404).json({ message: 'Member not found' });
        if (memberResults[0].status !== 'active') return res.status(400).json({ message: 'Member account is not active' });

        // Check book availability
        db.query('SELECT status FROM books WHERE id = ?', [book_id], (err, bookResults) => {
            if (err || bookResults.length === 0) return res.status(404).json({ message: 'Book not found' });
            if (bookResults[0].status !== 'available') {
                return res.status(400).json({ message: 'Book is not available', status: bookResults[0].status });
            }

            // Calculate due date (14 days from now)
            const dueDate = new Date();
            dueDate.setDate(dueDate.getDate() + 14);
            const formattedDueDate = dueDate.toISOString().slice(0, 19).replace('T', ' ');

            // Create borrowing record
            db.query(
                `INSERT INTO borrowings (book_id, member_id, due_date, ktm_verified, librarian_id, notes) 
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [book_id, member_id, formattedDueDate, ktm_verified, req.user.id, notes],
                (err, borrowResult) => {
                    if (err) return res.status(500).json({ message: 'Borrowing process failed' });

                    // Update book status
                    db.query('UPDATE books SET status = ? WHERE id = ?', ['borrowed', book_id]);

                    res.status(201).json({
                        message: 'Borrowing processed successfully',
                        borrowing_id: borrowResult.insertId,
                        due_date: dueDate
                    });
                }
            );
        });
    });
});

// Get all borrowings
app.get('/api/borrowings', authenticateToken, (req, res) => {
    const { status } = req.query;
    let query = `
        SELECT b.*, 
               bk.title as book_title, bk.author as book_author,
               m.full_name as member_name, m.npm as member_npm
        FROM borrowings b
        JOIN books bk ON b.book_id = bk.id
        JOIN members m ON b.member_id = m.id
        WHERE 1=1
    `;
    const params = [];

    if (status) {
        query += ' AND b.status = ?';
        params.push(status);
    }

    query += ' ORDER BY b.borrow_date DESC';

    db.query(query, params, (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        res.json(results);
    });
});

// Return book
app.patch('/api/borrowings/:id/return', authenticateToken, (req, res) => {
    const { id } = req.params;

    db.query(
        `UPDATE borrowings SET status = 'returned', return_date = CURRENT_TIMESTAMP WHERE id = ?`,
        [id],
        (err, result) => {
            if (err) return res.status(500).json({ message: 'Return process failed' });

            db.query('SELECT book_id FROM borrowings WHERE id = ?', [id], (err, rows) => {
                if (rows && rows.length > 0) {
                    db.query('UPDATE books SET status = ? WHERE id = ?', ['available', rows[0].book_id]);
                }
            });

            res.json({ message: 'Book returned successfully' });
        }
    );
});

// ==================== PROCUREMENT ROUTES ====================

app.post('/api/procurements', authenticateToken, (req, res) => {
    const { book_title, author, reason, requester_id } = req.body;

    db.query(
        `INSERT INTO procurements (book_title, author, reason, requester_id) VALUES (?, ?, ?, ?)`,
        [book_title, author, reason, requester_id],
        (err, result) => {
            if (err) return res.status(500).json({ message: 'Procurement request failed' });
            res.status(201).json({
                message: 'Procurement SOP initiated',
                procurement_id: result.insertId
            });
        }
    );
});

app.get('/api/procurements', authenticateToken, (req, res) => {
    db.query(`
        SELECT p.*, m.full_name as requester_name 
        FROM procurements p
        LEFT JOIN members m ON p.requester_id = m.id
        ORDER BY p.created_at DESC
    `, (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        res.json(results);
    });
});

// ==================== DASHBOARD STATS ====================

app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
    const stats = {};

    db.query('SELECT COUNT(*) as count FROM books', (err, r1) => {
        stats.totalBooks = r1[0].count;
        db.query("SELECT COUNT(*) as count FROM books WHERE status = 'available'", (err, r2) => {
            stats.availableBooks = r2[0].count;
            db.query("SELECT COUNT(*) as count FROM borrowings WHERE status = 'active'", (err, r3) => {
                stats.activeBorrowings = r3[0].count;
                db.query('SELECT COUNT(*) as count FROM members', (err, r4) => {
                    stats.totalMembers = r4[0].count;
                    db.query("SELECT COUNT(*) as count FROM borrowings WHERE status = 'pending'", (err, r5) => {
                        stats.pendingRequests = r5[0].count;
                        res.json(stats);
                    });
                });
            });
        });
    });
});

// Error handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Harvard Library Server running on port ${PORT}`);
});

module.exports = app;