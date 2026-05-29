// server.js - Main Server File
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql2 = require('mysql2').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'harvard-library-secret-key-2026';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database Setup
const db = new mysql2.Database('./library.db', (err) => {
    if (err) {
        console.error('Database connection failed:', err);
    } else {
        console.log('Connected to SQLite database');
        initializeDatabase();
    }
});

// Initialize Tables
function initializeDatabase() {
    db.serialize(() => {
        // Users table (Pustakawan & Admin)
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT DEFAULT 'librarian',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Members table (Anggota)
        db.run(`CREATE TABLE IF NOT EXISTS members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            npm TEXT UNIQUE NOT NULL,
            ktm_number TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT,
            address TEXT,
            status TEXT DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Books table (Koleksi)
        db.run(`CREATE TABLE IF NOT EXISTS books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            isbn TEXT UNIQUE,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            publisher TEXT,
            year INTEGER,
            category TEXT,
            location TEXT,
            status TEXT DEFAULT 'available',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Borrowings table (Peminjaman)
        db.run(`CREATE TABLE IF NOT EXISTS borrowings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            book_id INTEGER NOT NULL,
            member_id INTEGER NOT NULL,
            borrow_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            due_date DATETIME NOT NULL,
            return_date DATETIME,
            status TEXT DEFAULT 'active',
            ktm_verified BOOLEAN DEFAULT 0,
            librarian_id INTEGER,
            notes TEXT,
            FOREIGN KEY (book_id) REFERENCES books(id),
            FOREIGN KEY (member_id) REFERENCES members(id),
            FOREIGN KEY (librarian_id) REFERENCES users(id)
        )`);

        // Procurement SOP table (SOP Pengadaan)
        db.run(`CREATE TABLE IF NOT EXISTS procurements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            book_title TEXT NOT NULL,
            author TEXT,
            reason TEXT,
            requester_id INTEGER,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (requester_id) REFERENCES members(id)
        )`);

        // Insert default admin
        const hashedPassword = bcrypt.hashSync('admin123', 10);
        db.run(`INSERT OR IGNORE INTO users (username, password, full_name, role) 
                VALUES ('admin', ?, 'Administrator', 'admin')`, [hashedPassword]);
        
        // Insert default librarian
        const libPassword = bcrypt.hashSync('lib123', 10);
        db.run(`INSERT OR IGNORE INTO users (username, password, full_name, role) 
                VALUES ('pustakawan', ?, 'Pustakawan Utama', 'librarian')`, [libPassword]);
    });
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

// ==================== AUTH ROUTES ====================

// Login
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const validPassword = bcrypt.compareSync(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

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

    // Validation
    if (!npm || !ktm_number || !full_name || !email) {
        return res.status(400).json({ message: 'Required fields missing' });
    }

    db.run(
        `INSERT INTO members (npm, ktm_number, full_name, email, phone, address) 
         VALUES (?, ?, ?, ?, ?, ?)`,
        [npm, ktm_number, full_name, email, phone, address],
        function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(409).json({ message: 'NPM, KTM, or Email already exists' });
                }
                return res.status(500).json({ message: 'Registration failed' });
            }
            res.status(201).json({
                message: 'Member registered successfully',
                member_id: this.lastID
            });
        }
    );
});

// ==================== MEMBER ROUTES ====================

// Get all members
app.get('/api/members', authenticateToken, (req, res) => {
    db.all('SELECT * FROM members ORDER BY created_at DESC', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        res.json(rows);
    });
});

// Get member by KTM/NPM
app.get('/api/members/verify/:identifier', authenticateToken, (req, res) => {
    const { identifier } = req.params;
    
    db.get(
        'SELECT * FROM members WHERE ktm_number = ? OR npm = ?',
        [identifier, identifier],
        (err, member) => {
            if (err) {
                return res.status(500).json({ message: 'Database error' });
            }
            if (!member) {
                return res.status(404).json({ message: 'Member not found' });
            }
            res.json(member);
        }
    );
});

// Update member status
app.patch('/api/members/:id/status', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    db.run(
        'UPDATE members SET status = ? WHERE id = ?',
        [status, id],
        function(err) {
            if (err) {
                return res.status(500).json({ message: 'Update failed' });
            }
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

    db.all(query, params, (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        res.json(rows);
    });
});

// Get single book
app.get('/api/books/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    
    db.get('SELECT * FROM books WHERE id = ?', [id], (err, book) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        if (!book) {
            return res.status(404).json({ message: 'Book not found' });
        }
        res.json(book);
    });
});

// Add new book
app.post('/api/books', authenticateToken, (req, res) => {
    const { isbn, title, author, publisher, year, category, location } = req.body;

    db.run(
        `INSERT INTO books (isbn, title, author, publisher, year, category, location) 
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [isbn, title, author, publisher, year, category, location],
        function(err) {
            if (err) {
                return res.status(500).json({ message: 'Failed to add book' });
            }
            res.status(201).json({
                message: 'Book added successfully',
                book_id: this.lastID
            });
        }
    );
});

// Update book status
app.patch('/api/books/:id/status', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    db.run(
        'UPDATE books SET status = ? WHERE id = ?',
        [status, id],
        function(err) {
            if (err) {
                return res.status(500).json({ message: 'Update failed' });
            }
            res.json({ message: 'Book status updated' });
        }
    );
});

// ==================== BORROWING ROUTES ====================

// Process borrowing (Main SOP)
app.post('/api/borrowings', authenticateToken, (req, res) => {
    const { book_id, member_id, ktm_verified, notes } = req.body;

    // Validation according to SOP
    if (!book_id || !member_id) {
        return res.status(400).json({ message: 'Book ID and Member ID required' });
    }

    if (!ktm_verified) {
        return res.status(400).json({ message: 'KTM must be verified before borrowing' });
    }

    // Check if member is active
    db.get('SELECT status FROM members WHERE id = ?', [member_id], (err, member) => {
        if (err || !member) {
            return res.status(404).json({ message: 'Member not found' });
        }
        if (member.status !== 'active') {
            return res.status(400).json({ message: 'Member account is not active' });
        }

        // Check book availability
        db.get('SELECT status FROM books WHERE id = ?', [book_id], (err, book) => {
            if (err || !book) {
                return res.status(404).json({ message: 'Book not found' });
            }
            if (book.status !== 'available') {
                return res.status(400).json({ 
                    message: 'Book is not available',
                    status: book.status 
                });
            }

            // Calculate due date (14 days from now)
            const dueDate = new Date();
            dueDate.setDate(dueDate.getDate() + 14);

            // Create borrowing record
            db.run(
                `INSERT INTO borrowings (book_id, member_id, due_date, ktm_verified, librarian_id, notes) 
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [book_id, member_id, dueDate.toISOString(), ktm_verified, req.user.id, notes],
                function(err) {
                    if (err) {
                        return res.status(500).json({ message: 'Borrowing process failed' });
                    }

                    // Update book status
                    db.run('UPDATE books SET status = ? WHERE id = ?', ['borrowed', book_id]);

                    res.status(201).json({
                        message: 'Borrowing processed successfully',
                        borrowing_id: this.lastID,
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

    db.all(query, params, (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        res.json(rows);
    });
});

// Return book
app.patch('/api/borrowings/:id/return', authenticateToken, (req, res) => {
    const { id } = req.params;

    db.run(
        `UPDATE borrowings 
         SET status = 'returned', return_date = CURRENT_TIMESTAMP 
         WHERE id = ?`,
        [id],
        function(err) {
            if (err) {
                return res.status(500).json({ message: 'Return process failed' });
            }

            // Update book status back to available
            db.get('SELECT book_id FROM borrowings WHERE id = ?', [id], (err, row) => {
                if (row) {
                    db.run('UPDATE books SET status = ? WHERE id = ?', ['available', row.book_id]);
                }
            });

            res.json({ message: 'Book returned successfully' });
        }
    );
});

// ==================== PROCUREMENT SOP ROUTES ====================

// Create procurement request (when book not available)
app.post('/api/procurements', authenticateToken, (req, res) => {
    const { book_title, author, reason, requester_id } = req.body;

    db.run(
        `INSERT INTO procurements (book_title, author, reason, requester_id) 
         VALUES (?, ?, ?, ?)`,
        [book_title, author, reason, requester_id],
        function(err) {
            if (err) {
                return res.status(500).json({ message: 'Procurement request failed' });
            }
            res.status(201).json({
                message: 'Procurement SOP initiated',
                procurement_id: this.lastID
            });
        }
    );
});

// Get all procurements
app.get('/api/procurements', authenticateToken, (req, res) => {
    db.all(`
        SELECT p.*, m.full_name as requester_name 
        FROM procurements p
        LEFT JOIN members m ON p.requester_id = m.id
        ORDER BY p.created_at DESC
    `, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        res.json(rows);
    });
});

// ==================== DASHBOARD STATS ====================

app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
    const stats = {};

    db.get('SELECT COUNT(*) as count FROM books', [], (err, row) => {
        stats.totalBooks = row.count;
        
        db.get("SELECT COUNT(*) as count FROM books WHERE status = 'available'", [], (err, row) => {
            stats.availableBooks = row.count;
            
            db.get("SELECT COUNT(*) as count FROM borrowings WHERE status = 'active'", [], (err, row) => {
                stats.activeBorrowings = row.count;
                
                db.get('SELECT COUNT(*) as count FROM members', [], (err, row) => {
                    stats.totalMembers = row.count;
                    
                    db.get("SELECT COUNT(*) as count FROM borrowings WHERE status = 'pending'", [], (err, row) => {
                        stats.pendingRequests = row.count;
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
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;