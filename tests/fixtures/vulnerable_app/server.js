// Deliberately vulnerable JS file for testing SecureScope
const express = require('express');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');

const app = express();
const SECRET_KEY = "hardcoded_jwt_secret_key_12345";
const DB_PASSWORD = "admin123";

// SQL Injection via string concatenation
app.get('/users', (req, res) => {
    const userId = req.query.id;
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    db.query(query, (err, results) => {
        res.json(results);
    });
});

// XSS via innerHTML
app.get('/profile', (req, res) => {
    const name = req.query.name;
    res.send(`<div id="output"></div><script>document.getElementById('output').innerHTML = '${name}';</script>`);
});

// Insecure JWT
app.post('/login', (req, res) => {
    const token = jwt.decode(req.body.token, { algorithms: ['none'] });
    res.json({ user: token });
});

// eval with user input
app.post('/calc', (req, res) => {
    const result = eval(req.body.expression);
    res.json({ result });
});

// SSRF
app.get('/fetch', (req, res) => {
    const url = req.query.url;
    fetch(url).then(r => r.text()).then(data => res.send(data));
});

// Insecure cookie
app.get('/set-session', (req, res) => {
    res.cookie('session_id', 'abc123', { secure: false, httponly: false });
    res.send('Session set');
});
