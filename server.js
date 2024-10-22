const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true
}));

const upload = multer({ dest: 'uploads/' }); // Папка для збереження завантажених файлів

// Масив для збереження резервних копій
const backups = [];

// Фіктивні дані для авторизації
const users = {
    'user1': 'password1',
    'user2': 'password2'
};

// Функція для шифрування файлу
function encryptFile(filePath, key) {
    const algorithm = 'aes-256-cbc'; // Алгоритм шифрування
    const iv = crypto.randomBytes(16); // Вектор ініціалізації

    const cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
    const input = fs.createReadStream(filePath);
    const output = fs.createWriteStream(filePath + '.enc'); // Зберігайте зашифрований файл

    // Шифрування
    input.pipe(cipher).pipe(output);
    output.on('finish', () => {
        // Після завершення шифрування видаліть оригінальний файл
        fs.unlinkSync(filePath);
    });

    return iv.toString('hex'); // Повертаємо вектор ініціалізації для подальшого використання
}

// Маршрут для авторизації
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (users[username] && users[username] === password) {
        req.session.user = username;
        return res.status(200).send('Успіх');
    }
    res.status(401).send('Неправильне ім\'я користувача або пароль');
});

// Маршрут для завантаження файлів
app.post('/api/upload', upload.single('file'), (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Не авторизовано');
    }
    
    const file = req.file;
    if (!file) {
        return res.status(400).send('Не було завантажено файл');
    }

    // Шифруємо файл
    const encryptionKey = crypto.randomBytes(32); // Генеруємо ключ
    const iv = encryptFile(file.path, encryptionKey); // Шифруємо файл

    // Зберегти інформацію про резервну копію
    backups.push({
        name: file.originalname,
        date: new Date().toISOString(),
        path: file.path + '.enc', // Зберігаємо шлях до зашифрованого файлу
        iv: iv, // Зберігаємо вектор ініціалізації
        key: encryptionKey.toString('hex') // Зберігаємо ключ (можна зберігати в базі даних)
    });

    res.status(200).send('Файл успішно завантажено та зашифровано');
});

// Маршрут для отримання резервних копій
app.get('/api/backups', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Не авторизовано');
    }
    res.json(backups);
});

// Запуск сервера
app.listen(port, () => {
    console.log(`Сервер запущено на http://localhost:${port}`);
});

