const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
require('dotenv').config();
const app = express();
const port = process.env.PORT || 3000;

// Підключення до MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB підключено'))
  .catch(err => {
    console.error('Помилка підключення до MongoDB:', err);
    process.exit(1);
  });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Налаштування для завантаження файлів
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    const fileName = `${timestamp}-${file.originalname}`;
    cb(null, fileName);
  }
});

const upload = multer({ storage });

// Моделі для користувача, файлів та версій
const User = require('./models/User');
const File = require('./models/File');
const FileVersion = require('./models/FileVersion'); // Модель для версій файлів

// Функція шифрування файлів
const encryptFile = (fileBuffer, secretKey) => {
  const iv = crypto.randomBytes(16); // Генеруємо випадковий вектор ініціалізації (IV)
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey), iv);
  let encrypted = cipher.update(fileBuffer);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return { iv, encrypted };
};

// Функція дешифрування файлів
const decryptFile = (encryptedBuffer, iv, secretKey) => {
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey), iv);
  let decrypted = decipher.update(encryptedBuffer);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted;
};

// Middleware для перевірки токену
const authenticate = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(403).json({ success: false, message: 'Не авторизовано' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ success: false, message: 'Невірний токен' });
    req.userId = decoded.userId;
    next();
  });
};

// Завантаження нової версії файлу
app.post('/api/upload-version/:fileId?', authenticate, upload.single('file'), async (req, res) => {
  const { fileId } = req.params;  // fileId може бути необов'язковим (для нових файлів)
  const { file } = req;
  const secretKey = process.env.FILE_ENCRYPTION_KEY;

  if (!file) {
    return res.status(400).json({ success: false, message: 'Файл не вибраний' });
  }

  try {
    let fileRecord;

    if (fileId) {
      // Якщо передано fileId, шукаємо файл в базі даних для додавання нової версії
      fileRecord = await File.findById(fileId);
      if (!fileRecord) {
        return res.status(404).json({ success: false, message: 'Файл не знайдено' });
      }
    } else {
      // Якщо fileId не передано, створюємо новий файл (це буде перша версія файлу)
      fileRecord = new File({
        name: file.originalname,
        user: req.userId,
        versions: [],
      });
    }

    // Читання файлу з диска
    const fileBuffer = fs.readFileSync(file.path);
    const { iv, encrypted } = encryptFile(fileBuffer, secretKey); // Шифруємо файл

    // Створення шляху для збереження зашифрованої версії файлу
    const filePath = path.join(__dirname, 'uploads', file.filename);
    fs.writeFileSync(filePath, encrypted);

    // Створення нової версії файлу
    const newVersion = new FileVersion({
      filePath: file.filename,  // Зберігаємо ім'я файлу
      uploadedAt: new Date(),   // Дата завантаження
      iv: iv.toString('base64'),  // Ініціалізаційний вектор
      fileId: fileRecord._id,  // Зв'язуємо версію з файлом
      userId: req.userId,      // Зв'язуємо версію з користувачем
    });

    // Збереження нової версії файлу
    await newVersion.save();

    // Додаємо нову версію до масиву версій файлу
    fileRecord.versions.push(newVersion._id);
    await fileRecord.save();

    res.status(201).json({ success: true, message: 'Версія файлу успішно збережена' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Помилка при завантаженні резервної копії файлу' });
  }
});

// Завантаження файлу для відновлення (дефшифрування)
app.get('/api/download-version/:fileId/:versionId', authenticate, async (req, res) => {
  const { fileId, versionId } = req.params;

  try {
    const file = await File.findById(fileId);
    if (!file) return res.status(404).json({ success: false, message: 'Файл не знайдено' });

    // Знаходимо конкретну версію файлу
    const version = await FileVersion.findById(versionId);
    if (!version) return res.status(404).json({ success: false, message: 'Версія не знайдена' });

    const secretKey = process.env.FILE_ENCRYPTION_KEY;
    const encryptedBuffer = fs.readFileSync(path.join(__dirname, 'uploads', version.filePath));
    const iv = Buffer.from(version.iv, 'base64');

    // Дешифруємо файл
    const decryptedBuffer = decryptFile(encryptedBuffer, iv, secretKey);

    // Відправляємо файл
    res.status(200).send(decryptedBuffer);
  } catch (error) {
    res.status(500).json({ success: false, message: 'Помилка при завантаженні версії файлу' });
  }
});

app.listen(port, () => {
  console.log(`Сервер працює на порту ${port}`);
});
