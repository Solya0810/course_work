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

// Моделі для користувача та файлів
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const FileSchema = new mongoose.Schema({
  name: { type: String, required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  versions: [{
    date: { type: Date, default: Date.now },
    fileUrl: { type: String, required: true },
    iv: { type: String, required: true },  // IV для дешифрування
  }]
});

const User = mongoose.model('User', UserSchema);
const File = mongoose.model('File', FileSchema);

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

// Створення користувача (реєстрація)
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userExists = await User.findOne({ username });
    if (userExists) return res.status(400).json({ success: false, message: 'Користувач вже існує' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ success: true, message: 'Реєстрація успішна' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Помилка при реєстрації' });
  }
});

// Авторизація користувача (логін)
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ success: false, message: 'Користувача не знайдено' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ success: false, message: 'Невірний пароль' });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ success: true, token });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Помилка при авторизації' });
  }
});

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

// Отримання файлів користувача
app.get('/api/files', authenticate, async (req, res) => {
  try {
    // Знайдемо всі файли для поточного користувача
    const files = await File.find({ user: req.userId });

    if (!files || files.length === 0) {
      return res.status(404).json({ success: false, message: 'Файли не знайдено для цього користувача' });
    }

    // Відправляємо список файлів
    res.status(200).json(files);
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Помилка при отриманні файлів' });
  }
});

// Завантаження нової версії файлу (створення резервної копії)
app.post('/api/upload-version/:fileId', authenticate, upload.single('file'), async (req, res) => {
  const { fileId } = req.params;
  const { file } = req;
  const secretKey = process.env.FILE_ENCRYPTION_KEY;

  if (!file) {
    return res.status(400).json({ success: false, message: 'Файл не вибраний' });
  }

  try {
    // Знайдемо файл по ID
    const fileRecord = await File.findById(fileId);
    if (!fileRecord) {
      return res.status(404).json({ success: false, message: 'Файл не знайдений' });
    }

    // Читання файлу з диска
    const fileBuffer = fs.readFileSync(file.path);
    const { iv, encrypted } = encryptFile(fileBuffer, secretKey); // Шифруємо файл

    // Додаємо нову версію файлу
    const newVersion = {
      fileUrl: encrypted.toString('base64'),
      date: new Date(),
      iv: iv.toString('base64'),
    };

    // Додаємо нову версію до масиву версій
    fileRecord.versions.push(newVersion);
    await fileRecord.save(); // Зберігаємо файл з новою версією

    res.status(201).json({ success: true, message: 'Нова версія файлу успішно збережена' });
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
    const version = file.versions.id(versionId);
    if (!version) return res.status(404).json({ success: false, message: 'Версія не знайдена' });

    const secretKey = process.env.FILE_ENCRYPTION_KEY;
    const encryptedBuffer = Buffer.from(version.fileUrl, 'base64');
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
