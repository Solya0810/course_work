const mongoose = require('mongoose');

// Описуємо схему для версії файлу
const fileVersionSchema = new mongoose.Schema({
  filePath: { 
    type: String, 
    required: true,  // Шлях до фізичного файлу на сервері
  },
  uploadedAt: { 
    type: Date, 
    default: Date.now,  // Дата завантаження версії
  },
  iv: { 
    type: String, 
    required: true,  // Ініціалізаційний вектор для шифрування
  },
  fileId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'File',  // Посилання на файл, до якого належить версія
    required: true,
  },
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',  // Посилання на користувача, який завантажив версію
    required: true,
  },
});

// Створення моделі для версій файлів
const FileVersion = mongoose.model('FileVersion', fileVersionSchema);

module.exports = FileVersion;
