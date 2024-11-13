const mongoose = require('mongoose');

// Схема для версії файлу
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
});

// Схема для файлу
const fileSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: true,  // Назва файлу
  },
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',  // Зв'язок з користувачем, який завантажив файл
    required: true,
  },
  versions: [fileVersionSchema],  // Масив версій файлу
});

// Створення моделі для файлів
const File = mongoose.model('File', fileSchema);

module.exports = File;
