const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Описуємо схему для користувача
const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,  // Ім'я користувача повинно бути унікальним
  },
  password: { 
    type: String, 
    required: true, 
  },
});

// Хешуємо пароль перед збереженням користувача в базі даних
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();  // Якщо пароль не змінювався, пропускаємо хешування

  try {
    const salt = await bcrypt.genSalt(10);  // Генеруємо сіль
    this.password = await bcrypt.hash(this.password, salt);  // Хешуємо пароль
    next();
  } catch (error) {
    next(error);
  }
});

// Додаємо метод для перевірки пароля
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);  // Порівнюємо введений пароль з хешованим в базі даних
};

// Створюємо модель для користувача
const User = mongoose.model('User', userSchema);

module.exports = User;
