// Виконується після завантаження DOM
document.addEventListener('DOMContentLoaded', () => {

  // Функція для перевірки наявності токену
  const checkAuthToken = () => {
    return localStorage.getItem('token');
  };

  // Сторінка реєстрації
  if (document.getElementById('registerForm')) {
    const registerForm = document.getElementById('registerForm');
    registerForm.addEventListener('submit', async (event) => {
      event.preventDefault();

      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const confirmPassword = document.getElementById('confirmPassword').value;

      // Перевірка паролів
      if (password !== confirmPassword) {
        alert('Паролі не співпадають');
        return;
      }

      // Відправка даних на сервер для реєстрації
      try {
        const response = await fetch('/api/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });

        const result = await response.json();
        if (result.success) {
          alert('Реєстрація успішна! Тепер увійдіть');
          window.location.href = '/index.html'; // Перехід на сторінку входу
        } else {
          alert('Помилка реєстрації. Спробуйте ще раз');
        }
      } catch (error) {
        console.error(error);
        alert('Сталася помилка при реєстрації');
      }
    });
  }

  // Сторінка входу
  if (document.getElementById('loginForm')) {
    const loginForm = document.getElementById('loginForm');
    loginForm.addEventListener('submit', async (event) => {
      event.preventDefault();

      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;

      // Відправка даних на сервер для входу
      try {
        const response = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });

        const result = await response.json();
        if (result.token) {
          localStorage.setItem('token', result.token); // Зберігаємо токен
          window.location.href = '/backup.html'; // Перехід на сторінку резервних копій
        } else {
          alert('Невірний логін або пароль');
        }
      } catch (error) {
        console.error(error);
        alert('Сталася помилка при вході');
      }
    });
  }

  // Сторінка резервних копій
  if (document.getElementById('files')) {
    const token = checkAuthToken();
    if (!token) {
      window.location.href = '/index.html'; // Перенаправлення на сторінку входу, якщо токен відсутній
      return;
    }

    const fileList = document.getElementById('files');
    
    // Функція для отримання файлів користувача
    const fetchFiles = async () => {
      try {
        const response = await fetch('/api/files', {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token}`,
          }
        });

        const data = await response.json();
        if (data.files && data.files.length === 0) {
          fileList.innerHTML = '<li>Немає доступних файлів для резервного копіювання</li>';
        } else if (data.files) {
          data.files.forEach(file => {
            const li = document.createElement('li');
            const fileLink = document.createElement('a');
            fileLink.href = `versions.html?fileId=${file._id}`; // Додавання посилання на версії файлу
            fileLink.textContent = `${file.name} — Останнє оновлення: ${new Date(file.versions[0]?.date).toLocaleString()}`;
            li.appendChild(fileLink);
            fileList.appendChild(li);
          });
        } else {
          fileList.innerHTML = '<li>Сталася помилка при завантаженні файлів.</li>';
        }
      } catch (error) {
        console.error(error);
        fileList.innerHTML = '<li>Сталася помилка при завантаженні файлів.</li>';
      }
    };

    fetchFiles(); // Завантаження файлів

    // Обробка кнопки виходу
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', () => {
        localStorage.removeItem('token'); // Видаляємо токен при виході
        window.location.href = '/index.html'; // Перехід на сторінку входу
      });
    }
  }

  // Сторінка версій файлів
  if (document.getElementById('versions')) {
    const token = checkAuthToken();
    if (!token) {
      window.location.href = '/index.html'; // Перенаправлення на сторінку входу, якщо токен відсутній
      return;
    }

    const versionList = document.getElementById('versions');
    const fileId = new URLSearchParams(window.location.search).get('fileId'); // Отримуємо ID файлу з URL

    // Функція для отримання версій файлу
    const fetchVersions = async () => {
      try {
        const response = await fetch(`/api/file/versions/${fileId}`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token}`,
          }
        });

        if (response.ok) {
          const data = await response.json();
          if (data.versions && data.versions.length > 0) {
            data.versions.forEach(version => {
              const li = document.createElement('li');
              li.textContent = `Версія від: ${new Date(version.date).toLocaleString()} — ${version.size} байт`;
              versionList.appendChild(li);
            });
          } else {
            versionList.innerHTML = '<li>Немає доступних версій для цього файлу.</li>';
          }
        } else {
          throw new Error('Не вдалося отримати версії файлу');
        }
      } catch (error) {
        console.error(error);
        versionList.innerHTML = '<li>Сталася помилка при завантаженні версій файлу.</li>';
      }
    };

    fetchVersions(); // Завантаження версій файлу

    // Кнопка повернення
    const backToBackupBtn = document.getElementById('backToBackupBtn');
    if (backToBackupBtn) {
      backToBackupBtn.addEventListener('click', () => {
        window.location.href = 'backup.html'; // Перехід до резервних копій
      });
    }
  }

});
