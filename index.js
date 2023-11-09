const express = require('express')
const config = require("config")
const sqlite3 = require('sqlite3')
const bcrypt = require('bcrypt')
const cors = require('cors')
const jwt = require('jsonwebtoken')
const multer = require('multer');
const fs = require('fs');
const router = express.Router();

const port = config.get('PORT')
const {
    open
} = require('sqlite')
const app = express()


app.use(express.json())
start = async () => {
    open({
        filename: "./db/tilt-db",
        driver: sqlite3.Database
    }).then((db) => {
        try {
            app.post('/registration', async (req, res) => {
                const {
                    username,
                    password
                } = req.body
                if (password.length < 5 || password.length > 12 && username.length < 5 || username.length > 12) {
                    return res.status(400).json({
                        message: "Длина username и пароля должна быть не менее 5 и не больше 12 символов"
                    })
                }
                const hash = await bcrypt.hash(password, 4)
                const result = await db.all(`SELECT * FROM users WHERE username = "${username}"`)
                if (result.length > 0) {
                    return res.status(400).json({
                        message: 'Пользователь с таким username уже существует'
                    });
                } else {
                    await db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], function (err) {
                        if (err) {
                            console.error(err);
                            return res.status(500).json({
                                error: 'че то не але'
                            });
                        } else {
                            return res.json({
                                message: 'Пользователь зарегистрирован'
                            });
                        }
                    });
                }
            })
            app.post('/login', async (req, res) => {
                const user = {
                    username,
                    password
                } = req.body;
                const usernam = await db.all(`SELECT * FROM users WHERE username = "${username}"`)
                const passwor = await db.all(`SELECT * FROM users WHERE password = "${password}"`)
                const hash = await bcrypt.hash(password, 4)
                try {
                    if ((usernam.length > 0) || (user.username === `${username}`) && (passwor.password === `${(hash)}`)) {
                        const token = jwt.sign({
                            username: username
                        }, 'secret_key');
                        return res.json({
                            message: "Успешный вход",
                            token
                        })
                    } else {
                        return res.status(400).json({
                            message: "Ошибка логина/пароля"
                        })
                    }
                } catch (e) {
                    console.log(e)
                }
            })
            app.post('/upload', (req, res) => {
                const {
                    name,
                    size,
                    path,
                    date
                } = req.body;

                db.run('INSERT INTO Files (name, size, path, date) VALUES (?, ?, ?, ?)', [name, size, path, Date(date)], (err) => {
                    if (err) {
                        return res.status(500).json({
                            error: 'Ошибка сохранения файла в базе данных'
                        });
                    } else {
                        return res.json({
                            message: 'Файл успешно сохранен'
                        });
                    }
                });

                app.get('/files', (res) => {
                    db.all('SELECT * FROM Files', (err, rows) => {
                        if (err) {
                            return res.status(500).json({
                                error: 'Ошибка получения списка файлов из базы данных'
                            });
                        } else {
                            return res.json(rows);
                        }
                    });
                });

                function isAuthenticated(req, res, next) {
                    const token = req.headers.authorization;

                    if (!token) {
                        return res.status(403).json({
                            error: 'Отсутствует токен авторизации'
                        });
                    }

                    try {
                        const decoded = jwt.verify(token, 'secret_key');
                        req.user = decoded;
                        next();
                    } catch (err) {
                        return res.status(401).json({
                            error: 'Неверный токен авторизации'
                        });
                    }
                }
                app.get('/user/files', isAuthenticated, (req, res) => {
                    const userId = req.user.userId; // Идентификатор пользователя из авторизационного токена
                    const userDir = uploads `${userId}`

                    // Получение списка файлов пользователя
                    const userFiles = fs.readdirSync(userDir);
                    res.json({
                        files: userFiles
                    });
                    // Получение файлов пользователя
                });


                app.get('/download/:id', (req, res) => {
                    const fileId = req.params.id;

                    db.get('SELECT * FROM Files WHERE id = ?', [fileId], (err, row) => {
                        if (err) {
                            return res.status(500).json({
                                error: 'Ошибка получения информации о файле из базы данных'
                            });
                        } else if (row) {
                            const filePath = row.path;

                            fs.readFile(filePath, (err, data) => {
                                if (err) {
                                    return res.status(500).json({
                                        error: 'Ошибка чтения файла'
                                    });
                                } else {
                                    // Отправка файла клиенту
                                    res.set('Content-Type', 'application/octet-stream');
                                    res.set('Content-Disposition', `attachment, filename=${row.name}`);
                                    return res.send(data);
                                }
                            });
                            return res.status(404).json({
                                error: 'Файл не найден'
                            });
                        }
                    });
                })

                // Настройка multer для загрузки файлов
                const storage = multer.diskStorage({
                    destination: function (req, file, cb) {
                        const userId = req.user.userId; // Получаем идентификатор пользователя из авторизационного токена
                        const userDir = uploads `${userId}`;
                        if (!fs.existsSync(userDir)) {
                            fs.mkdirSync(userDir, {
                                recursive: true
                            });
                        }
                        cb(null, userDir);
                    },
                    filename: function (file, cb) {
                        cb(null, file.originalname);
                    }
                });

                const upload = multer({
                    storage: storage
                });

                // Обработка загрузки файла пользователем
                app.post('/upload', isAuthenticated, upload.single('file'), (res) => {
                    res.json({
                        message: 'Файл успешно загружен'
                    });
                });





            });
            app.listen(port, () => {
                console.log("Сервер запущен на: ", port)
            })
        } catch (e) {
            console.log(e)
        }
    })
}

start()