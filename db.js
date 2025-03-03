const mysql = require("mysql2");

// 📌 Configuración de la conexión a la BD
const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost", // Usa variables de entorno para mayor seguridad
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "clinica_veterinaria",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// 📌 Exportamos la conexión en modo Promises
module.exports = pool.promise();
