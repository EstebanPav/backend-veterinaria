const mysql = require("mysql2");

// 📌 Configuración de la conexión a la BD
const pool = mysql.createPool({
  host: process.env.DB_HOST, 
  user: process.env.DB_USER, 
  password: process.env.DB_PASSWORD, 
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// 📌 Exportamos la conexión en modo Promises
pool.getConnection((err, connection) => {
  if (err) {
    console.error("❌ Error de conexión a la BD:", err);
  } else {
    console.log("✅ Conexión exitosa a la base de datos.");
    connection.release();
  }
});

module.exports = pool.promise();
