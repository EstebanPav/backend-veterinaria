const mysql = require('mysql');

const db = mysql.createConnection({
    host: "sql211.infinityfree.com", // Reemplaza con el host de tu BD
    user: "if0_38439434", // Tu usuario de InfinityFree
    password: "m9XQUnPJEia8Mg", // Tu contraseña de InfinityFree
    database: "if0_38439434_clinica_veterinaria" // Nombre exacto de la BD
});

db.connect((err) => {
    if (err) {
        console.error('❌ Error de conexión:', err);
    } else {
        console.log('✅ Conexión exitosa a la base de datos.');
    }
});

module.exports = db;
