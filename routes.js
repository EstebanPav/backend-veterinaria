const express = require("express");
const router = express.Router();
const db = require("./db"); // Asegúrate de que la ruta sea correcta
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config(); // 🔹 Cargar variables de entorno

const saltRounds = 10; // Nivel de encriptación


const verificarToken = (req, res, next) => {
    const token = req.headers["x-access-token"];
    if (!token) {
        return res.status(403).json({ message: "Acceso denegado. Token no proporcionado." });
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: "Token inválido" });
        }
        req.usuario = decoded;
        next();
    });
};

// 📌 **Registrar un usuario o veterinario**
router.post("/api/registrar-usuario", async (req, res) => {
    try {
        const { nombre, correo, contrasena, celular, rol } = req.body;

        // 📌 Verificar que todos los campos sean proporcionados
        if (!nombre || !correo || !contrasena || !rol) {
            return res.status(400).json({ message: "Todos los campos son obligatorios." });
        }

        // 📌 Verificar si el usuario ya existe
        const [usuarioExistente] = await db.query("SELECT id FROM usuarios WHERE correo = ?", [correo]);
        if (usuarioExistente.length > 0) {
            return res.status(409).json({ message: "El correo ya está registrado." });
        }

        // 🔐 Hashear la contraseña antes de guardarla
        const hashedPassword = await bcrypt.hash(contrasena, saltRounds);

        // 📌 Insertar usuario en la base de datos
        const sql = `INSERT INTO usuarios (nombre, correo, contrasena, celular, rol) VALUES (?, ?, ?, ?, ?)`;
        const [result] = await db.query(sql, [nombre, correo, hashedPassword, celular, rol]);

        res.status(201).json({
            message: "Usuario registrado correctamente",
            usuarioId: result.insertId
        });

    } catch (error) {
        console.error("❌ Error en el registro:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});



router.post("/api/login", async (req, res) => {
    try {
        const { correo, contrasena } = req.body;

        // 📌 Buscar el usuario por correo
        const [results] = await db.query("SELECT * FROM usuarios WHERE correo = ?", [correo]);
        if (results.length === 0) {
            return res.status(401).json({ message: "Usuario no encontrado" });
        }

        const usuario = results[0];

        // 🔐 Comparar contraseñas encriptadas
        const isMatch = await bcrypt.compare(contrasena, usuario.contrasena);
        if (!isMatch) {
            return res.status(401).json({ message: "Contraseña incorrecta" });
        }

        // 📌 Generar Token JWT
        const token = jwt.sign(
            { id: usuario.id, nombre: usuario.nombre, rol: usuario.rol },
            process.env.JWT_SECRET,
            { expiresIn: "2h" } // 🔐 Token expira en 2 horas
        );

        res.json({
            message: "Inicio de sesión exitoso",
            token,
            usuario: {
                id: usuario.id,
                nombre: usuario.nombre,
                correo: usuario.correo,
                rol: usuario.rol
            }
        });

    } catch (error) {
        console.error("❌ Error en el login:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});


// 📌 **Registrar un usuario (Administrador)**
router.post("/api/registro", async (req, res) => {
    try {
        const { nombre, correo, contrasena, celular, rol } = req.body;

        // Validar datos
        if (!nombre || !correo || !contrasena || !rol) {
            return res.status(400).json({ message: "Todos los campos son obligatorios." });
        }

        // Encriptar contraseña
        const hashedPassword = await bcrypt.hash(contrasena, saltRounds);

        const sql = `INSERT INTO usuarios (nombre, correo, contrasena, celular, rol) VALUES (?, ?, ?, ?, ?)`;
        const [result] = await db.query(sql, [nombre, correo, hashedPassword, celular, rol]);

        res.status(201).json({ message: "Usuario registrado correctamente", usuarioId: result.insertId });
    } catch (error) {
        console.error("Error en el registro:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// 📌 **Ruta protegida de prueba**
router.get("/api/protegido", verificarToken, (req, res) => {
    res.json({ message: "Accediste a una ruta protegida", usuario: req.usuario });
});





router.get('/api/propietario/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const [result] = await db.query('SELECT * FROM propietarios WHERE id = ?', [id]);
        if (result.length === 0) return res.status(404).json({ error: "Propietario no encontrado" });
        res.json(result[0]);
    } catch (error) {
        res.status(500).json({ error: "Error al obtener el propietario" });
    }
});



router.get("/api/ver_propietario/:id", async (req, res) => {
    const { id } = req.params;

    try {
        const [results] = await db.query(`
            SELECT p.id, p.nombre, p.direccion, p.ciudad, p.provincia, p.cedula, p.celular
            FROM propietarios p
            JOIN mascotas m ON p.id = m.propietario_id
            WHERE m.id = ?
        `, [id]);

        if (results.length > 0) {
            res.status(200).json(results[0]); // Retorna la información del propietario
        } else {
            res.status(404).json({ error: "Propietario no encontrado." });
        }
    } catch (error) {
        console.error("Error al obtener el propietario:", error);
        res.status(500).json({ error: "Error al obtener el propietario." });
    }
});


router.get('/api/historia-clinica/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const [result] = await db.query('SELECT * FROM historias_clinicas WHERE mascota_id = ?', [id]);
        if (result.length === 0) return res.status(404).json({ error: "Historia no encontrada" });
        res.json(result[0]);
    } catch (error) {
        res.status(500).json({ error: "Error al obtener la historia clínica" });
    }
});

router.get('/api/examen-clinico/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const [result] = await db.query('SELECT * FROM examenes_clinicos WHERE mascota_id = ?', [id]);
        if (result.length === 0) return res.status(404).json({ error: "Examen clínico no encontrado" });
        res.json(result[0]);
    } catch (error) {
        res.status(500).json({ error: "Error al obtener el examen clínico" });
    }
});


// ==================== PROPIETARIOS ====================
/**
 * Obtener todos los propietarios
 */
// 📌 Obtener un propietario por su ID
router.get("/api/propietarios/:id", async (req, res) => {
    const { id } = req.params;
    try {
        const [results] = await db.query("SELECT * FROM propietarios WHERE id = ?", [id]);
        
        if (results.length > 0) {
            res.status(200).json(results[0]); // Devuelve el primer resultado
        } else {
            res.status(404).json({ error: "❌ Propietario no encontrado." });
        }
    } catch (error) {
        console.error("Error al obtener el propietario:", error);
        res.status(500).json({ error: "❌ Error al obtener el propietario." });
    }
});



router.get('/api/clinica', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM informacion_veterinaria');
        if (results.length > 0) {
            res.status(200).json(results[0]); // 🔹 Devuelve solo el primer resultado
        } else {
            res.status(404).json({ error: 'No se encontró información de la clínica' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener la información de la clínica' });
    }
});


// 📌 Obtener todos los propietarios
router.get("/api/propietarios", async (req, res) => {
    try {
        const [results] = await db.query("SELECT id, nombre FROM propietarios");
        res.status(200).json(results);
    } catch (error) {
        console.error("Error al obtener propietarios:", error);
        res.status(500).json({ error: "❌ Error al obtener propietarios." });
    }
});


/**
 * Registrar un nuevo propietario
 */
router.post('/api/propietarios', async (req, res) => {
    try {
        const { nombre, direccion, ciudad, provincia, cedula, celular } = req.body;
        if (!nombre || !direccion || !ciudad || !provincia || !cedula || !celular) {
            return res.status(400).json({ error: 'Todos los campos son obligatorios' });
        }

        const [result] = await db.query(
            'INSERT INTO propietarios (nombre, direccion, ciudad, provincia, cedula, celular) VALUES (?, ?, ?, ?, ?, ?)',
            [nombre, direccion, ciudad, provincia, cedula, celular]
        );
        res.status(201).json({ message: 'Propietario registrado exitosamente', propietarioId: result.insertId });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al registrar el propietario' });
    }
});

// 📌 Editar un propietario por ID
router.put("/api/editar_propietario/:id", async (req, res) => {
    const { id } = req.params;
    const { nombre, direccion, ciudad, provincia, cedula, celular } = req.body;

    try {
        await db.query(
            "UPDATE propietarios SET nombre = ?, direccion = ?, ciudad = ?, provincia = ?, cedula = ?, celular = ? WHERE id = ?",
            [nombre, direccion, ciudad, provincia, cedula, celular, id]
        );
        res.status(200).json({ message: "✅ Propietario actualizado correctamente." });
    } catch (error) {
        console.error("Error al actualizar propietario:", error);
        res.status(500).json({ error: "❌ Error al actualizar el propietario." });
    }
});

// ==================== MASCOTAS ====================
/**
 * Obtener todas las mascotas
 */
router.get('/api/mascotas', async (req, res) => {
    try {
        const query = `
            SELECT 
                mascotas.id, 
                mascotas.nombre, 
                mascotas.especie, 
                mascotas.raza, 
                mascotas.sexo, 
                mascotas.color, 
                mascotas.fecha_nacimiento, 
                mascotas.edad, 
                mascotas.procedencia, 
                mascotas.chip, 
                propietarios.nombre AS propietario_nombre
            FROM mascotas
            LEFT JOIN propietarios ON mascotas.propietario_id = propietarios.id
        `;

        const [results] = await db.query(query);
        res.status(200).json(results);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener las mascotas' });
    }
});


/**
 * Registrar una nueva mascota
 */
router.post('/api/mascotas', async (req, res) => {
    try {
        const { nombre, especie, raza, sexo, color, fecha_nacimiento, edad, procedencia, chip, propietario_id } = req.body;
        if (!nombre || !especie || !raza || !sexo || !fecha_nacimiento || !edad || !procedencia) {
            return res.status(400).json({ error: 'Todos los campos son obligatorios' });
        }

        const [result] = await db.query(
            'INSERT INTO mascotas (nombre, especie, raza, sexo, color, fecha_nacimiento, edad, procedencia, chip, propietario_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [nombre, especie, raza, sexo, color, fecha_nacimiento, edad, procedencia, chip, propietario_id || null]
        );
        res.status(201).json({ message: 'Mascota registrada exitosamente', mascotaId: result.insertId });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al registrar la mascota' });
    }
});

//Obtener Mascota por id
router.get('/api/mascotas/:id', async (req, res) => {
    try {
        const { id } = req.params;

        // 🔹 Consulta con JOIN para obtener todos los datos de la mascota + propietario
        const [result] = await db.query(
            `SELECT 
                m.id AS mascota_id, 
                m.nombre AS mascota_nombre, 
                m.especie, 
                m.raza, 
                m.sexo, 
                m.color, 
                m.fecha_nacimiento, 
                m.edad, 
                m.propietario_id,
                p.nombre AS propietario_nombre
             FROM mascotas m
             JOIN propietarios p ON m.propietario_id = p.id
             WHERE m.id = ?`, 
            [id]
        );

        if (result.length === 0) {
            return res.status(404).json({ error: 'Mascota no encontrada' });
        }

        res.status(200).json(result[0]); // 🔹 Devuelve todos los datos correctamente
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener la mascota' });
    }
});


router.get('/api/lista-mascotas', async (req, res) => {
    try {
        const [results] = await db.query('SELECT id, nombre FROM mascotas');
        res.status(200).json(results);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener la lista de mascotas' });
    }
});



// Actualizar una mascota por ID sin modificar el nombre
router.put('/api/editar-mascotas/:id', async (req, res) => {
    const { id } = req.params;
    const { especie, raza, sexo, color, fecha_nacimiento, edad, propietario_id } = req.body;

    try {
        const [result] = await db.query(
            `UPDATE mascotas SET 
            especie = ?, raza = ?, sexo = ?, color = ?, 
            fecha_nacimiento = ?, edad = ?, propietario_id = ? WHERE id = ?`,
            [especie, raza, sexo, color, fecha_nacimiento, edad, propietario_id, id]
        );

        if (result.affectedRows > 0) {
            res.status(200).json({ message: "Mascota actualizada correctamente" });
        } else {
            res.status(404).json({ error: "Mascota no encontrada" });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error al actualizar la mascota" });
    }
});

// 📌 Eliminar Mascota por ID
router.delete("/eliminar/mascotas/:id", async (req, res) => {
    const { id } = req.params;

    try {
        // 🔹 Verificar si la mascota existe
        const [result] = await db.query("SELECT * FROM mascotas WHERE id = ?", [id]);

        if (result.length === 0) {
            return res.status(404).json({ message: "Mascota no encontrada" });
        }

        // 🔹 Eliminar mascota
        await db.query("DELETE FROM mascotas WHERE id = ?", [id]);

        return res.status(200).json({ message: "✅ Mascota eliminada correctamente" });
    } catch (error) {
        console.error("❌ Error al eliminar mascota:", error);
        return res.status(500).json({ message: "❌ Error interno del servidor" });
    }
});
// ==================== HISTORIAS CLÍNICAS ====================
/**
 * Obtener todas las historias clínicas
 */
router.get('/api/historias_clinicas', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM historias_clinicas');
        res.status(200).json(results);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener las historias clínicas' });
    }
});


// Ruta para registrar historias clínicas
router.post("/api/historias_clinicas", async (req, res) => {
    try {
      const {
        mascota_id,
        fecha,
        vacunacion_tipo,
        vacunacion_fecha,
        desparasitacion_producto,
        desparasitacion_fecha,
        estado_reproductivo,
        alimentacion,
        habitat,
        alergias,
        cirugias,
        antecedentes,
        EnfermedadesAnteriores,
        observaciones,
        veterinario_id,
      } = req.body;
  
      // Validar campos obligatorios
      if (!mascota_id || !fecha || !estado_reproductivo || !alimentacion || !habitat || !veterinario_id) {
        return res.status(400).json({ error: "Faltan campos obligatorios." });
      }
  
      // SQL para insertar los datos en la tabla
      const query = `
        INSERT INTO historias_clinicas (
          mascota_id,
          fecha,
          vacunacion_tipo,
          vacunacion_fecha,
          desparasitacion_producto,
          desparasitacion_fecha,
          estado_reproductivo,
          alimentacion,
          habitat,
          alergias,
          cirugias,
          antecedentes,
          EnfermedadesAnteriores,
          observaciones,
          veterinario_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;
  
      // Ejecutar consulta a la base de datos
      const [result] = await db.query(query, [
        mascota_id,
        fecha,
        vacunacion_tipo || null,
        vacunacion_fecha || null,
        desparasitacion_producto || null,
        desparasitacion_fecha || null,
        estado_reproductivo,
        alimentacion,
        habitat,
        alergias || null,
        cirugias || null,
        antecedentes || null,
        EnfermedadesAnteriores || null,
        observaciones || null,
        veterinario_id,
      ]);
  
      // Respuesta en caso de éxito
      res.status(201).json({
        message: "Historia clínica registrada exitosamente.",
        historia_clinica_id: result.insertId,
      });
    } catch (error) {
      console.error("Error al registrar la historia clínica:", error);
      res.status(500).json({ error: "Error al registrar la historia clínica." });
    }
  });
    
  router.get("/api/historia_clinica/:mascotaId", async (req, res) => {
    const { mascotaId } = req.params;
    try {
        const [result] = await db.query(`
            SELECT hc.id AS historia_id, hc.*, v.nombre AS veterinario
            FROM historias_clinicas hc
            JOIN usuarios v ON hc.veterinario_id = v.id
            WHERE hc.mascota_id = ?
        `, [mascotaId]);

        if (result.length > 0) {
            res.status(200).json(result); // Devuelve todas las historias clínicas de la mascota
        } else {
            res.status(404).json({ error: "No se encontraron historias clínicas para esta mascota." });
        }
    } catch (error) {
        console.error("Error al obtener la historia clínica:", error);
        res.status(500).json({ error: "Error al obtener la historia clínica." });
    }
});


router.get("/api/historia_clinica_detalle/:id", async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await db.query(`
            SELECT hc.id AS historia_id, hc.*, v.nombre AS veterinario
            FROM historias_clinicas hc
            JOIN usuarios v ON hc.veterinario_id = v.id
            WHERE hc.id = ?
        `, [id]);

        if (result.length > 0) {
            res.status(200).json(result[0]);
        } else {
            res.status(404).json({ error: "No se encontró la historia clínica." });
        }
    } catch (error) {
        console.error("Error al obtener la historia clínica:", error);
        res.status(500).json({ error: "Error al obtener la historia clínica." });
    }
});


router.get("/api/historia_clinica/:mascotaId", async (req, res) => {
    const { mascotaId } = req.params;
    try {
        const [result] = await db.query(`
            SELECT hc.id AS historia_id, hc.fecha, hc.vacunacion_tipo, hc.vacunacion_fecha,
                hc.desparasitacion_producto, hc.desparasitacion_fecha, hc.estado_reproductivo, 
                hc.alimentacion, hc.habitat, hc.alergias, hc.cirugias, hc.antecedentes, 
                hc.EnfermedadesAnteriores, hc.observaciones, hc.veterinario_id, v.nombre AS veterinario
            FROM historias_clinicas hc
            JOIN usuarios v ON hc.veterinario_id = v.id
            WHERE hc.mascota_id = ?
        `, [mascotaId]);

        if (result.length > 0) {
            res.status(200).json(result);
        } else {
            res.status(404).json({ error: "No se encontraron historias clínicas para esta mascota." });
        }
    } catch (error) {
        console.error("Error al obtener las historias clínicas:", error);
        res.status(500).json({ error: "Error al obtener las historias clínicas." });
    }
});


router.put("/api/historia_clinica/:id", async (req, res) => {
    const { id } = req.params;
    const {
        fecha,
        vacunacion_tipo,
        vacunacion_fecha,
        desparasitacion_producto,
        desparasitacion_fecha,
        estado_reproductivo,
        alimentacion,
        habitat,
        alergias,
        cirugias,
        antecedentes,
        EnfermedadesAnteriores,
        observaciones,
        veterinario_id,
    } = req.body;

    try {
        const query = `
            UPDATE historias_clinicas SET
                fecha = ?,
                vacunacion_tipo = ?,
                vacunacion_fecha = ?,
                desparasitacion_producto = ?,
                desparasitacion_fecha = ?,
                estado_reproductivo = ?,
                alimentacion = ?,
                habitat = ?,
                alergias = ?,
                cirugias = ?,
                antecedentes = ?,
                EnfermedadesAnteriores = ?,
                observaciones = ?,
                veterinario_id = ?
            WHERE id = ?
        `;

        const [result] = await db.query(query, [
            fecha,
            vacunacion_tipo || null,
            vacunacion_fecha || null,
            desparasitacion_producto || null,
            desparasitacion_fecha || null,
            estado_reproductivo,
            alimentacion,
            habitat,
            alergias || null,
            cirugias || null,
            antecedentes || null,
            EnfermedadesAnteriores || null,
            observaciones || null,
            veterinario_id,
            id,
        ]);

        if (result.affectedRows > 0) {
            res.status(200).json({ message: "Historia clínica actualizada correctamente." });
        } else {
            res.status(404).json({ error: "No se encontró la historia clínica para actualizar." });
        }
    } catch (error) {
        console.error("Error al actualizar la historia clínica:", error);
        res.status(500).json({ error: "Error al actualizar la historia clínica." });
    }
});




// Endpoint para actualizar una historia clínica completa
router.put("/api/historia_clinica/:id", async (req, res) => {
    const { id } = req.params;
    const {
        fecha, vacunacion_tipo, vacunacion_fecha, desparasitacion_producto, desparasitacion_fecha,
        estado_reproductivo, alimentacion, habitat, alergias, cirugias, antecedentes, 
        EnfermedadesAnteriores, observaciones, veterinario_id
    } = req.body;

    try {
        const query = `
            UPDATE historias_clinicas SET
                fecha = ?, vacunacion_tipo = ?, vacunacion_fecha = ?, 
                desparasitacion_producto = ?, desparasitacion_fecha = ?, 
                estado_reproductivo = ?, alimentacion = ?, habitat = ?, 
                alergias = ?, cirugias = ?, antecedentes = ?, 
                EnfermedadesAnteriores = ?, observaciones = ?, veterinario_id = ?
            WHERE id = ?
        `;

        const [result] = await db.query(query, [
            fecha, vacunacion_tipo || null, vacunacion_fecha || null, 
            desparasitacion_producto || null, desparasitacion_fecha || null, 
            estado_reproductivo, alimentacion, habitat, 
            alergias || null, cirugias || null, antecedentes || null, 
            EnfermedadesAnteriores || null, observaciones || null, veterinario_id, id
        ]);

        if (result.affectedRows > 0) {
            res.status(200).json({ message: "Historia clínica actualizada correctamente." });
        } else {
            res.status(404).json({ error: "No se encontró la historia clínica para actualizar." });
        }
    } catch (error) {
        console.error("Error al actualizar la historia clínica:", error);
        res.status(500).json({ error: "Error al actualizar la historia clínica." });
    }
});

router.delete("/api/historia_clinica/:id", async (req, res) => {
    const { id } = req.params;
    try {
        // Verificar si la historia clínica existe
        const [exist] = await db.query("SELECT * FROM historias_clinicas WHERE id = ?", [id]);
        if (exist.length === 0) {
            return res.status(404).json({ error: "No se encontró la historia clínica a eliminar." });
        }

        // Eliminar la historia clínica
        const [result] = await db.query("DELETE FROM historias_clinicas WHERE id = ?", [id]);

        if (result.affectedRows > 0) {
            res.status(200).json({ message: "Historia clínica eliminada correctamente." });
        } else {
            res.status(500).json({ error: "Error al eliminar la historia clínica." });
        }
    } catch (error) {
        console.error("Error al eliminar la historia clínica:", error);
        res.status(500).json({ error: "Error interno al eliminar la historia clínica." });
    }
});

router.delete("/api/examen_clinico/:id", async (req, res) => {
    const { id } = req.params;
    try {
        // Verificar si la historia clínica existe
        const [exist] = await db.query("SELECT * FROM examenes_clinicos WHERE id = ?", [id]);
        if (exist.length === 0) {
            return res.status(404).json({ error: "No se encontró el examen clínico a eliminar." });
        }

        // Eliminar la historia clínica
        const [result] = await db.query("DELETE FROM examenes_clinicos WHERE id = ?", [id]);

        if (result.affectedRows > 0) {
            res.status(200).json({ message: "Examen clínico eliminada correctamente." });
        } else {
            res.status(500).json({ error: "Error al eliminar el examen clinico." });
        }
    } catch (error) {
        console.error("Error al eliminar el examen clinico:", error);
        res.status(500).json({ error: "Error interno al eliminar el examen clinico" });
    }
});
  
// Endpoint para obtener la lista de veterinarios
router.get("/api/veterinarios", async (req, res) => {
    try {
        const [results] = await db.query(
            "SELECT id, nombre FROM usuarios WHERE rol = 'veterinario'"
        );
        res.json(results);
    } catch (error) {
        console.error("Error al obtener veterinarios:", error);
        res.status(500).json({ error: "Error al obtener veterinarios" });
    }
});

router.get("/api/mascotasHistorial", async (req, res) => {
    try {
        const query = `
            SELECT id, nombre 
            FROM mascotas
        `;

        const [results] = await db.query(query); // Ya no necesitas usar db.promise()
        res.status(200).json(results);
    } catch (error) {
        console.error("Error al obtener las mascotas:", error);
        res.status(500).json({ error: "Error al obtener las mascotas" });
    }
});


router.get('/api/propietariosHistorial', async (req, res) => {
    try {
        const [results] = await db.query('SELECT id, nombre FROM propietarios');
        res.json(results);
    } catch (error) {
        console.error('Error al obtener los propietarios:', error);
        res.status(500).json({ error: 'Error al obtener los propietarios' });
    }
});

/* CONSULTA Y 
REGISTRO DE EXAMENES CLINICOS */
router.get('/api/examenes_clinicos', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM examenes_clinicos');
        res.status(200).json(results);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener los examenes clinicos' });
    } 
});

router.post('/api/examenes_clinicos', async (req, res) => {
    try {
        const {
            mascota_id,
            fecha,
            actitud,
            condicion_corporal,
            hidratacion,
            observaciones,
            mucosa_conjuntiva,
            mucosa_conjuntiva_observaciones,
            mucosa_oral,
            mucosa_oral_observaciones,
            mucosa_vulvar_prepu,
            mucosa_vulvar_prepu_observaciones,
            mucosa_rectal,
            mucosa_rectal_observaciones,
            mucosa_ojos,
            mucosa_ojos_observaciones,
            mucosa_oidos,
            mucosa_oidos_observaciones,
            mucosa_nodulos,
            mucosa_nodulos_observaciones,
            mucosa_piel_anexos,
            mucosa_piel_anexos_observaciones,
            locomocion_estado,
            locomocion_observaciones,
            musculo_estado,
            musculo_observaciones,
            nervioso_estado,
            nervioso_observaciones,
            cardiovascular_estado,
            cardiovascular_observaciones,
            respiratorio_estado,
            respiratorio_observaciones,
            digestivo_estado,
            digestivo_observaciones,
            genitourinario_estado,
            genitourinario_observaciones,
        } = req.body;

        // Validación de campos obligatorios
        if (!mascota_id || !fecha || !actitud || !condicion_corporal || !hidratacion) {
            return res.status(400).json({ error: 'Faltan campos obligatorios.' });
        }

        // Consulta SQL para insertar datos
        const query = `
        INSERT INTO examenes_clinicos (
            mascota_id,
            fecha,
            actitud,
            condicion_corporal,
            hidratacion,
            observaciones,
            mucosa_conjuntiva,
            mucosa_conjuntiva_observaciones,
            mucosa_oral,
            mucosa_oral_observaciones,
            mucosa_vulvar_prepu,
            mucosa_vulvar_prepu_observaciones,
            mucosa_rectal,
            mucosa_rectal_observaciones,
            mucosa_ojos,
            mucosa_ojos_observaciones,
            mucosa_oidos,
            mucosa_oidos_observaciones,
            mucosa_nodulos,
            mucosa_nodulos_observaciones,
            mucosa_piel_anexos,
            mucosa_piel_anexos_observaciones,
            locomocion_estado,
            locomocion_observaciones,
            musculo_estado,
            musculo_observaciones,
            nervioso_estado,
            nervioso_observaciones,
            cardiovascular_estado,
            cardiovascular_observaciones,
            respiratorio_estado,
            respiratorio_observaciones,
            digestivo_estado,
            digestivo_observaciones,
            genitourinario_estado,
            genitourinario_observaciones
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
        const [result] = await db.query(query, [
            mascota_id,
    fecha,
    actitud,
    condicion_corporal,
    hidratacion,
    observaciones || null,
    mucosa_conjuntiva || null,
    mucosa_conjuntiva_observaciones || null,
    mucosa_oral || null,
    mucosa_oral_observaciones || null,
    mucosa_vulvar_prepu || null,
    mucosa_vulvar_prepu_observaciones || null,
    mucosa_rectal || null,
    mucosa_rectal_observaciones || null,
    mucosa_ojos || null,
    mucosa_ojos_observaciones || null,
    mucosa_oidos || null,
    mucosa_oidos_observaciones || null,
    mucosa_nodulos || null,
    mucosa_nodulos_observaciones || null,
    mucosa_piel_anexos || null,
    mucosa_piel_anexos_observaciones || null,
    locomocion_estado || null,
    locomocion_observaciones || null,
    musculo_estado || null,
    musculo_observaciones || null,
    nervioso_estado || null,
    nervioso_observaciones || null,
    cardiovascular_estado || null,
    cardiovascular_observaciones || null,
    respiratorio_estado || null,
    respiratorio_observaciones || null,
    digestivo_estado || null,
    digestivo_observaciones || null,
    genitourinario_estado || null,
    genitourinario_observaciones || null,
        ]);

        res.status(201).json({
            message: 'Examen clínico registrado con éxito.',
            examen_clinico_id: result.insertId,
        });
    } catch (error) {
        console.error('Error al registrar el examen clínico:', error);
        res.status(500).json({ error: 'Error al registrar el examen clínico.' });
    }
});

router.get("/api/examen_clinico/:mascotaId", async (req, res) => {
    const { mascotaId } = req.params;
    try {
        const [result] = await db.query(`
            SELECT ec.*, m.nombre AS mascota_nombre
            FROM examenes_clinicos ec
            JOIN mascotas m ON ec.mascota_id = m.id
            WHERE ec.mascota_id = ?
        `, [mascotaId]);

        if (result.length > 0) {
            res.status(200).json(result);
        } else {
            res.status(404).json({ error: "No se encontraron exámenes clínicos para esta mascota." });
        }
    } catch (error) {
        console.error("Error al obtener los exámenes clínicos:", error);
        res.status(500).json({ error: "Error interno al obtener los exámenes clínicos." });
    }
});

router.get("/api/examen_clinico_detalle/:id", async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await db.query(`
            SELECT * FROM examenes_clinicos WHERE id = ?
        `, [id]);

        if (result.length > 0) {
            res.status(200).json(result[0]);
        } else {
            res.status(404).json({ error: "No se encontró el examen clínico." });
        }
    } catch (error) {
        console.error("Error al obtener el examen clínico:", error);
        res.status(500).json({ error: "Error interno al obtener el examen clínico." });
    }
});

router.put("/api/examen_clinico/:id", async (req, res) => {
    const { id } = req.params;
    const {
        fecha,
        actitud,
        condicion_corporal,
        hidratacion,
        observaciones,
        mucosa_conjuntiva,
        mucosa_conjuntiva_observaciones,
        mucosa_oral,
        mucosa_oral_observaciones,
        mucosa_vulvar_prepu,
        mucosa_vulvar_prepu_observaciones,
        mucosa_rectal,
        mucosa_rectal_observaciones,
        mucosa_ojos,
        mucosa_ojos_observaciones,
        mucosa_oidos,
        mucosa_oidos_observaciones,
        mucosa_nodulos,
        mucosa_nodulos_observaciones,
        mucosa_piel_anexos,
        mucosa_piel_anexos_observaciones,
        locomocion_estado,
        locomocion_observaciones,
        musculo_estado,
        musculo_observaciones,
        nervioso_estado,
        nervioso_observaciones,
        cardiovascular_estado,
        cardiovascular_observaciones,
        respiratorio_estado,
        respiratorio_observaciones,
        digestivo_estado,
        digestivo_observaciones,
        genitourinario_estado,
        genitourinario_observaciones
    } = req.body;

    try {
        const query = `
            UPDATE examenes_clinicos
            SET fecha = ?, actitud = ?, condicion_corporal = ?, hidratacion = ?, observaciones = ?, 
                mucosa_conjuntiva = ?, mucosa_conjuntiva_observaciones = ?, mucosa_oral = ?, mucosa_oral_observaciones = ?, 
                mucosa_vulvar_prepu = ?, mucosa_vulvar_prepu_observaciones = ?, mucosa_rectal = ?, mucosa_rectal_observaciones = ?, 
                mucosa_ojos = ?, mucosa_ojos_observaciones = ?, mucosa_oidos = ?, mucosa_oidos_observaciones = ?, 
                mucosa_nodulos = ?, mucosa_nodulos_observaciones = ?, mucosa_piel_anexos = ?, mucosa_piel_anexos_observaciones = ?, 
                locomocion_estado = ?, locomocion_observaciones = ?, musculo_estado = ?, musculo_observaciones = ?, 
                nervioso_estado = ?, nervioso_observaciones = ?, cardiovascular_estado = ?, cardiovascular_observaciones = ?, 
                respiratorio_estado = ?, respiratorio_observaciones = ?, digestivo_estado = ?, digestivo_observaciones = ?, 
                genitourinario_estado = ?, genitourinario_observaciones = ?
            WHERE id = ?
        `;

        await db.query(query, [
            fecha, actitud, condicion_corporal, hidratacion, observaciones, 
            mucosa_conjuntiva, mucosa_conjuntiva_observaciones, mucosa_oral, mucosa_oral_observaciones, 
            mucosa_vulvar_prepu, mucosa_vulvar_prepu_observaciones, mucosa_rectal, mucosa_rectal_observaciones, 
            mucosa_ojos, mucosa_ojos_observaciones, mucosa_oidos, mucosa_oidos_observaciones, 
            mucosa_nodulos, mucosa_nodulos_observaciones, mucosa_piel_anexos, mucosa_piel_anexos_observaciones, 
            locomocion_estado, locomocion_observaciones, musculo_estado, musculo_observaciones, 
            nervioso_estado, nervioso_observaciones, cardiovascular_estado, cardiovascular_observaciones, 
            respiratorio_estado, respiratorio_observaciones, digestivo_estado, digestivo_observaciones, 
            genitourinario_estado, genitourinario_observaciones, id
        ]);

        res.status(200).json({ message: "Examen clínico actualizado correctamente." });
    } catch (error) {
        console.error("Error al actualizar el examen clínico:", error);
        res.status(500).json({ error: "Error interno al actualizar el examen clínico." });
    }
});



// 📌 API para obtener todas las citas
router.get('/api/citas', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM citas_veterinarias');
        res.status(200).json(results);
    } catch (error) {
        console.error('Error al obtener las citas:', error);
        res.status(500).json({ error: 'Error al obtener las citas' });
    }
});

// 📌 Registrar una nueva cita con mascota_id
router.post('/api/citas', async (req, res) => {
    try {
        const { fecha_hora, motivo, propietario_id, veterinario_id, mascota_id } = req.body;

        if (!fecha_hora || !motivo || !propietario_id || !veterinario_id || !mascota_id) {
            return res.status(400).json({ error: "Todos los campos son obligatorios." });
        }

        const query = `
            INSERT INTO citas_veterinarias (fecha_hora, motivo, propietario_id, veterinario_id, mascota_id)
            VALUES (?, ?, ?, ?, ?)
        `;
        const values = [fecha_hora, motivo, propietario_id, veterinario_id, mascota_id];

        const [result] = await db.query(query, values);

        res.status(201).json({ message: "Cita registrada exitosamente", citaId: result.insertId });
    } catch (error) {
        console.error("Error al registrar la cita:", error);
        res.status(500).json({ error: "Error interno del servidor" });
    }
});




// 📌 API para eliminar una cita
router.delete('/api/citas/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await db.query('DELETE FROM citas_veterinarias WHERE id = ?', [id]);
        res.status(200).json({ message: 'Cita eliminada correctamente' });
    } catch (error) {
        console.error('Error al eliminar la cita:', error);
        res.status(500).json({ error: 'Error al eliminar la cita' });
    }
});

// 📌 Obtener todos los veterinarios para las citas 
router.get('/api/veterinarios_cita', async (req, res) => {
    try {
        const [results] = await db.query(
            'SELECT id, nombre, COALESCE(celular, "Sin teléfono") AS celular FROM usuarios WHERE rol = "veterinario"'
        );
        res.status(200).json(results);
    } catch (error) {
        console.error('Error al obtener veterinarios:', error);
        res.status(500).json({ error: 'Error al obtener los veterinarios' });
    }
});
// 📌 Obtener todos los propietarios para las citas 
router.get('/api/propietarios_cita', async (req, res) => {
    try {
        const [results] = await db.query('SELECT id, nombre, celular FROM propietarios');
        res.status(200).json(results);
    } catch (error) {
        console.error('Error al obtener propietarios:', error);
        res.status(500).json({ error: 'Error al obtener los propietarios' });
    }
});

// 📌 Obtener todas las mascotas con su ID y nombre (citas)
router.get('/api/mascotas_citas', async (req, res) => {
    try {
        const [results] = await db.query('SELECT id, nombre, propietario_id FROM mascotas');
        res.status(200).json(results);
    } catch (error) {
        console.error('Error al obtener mascotas:', error);
        res.status(500).json({ error: 'Error al obtener las mascotas' });
    }
});

// 📌 Obtener todas las citas con detalles completos
router.get("/api/ver_citas", async (req, res) => {
    try {
        const [results] = await db.query(`
            SELECT c.id, c.fecha_hora, c.motivo, 
                   m.nombre AS mascota, 
                   p.nombre AS propietario, 
                   p.celular AS propietario_celular, 
                   v.nombre AS veterinario
            FROM citas_veterinarias c
            JOIN mascotas m ON c.mascota_id = m.id
            JOIN propietarios p ON c.propietario_id = p.id
            JOIN usuarios v ON c.veterinario_id = v.id
            ORDER BY c.fecha_hora ASC
        `);
        
        console.log("Citas cargadas desde la API:", results); // 🔍 Verifica los datos en consola
        res.status(200).json(results);
    } catch (error) {
        console.error("Error al obtener citas:", error);
        res.status(500).json({ error: "Error al obtener las citas." });
    }
});

// 📌 Obtener una cita específica por su ID
router.get("/api/ver_cita/:id", async (req, res) => {
    const { id } = req.params;

    try {
        const [results] = await db.query(`
            SELECT c.id, c.fecha_hora, c.motivo, 
                   m.id AS mascota_id, m.nombre AS mascota, 
                   p.id AS propietario_id, p.nombre AS propietario, p.celular AS propietario_celular, 
                   v.id AS veterinario_id, v.nombre AS veterinario, v.celular AS veterinario_celular
            FROM citas_veterinarias c
            JOIN mascotas m ON c.mascota_id = m.id
            JOIN propietarios p ON c.propietario_id = p.id
            JOIN usuarios v ON c.veterinario_id = v.id
            WHERE c.id = ?
        `, [id]);

        if (results.length > 0) {
            res.status(200).json(results[0]); // Retornar la cita encontrada
        } else {
            res.status(404).json({ error: "❌ Cita no encontrada." });
        }
    } catch (error) {
        console.error("Error al obtener la cita:", error);
        res.status(500).json({ error: "❌ Error al obtener la cita." });
    }
});


// 📌 Actualizar todos los campos de una cita
router.put("/api/editar_cita/:id", async (req, res) => {
    const { id } = req.params;
    const { fecha_hora, motivo, veterinario_id } = req.body; // 📌 Solo los datos editables

    try {
        const [result] = await db.query(
            `UPDATE citas_veterinarias 
            SET fecha_hora = ?, motivo = ?, veterinario_id = ? 
            WHERE id = ?`,
            [fecha_hora, motivo, veterinario_id, id]
        );

        if (result.affectedRows > 0) {
            res.status(200).json({ message: "✅ Cita actualizada correctamente." });
        } else {
            res.status(404).json({ error: "❌ Cita no encontrada." });
        }
    } catch (error) {
        console.error("Error al actualizar la cita:", error);
        res.status(500).json({ error: "❌ Error al actualizar la cita." });
    }
});


module.exports = router;
