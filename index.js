require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const routes = require("./routes"); // Importa tus rutas

const app = express();

app.use(cors());
app.use(bodyParser.json());

// Usar las rutas
app.use(routes);

const PORT = 5000;

app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
