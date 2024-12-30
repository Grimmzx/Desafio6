
const fs = require('fs');
const path = require('path');

const registrarConsulta = (req, res, next) => {

    const logDir = path.join(__dirname, '..', 'logs');
    const logFilePath = path.join(logDir, 'consultas.log');


    if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir);
    }

    const token = req.headers['authorization'];
    const body = req.body;

    let log = "";

    if (!token) {
        log += `Ruta consultada: ${req.originalUrl} ; Método: ${req.method} ; Fecha: ${new Date().toISOString()} ; Ruta sin credenciales\n`;
    } else {
        log += `Ruta consultada: ${req.originalUrl} ; Método: ${req.method} ; Fecha: ${new Date().toISOString()} ; Ruta con credenciales: ${token}\n`;
    }

    if (Object.keys(body).length > 0) {
        log += `Ruta consultada: ${req.originalUrl} ; Método: ${req.method} ; Fecha: ${new Date().toISOString()} ; Parametros Body :  ${JSON.stringify(body)} \n`;
    }

    console.log(log)

    fs.appendFile(logFilePath, log, (err) => {
        if (err) {
            console.error('Error al registrar la consulta:', err);
        }
    });

    next();
};

const registrarRespuesta = (req, res, next) => {

    const logDir = path.join(__dirname, '..', 'logs');
    const logFilePath = path.join(logDir, 'consultas.log');

    if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir);
    }

    const originalSend = res.send;
    res.send = function (body) {

        const responseBody = typeof body === 'object' ? JSON.stringify(body) : body;

        const log = `Ruta: ${req.originalUrl} ; Método: ${req.method} ; Fecha: ${new Date().toISOString()} ; Respuesta: ${responseBody}\n`;
        console.log(log)

        fs.appendFile(logFilePath, log, (err) => {
            if (err) {
                console.error('Error al registrar la respuesta:', err);
            }
        });
        return originalSend.apply(this, arguments);
    };

    next();
};


module.exports = { registrarConsulta, registrarRespuesta }