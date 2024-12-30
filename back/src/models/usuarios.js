
const { DB } = require("../config/db")
const format = require('pg-format')


const existeCorreo = async (email) => {
    try {
        const SQLQuery = format(`
            SELECT * FROM usuarios
            WHERE email = %L`,
            email
        );

        const { rowCount } = await DB.query(SQLQuery);

        return rowCount > 0;

    } catch (error) {
        throw error;
    }
}

const nuevoRegistro = async (email, passwordHashed, rol, lenguaje) => {
    try {

        const correoExiste = await existeCorreo(email);

        if (correoExiste) {
            return { error: 'Correo ya registrado.' };
        }

        const SQLQuery = format(`
            INSERT INTO usuarios
            VALUES (DEFAULT, %L, %L, %L, %L) RETURNING *`,
            email,
            passwordHashed,
            rol,
            lenguaje
        );

        const { rows: [user] } = await DB.query(SQLQuery);

        return user;

    } catch (error) {
        throw error;
    }
}

const verificaCredenciales = async (email) => {
    try {

        const correoExiste = await existeCorreo(email);

        if (!correoExiste) {

            return null;
        }

        const SQLQuery = format(`
            SELECT * FROM usuarios
            WHERE email = %L`,
            email
        );

        const {rows} = await DB.query(SQLQuery)

        return rows[0]

    } catch (error) {
        throw error
    }
}


module.exports = {
    nuevoRegistro, verificaCredenciales
}