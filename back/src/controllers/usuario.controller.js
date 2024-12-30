
const { hashPassword, verifyPasswords } = require('../helpers/helpers')
const { signToken, verifyToken, decodeToken, getHeadersToken } = require('../helpers/helpers')
const usuarios = require('../models/usuarios')
const { validaEmail } = require('../helpers/helpers')

const nuevoRegistro = async (req, res, next) => {

    try {

        const { email, password, rol, lenguage } = req.body;

        if (!validaEmail(email)) {
            return res.status(400).json({ error: 'Formato de correo inválido' });
        }

        if (!password) {
            return res.status(400).json({ error: 'Password inválida' });
        }

        if (!rol || rol === 'Seleccione un rol') {
            return res.status(400).json({ error: 'Rol inválido' });
        }

        if (!lenguage || lenguage === 'Seleccione un Lenguage') {
            return res.status(400).json({ error: 'Lenguage inválido' });
        }

        const passwordHashed = hashPassword(password)
        const nuevoUsuario = await usuarios.nuevoRegistro(email, passwordHashed, rol, lenguage)

        res.send(nuevoUsuario)

    } catch (error) {
        next(error)
    }
}


const Login = async (req, res, next) => {

    try {
        const { email, password } = req.body

        if (!validaEmail(email)) {
            return res.status(400).json({ error: 'Formato de correo inválido' });
        }

        if (!password) {

            return res.status(400).json({ error: 'password inválido' });
        }

        const registroUsuario = await usuarios.verificaCredenciales(email)
        if (!registroUsuario) {

            return res.status(400).json({ error: 'Correo NO Registrado' });
        }

        const match = verifyPasswords(password, registroUsuario.password)

        if (match) {
            const data = {
                email
            }

            const token = signToken(data)
            
            res.status(200).json({
                token,
                email: registroUsuario.email,
                rol: registroUsuario.rol,
                lenguage: registroUsuario.lenguage
            });

        } else {
            res.send('Password incorrecto')
        }
    } catch (error) {
        next(error)
    }
}

const datosUsuario = async (req, res, next) => {

    try {

        const token = getHeadersToken(req)

        const result = verifyToken(token);
        if (!result.valid) {
            return res.status(401).json({ error: result.message });
        }

        const { email } = decodeToken(token)


        const registroUsuario = await usuarios.verificaCredenciales(email)

        res.status(200).json([{
            email: registroUsuario.email,
            rol: registroUsuario.rol,
            lenguage: registroUsuario.lenguage
        }]);

    } catch (error) {
                if (error.name === 'TokenExpiredError') {
            console.error('TokenExpiredError: jwt expired');
            return res.status(401).json({ error: 'TokenExpiredError: jwt expired' });
        }
        next(error);
    }
}


module.exports = {
    nuevoRegistro, Login, datosUsuario
}
