
const bcrypt = require('bcryptjs');
const salt = bcrypt.genSaltSync(10);

const hashPassword = (password) => {
    return bcrypt.hashSync(password, salt);
};

const verifyPasswords = (password, passwordHashed) => {
    return bcrypt.compareSync(password, passwordHashed);
};

require('dotenv').config();
const jwt = require('jsonwebtoken');
const { JWT_SECRET, JWT_TIME } = process.env;

const signToken = (data) => {
    return jwt.sign(
        data,
        String(JWT_SECRET),
        {
            algorithm: 'HS256',
            expiresIn: JWT_TIME
        }
    );
};

const verifyToken = (token) => {
    try {
        const decoded = jwt.verify(token, String(JWT_SECRET));
        return { valid: true, decoded };
    } catch (err) {
        return { valid: false, message: 'Invalid token' };
    }
};

const decodeToken = (token) => {
    return jwt.decode(token);
};

const getHeadersToken = (req) => {
    const Authorization = req.header('Authorization');
    return Authorization.split('Bearer ')[1];
};

const validaEmail = (email) => {
    const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
};

const ERROR_MESSAGES = {
    TRIP_NOT_FOUND: {
        id: 'NoEncontrado',
        statusCode: 404,
        message: 'NoEncontrado',
        description: 'NoEncontrado',
    },
    SERVER_ERROR: {
        id: 'serverError',
        statusCode: 500,
        message: 'Internal server error. Please try again later',
        description: 'Unexpected server error',
    },
    USER_NOT_FOUND: {
        id: 'userNotFound',
        statusCode: 404,
        message: 'User not found',
        description: 'The user does not exist in the system',
    }
};

module.exports = {
    hashPassword,
    verifyPasswords,
    signToken,
    verifyToken,
    decodeToken,
    getHeadersToken,
    validaEmail,
    ERROR_MESSAGES
};
